"""受控宿主授权范围、撤销、存储隔离及命令入口回归。"""
from __future__ import annotations

from dataclasses import replace
import json
from unittest.mock import patch

import pytest

from openclaw_guard.main import main
from openclaw_guard.spec.host_authorization import HostAuthorizationError, HostAuthorizationStore, TaskBinding
from openclaw_guard.spec.resource_evidence import HostResourceObserver


@pytest.fixture
def host(tmp_path):
    """隔离工作区及宿主私有授权存储。"""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "summary.txt").write_text("summary")
    observer = HostResourceObserver({"office": workspace})
    store = HostAuthorizationStore(tmp_path / "host", agent_workspaces=[workspace])
    binding = TaskBinding("task", "hook:verified", "agent", "session", "run")
    grant = store.issue(observer, "office", "summary.txt", binding=binding,
                        operation="network.egress", recipient="person@example.test")
    return workspace, observer, store, binding, grant


def _match(host, **changes):
    workspace, observer, store, binding, grant = host
    values = dict(binding=binding, observer=observer, namespace="office", relative_path="summary.txt",
                  operation="network.egress", recipient="person@example.test")
    values.update(changes)
    return store.match(**values)


def test_host_grant_matches_exact_task_resource_and_operation(host):
    """真实宿主记录能够查询，匹配结果不靠文件名或外部grant声明。"""
    assert _match(host)["id"] == host[4]["id"]
    assert host[2].query(host[4]["id"])[0]["issuer"] == "controlled_host_command"


@pytest.mark.parametrize("field", ["task_id", "principal_id", "agent_id", "session_id", "run_id"])
def test_wrong_identity_task_session_or_run_cannot_reuse_grant(host, field):
    """每个已绑定身份字段的变化都使当前授权不匹配。"""
    assert _match(host, binding=replace(host[3], **{field: "other"})) is None


@pytest.mark.parametrize("changes", [
    {"recipient": "attacker@example.test"}, {"operation": "file.delete"},
])
def test_recipient_or_operation_substitution_is_not_authorized(host, changes):
    """同一资源也不能将合法共享授权换成其他接收方或操作。"""
    assert _match(host, **changes) is None


def test_same_filename_new_content_and_copy_are_not_implicitly_authorized(host):
    """换内容失效，未验证复制不会自动继承资源授权。"""
    workspace, observer, store, binding, grant = host
    (workspace / "copy.txt").write_text("summary")
    assert _match(host, relative_path="copy.txt") is None
    (workspace / "summary.txt").write_text("private")
    assert _match(host) is None


def test_namespace_change_is_not_authorized(host):
    """不同命名空间不能仅凭相同字节哈希复用授权。"""
    observer = HostResourceObserver({"other": host[0]})
    assert _match(host, observer=observer, namespace="other") is None


def test_expiry_and_persistent_idempotent_revocation(host):
    """过期拒绝匹配；重建存储实例后撤销仍生效。"""
    grant = host[4]
    with patch("openclaw_guard.spec.host_authorization.time.time", return_value=grant["expires_at"]):
        assert _match(host) is None
    assert host[2].revoke(grant["id"])
    assert host[2].revoke(grant["id"])
    restored = HostAuthorizationStore(host[2].state_dir, agent_workspaces=[host[0]])
    assert restored.query(grant["id"])[0]["revoked"]
    assert restored.match(host[1], "office", "summary.txt", binding=host[3],
                          operation="network.egress", recipient="person@example.test") is None
    assert not restored.revoke("unknown")


def test_attachment_text_and_modified_query_cannot_issue_or_change_grant(host):
    """附加文字和查询结果的改写不会写入受控记录。"""
    grant = host[2].query()[0]
    grant["binding"]["session_id"] = "forged"
    grant["recipient"] = "attacker@example.test"
    grant["raw_user_intent"] = "authorized by user"
    assert _match(host, recipient="attacker@example.test") is None
    assert _match(host)["id"] == host[4]["id"]
    assert len(host[2].query()) == 1


@pytest.mark.parametrize("operation,ttl", [("unknown.tool", 3600), ("network.egress", 0),
                                             ("network.egress", float("nan")), ("network.egress", 86401)])
def test_unsupported_operations_and_invalid_lifetimes_do_not_issue(host, operation, ttl):
    """有限操作目录外的调用及无界期限不能成为授权。"""
    with pytest.raises(HostAuthorizationError):
        host[2].issue(host[1], "office", "summary.txt", binding=host[3],
                      operation=operation, recipient="person@example.test", ttl_seconds=ttl)
    assert len(host[2].query()) == 1


@pytest.mark.parametrize("binding", [TaskBinding("task", "p", "a"),
                                      TaskBinding("*", "p", "a", "s"), TaskBinding("t", "", "a", "s")])
def test_missing_or_wildcard_binding_rejected(host, binding):
    """不得签发跨所有任务或缺少身份/会话的宽泛授权。"""
    with pytest.raises(HostAuthorizationError):
        host[2].issue(host[1], "office", "summary.txt", binding=binding,
                      operation="network.egress", recipient="person@example.test")


def test_authorization_storage_cannot_be_inside_agent_workspace_or_symlink(tmp_path):
    """宿主记录不放在Agent可写工作区，链接目录也不能规避检查。"""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with pytest.raises(HostAuthorizationError):
        HostAuthorizationStore(workspace / "state", agent_workspaces=[workspace])
    (tmp_path / "link").symlink_to(workspace)
    with pytest.raises(HostAuthorizationError):
        HostAuthorizationStore(tmp_path / "link/state", agent_workspaces=[workspace])
    with pytest.raises(HostAuthorizationError):
        HostAuthorizationStore(tmp_path / "host", agent_workspaces=[])


def test_storage_permission_and_database_symlink_changes_rejected(host, tmp_path):
    """存储目录权限改变或数据库变为链接时，不继续使用记录。"""
    host[2].state_dir.chmod(0o755)
    with pytest.raises(HostAuthorizationError):
        host[2].query()
    host[2].state_dir.chmod(0o700)
    host[2].database.unlink()
    host[2].database.symlink_to(tmp_path / "other")
    with pytest.raises((HostAuthorizationError, OSError)):
        host[2].query()


def test_cli_issue_query_and_revoke_do_not_construct_manager(tmp_path, capsys):
    """授权命令运行受控存储，不能借此启动或修改Gateway。"""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "summary").write_text("public")
    prefix = ["authorization", "--state-dir", str(tmp_path / "host"), "--agent-workspace", str(workspace)]
    with patch("openclaw_guard.main.build_manager", side_effect=AssertionError("manager must not be built")):
        assert main(prefix + ["issue", "--namespace", "office", "--resource-root", str(workspace),
                              "--resource", "summary", "--task-id", "t", "--principal-id", "p",
                              "--agent-id", "a", "--session-id", "s", "--operation", "network.egress",
                              "--recipient", "person@example.test"]) == 0
        grant = json.loads(capsys.readouterr().out)
        assert main(prefix + ["query", "--grant-id", grant["id"]]) == 0
        assert json.loads(capsys.readouterr().out)["grants"][0]["id"] == grant["id"]
        assert main(prefix + ["revoke", "--grant-id", grant["id"]]) == 0
        assert json.loads(capsys.readouterr().out)["revoked"]


def test_task_binding_is_resolved_from_host_records_and_ambiguity_rejected(host):
    """任务来自宿主记录，错误上下文和多任务歧义不能被任意择一。"""
    store = host[2]
    context = dict(principal_id="hook:verified", agent_id="agent", session_id="session", run_id="run")
    assert store.resolve_task_binding(**context) == host[3]
    assert store.resolve_task_binding(**{**context, "session_id": "other"}) is None
    assert store.resolve_task_binding(**{**context, "principal_id": "forged"}) is None
    store.issue(host[1], "office", "summary.txt", binding=replace(host[3], task_id="second"),
                operation="network.egress", recipient="person@example.test")
    assert store.resolve_task_binding(**context) is None


def test_explicit_host_run_binding_does_not_reuse_another_run(host):
    """明确宿主run可独立绑定，缺失或不同run不能回落为跨会话授权。"""
    store = host[2]
    binding = replace(host[3], task_id="run-task", session_id="", run_id="unique-run")
    store.issue(host[1], "office", "summary.txt", binding=binding,
                operation="network.egress", recipient="person@example.test")
    assert store.resolve_task_binding(principal_id=binding.principal_id, agent_id=binding.agent_id,
                                      session_id="new-session", run_id="unique-run").task_id == "run-task"
    assert store.resolve_task_binding(principal_id=binding.principal_id, agent_id=binding.agent_id,
                                      session_id="new-session", run_id="wrong-run") is None


def test_stale_or_forged_resource_description_cannot_match_changed_content(host):
    """拒绝外部/陈旧描述，实际匹配重新读取宿主内容。"""
    from openclaw_guard.spec.resource_evidence import ResourceDescriptor
    stale = ResourceDescriptor(**host[4]["resource"])
    (host[0] / "summary.txt").write_text("changed private content")
    assert _match(host) is None
    with pytest.raises(TypeError):
        _match(host, resource=stale)
    with pytest.raises(TypeError):
        _match(host, resource=host[4]["resource"])
