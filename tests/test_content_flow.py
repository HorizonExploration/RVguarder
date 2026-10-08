"""无需列举攻击链的有限调用内容关系组合、隔离和失效验证。"""
from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from openclaw_guard.spec.content_flow import VerifiedContentFlow
from openclaw_guard.spec.content_receipts import ContentReceiptError, ExecutedContentLedger, HostContentReceiptAuthority, content_version
from openclaw_guard.spec.host_authorization import HostAuthorizationStore, TaskBinding
from openclaw_guard.spec.resource_evidence import HostResourceObserver


@pytest.fixture
def flow(tmp_path):
    """登记任务，并仅通过真实签名成功提交生成内容边。"""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "source.txt").write_bytes(b"source bytes")
    store = HostAuthorizationStore(tmp_path / "host", agent_workspaces=[workspace])
    binding = TaskBinding("task", "hook:binding", "agent", "session", "run")
    grant = store.issue(HostResourceObserver({"office": workspace}), "office", "source.txt", binding=binding,
                        operation="file.write", recipient="local-destination")
    authority = HostContentReceiptAuthority(store, issuer="producer", tool_operations={"write": "file.write"})
    ledger = ExecutedContentLedger(authority)
    def commit(call, source, output, kind="transform", identity=binding):
        params = {"path": output.resource_id}
        envelope = authority.issue(binding=identity, tool_call_id=call, tool_name="write", kind=kind,
                                   inputs=[source], outputs=[output], arguments=params)
        event = SimpleNamespace(raw_payload={"params": params}, metadata={"hook_auth_verified": True,
            "hook_auth_binding": "binding", "agent_id": identity.agent_id, "session_id": identity.session_id,
            "run_id": identity.run_id, "tool_call_id": call})
        ledger.commit(envelope, event=event, step={"event_model": "tool-call-v1", "tool_name": "write",
                      "operation_family": "file.write", "effects": ["write", "transform"], "execution_state": "succeeded"})
    return VerifiedContentFlow(ledger), ledger, binding, grant, commit


def test_unlisted_copy_transform_copy_path_has_signed_finite_call_witnesses(flow):
    """复制→未知变换→复制自动组合来源关系，不需要攻击链名称/规则。"""
    graph, ledger, binding, grant, commit = flow
    source = content_version("office", "source.txt", b"source bytes")
    staging = content_version("office", "stage.txt", b"source bytes")
    transformed = content_version("office", "bundle.bin", b"derived bytes")
    output = content_version("office", "public-summary.txt", b"derived bytes")
    commit("copy-in", source, staging, "copy")
    commit("unknown-transform", staging, transformed)
    commit("copy-out", transformed, output, "copy")
    result = graph.ancestors(output, binding=binding)
    assert {node["resource_id"] for node in result["ancestors"]} == {source.resource_id, staging.resource_id, transformed.resource_id}
    assert {item["tool_call_id"] for item in result["witnesses"]} == {"copy-in", "unknown-transform", "copy-out"}
    assert len(ledger.snapshot()) == 3
    assert result["classification_evidence"] == "not_provided"


def test_same_name_different_content_or_namespace_does_not_inherit_edges(flow):
    """文件名、相同hash或公开标签不能跨资源版本/命名空间建立关系。"""
    graph, ledger, binding, grant, commit = flow
    source = content_version("office", "source.txt", b"source bytes")
    output = content_version("office", "public.txt", b"derived")
    commit("transform", source, output)
    for target in (content_version("office", "public.txt", b"changed"), content_version("other", "public.txt", b"derived")):
        assert graph.ancestors(target, binding=binding)["ancestors"] == []


@pytest.mark.parametrize("field", ["task_id", "agent_id", "session_id", "run_id", "principal_id"])
def test_content_relations_do_not_cross_wrong_identity(flow, field):
    """不同任务、Agent、session/run、认证主体不复用签名内容关系。"""
    graph, ledger, binding, grant, commit = flow
    source = content_version("office", "source.txt", b"source bytes")
    output = content_version("office", "out.txt", b"derived")
    commit("transform", source, output)
    result = graph.ancestors(output, binding=replace(binding, **{field: "other"}))
    assert result["status"] == "untrusted_task"
    assert result["ancestors"] == []


def test_revocation_and_receipt_expiry_remove_reusable_relations(flow):
    """旧成功记录保留审计；任务撤销/收据过期后不作为可复用关系。"""
    graph, ledger, binding, grant, commit = flow
    source = content_version("office", "source.txt", b"source bytes")
    output = content_version("office", "out.txt", b"derived")
    commit("transform", source, output)
    expiry = ledger.snapshot()[0]["expires_at_ms"] / 1000
    with patch("openclaw_guard.spec.content_flow.time.time", return_value=expiry):
        assert graph.ancestors(output, binding=binding)["ancestors"] == []
    ledger.authority._store.revoke(grant["id"])
    assert graph.ancestors(output, binding=binding)["status"] == "untrusted_task"
    assert len(ledger.snapshot()) == 1


def test_cycles_terminate_and_runless_query_is_refused(flow):
    """循环关系不生成无限调用或自祖先，尚不支持跨run复用。"""
    graph, ledger, binding, grant, commit = flow
    first = content_version("office", "a.txt", b"a")
    second = content_version("office", "b.txt", b"b")
    commit("a-to-b", first, second)
    commit("b-to-a", second, first)
    result = graph.ancestors(first, binding=binding)
    assert len(result["ancestors"]) == 1
    assert len(result["witnesses"]) == 2
    with pytest.raises(ContentReceiptError):
        graph.ancestors(first, binding=replace(binding, run_id=""))
