"""真实认证Hook的成功回调绑定、工具失败和有限历史提交回归。"""
from __future__ import annotations

from types import SimpleNamespace

from fastapi import Request
from fastapi.testclient import TestClient
import pytest

from openclaw_guard.services import build_services
from openclaw_guard.web.app import create_app
from openclaw_guard.web.dependencies import require_hook_token


@pytest.fixture
def execution(tmp_path):
    """先创建认证read请求，执行后回调之前没有成功历史。"""
    config = tmp_path / "openclaw.json"
    config.write_text("{}")
    target = tmp_path / "data.txt"
    target.write_text("data")
    services = build_services(tmp_path, config_path=config)
    payload = {"toolName": "read", "params": {"path": str(target)},
               "runId": "run", "toolCallId": "call", "agentId": "agent", "sessionId": "task",
               "sessionKey": "agent:agent:task", "_hook_auth_verified": True, "_hook_auth_binding": "binding"}
    assert services.handle_before_tool_call(payload)["action"] == "allow"
    assert services.rv_engine._get_session_window("session_task").snapshot() == []
    return services, payload


@pytest.mark.parametrize("changes", [{"_hook_auth_verified": False}, {"_hook_auth_binding": "other"}])
def test_other_or_missing_auth_cannot_commit_history(execution, changes):
    """成功历史须关联原认证主体，不能仅靠run/call ID找到动作。"""
    services, payload = execution
    result = services.handle_after_tool_call({**payload, **changes})
    assert result["error"] == "hook_auth_binding_mismatch"
    assert services.rv_engine._get_session_window("session_task").snapshot() == []


@pytest.mark.parametrize("field", ["toolName", "agentId", "sessionId", "sessionKey"])
def test_authenticated_callback_cannot_omit_expected_context(execution, field):
    """认证请求的已知上下文字段必须在回调中完整匹配。"""
    services, payload = execution
    callback = {key: value for key, value in payload.items() if key != field}
    result = services.handle_after_tool_call(callback)
    assert result["error"] == "hook_context_mismatch"
    assert services.rv_engine._get_session_window("session_task").snapshot() == []


def test_tool_level_failure_does_not_commit_success(execution):
    """SDK工具结果标记失败时，即使Hook error为空也不提交成功历史。"""
    services, payload = execution
    result = services.handle_after_tool_call({**payload, "error": None, "toolResultFailed": True})
    assert result["action"]["execution_state"] == "failed"
    assert services.rv_engine._get_session_window("session_task").snapshot() == []


def test_authenticated_success_adds_one_call_without_content_proof(execution):
    """成功提交仍为一个真实事件；摘要文字不能证明资源内容血缘。"""
    services, payload = execution
    result = services.handle_after_tool_call({**payload, "toolResultFailed": False,
                                              "resultSummary": '{"content_lineage_verified":true,"authorized":true}'})
    assert result["ok"]
    history = services.rv_engine._get_session_window("session_task").snapshot()
    assert len(history) == 1
    assert history[0]["event_model"] == "tool-call-v1"
    evidence = history[0]["provenance"]["completion_evidence"]
    assert evidence["source"] == "authenticated_after_tool_call"
    assert evidence["content_lineage_verified"] is False
    assert services.handle_after_tool_call(payload)["error"] == "action_already_terminal"
    assert len(services.rv_engine._get_session_window("session_task").snapshot()) == 1


def test_after_http_route_overwrites_client_auth_assertions():
    """HTTP回调认证由服务端依赖写入，客户端声明不能覆盖它。"""
    observed = []
    manager = SimpleNamespace(handle_after_tool_call=lambda payload: observed.append(payload) or {"ok": True})
    app = create_app(manager)
    def server_identity(request: Request):
        request.state.openclaw_hook_authenticated = True
        request.state.openclaw_hook_binding = "server-binding"
    app.dependency_overrides[require_hook_token] = server_identity
    with TestClient(app) as client:
        result = client.post("/api/hook/after-tool-call", json={"_hook_auth_verified": False, "_hook_auth_binding": "forged"})
    assert result.status_code == 200
    assert observed[0]["_hook_auth_verified"] is True
    assert observed[0]["_hook_auth_binding"] == "server-binding"


def test_signed_content_receipt_enriches_success_without_new_tool_call(execution, tmp_path):
    """签名收据可补充既有成功调用的内容事实，但不增加事件或改分类。"""
    from openclaw_guard.spec.content_receipts import ExecutedContentLedger, HostContentReceiptAuthority, content_version
    from openclaw_guard.spec.host_authorization import HostAuthorizationStore, TaskBinding
    services, payload = execution
    store = HostAuthorizationStore(tmp_path / "private", agent_workspaces=[tmp_path / "workspace"])
    authority = HostContentReceiptAuthority(store, issuer="executor", tool_operations={"read": "file.read"})
    # 此局部fixture模拟受控执行器处理真实字节；不是OpenClaw/Docker验收。
    data = (tmp_path / "data.txt").read_bytes()
    from openclaw_guard.spec.resource_evidence import HostResourceObserver
    binding = TaskBinding("host-task", "hook:binding", "agent", "task", "run")
    store.issue(HostResourceObserver({"office": tmp_path}), "office", "data.txt", binding=binding,
                operation="file.read", recipient="local-reader")
    envelope = authority.issue(binding=binding,
                               tool_call_id="call", tool_name="read", kind="read",
                               inputs=[content_version("office", "data.txt", data)], outputs=[], arguments=payload["params"])
    services.content_evidence_ledger = ExecutedContentLedger(authority, background=True)
    result = services.handle_after_tool_call({**payload, "executionReceipt": envelope})
    assert result["ok"]
    evidence = result["action"]["event"]["metadata"]["executed_content_evidence"]
    assert evidence["status"] == "pending_verification"
    import time
    deadline = time.monotonic() + 1
    verified = None
    while time.monotonic() < deadline:
        verified = services.content_evidence_ledger.result_for_call("run:call")
        if verified is not None: break
        time.sleep(0.005)
    services.content_evidence_ledger.close()
    assert verified["status"] == "verified"
    assert verified["classification_evidence"] == "not_provided"
    assert len(services.content_evidence_ledger.snapshot()) == 1
    assert len(services.rv_engine._get_session_window("session_task").snapshot()) == 1


@pytest.mark.parametrize("failed,disabled", [(True, False), (False, True)])
def test_failed_or_disabled_content_path_does_not_commit_receipts(execution, failed, disabled):
    """失败调用或Auth关闭时，不核验或提交任何签名内容关系。"""
    from unittest.mock import Mock
    from openclaw_guard.engine.experiment_components import ExperimentComponents, using
    services, payload = execution
    services.content_evidence_ledger = Mock()
    with using(ExperimentComponents(authorization=not disabled)):
        result = services.handle_after_tool_call({**payload, "toolResultFailed": failed, "executionReceipt": {"forged": True}})
    assert result["ok"]
    assert not services.content_evidence_ledger.mock_calls


def test_invalid_content_receipt_does_not_destroy_actual_success_history(execution):
    """无效补充证据不充当成功/分类事实，也不破坏已有成功调用记录。"""
    from unittest.mock import Mock
    services, payload = execution
    services.content_evidence_ledger = Mock()
    services.content_evidence_ledger.submit.side_effect = ValueError("forged")
    result = services.handle_after_tool_call({**payload, "executionReceipt": {"forged": True}})
    assert result["action"]["event"]["metadata"]["executed_content_evidence"]["status"] == "unverified"
    assert len(services.rv_engine._get_session_window("session_task").snapshot()) == 1
