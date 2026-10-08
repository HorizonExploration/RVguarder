"""实际Node快照证明与当前宿主精确授权互通，尚不进入裁决。"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import hmac
import threading
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from test_native_content_receipts import native_producer, run_producer
from openclaw_guard.engine import experiment_components as ec
from openclaw_guard.spec.content_receipts import ContentReceiptError, _canonical
from openclaw_guard.spec.execution_proposals import HostExecutionProposalVerifier


def fixture_call(native_producer, *, tool="office_message_send", **options):
    """执行真实工具代码并取得其执行前证明、原参数及实际本地效果。"""
    authority, config = native_producer
    config["snapshotExecution"] = True
    params = {"recipient": "partner@example.test", "sourcePath": "note.txt"}
    if tool == "office_network_post":
        params = {"url": "https://partner.example.test/upload", "sourcePath": "note.txt"}
    elif tool == "office_document_share":
        params["document"] = "note.txt"
    result = run_producer(config, tool, params, **options)
    event = SimpleNamespace(raw_payload={"params": params}, metadata={"hook_auth_verified": True,
        "hook_auth_binding": "binding", "agent_id": "agent", "session_id": "session", "run_id": "run", "tool_call_id": "call"})
    step = {"event_model": "tool-call-v1", "execution_state": "proposed", "tool_name": tool,
            "operation_family": authority.tool_operations[tool], "effects": ["egress"]}
    return HostExecutionProposalVerifier(authority), result, event, step


@pytest.mark.parametrize("tool", ["office_message_send", "office_network_post", "office_document_share"])
def test_actual_node_proposal_matches_consumed_snapshot(native_producer, tool):
    """三个实际工具的证明版本等于换文件后仍消费的固定版本。"""
    verifier, result, event, step = fixture_call(native_producer, tool=tool, replaceContent="changed")
    proof = verifier.verify(result["proposal"], event=event, step=step)
    assert proof.source.sha256 == result["sideEffect"]["sourceSha256"] == hashlib.sha256("真实内容\n".encode()).hexdigest()
    assert proof.recipient == result["sideEffect"]["recipient"]
    diagnostic = verifier.inspect_authorization(result["proposal"], event=event, step=step)
    # fixture只签发message授权；其他有限操作不得复用它。
    assert diagnostic["snapshot_grant_match"] is (tool == "office_message_send")
    assert diagnostic["decision_eligible"] is False
    assert diagnostic["execution_state"] == "proposed"


@pytest.mark.parametrize("field", ["agent_id", "session_id", "run_id", "tool_call_id", "hook_auth_binding"])
def test_proposal_cannot_cross_call_scope(native_producer, field):
    """签名合法也不能把证明关联到其他原生调用上下文。"""
    verifier, result, event, step = fixture_call(native_producer)
    event.metadata[field] = "other"
    with pytest.raises(ContentReceiptError):
        verifier.verify(result["proposal"], event=event, step=step)


def test_forged_proposal_and_changed_recipient_parameters_are_rejected(native_producer):
    """工具自报授权、改签名负载或检查后换接收方不能通过。"""
    verifier, result, event, step = fixture_call(native_producer)
    bad = deepcopy(result["proposal"])
    bad["payload"]["recipient"] = "attacker@example.test"
    with pytest.raises(ContentReceiptError):
        verifier.verify(bad, event=event, step=step)
    event.raw_payload["params"]["recipient"] = "attacker@example.test"
    with pytest.raises(ContentReceiptError):
        verifier.verify(result["proposal"], event=event, step=step)


def test_success_receipt_and_proposal_are_not_interchangeable(native_producer):
    """真实成功收据不能充当未来计划，未来计划不能提交成功历史。"""
    verifier, result, event, step = fixture_call(native_producer)
    with pytest.raises(ValidationError):
        verifier.verify(result["result"]["details"]["rvExecutionReceipt"], event=event, step=step)
    with pytest.raises(ValidationError):
        verifier.authority.verify(result["proposal"], event=event, step={**step, "execution_state": "succeeded"})
    with pytest.raises(ContentReceiptError):
        verifier.verify(result["proposal"], event=event, step={**step, "execution_state": "succeeded"})


def test_expired_revoked_or_legally_signed_wrong_task_proposal_is_rejected(native_producer):
    """签名不替代TTL、撤销和唯一任务关联。"""
    verifier, result, event, step = fixture_call(native_producer)
    envelope = result["proposal"]
    with patch("openclaw_guard.spec.execution_proposals.time.time", return_value=envelope["payload"]["expires_at_ms"] / 1000):
        with pytest.raises(ContentReceiptError):
            verifier.verify(envelope, event=event, step=step)
    bad = deepcopy(envelope)
    bad["payload"]["task_id"] = "wrong"
    bad["signature"] = hmac.new(verifier.authority._key, _canonical(bad["payload"]), hashlib.sha256).hexdigest()
    with pytest.raises(ContentReceiptError):
        verifier.verify(bad, event=event, step=step)
    verifier.authority._store.revoke(verifier.authority._store.query()[0]["id"])
    with pytest.raises(ContentReceiptError):
        verifier.verify(envelope, event=event, step=step)


def test_auth_disabled_does_not_verify_or_query(native_producer):
    """Full-Auth关闭时完全不核验，也不访问宿主存储。"""
    verifier, result, event, step = fixture_call(native_producer)
    with ec.using(ec.ExperimentComponents(authorization=False)), patch.object(verifier, "verify") as verify:
        assert verifier.inspect_authorization(result["proposal"], event=event, step=step)["status"] == "disabled"
        verify.assert_not_called()


def test_proposal_memory_provider_never_reads_changed_file(native_producer):
    """get证明只使用已准备的私有快照；替换文件不改版本或授予新版本。"""
    verifier, result, event, step = fixture_call(native_producer, replaceContent="changed")
    assert verifier.inspect_authorization(result["proposal"], event=event, step=step)["snapshot_grant_match"]
    assert result["sideEffect"]["sourceSha256"] != hashlib.sha256(b"changed").hexdigest()


@pytest.mark.parametrize("field,value", [("recipient", "other@example.test"),
    ("sha256", "0" * 64), ("resource_id", "office:another.txt")])
def test_even_legally_signed_different_scope_has_no_grant_match(native_producer, field, value):
    """受控执行器合法签名仍不能替代精确接收方、资源ID和内容版本授权。"""
    verifier, result, event, step = fixture_call(native_producer)
    bad = deepcopy(result["proposal"])
    if field == "recipient":
        bad["payload"][field] = value
    else:
        bad["payload"]["source"][field] = value
    bad["signature"] = hmac.new(verifier.authority._key, _canonical(bad["payload"]), hashlib.sha256).hexdigest()
    assert not verifier.inspect_authorization(bad, event=event, step=step)["snapshot_grant_match"]


@pytest.mark.parametrize("options", [{"eventContext": {"agentId": "wrong"}},
    {"eventContext": {"sessionId": "wrong"}}, {"contextOverrides": {"runId": "wrong"}},
    {"contextOverrides": {"toolCallId": "wrong"}}, {"reverseConflict": True}])
def test_conflicting_sdk_fields_cannot_sign_another_identity(native_producer, options):
    """event/context任一身份字段冲突，强执行契约拒绝且无首次副作用。"""
    _, config = native_producer
    config["snapshotExecution"] = True
    result = run_producer(config, "office_message_send", {"recipient": "partner@example.test", "sourcePath": "note.txt"}, **options)
    assert "snapshot" in result["error"]
    assert result["sideEffectExists"] is False


def test_host_bridge_verifies_proposal_only_in_background(native_producer):
    """认证before只冻结提交，后台才查询签名授权；已变文件引用不替换快照。"""
    from openclaw_guard.integrations.host_authorization_bridge import HostAuthorizationBridge
    from openclaw_guard.spec.resource_evidence import HostResourceObserver
    verifier, result, event, step = fixture_call(native_producer, replaceContent="changed")
    event.event_id = "event"
    event.raw_payload["executionProposal"] = result["proposal"]
    event.metadata.update(hook_bridge=True, trusted_identity={"binding": "hook_token",
        "principal_id": "hook:binding", "agent_id": "agent"})
    bridge = HostAuthorizationBridge(verifier.authority._store,
        HostResourceObserver({"office": native_producer[1]["workspaceRoot"]}),
        tool_namespaces={"office_message_send": "office"})
    bridge.execution_proposal_verifier = verifier
    original = verifier.inspect_authorization
    threads = []
    def inspect(*args, **kwargs):
        threads.append(threading.get_ident())
        return original(*args, **kwargs)
    try:
        with patch.object(verifier, "inspect_authorization", side_effect=inspect):
            assert bridge.submit(event, step)["status"] == "pending_reference_observation"
            bridge._queue.join()
        diagnostic = bridge.reference_evidence("event")
        assert not diagnostic["reference_grant_match"] # 旁路当前文件已经变化。
        assert diagnostic["execution_proposal"]["snapshot_grant_match"]
        assert diagnostic["execution_proposal"]["decision_eligible"] is False
        assert threads and threading.get_ident() not in threads
    finally:
        bridge.close()


@pytest.mark.parametrize("policy_effect", ["allow", "ask"])
def test_matching_proposal_diagnostic_cannot_suppress_independent_rv_block(native_producer, policy_effect):
    """真实DSL根据成功历史独立block，不依赖PMKB block，也不被诊断授权降低。"""
    from test_rv_tool_call_model import project
    from openclaw_guard.rv.runtime_verification import RuntimeVerificationEngine
    from openclaw_guard.engine.pipeline import _apply_rv_if_available
    verifier, result, event, step = fixture_call(native_producer)
    diagnostic = verifier.inspect_authorization(result["proposal"], event=event, step=step)
    assert diagnostic["snapshot_grant_match"]
    engine = RuntimeVerificationEngine(window_ttl_seconds=None)
    read = project("read", {"path": "/workspace/secret.txt"}, labels=["contains_secret"], call_id="read")
    read["execution_state"] = "succeeded"
    engine.evaluate([read], session_key="session_session")
    send = project("office_message_send", event.raw_payload["params"], labels=["external_recipient"], call_id="call")
    send["context"]["host_authorization"] = {"execution_proposal": diagnostic}
    rv = engine.preview([send], session_key="session_session", policy_decision={"effect": policy_effect})
    assert rv["verdict"] == "block"
    assert rv["hard_block_evidence"] == "rv_rule_match"
    assert rv["downgrade_reason"] is None
    assert read["step_id"] in rv["matched_history_step_ids"]
    event.metadata["rv_trace"] = [send]
    decision = SimpleNamespace(action=policy_effect, reason="single step policy", rule_ids=[],
                               policy_decision={"effect": policy_effect})
    applied = _apply_rv_if_available(SimpleNamespace(rv_enabled=lambda: True, rv_engine=engine), event, decision)
    assert applied.action == "block"
    assert applied.reason.startswith("[RV]")
