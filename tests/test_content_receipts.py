"""受控执行器签名内容证据的范围、血缘及失败反例验收。"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from openclaw_guard.spec.content_receipts import ContentReceiptError, ExecutedContentLedger, HostContentReceiptAuthority, content_version
from openclaw_guard.spec.host_authorization import HostAuthorizationStore, TaskBinding


@pytest.fixture
def producer(tmp_path):
    """私有签发器与真实读取字节；不把参数中的hash当作证据。"""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "source.txt"
    source.write_bytes(b"actual content")
    store = HostAuthorizationStore(tmp_path / "host", agent_workspaces=[workspace])
    authority = HostContentReceiptAuthority(store, issuer="executor", tool_operations={"read": "file.read", "write": "file.write"})
    binding = TaskBinding("task", "hook:binding", "agent", "session", "run")
    from openclaw_guard.spec.resource_evidence import HostResourceObserver
    store.issue(HostResourceObserver({"office": workspace}), "office", "source.txt", binding=binding,
                operation="file.read", recipient="local-reader")
    version = content_version("office", "source.txt", source.read_bytes())
    envelope = authority.issue(binding=binding, tool_call_id="call", tool_name="read", kind="read", inputs=[version], outputs=[], arguments={"path": "source.txt"})
    event = SimpleNamespace(raw_payload={"params": {"path": "source.txt"}}, metadata={"hook_auth_verified": True, "hook_auth_binding": "binding", "agent_id": "agent",
                                      "session_id": "session", "run_id": "run", "tool_call_id": "call"})
    step = {"tool_name": "read", "operation_family": "file.read", "effects": ["read"],
            "event_model": "tool-call-v1", "execution_state": "succeeded"}
    return authority, binding, version, envelope, event, step


def test_success_receipt_records_actual_bytes_without_classification_or_new_call(producer):
    """成功内容证据只补充当前调用，不证明公开分类或额外调用。"""
    authority, binding, version, envelope, event, step = producer
    ledger = ExecutedContentLedger(authority)
    result = ledger.commit(envelope, event=event, step=step)
    assert result["status"] == "verified"
    assert result["inputs"][0]["sha256"] == version.sha256
    assert result["classification_evidence"] == "not_provided"
    assert not result["content_lineage_verified"]
    assert len(ledger.snapshot()) == 1
    assert step["effects"] == ["read"]


def test_previous_arm_records_are_invisible_after_disable_and_reenable(producer):
    """旧臂已完成事实不能在再次启用Auth的新臂中被查询或关联。"""
    from openclaw_guard.engine import experiment_components as ec
    authority, _, _, envelope, event, step = producer
    ledger = ExecutedContentLedger(authority)
    try:
        ledger.commit(envelope, event=event, step=step)
        assert len(ledger.snapshot()) == 1
        ec.configure(ec.ExperimentComponents(authorization=False))
        assert ledger.snapshot() == []
        with patch.object(authority, "verify") as verify:
            assert ledger.commit(envelope, event=event, step=step)["status"] == "disabled"
            verify.assert_not_called()
        ec.reset()
        assert ledger.snapshot() == []
        assert ledger.commit(envelope, event=event, step=step)["status"] == "verified"
        assert len(ledger.snapshot()) == 1
    finally:
        ledger.close()
        ec.reset()


@pytest.mark.parametrize("mutation", ["hash", "task", "signature", "issuer"])
def test_forged_receipt_cannot_commit(producer, mutation):
    """改写hash/task/签名/签发器都使收据失效，无任何关系入表。"""
    authority, binding, version, envelope, event, step = producer
    bad = deepcopy(envelope)
    if mutation == "hash":bad["payload"]["inputs"][0]["sha256"] = "0" * 64
    elif mutation == "task":bad["payload"]["task_id"] = "other"
    elif mutation == "issuer":bad["payload"]["issuer"] = "other"
    else:bad["signature"] = "0" * 64
    ledger = ExecutedContentLedger(authority)
    with pytest.raises(ContentReceiptError):ledger.commit(bad, event=event, step=step)
    assert ledger.snapshot() == []


@pytest.mark.parametrize("field", ["agent_id", "session_id", "run_id", "tool_call_id", "hook_auth_binding"])
def test_receipt_cannot_cross_call_identity(producer, field):
    """真实签名也不能关联到其他Agent/session/run/call或认证主体。"""
    authority, binding, version, envelope, event, step = producer
    event.metadata[field] = "other"
    with pytest.raises(ContentReceiptError):ExecutedContentLedger(authority).commit(envelope, event=event, step=step)


def test_failed_or_unknown_effect_call_has_no_content_success(producer):
    """失败/未执行及未知复合效果不能借内容收据升级为成功事实。"""
    authority, binding, version, envelope, event, step = producer
    ledger = ExecutedContentLedger(authority)
    for changes in ({"execution_state": "proposed"}, {"effects": ["unknown"]}, {"effects": ["egress"]}):
        with pytest.raises(ContentReceiptError):ledger.commit(envelope, event=event, step={**step, **changes})
    assert ledger.snapshot() == []


def test_expiry_duplicate_and_conflicting_call(producer):
    """有效期严格；重复幂等，单调用的矛盾签名记录不能重复提交。"""
    authority, binding, version, envelope, event, step = producer
    with patch("openclaw_guard.spec.content_receipts.time.time", return_value=envelope["payload"]["expires_at_ms"] / 1000):
        with pytest.raises(ContentReceiptError):ExecutedContentLedger(authority).commit(envelope, event=event, step=step)
    ledger = ExecutedContentLedger(authority)
    ledger.commit(envelope, event=event, step=step)
    assert ledger.commit(envelope, event=event, step=step)["status"] == "duplicate"
    second = authority.issue(binding=binding, tool_call_id="call", tool_name="read", kind="read", inputs=[version], outputs=[], arguments={"path": "source.txt"})
    with pytest.raises(ContentReceiptError):ledger.commit(second, event=event, step=step)
    assert len(ledger.snapshot()) == 1


def test_copy_transform_and_partial_read_do_not_invent_public_content(producer):
    """复制需相同字节，部分输入不建完整血缘，变换无分类降级。"""
    authority, binding, version, envelope, event, step = producer
    output = content_version("office", "copy.txt", b"actual content")
    copy = authority.issue(binding=binding, tool_call_id="copy-call", tool_name="write", kind="copy", inputs=[version], outputs=[output], arguments={"path": "source.txt"})
    event.metadata["tool_call_id"] = "copy-call"
    step.update(tool_name="write", operation_family="file.write", effects=["write", "transform"])
    result = ExecutedContentLedger(authority).commit(copy, event=event, step=step)
    assert result["content_lineage_verified"]
    assert result["classification_evidence"] == "not_provided"
    different = content_version("office", "summary.txt", b"summary")
    with pytest.raises(ValidationError):authority.issue(binding=binding, tool_call_id="c", tool_name="write", kind="copy", inputs=[version], outputs=[different], arguments={"path": "source.txt"})
    partial = content_version("office", "source.txt", b"actual", full_resource=False)
    with pytest.raises(ValidationError):authority.issue(binding=binding, tool_call_id="c", tool_name="write", kind="transform", inputs=[partial], outputs=[different], arguments={"path": "source.txt"})
    transformed = authority.issue(binding=binding, tool_call_id="transform-call", tool_name="write", kind="transform", inputs=[version], outputs=[different], arguments={"path": "source.txt"})
    event.metadata["tool_call_id"] = "transform-call"
    result = ExecutedContentLedger(authority).commit(transformed, event=event, step=step)
    assert result["content_lineage_verified"] and result["classification_evidence"] == "not_provided"


def test_untrusted_callback_and_bounded_ledger(producer):
    """无认证不可入表；容量满不静默丢弃既有关系；快照不能改写记录。"""
    authority, binding, version, envelope, event, step = producer
    event.metadata["hook_auth_verified"] = False
    ledger = ExecutedContentLedger(authority, capacity=1)
    with pytest.raises(ContentReceiptError):ledger.commit(envelope, event=event, step=step)
    event.metadata["hook_auth_verified"] = True
    ledger.commit(envelope, event=event, step=step)
    snapshot = ledger.snapshot();snapshot[0]["task_id"] = "fake"
    assert ledger.snapshot()[0]["task_id"] == "task"
    event.metadata["tool_call_id"] = "new-call"
    second = authority.issue(binding=binding, tool_call_id="new-call", tool_name="read", kind="read", inputs=[version], outputs=[], arguments={"path": "source.txt"})
    with pytest.raises(ContentReceiptError):ledger.commit(second, event=event, step=step)


def test_changed_tool_arguments_are_not_covered_by_signed_content(producer):
    """同call的路径/接收方参数替换不能借真实旧收据建立内容证据。"""
    authority, binding, version, envelope, event, step = producer
    event.raw_payload["params"] = {"path": "other.txt", "recipient": "attacker@example.test"}
    with pytest.raises(ContentReceiptError):
        ExecutedContentLedger(authority).commit(envelope, event=event, step=step)


def test_legally_signed_wrong_task_is_rejected_by_host_task_binding(producer):
    """即使签名合法，收据task与宿主唯一任务不符也不能入表。"""
    import hashlib
    import hmac
    from openclaw_guard.spec.content_receipts import _canonical
    authority, binding, version, envelope, event, step = producer
    wrong = deepcopy(envelope)
    wrong["payload"]["task_id"] = "wrong-host-task"
    # 模拟签发器错误签名；反例不限于Agent不能改签名的简单篡改。
    wrong["signature"] = hmac.new(authority._key, _canonical(wrong["payload"]), hashlib.sha256).hexdigest()
    with pytest.raises(ContentReceiptError):
        ExecutedContentLedger(authority).commit(wrong, event=event, step=step)
    with pytest.raises(ContentReceiptError):
        authority.issue(binding=replace(binding, task_id="wrong-host-task"), tool_call_id="call", tool_name="read",
                        kind="read", inputs=[version], outputs=[], arguments={"path": "source.txt"})


def test_revoked_or_ambiguous_task_cannot_accept_old_valid_signature(producer):
    """任务撤销和宿主记录歧义使旧签名失效，不沿用旧任务关联。"""
    from openclaw_guard.spec.resource_evidence import HostResourceObserver
    authority, binding, version, envelope, event, step = producer
    store = authority._store
    grant = store.query()[0]
    store.revoke(grant["id"])
    with pytest.raises(ContentReceiptError):
        ExecutedContentLedger(authority).commit(envelope, event=event, step=step)
    workspace = store.state_dir.parent / "workspace"
    observer = HostResourceObserver({"office": workspace})
    for task in ("task", "different-task"):
        store.issue(observer, "office", "source.txt", binding=replace(binding, task_id=task), operation="file.read", recipient="local-reader")
    with pytest.raises(ContentReceiptError):
        ExecutedContentLedger(authority).commit(envelope, event=event, step=step)


def test_slow_task_database_does_not_block_success_callback_submission(producer):
    """宿主任务查询慢时，提交只入有界队列，不在回调等数据库。"""
    import threading
    import time
    authority, binding, version, envelope, event, step = producer
    event.event_id = "run:call"
    started, release = threading.Event(), threading.Event()
    original = authority._store.resolve_task_binding
    def slow_lookup(**kwargs):
        started.set()
        release.wait(timeout=3)
        return original(**kwargs)
    authority._store.resolve_task_binding = slow_lookup
    ledger = ExecutedContentLedger(authority, background=True)
    try:
        before = time.monotonic()
        assert ledger.submit(envelope, event=event, step=step)["status"] == "pending_verification"
        assert time.monotonic() - before < 0.1
        assert started.wait(timeout=1)
        assert ledger.snapshot() == []
        assert ledger.result_for_call(event.event_id) is None
        for _ in range(32):
            result = ledger.submit(envelope, event=event, step=step)
        assert result["status"] == "verification_queue_full"
    finally:
        ledger.close()
        release.set()


def test_async_receipt_and_nested_parameters_are_frozen_at_submission(producer):
    """暂停后台核验后改写调用者对象，已提交证据仍为回调时刻副本。"""
    import threading
    import time
    authority, binding, version, envelope, event, step = producer
    arguments = {"path": "source.txt", "nested": {"labels": ["original"]}}
    event.raw_payload["params"] = arguments
    event.event_id = "freeze-call"
    envelope = authority.issue(binding=binding, tool_call_id="call", tool_name="read", kind="read",
                               inputs=[version], outputs=[], arguments=arguments)
    started, release = threading.Event(), threading.Event()
    original = authority.verify
    def delayed_verify(*args, **kwargs):
        started.set()
        release.wait(timeout=2)
        return original(*args, **kwargs)
    authority.verify = delayed_verify
    ledger = ExecutedContentLedger(authority, background=True)
    try:
        ledger.submit(envelope, event=event, step=step)
        assert started.wait(timeout=1)
        arguments["nested"]["labels"][0] = "changed"
        envelope["payload"]["inputs"][0]["sha256"] = "0" * 64
        release.set()
        deadline = time.monotonic() + 1
        while ledger.result_for_call(event.event_id) is None and time.monotonic() < deadline:
            time.sleep(0.005)
        assert ledger.result_for_call(event.event_id)["status"] == "verified"
        assert ledger.snapshot()[0]["inputs"][0]["sha256"] == version.sha256
    finally:
        release.set()
        ledger.close()


def test_oversize_or_deep_json_is_rejected_before_serialization(producer):
    """巨型字符串或深结构不触发同步JSON序列化，失败仅丢可选证据。"""
    from openclaw_guard.spec.content_receipts import _freeze_bounded_json
    deep = {"child": None}
    for _ in range(40):
        deep = {"child": deep}
    for value in ({"body": "x" * 1000000}, deep, [None] * 10000):
        with patch("openclaw_guard.spec.content_receipts._canonical", side_effect=AssertionError("should not serialize")):
            with pytest.raises(ContentReceiptError):
                _freeze_bounded_json(value, 65536)


@pytest.mark.parametrize("change", ["disable", "disable_then_enable", "close"])
def test_inflight_verification_cannot_commit_after_component_switch_or_close(producer, change):
    """核验中切臂/关闭，旧臂不能提交；即使开关恢复相同也不复用旧代际。"""
    import threading
    import time
    from openclaw_guard.engine import experiment_components as ec
    authority, binding, version, envelope, event, step = producer
    event.event_id = "old-arm-call"
    started, release = threading.Event(), threading.Event()
    original = authority.verify
    def delayed_verify(*args, **kwargs):
        started.set()
        release.wait(timeout=2)
        return original(*args, **kwargs)
    authority.verify = delayed_verify
    ledger = ExecutedContentLedger(authority, background=True)
    try:
        ledger.submit(envelope, event=event, step=step)
        assert started.wait(timeout=1)
        if change == "close":
            ledger.close()
        else:
            ec.configure(ec.ExperimentComponents(authorization=False))
            if change == "disable_then_enable":
                ec.reset()
        release.set()
        deadline = time.monotonic() + 1
        while ledger.result_for_call(event.event_id) is None and time.monotonic() < deadline:
            time.sleep(0.005)
        assert ledger.result_for_call(event.event_id)["status"] == "disabled"
        assert ledger.snapshot() == []
    finally:
        release.set()
        ledger.close()
        ec.reset()
