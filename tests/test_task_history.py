"""宿主跨会话关联的隔离、持久恢复、撤销与确切版本反例。"""
from __future__ import annotations

from dataclasses import replace

import pytest

from openclaw_guard.spec.content_receipts import ContentReceipt, ContentReceiptError, HostContentReceiptAuthority, content_version
from openclaw_guard.spec.host_authorization import HostAuthorizationError, HostAuthorizationStore, TaskBinding
from openclaw_guard.spec.resource_evidence import HostResourceObserver
from openclaw_guard.spec.task_history import HostTaskHistory


@pytest.fixture
def history(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "source.txt").write_bytes(b"synthetic secret")
    store = HostAuthorizationStore(tmp_path / "private", agent_workspaces=[workspace])
    source = TaskBinding("task", "principal", "agent", "session-1", "run-1")
    target = replace(source, session_id="session-2", run_id="run-2")
    observer = HostResourceObserver({"office": workspace})
    for binding in (source, target):
        store.issue(observer, "office", "source.txt", binding=binding, operation="file.read", recipient="local")
    authority = HostContentReceiptAuthority(store, issuer="executor", tool_operations={"read": "file.read"})
    service = HostTaskHistory(store, authority)
    version = content_version("office", "source.txt", b"synthetic secret")
    link = service.register([source, target], sensitive_versions=[version.model_dump(mode="json")])
    envelope = authority.issue(binding=source, tool_call_id="read-1", tool_name="read", kind="read",
                               inputs=[version], outputs=[], arguments={"path": "source.txt"})
    receipt = ContentReceipt.model_validate(envelope["payload"])
    service.record_verified(envelope, receipt)
    return service, source, target, version, link, envelope, receipt


def test_exact_byte_copy_survives_restart_and_is_idempotent(history):
    service, _, target, version, _, envelope, receipt = history
    assert service.record_verified(envelope, receipt)["status"] == "duplicate"
    restarted = HostTaskHistory(service.store, service.authority)
    renamed = version.model_copy(update={"resource_id": "office:renamed.txt"})
    facts = restarted.sensitive_history(target, renamed)
    assert len(facts) == 1 and facts[0]["step_id"] == "run-1:read-1"
    assert facts[0]["relationship"] == "exact_consumed_byte_identity"


@pytest.mark.parametrize("field,value", [("task_id", "unrelated"), ("principal_id", "other"),
    ("agent_id", "other"), ("session_id", "unregistered"), ("run_id", "wrong")])
def test_other_context_does_not_inherit_sensitive_history(history, field, value):
    service, _, target, version, *_ = history
    assert service.sensitive_history(replace(target, **{field: value}), version) == []


def test_changed_bytes_and_same_session_are_not_cross_history(history):
    service, source, target, version, *_ = history
    assert not service.sensitive_history(target, content_version("office", "source.txt", b"public"))
    assert not service.sensitive_history(source, version)


def test_revoked_link_is_not_restored_as_active(history):
    service, _, target, version, link, *_ = history
    assert service.revoke(link["id"])
    assert not HostTaskHistory(service.store, service.authority).sensitive_history(target, version)


def test_expired_link_and_receipt_are_not_reused(history, monkeypatch):
    service, _, target, version, link, *_ = history
    monkeypatch.setattr("openclaw_guard.spec.task_history.time.time", lambda: link["expires_at"] + 1)
    assert not service.sensitive_history(target, version)


def test_signature_tampering_cannot_restore_success(history):
    service, _, target, version, *_ = history
    with service.store._connect() as db:
        db.execute("UPDATE content_history SET envelope=replace(envelope, 'synthetic', 'forged')")
        # Alter a signed canonical resource ID while retaining a well-formed record.
        db.execute("UPDATE content_history SET envelope=replace(envelope, 'source.txt', 'forged.txt')")
    with pytest.raises(ContentReceiptError):
        service.sensitive_history(target, version)


def test_registration_never_joins_different_agents(history):
    service, source, target, version, *_ = history
    with pytest.raises(HostAuthorizationError):
        service.register([source, replace(target, agent_id="other")], sensitive_versions=[version.model_dump(mode="json")])


def test_ambiguous_context_resolves_to_no_task(history):
    service, source, target, version, *_ = history
    service.register([replace(source, task_id="second"), replace(target, task_id="second")],
                     sensitive_versions=[version.model_dump(mode="json")])
    assert service.resolve_task_binding(principal_id=target.principal_id, agent_id=target.agent_id,
                                       session_id=target.session_id, run_id=target.run_id) is None


def test_reregistering_a_revoked_link_does_not_resurrect_old_read(history):
    service, source, target, version, link, *_ = history
    service.revoke(link["id"])
    service.register([source, target], sensitive_versions=[version.model_dump(mode="json")])
    assert not service.sensitive_history(target, version)


def test_later_classification_does_not_retroactively_attach_old_read(history):
    service, source, target, version, link, envelope, receipt = history
    with service.store._connect() as db:
        db.execute("DELETE FROM content_history")
    service.revoke(link["id"])
    other = content_version("office", "different.txt", b"other secret")
    service.register([source, target], sensitive_versions=[other.model_dump(mode="json")])
    assert service.record_verified(envelope, receipt)["status"] == "unlinked_or_unclassified_read"
    service.register([source, target], sensitive_versions=[version.model_dump(mode="json")])
    assert not service.sensitive_history(target, version)


def test_revoked_links_release_active_capacity(history):
    service, source, target, version, link, *_ = history
    service.capacity = 1
    with pytest.raises(HostAuthorizationError):
        service.register([source, target], sensitive_versions=[version.model_dump(mode="json")])
    service.revoke(link["id"])
    assert service.register([source, target], sensitive_versions=[version.model_dump(mode="json")])["id"] != link["id"]


def test_successful_revocation_invalidates_the_prepared_read_lease(history):
    """撤销与短决策租约串行；撤销成功后纯内存事实不再活跃。"""
    import threading
    import time
    from openclaw_guard.spec.task_history import HostHistoryLease
    service, _, _, _, link, *_ = history
    lease = HostHistoryLease(service, [link["id"]], expires_at_ms=int(time.time() * 1000) + 1000)
    revoked = threading.Event()
    worker = threading.Thread(target=lambda: (service.revoke(link["id"]), revoked.set()))
    worker.start()
    try:
        assert not revoked.wait(0.03)
        assert lease.is_active()
        lease.release()
        assert revoked.wait(1)
        assert not lease.is_active()
    finally:
        lease.release()
        worker.join(timeout=2)


def test_observed_read_access_never_establishes_consumed_byte_identity(history):
    """原生脱敏访问只能触发访问风险守卫，不能触发精确字节守卫。"""
    import hashlib
    import hmac
    from openclaw_guard.spec.content_receipts import _canonical
    from openclaw_guard.spec.read_access_receipts import NativeReadAccessReceipt
    service, _, target, version, _, _, receipt = history
    with service.store._connect() as db:
        db.execute('DELETE FROM content_history')
    payload = receipt.model_dump(mode='json')
    payload.update(kind='read_access', inputs=[], accessed_resource=version.model_dump(mode='json'),
                   observation='observed_before_after', details_content_sha256=hashlib.sha256(b'[REDACTED]').hexdigest(),
                   details_content_size_bytes=len(b'[REDACTED]'))
    access = NativeReadAccessReceipt.model_validate(payload)
    envelope = {'payload':payload, 'signature':hmac.new(service.authority._key,_canonical(payload),hashlib.sha256).hexdigest()}
    service.record_verified(envelope,access)
    assert not service.sensitive_history(target,version)
    witnesses = service.sensitive_history(target,version,require_same_bytes=False)
    assert witnesses[0]['relationship']=='same_task_sensitive_read_capability'
    assert witnesses[0]['source_observation']=='observed_before_after'
