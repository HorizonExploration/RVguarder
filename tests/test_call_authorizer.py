"""后台真实签名核验器及宿主许可协议；非原生安全场景分母。"""
from __future__ import annotations

import hashlib
import hmac
from unittest.mock import patch

import pytest

from test_native_content_receipts import native_producer
from test_execution_proposals import fixture_call
from openclaw_guard.engine import experiment_components as ec
from openclaw_guard.spec.call_authorizer import HostCallAuthorizer
from openclaw_guard.spec.content_receipts import ContentReceiptError, _canonical
from openclaw_guard.spec.host_authorization import HostAuthorizationError


def prepared_fixture(native_producer):
    """登记实际宿主数据库和快照消费契约，读取实际Node签名证明。"""
    authority, config = native_producer
    config["executionEvidence"]["authorizationDatabase"] = str(authority._store.database)
    verifier, result, event, step = fixture_call(native_producer)
    step["step_id"] = "run:call"
    return HostCallAuthorizer(verifier), result["proposal"], event, step


def test_host_authorizer_produces_exact_fact_and_verifiable_execution_permit(native_producer):
    authorizer, proposal, event, step = prepared_fixture(native_producer)
    prepared = authorizer.prepare(proposal, event=event, step=step)
    assert prepared is not None
    fact = prepared.fact
    assert fact.step_id == step["step_id"] and fact.snapshot_id == proposal["payload"]["snapshot_id"]
    assert fact.recipient == "partner@example.test"
    assert fact.component_generation == ec.snapshot()[1]
    assert prepared.permit["payload"]["proposal"] == proposal["payload"]
    assert prepared.permit["signature"] == hmac.new(authorizer.verifier.authority._key, _canonical(prepared.permit["payload"]), hashlib.sha256).hexdigest()
    assert fact.expires_at_ms == prepared.permit["payload"]["expires_at_ms"]


def test_snapshot_without_live_grant_consumption_contract_cannot_issue_fact(native_producer):
    verifier, result, event, step = fixture_call(native_producer)
    step["step_id"] = "run:call"
    assert HostCallAuthorizer(verifier).prepare(result["proposal"], event=event, step=step) is None


def test_disabled_auth_does_not_access_store_or_sign(native_producer):
    authorizer, proposal, event, step = prepared_fixture(native_producer)
    with ec.using(ec.ExperimentComponents(authorization=False)), patch.object(authorizer.verifier.authority._store, "query_for_decision") as query:
        assert authorizer.prepare(proposal, event=event, step=step) is None
        query.assert_not_called()


def test_revoked_authorization_cannot_prepare_fact(native_producer):
    authorizer, proposal, event, step = prepared_fixture(native_producer)
    store = authorizer.verifier.authority._store
    store.revoke(store.query()[0]["id"])
    with pytest.raises(ContentReceiptError):
        authorizer.prepare(proposal, event=event, step=step)


def test_unauthenticated_transport_cannot_prepare_fact(native_producer):
    authorizer, proposal, event, step = prepared_fixture(native_producer)
    event.metadata["hook_auth_verified"] = False
    with pytest.raises(ContentReceiptError):
        authorizer.prepare(proposal, event=event, step=step)


def test_host_snapshot_budget_fails_conservatively(native_producer):
    authorizer, proposal, event, step = prepared_fixture(native_producer)
    with patch.object(authorizer.verifier.authority._store, "query_for_decision", side_effect=HostAuthorizationError("budget")):
        with pytest.raises(HostAuthorizationError):
            authorizer.prepare(proposal, event=event, step=step)
