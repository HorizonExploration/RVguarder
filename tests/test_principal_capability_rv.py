"""Principal/capability runtime-verification state coverage."""

from __future__ import annotations

import openclaw_guard.spec.session_state as session_state_module

from openclaw_guard.policy.models import (
    AuthorizationTrace,
    ContextRef,
    CoverageResult,
    DataRef,
    OperationRef,
    PolicyDecision,
    PrincipalRef,
    ResourceRef,
)
from openclaw_guard.rv.runtime_verification import RuntimeVerificationEngine
from openclaw_guard.spec.session_state import PrincipalSecurityState


def allow_policy() -> PolicyDecision:
    """Return the normal allow decision used before a sensitive read."""
    return PolicyDecision(effect="auto_allow_audit", match_status="matched")


def approval_policy() -> PolicyDecision:
    """Return the policy approval decision used for uncertain egress."""
    return PolicyDecision(effect="openclaw_approval", match_status="matched")


def secret_read_trace(*, session_id: str, principal_id: str = "u1") -> AuthorizationTrace:
    """Create normalized evidence for a secret read."""
    return AuthorizationTrace(
        trace_id=f"{session_id}-secret-read",
        principal=PrincipalRef(id=principal_id, type="human", trust="verified"),
        agent_id="agent1",
        session_id=session_id,
        capability_lineage=["grant1"],
        operation=OperationRef(family="secret.read"),
        resource=ResourceRef(type="path", ids=["vault"], scope="workspace"),
        coverage=CoverageResult(status="complete"),
        data=DataRef(classification="secret", quantity=1),
        context=ContextRef(recipient_zone="internal"),
    )


def external_egress_trace(*, session_id: str, principal_id: str = "u1") -> AuthorizationTrace:
    """Create normalized evidence for external egress."""
    return AuthorizationTrace(
        trace_id=f"{session_id}-external-egress",
        principal=PrincipalRef(id=principal_id, type="human", trust="verified"),
        agent_id="agent1",
        session_id=session_id,
        capability_lineage=["grant1"],
        operation=OperationRef(family="network.egress"),
        resource=ResourceRef(type="endpoint", ids=["partner.example"], scope="external"),
        coverage=CoverageResult(status="complete"),
        data=DataRef(classification="secret", quantity=1),
        context=ContextRef(recipient_zone="external"),
    )


def test_same_principal_secret_read_then_external_egress_escalates_across_sessions():
    """Removing cross-session principal state would miss the toxic secret-egress chain."""
    state = PrincipalSecurityState("u1", "agent1", ("grant1",))

    assert state.record(secret_read_trace(session_id="s1"), allow_policy()) is None
    assert state.record(external_egress_trace(session_id="s2"), approval_policy()) in {
        "block", "openclaw_approval",
    }


def test_different_principal_cannot_inherit_sensitive_lineage():
    """Collapsing state by agent or lineage would leak u1's secret read to u2."""
    state_a = PrincipalSecurityState("u1", "agent1", ("grant1",))
    state_b = PrincipalSecurityState("u2", "agent1", ("grant1",))

    state_a.record(secret_read_trace(session_id="s1"), allow_policy())

    assert state_b.record(external_egress_trace(session_id="s2", principal_id="u2"), approval_policy()) is None


def test_engine_keeps_each_principal_agent_and_lineage_key_separate():
    """Any differing identity component must select a separate principal state."""
    engine = RuntimeVerificationEngine()
    state = engine.state_for_principal("u1", "agent1", ("grant1",))

    assert engine.state_for_principal("u1", "agent1", ("grant1",)) is state
    assert engine.state_for_principal("u2", "agent1", ("grant1",)) is not state
    assert engine.state_for_principal("u1", "agent2", ("grant1",)) is not state
    assert engine.state_for_principal("u1", "agent1", ("grant2",)) is not state


def test_principal_snapshots_round_trip_without_changing_session_windows():
    """Dropping principal snapshot data would lose a cross-session chain after restart."""
    engine = RuntimeVerificationEngine()
    state = engine.state_for_principal("u1", "agent1", ("grant1",))
    state.record(secret_read_trace(session_id="s1"), allow_policy())
    engine.evaluate([{"event": "read", "props": ["file_read"]}], session_key="legacy")

    restored = RuntimeVerificationEngine()
    restored.deserialize_state(engine.serialize_state())

    assert restored.session_count() == 1
    assert restored.state_for_principal("u1", "agent1", ("grant1",)).record(
        external_egress_trace(session_id="s2"), approval_policy()
    ) in {"block", "openclaw_approval"}


def test_snapshot_ttl_survives_a_monotonic_clock_restart(monkeypatch):
    """Persisted TTL evidence must not expire only because a process restarts."""
    monkeypatch.setattr(session_state_module._time, "monotonic", lambda: 10.0)
    state = PrincipalSecurityState("u1", "agent1", ("grant1",))
    state.record(secret_read_trace(session_id="s1"), allow_policy())
    snapshot = state.to_dict()

    monkeypatch.setattr(session_state_module._time, "monotonic", lambda: 1_000.0)
    restored = PrincipalSecurityState.from_dict(snapshot)

    assert restored.record(external_egress_trace(session_id="s2"), approval_policy()) == "block"


def test_injected_relation_bundle_survives_principal_state_restart():
    from dataclasses import replace
    from openclaw_guard.policy.catalog import PolicyBundle, default_policy_root
    bundle = replace(PolicyBundle.load(default_policy_root()), relations=())
    engine = RuntimeVerificationEngine(permission_bundle=bundle)
    state = engine.state_for_principal("u1", "agent1", ("grant1",))
    state.record(secret_read_trace(session_id="s1"), allow_policy())
    assert state.evaluate(external_egress_trace(session_id="s2"), approval_policy()) is None
    restored = RuntimeVerificationEngine(permission_bundle=bundle)
    restored.deserialize_state(engine.serialize_state())
    assert restored.state_for_principal("u1", "agent1", ("grant1",)).evaluate(
        external_egress_trace(session_id="s3"), approval_policy()
    ) is None


def test_reconfigure_permission_bundle_discards_previous_authority():
    from dataclasses import replace
    from openclaw_guard.policy.catalog import PolicyBundle, default_policy_root
    bundle = PolicyBundle.load(default_policy_root())
    engine = RuntimeVerificationEngine(permission_bundle=bundle)
    old = engine.state_for_principal("u1", "agent1", ("grant1",))
    old.record(secret_read_trace(session_id="s1"), allow_policy())
    assert old.effective_grants
    engine.configure_permission_monitors(replace(bundle, relations=()))
    current = engine.state_for_principal("u1", "agent1", ("grant1",))
    assert current is not old
    assert not current.effective_grants
