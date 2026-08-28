"""PMKB-to-RV compiler and runtime integration coverage."""

from __future__ import annotations

from pathlib import Path

from openclaw_guard.policy.catalog import PolicyBundle
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
from openclaw_guard.policy.rv_compiler import PermissionAutomatonCompiler
from openclaw_guard.rv.runtime_verification import RuntimeVerificationEngine


POLICY_ROOT = Path(__file__).parents[1] / "policies" / "permissions"


def _trace() -> AuthorizationTrace:
    return AuthorizationTrace(
        trace_id="permission-rv-1",
        principal=PrincipalRef(id="user-1", type="human", trust="verified"),
        agent_id="agent-1",
        session_id="session-a",
        capability_lineage=["grant-1"],
        operation=OperationRef(family="session.token.read"),
        resource=ResourceRef(type="path", ids=["token"], scope="workspace"),
        coverage=CoverageResult(status="complete"),
        data=DataRef(classification="secret", quantity=1),
        context=ContextRef(recipient_zone="internal"),
    )


def test_compiler_emits_one_monitor_per_rule_and_enforceable_relation() -> None:
    bundle = PolicyBundle.load(POLICY_ROOT)
    ruleset = PermissionAutomatonCompiler(bundle).compile_ruleset()

    names = {monitor.name for monitor in ruleset.monitors}
    assert "PMKBRule_P1_SESSION_TOKEN_READ" in names
    assert "PMKBRelation_token_egress" in names
    assert len([name for name in names if name.startswith("PMKBRule_")]) == len(bundle.rules)
    assert all(monitor.source == "pmkb" for monitor in ruleset.monitors)


def test_compiled_permission_rule_projects_authoritative_pmkb_effect() -> None:
    bundle = PolicyBundle.load(POLICY_ROOT)
    engine = RuntimeVerificationEngine(permission_bundle=bundle, window_ttl_seconds=None)
    decision = PolicyDecision(
        effect="block",
        match_status="matched",
        selected_rule_ids=["P1-SESSION-TOKEN-READ"],
        policy_version=bundle.version,
    )

    result = engine.evaluate([], session_key="session-a", authorization_trace=_trace(), policy_decision=decision)

    assert result["verdict"] == "block"
    assert result["triggered_by"] == "PMKBRule_P1_SESSION_TOKEN_READ"
    assert result["monitor_sources"]["permission"] > 0


def test_relation_monitors_are_principal_scoped_and_do_not_mix_identities() -> None:
    bundle = PolicyBundle.load(POLICY_ROOT)
    engine = RuntimeVerificationEngine(permission_bundle=bundle, window_ttl_seconds=None)
    decision = PolicyDecision(
        effect="block",
        match_status="matched",
        combo_violations=["token-egress"],
        policy_version=bundle.version,
    )

    result = engine.evaluate([], session_key="session-b", authorization_trace=_trace(), policy_decision=decision)

    assert result["verdict"] == "block"
    assert result["triggered_by"] == "PMKBRelation_token_egress"
    assert engine.principal_monitor_count() == 1
