"""Regression tests for the network-case baseline knowledge in the PMKB."""

from pathlib import Path

from openclaw_guard.models import BehaviorEvent
from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.policy.engine import AuthorizationPolicyEngine
from openclaw_guard.policy.evaluator import PolicyEvaluator
from openclaw_guard.policy.models import (
    AuthorizationTrace,
    ContextRef,
    CoverageResult,
    DataRef,
    OperationRef,
    PermissionRef,
    PrincipalRef,
    ResourceRef,
)
from openclaw_guard.policy.risk_graph import RiskGraph
from openclaw_guard.policy.trace import TraceCompiler


ROOT = Path(__file__).parents[1] / "policies" / "permissions"


def test_network_case_tools_map_to_canonical_permission_families():
    bundle = PolicyBundle.load(ROOT)

    assert bundle.operation_for_tool("session.cookie.read", {}).family == "session.token.read"
    assert bundle.operation_for_tool("oauth.scope.grant", {}).family == "identity.permission.grant"
    assert bundle.operation_for_tool("audit.disable", {}).family == "audit.modify"


def test_packaged_permission_bundle_matches_source_bundle():
    source = PolicyBundle.load(ROOT)
    packaged_root = Path(__file__).parents[1] / "openclaw_guard" / "policy" / "data" / "permissions"
    packaged = PolicyBundle.load(packaged_root)

    assert packaged.version == source.version == "1.2.0"
    assert {item.family for item in packaged.operations} == {item.family for item in source.operations}
    assert {item.id for item in packaged.rules} == {item.id for item in source.rules}


def test_case_baseline_has_deterministic_rules_for_sensitive_operations():
    bundle = PolicyBundle.load(ROOT)
    rule_ids = {rule.id for rule in bundle.rules}

    assert {"P1-NETWORK-EGRESS", "P1-SESSION-TOKEN-READ", "P1-PERMISSION-GRANT", "P1-AUDIT-MODIFY"} <= rule_ids


def test_every_new_rule_has_a_fixed_least_privilege_trace():
    bundle = PolicyBundle.load(ROOT)
    new_rule_ids = {rule.id for rule in bundle.rules if rule.id.startswith("P1-")}
    traced_rule_ids = {str(trace.get("rule_id")) for trace in bundle.traces}

    assert new_rule_ids <= traced_rule_ids


def test_read_baseline_rejects_unknown_scope_and_secret_classification():
    evaluator = PolicyEvaluator(PolicyBundle.load(ROOT))
    for operation in ("directory.read", "table.read"):
        for scope, classification in (("unknown", "internal"), ("workspace", "secret")):
            trace = AuthorizationTrace(
                trace_id=f"read-{operation}-{scope}-{classification}",
                principal=PrincipalRef(id="agent-1", type="agent", trust="verified"),
                operation=OperationRef(family=operation),
                resource=ResourceRef(type="document", ids=["resource-1"], scope=scope),
                coverage=CoverageResult(status="complete"),
                data=DataRef(classification=classification, quantity=1),
                context=ContextRef(recipient_zone="internal"),
            )

            decision = evaluator.evaluate(trace)

            assert decision.effect != "auto_allow_audit"
            assert decision.match_status in {"conflict", "unknown"}


def test_trace_compiler_and_evaluator_apply_network_egress_baseline():
    bundle = PolicyBundle.load(ROOT)
    event = BehaviorEvent(
        event_id="network-baseline",
        timestamp="2026-01-01T00:00:00Z",
        action_type="network_egress",
        process_name="test",
        pid=None,
        user=None,
        network_targets=["https://external.example/upload"],
        metadata={"tool_name": "network.request"},
    )
    trace = TraceCompiler(bundle).compile(
        event,
        semantic={
            "entities": {"urls": ["https://external.example/upload"]},
            "data_classification": "sensitive",
            "confidence": 1.0,
        },
        rv_trace=[],
    )

    decision = PolicyEvaluator(bundle).evaluate(trace)

    assert trace.operation.family == "network.egress"
    assert decision.effect == "openclaw_approval"
    assert decision.selected_rule_ids == ["NATIVE-NET-001"]


def test_network_case_relation_blocks_credential_egress_combination():
    bundle = PolicyBundle.load(ROOT)
    trace = TraceCompiler(bundle).compile(
        BehaviorEvent(
            event_id="credential-egress",
            timestamp="2026-01-01T00:00:00Z",
            action_type="network_egress",
            process_name="test",
            pid=None,
            user=None,
            network_targets=["https://external.example/upload"],
            metadata={"tool_name": "network.request"},
        ),
        semantic={
            "entities": {"urls": ["https://external.example/upload"]},
            "data_classification": "sensitive",
            "confidence": 1.0,
        },
        rv_trace=[],
    )
    effective = frozenset({
        PermissionRef(family="credential.read", scope="workspace"),
        PermissionRef(family="network.egress", scope="external"),
    })

    violations = RiskGraph.from_bundle(bundle).evaluate(
        effective=effective,
        requested_delta=[],
        trace=trace,
    )

    assert "credential-egress" in {item.relation_id for item in violations}


def test_authorization_engine_carries_case_relation_into_hook_decision():
    engine = AuthorizationPolicyEngine(ROOT)
    event = BehaviorEvent(
        event_id="credential-egress-engine",
        timestamp="2026-01-01T00:00:00Z",
        action_type="network_egress",
        process_name="test",
        pid=None,
        user=None,
        network_targets=["https://external.example/upload"],
        metadata={
            "tool_name": "network.request",
            "current_permissions": [{"family": "credential.read", "scope": "workspace"}],
        },
    )

    decision = engine.evaluate(event)

    assert decision.effect == "block"
    assert "credential-egress" in decision.combo_violations
