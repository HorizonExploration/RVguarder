from dataclasses import replace

from openclaw_guard.policy.catalog import PolicyBundle
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


ROOT = "policies/permissions"


def permission(family: str, *, scope: str = "unknown", classification: str = "internal") -> PermissionRef:
    return PermissionRef(family=family, scope=scope, classification=classification)


def trace_for_external_secret_egress() -> AuthorizationTrace:
    return AuthorizationTrace(
        trace_id="trace-secret-egress",
        principal=PrincipalRef(id="agent-1", type="agent", trust="verified"),
        operation=OperationRef(family="network.egress"),
        resource=ResourceRef(type="endpoint", scope="external"),
        coverage=CoverageResult(status="complete"),
        data=DataRef(classification="secret", quantity=1),
        context=ContextRef(recipient_zone="external"),
    )


def trace_for_internal_read() -> AuthorizationTrace:
    return AuthorizationTrace(
        trace_id="trace-internal-read",
        principal=PrincipalRef(id="agent-1", type="agent", trust="verified"),
        operation=OperationRef(family="document.read"),
        resource=ResourceRef(type="document", scope="workspace"),
        coverage=CoverageResult(status="complete"),
        data=DataRef(classification="internal"),
        context=ContextRef(recipient_zone="internal"),
    )


def test_secret_read_plus_external_egress_is_hard_block():
    graph = RiskGraph.from_bundle(PolicyBundle.load(ROOT))
    violations = graph.evaluate(
        effective=frozenset({permission("secret.read")}),
        requested_delta=[permission("network.egress", scope="external")],
        trace=trace_for_external_secret_egress(),
    )
    assert {v.relation_id for v in violations} == {"COMBO-SECRET-EGRESS-001"}
    assert violations[0].effect == "block"


def test_unrelated_read_permissions_do_not_trigger_hyperedge():
    graph = RiskGraph.from_bundle(PolicyBundle.load(ROOT))
    violations = graph.evaluate(
        effective=frozenset({permission("document.read"), permission("calendar.read")}),
        requested_delta=[],
        trace=trace_for_internal_read(),
    )
    assert violations == []


def test_match_preserves_conditions_and_evidence():
    bundle = PolicyBundle.load(ROOT)
    bundle = replace(bundle, relations=({
        "id": "combo",
        "version": "1",
        "effect": "openclaw_approval",
        "requires": ["document.read", "external_target"],
        "conditions": {"quantity": {"gte": 2}},
    },))
    graph = RiskGraph.from_bundle(bundle)
    trace = trace_for_external_secret_egress().model_copy(
        update={"operation": OperationRef(family="document.read"), "data": DataRef(classification="internal", quantity=2)}
    )
    violations = graph.evaluate(
        effective=frozenset({permission("document.read")}),
        requested_delta=[],
        trace=trace,
    )
    assert violations[0].relation_id == "combo"
    assert violations[0].conditions == {"quantity": {"gte": 2}}
    assert violations[0].evidence["trace_id"] == "trace-secret-egress"


def test_explicit_conflicts_relation_is_evaluated():
    bundle = PolicyBundle.load(ROOT)
    bundle = replace(bundle, relations=({"id": "separation", "version": "1", "type": "conflicts",
                                         "effect": "block", "requires": ["credential.read", "process.execute"]},))
    violations = RiskGraph.from_bundle(bundle).evaluate(
        effective=frozenset({permission("credential.read")}),
        requested_delta=[permission("process.execute")],
        trace=trace_for_internal_read(),
    )
    assert violations[0].relation_id == "separation"
    assert violations[0].evidence["relation_type"] == "conflicts"


def test_explicit_toxic_with_relation_is_evaluated():
    bundle = PolicyBundle.load(ROOT)
    bundle = replace(bundle, relations=({"id": "toxic", "version": "1", "relation": "toxic_with",
                                         "effect": "openclaw_approval", "requires": ["data.export", "external_recipient", "sensitive_data"]},))
    trace = trace_for_external_secret_egress().model_copy(update={
        "operation": OperationRef(family="data.export"),
        "data": DataRef(classification="sensitive", quantity=1),
    })
    violations = RiskGraph.from_bundle(bundle).evaluate(
        effective=frozenset({permission("data.export")}),
        requested_delta=[],
        trace=trace,
    )
    assert violations[0].evidence["relation_type"] == "toxic_with"


def test_p0_credential_process_and_export_sensitive_vectors_match():
    graph = RiskGraph.from_bundle(PolicyBundle.load(ROOT))
    credential = graph.evaluate(
        effective=frozenset({permission("credential.read")}),
        requested_delta=[permission("process.execute")],
        trace=trace_for_internal_read(),
    )
    export_trace = trace_for_external_secret_egress().model_copy(update={
        "operation": OperationRef(family="data.export"),
        "data": DataRef(classification="sensitive", quantity=2),
    })
    export = graph.evaluate(
        effective=frozenset({permission("data.export")}),
        requested_delta=[],
        trace=export_trace,
    )
    assert {v.relation_id for v in credential} == {"COMBO-CREDENTIAL-PROCESS-001"}
    assert {v.relation_id for v in export} == {"COMBO-EXPORT-SENSITIVE-001"}
