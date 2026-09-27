from pathlib import Path

from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.policy.evaluator import PolicyEvaluator
from openclaw_guard.policy.models import (
    CoverageResult,
    OperationRef,
    PolicyRule,
    PrincipalRef,
    SecurityFactEvidence,
)
from tests.policy_factories import trace_for_message


ROOT = Path(__file__).parents[1] / "policies" / "permissions"


def test_known_internal_small_message_is_auto_allow_audit():
    evaluator = PolicyEvaluator(PolicyBundle.load(ROOT))
    trace = trace_for_message(recipient_zone="internal", recipient_count=2,
                              classification="internal", purpose="meeting_notice")
    result = evaluator.evaluate(trace)
    assert result.effect == "auto_allow_audit"
    assert result.match_status == "matched"


def test_external_unknown_recipient_is_approval_with_gap():
    evaluator = PolicyEvaluator(PolicyBundle.load(ROOT))
    trace = trace_for_message(recipient_zone="unknown", recipient_count=None, classification="internal")
    result = evaluator.evaluate(trace)
    assert result.effect == "openclaw_approval"
    assert "context.recipient_zone" in result.missing_features


def test_conflicting_allow_and_block_rules_choose_block():
    evaluator = PolicyEvaluator(PolicyBundle.load(ROOT))
    trace = trace_for_message(recipient_zone="external", classification="secret", purpose="report_delivery")
    result = evaluator.evaluate(trace)
    assert result.effect == "block"
    assert result.conflicts == [] or "rule_conflict" in result.conflicts


def test_alias_family_trace_matches_canonical_rule():
    evaluator = PolicyEvaluator(PolicyBundle.load(ROOT))
    trace = trace_for_message(recipient_zone="external", recipient_count=11).model_copy(update={
        "operation": OperationRef(family="batch_file_transfer", tool_id="batch_file_transfer")
    })
    candidate = evaluator.match_rule(next(r for r in evaluator.bundle.rules if r.id == "EX-27"), trace)
    assert candidate.status == "matched"
    assert candidate.score > 0


def test_partial_coverage_without_explicit_gaps_cannot_auto_allow():
    evaluator = PolicyEvaluator(PolicyBundle.load(ROOT))
    trace = trace_for_message().model_copy(update={
        "coverage": CoverageResult(status="partial")
    })
    result = evaluator.evaluate(trace)
    assert result.match_status == "partial"
    assert result.effect != "auto_allow_audit"


def test_unknown_or_conflict_coverage_is_retained_and_fail_closed():
    evaluator = PolicyEvaluator(PolicyBundle.load(ROOT))
    for status in ("unknown", "conflict"):
        trace = trace_for_message().model_copy(update={
            "coverage": CoverageResult(status=status)
        })
        result = evaluator.evaluate(trace)
        assert result.match_status == status
        assert result.effect in {"openclaw_approval", "block"}


def test_partial_match_cannot_weaken_real_block_rule():
    """Incomplete evidence routes to the single approval gate."""
    evaluator = PolicyEvaluator(PolicyBundle.load(ROOT))
    trace = trace_for_message().model_copy(update={
        "principal": PrincipalRef(id="unknown", type="agent", trust="unknown"),
        "operation": OperationRef(family="data.query", tool_id="feishu.bitable.query"),
        "data": trace_for_message(recipient_zone="external", recipient_count=11, classification="sensitive").data,
    })

    result = evaluator.evaluate(trace)

    assert result.match_status == "partial"
    assert result.selected_rule_ids == ["EX-19"]
    assert result.effect == "openclaw_approval"


def _fact_rule(rule_id: str, effect: str, *, priority: int = 10, extra_match=None) -> PolicyRule:
    match = {"operation": "network.egress", "facts.network.upload": True}
    match.update(extra_match or {})
    return PolicyRule(
        id=rule_id,
        version="test",
        effect=effect,
        priority=priority,
        match=match,
        required_fields=[],
        negative_conditions=[],
        obligations=["audit"],
        source="test",
        test_vectors=[],
        rollback_state="previous",
        positive_examples=[],
        negative_examples=[],
    )


def _evaluator_for(*rules: PolicyRule) -> PolicyEvaluator:
    base = PolicyBundle.load(ROOT)
    bundle = PolicyBundle(base.operations, rules, (), (), (), "test")
    return PolicyEvaluator(bundle)


def _network_trace(*, trust: str, coverage: str = "complete"):
    return trace_for_message(recipient_zone="internal").model_copy(update={
        "operation": OperationRef(family="network.egress", tool_id="network.request"),
        "coverage": CoverageResult(status=coverage),
        "security_facts": {
            "network.upload": SecurityFactEvidence(
                value=True,
                source="llm" if trust == "suggested" else "deterministic",
                trust=trust,
                confidence=0.9,
                evidence="test",
            )
        },
    })


def test_suggested_only_fact_cannot_auto_allow_or_hard_block():
    for effect in ("auto_allow_audit", "block"):
        result = _evaluator_for(_fact_rule(f"rule-{effect}", effect)).evaluate(
            _network_trace(trust="suggested")
        )
        assert result.effect == "openclaw_approval"
        assert result.match_status == "partial"


def test_verified_fact_can_select_hard_block():
    result = _evaluator_for(_fact_rule("verified-block", "block")).evaluate(
        _network_trace(trust="verified")
    )
    assert result.effect == "block"
    assert result.selected_rule_ids == ["verified-block"]


def test_conflicting_evidence_always_routes_to_approval():
    trace = _network_trace(trust="verified").model_copy(update={
        "coverage": CoverageResult(
            status="conflict",
            conflicts=["fact_conflict:network.upload"],
        )
    })
    result = _evaluator_for(_fact_rule("conflicted-block", "block")).evaluate(trace)
    assert result.effect == "openclaw_approval"
    assert result.match_status == "conflict"


def test_primary_rule_uses_priority_then_specificity_and_retains_candidates():
    broad = _fact_rule("broad", "openclaw_approval", priority=10)
    specific = _fact_rule(
        "specific",
        "openclaw_approval",
        priority=20,
        extra_match={"scope": "workspace"},
    )
    result = _evaluator_for(broad, specific).evaluate(_network_trace(trust="verified"))

    assert result.selected_rule_ids == ["specific"]
    assert result.candidate_rule_ids == ["broad", "specific"]
