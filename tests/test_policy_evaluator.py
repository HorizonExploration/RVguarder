from pathlib import Path

from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.policy.evaluator import PolicyEvaluator
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
