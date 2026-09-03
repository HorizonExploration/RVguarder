"""Deletion gate: every LEGACY record replays equivalently through PMKB."""

from pathlib import Path

from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.policy.evaluator import PolicyEvaluator
from openclaw_guard.policy.models import AuthorizationTrace, CoverageResult, OperationRef, PrincipalRef, ResourceRef
from openclaw_guard.policy.legacy import legacy_rules


def test_legacy_rm_rf_is_blocked_by_the_pmkb_compatibility_record():
    trace = AuthorizationTrace(
        trace_id="legacy-cmd-001",
        principal=PrincipalRef(id="u", type="human", trust="verified"),
        operation=OperationRef(family="unknown_tool", arguments={"action_type": "command_exec"}),
        resource=ResourceRef(type="command", ids=["rm -rf /tmp/x"], scope="workspace"),
        coverage=CoverageResult(status="complete"),
        legacy_steps=[{"props": ["command_exec", "command_rm_rf"]}],
    )
    root = Path(__file__).parents[1] / "policies" / "permissions"

    decision = PolicyEvaluator(PolicyBundle.load(root)).evaluate(trace)

    assert decision.effect == "block"
    assert "LEGACY-CMD-001" in decision.selected_rule_ids


def test_every_legacy_record_replays_to_an_equivalent_pmkb_effect():
    root = Path(__file__).parents[1] / "policies" / "permissions"
    evaluator = PolicyEvaluator(PolicyBundle.load(root))
    expected_effect = {"block": "block", "ask": "openclaw_approval", "escalate": "openclaw_approval"}
    rank = {"auto_allow_audit": 0, "openclaw_approval": 1, "block": 2}

    for rule in legacy_rules():
        for action_type in rule.action_types:
            trace = AuthorizationTrace(
                trace_id=f"legacy-{rule.rule_id}-{action_type}",
                principal=PrincipalRef(id="u", type="human", trust="verified"),
                operation=OperationRef(family="unknown_tool", arguments={"action_type": action_type}),
                resource=ResourceRef(type="unknown", scope="unknown"),
                coverage=CoverageResult(status="complete"),
                legacy_steps=[{"props": list(rule.match_labels)}],
            )

            decision = evaluator.evaluate(trace)

            migrated_rule = next(
                candidate for candidate in evaluator.bundle.legacy_rules()
                if candidate.id == f"LEGACY-{rule.rule_id}"
            )
            assert evaluator.match_rule(migrated_rule, trace).status == "matched"
            assert f"LEGACY-{rule.rule_id}" in decision.candidate_rule_ids
            assert rank[decision.effect] >= rank[expected_effect[rule.decision]]
            assert not decision.conflicts
