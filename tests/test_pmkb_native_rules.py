"""Small regression vectors for PMKB-native high-frequency predicates."""

from pathlib import Path

from openclaw_guard.models import BehaviorEvent
from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.policy.evaluator import PolicyEvaluator
from openclaw_guard.policy.trace import TraceCompiler


ROOT = Path(__file__).parents[1] / "policies" / "permissions"


def _decision(event: BehaviorEvent, *, semantic: dict) -> tuple[str, list[str]]:
    bundle = PolicyBundle.load(ROOT)
    trace = TraceCompiler(bundle).compile(event, semantic=semantic, rv_trace=[])
    result = PolicyEvaluator(bundle).evaluate(trace)
    return result.effect, result.selected_rule_ids


def test_destructive_command_uses_native_pmkb_predicate():
    effect, selected = _decision(
        BehaviorEvent(
            event_id="native-rm-rf",
            timestamp="2026-01-01T00:00:00Z",
            action_type="command_exec",
            process_name="shell",
            pid=None,
            user=None,
            command="rm -rf /tmp/example",
            metadata={
                "tool_name": "process.execute",
                "command_safety": {"classification": "destructive"},
            },
        ),
        semantic={"confidence": 1.0},
    )

    assert effect == "block"
    assert "NATIVE-PROCESS-DESTRUCTIVE" in selected


def test_secret_external_egress_uses_native_pmkb_predicate():
    effect, selected = _decision(
        BehaviorEvent(
            event_id="native-secret-egress",
            timestamp="2026-01-01T00:00:00Z",
            action_type="network_egress",
            process_name="test",
            pid=None,
            user=None,
            network_targets=["https://external.example/upload"],
            raw_payload={"params": {"body": "token=top-secret"}},
            metadata={"tool_name": "network.request"},
        ),
        semantic={
            "entities": {"urls": ["https://external.example/upload"]},
            "data_classification": "secret",
            "confidence": 1.0,
        },
    )

    assert effect == "block"
    assert "NATIVE-NETWORK-SECRET-EXTERNAL" in selected


def test_native_rules_do_not_depend_on_legacy_label_fields():
    bundle = PolicyBundle.load(ROOT)
    native = [rule for rule in bundle.rules if rule.id.startswith("NATIVE-")]

    assert native
    assert all("legacy_labels_all" not in rule.match for rule in native)
    assert all("legacy_action_types" not in rule.match for rule in native)
