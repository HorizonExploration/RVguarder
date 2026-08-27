from pathlib import Path

from openclaw_guard.models import BehaviorEvent
from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.policy.trace import TraceCompiler


ROOT = Path("policies/permissions")


def make_event(**overrides):
    data = {
        "event_id": "evt-1",
        "timestamp": "2026-08-27T00:00:00Z",
        "action_type": "network_egress",
        "process_name": "openclaw",
        "pid": 1,
        "user": "alice",
        "network_targets": [],
        "metadata": {"outside_workspace": True, "tool_name": "network.request"},
    }
    data.update(overrides)
    return BehaviorEvent(**data)


def test_compile_external_report_send_preserves_negation_and_scope():
    event = make_event(action_type="network_egress", network_targets=["partner.example"])
    trace = TraceCompiler(PolicyBundle.load(ROOT)).compile(
        event,
        semantic={"scenario": "report_send", "labels": ["internal_source"], "purpose": "report_delivery"},
        rv_trace=[],
    )
    assert trace.operation.family == "network.egress"
    assert trace.resource.scope == "external"
    assert trace.context.purpose == "report_delivery"


def test_compile_missing_recipient_is_partial_not_safe():
    event = make_event(action_type="channel_send", metadata={"tool_name": "feishu.im.send"})
    trace = TraceCompiler(PolicyBundle.load(ROOT)).compile(event, semantic={"scenario": "message_send"}, rv_trace=[])
    assert trace.coverage.status == "partial"
    assert "resource.recipient" in trace.coverage.missing_features


def test_compile_keeps_legacy_ir_and_event_action_type():
    event = make_event(action_type="channel_send", metadata={"tool_name": "im.send"})
    rv = [{"step_id": "s1", "event": "mail_send", "props": ["external_recipient"],
           "entities": [{"kind": "recipients", "values": ["x@example.com"]}],
           "constraints": [{"kind": "exclude", "value": "attachments"}],
           "negated": True, "excluded_entities": ["attachments"], "quantity": 2}]
    trace = TraceCompiler(PolicyBundle.load(ROOT)).compile(event, semantic={}, rv_trace=rv)
    assert trace.legacy_steps == rv
    assert trace.resource.scope == "external"
    assert event.action_type == "channel_send"
