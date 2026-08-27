"""PMKB integration tests for the OpenClaw hook decision pipeline."""

from __future__ import annotations

import json

import pytest

from openclaw_guard.models import BehaviorEvent, DetectionDecision
from openclaw_guard.services import build_services
from openclaw_guard.utils import utc_now_iso


@pytest.fixture
def services(tmp_path):
    """Construct hook services with an isolated local runtime."""
    project = tmp_path / "OpenclawGuard"
    project.mkdir()
    config_path = project / "openclaw.json"
    config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
    return build_services(project, config_path=config_path)


def internal_message_payload() -> dict[str, object]:
    """Return a small internal message hook payload."""
    return {
        "toolName": "feishu.im.send",
        "params": {"to": "teammate@company.local", "body": "Internal meeting reminder"},
        "runId": "policy-internal",
        "toolCallId": "message",
        "sessionId": "policy-internal-session",
    }


def secret_external_egress_payload() -> dict[str, object]:
    """Return an external secret-egress request with an existing secret grant."""
    return {
        "toolName": "network.request",
        "params": {"url": "https://partner.example/upload", "body": "secret=top-secret"},
        "runId": "policy-secret",
        "toolCallId": "egress",
        "sessionId": "policy-secret-session",
        "current_permissions": [{"family": "secret.read", "scope": "external"}],
    }


def unknown_tool_payload() -> dict[str, object]:
    """Return a payload whose tool has no PMKB operation mapping."""
    return {
        "toolName": "vendor.unmapped.operation",
        "params": {},
        "runId": "policy-unknown",
        "toolCallId": "tool",
        "sessionId": "policy-unknown-session",
    }


def test_p0_internal_message_is_allowed_with_policy_evidence(services, monkeypatch):
    """A PMKB allow remains allow when the pre-existing detector allows it."""
    def detector_allow(event):
        return DetectionDecision(
            event_id=event.event_id,
            timestamp=utc_now_iso(),
            action_type=event.action_type,
            risk_level="safe",
            action="allow",
            reason="test detector allow",
        )

    monkeypatch.setattr(services.detector, "evaluate", detector_allow)
    result = services.handle_before_tool_call(internal_message_payload())

    evidence = result["action_record"]["decision"]["policy_decision"]
    assert result["action"] == "allow"
    assert evidence["effect"] == "auto_allow_audit"
    assert evidence["policy_version"]
    assert evidence["grant_source"] == "empty_default"


def test_p0_auto_allow_does_not_downgrade_existing_ask(services):
    """Removing monotonic overlay protection would silently bypass an approval."""
    result = services.handle_before_tool_call(internal_message_payload())

    assert result["action"] == "require_approval"
    assert result["action_record"]["decision"]["policy_decision"]["effect"] == "auto_allow_audit"


def test_secret_external_egress_cannot_be_downgraded_by_policy_overlay(services):
    """Removing the risk graph overlay should lose the toxic-combination evidence."""
    result = services.handle_before_tool_call(secret_external_egress_payload())

    evidence = result["action_record"]["decision"]["policy_decision"]
    assert result["action"] in {"block", "require_approval"}
    assert evidence["combo_violations"]
    assert "COMBO-SECRET-EGRESS-001" in evidence["combo_violations"]


def test_unknown_tool_records_gap_and_does_not_create_silent_allow(services):
    """Removing coverage propagation would turn an unknown operation into a silent allow."""
    result = services.handle_before_tool_call(unknown_tool_payload())

    evidence = result["action_record"]["decision"]["policy_decision"]
    assert evidence["match_status"] in {"partial", "unknown"}
    assert "tool_mapping" in evidence["missing_features"]
    assert result["action"] != "allow" or evidence["effect"] == "auto_allow_audit"


def test_whitelist_cannot_bypass_a_pmkb_approval(services):
    """Removing PMKB protection from the controller would silently allow this action."""
    event = BehaviorEvent(
        event_id="policy-whitelist",
        timestamp=utc_now_iso(),
        action_type="chat_message",
        process_name="openclaw",
        pid=None,
        user="openclaw",
        target_paths=["/tmp/openclaw-safe.txt"],
    )
    decision = DetectionDecision(
        event_id=event.event_id,
        timestamp=utc_now_iso(),
        action_type=event.action_type,
        risk_level="caution",
        action="ask",
        reason="PMKB approval",
        policy_decision={"effect": "openclaw_approval"},
    )

    controlled = services.controller.decide(event, decision, "read a local file")

    assert controlled.status == "pending_approval"
    assert controlled.decision.policy_decision == {"effect": "openclaw_approval"}
