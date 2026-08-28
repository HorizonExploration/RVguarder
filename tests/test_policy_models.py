import pytest

from openclaw_guard.models import DetectionDecision
from pydantic import ValidationError
from openclaw_guard.policy.models import (
    AuthorizationTrace,
    CoverageResult,
    OperationRef,
    PolicyDecision,
    PolicyRule,
    PrincipalRef,
    ResourceRef,
)


def test_trace_requires_operation_and_preserves_unknown_scope():
    trace = AuthorizationTrace(
        trace_id="h1",
        principal=PrincipalRef(id="agent-1", type="agent", trust="verified"),
        operation=OperationRef(family="document.read", tool_id="docs.read"),
        resource=ResourceRef(type="document", scope="unknown"),
        coverage=CoverageResult(status="partial", missing_features=["resource.id"]),
    )
    assert trace.resource.scope == "unknown"
    assert trace.coverage.status == "partial"


def test_policy_decision_separates_confidence_and_risk():
    decision = PolicyDecision(
        effect="openclaw_approval",
        match_status="matched",
        match_confidence=0.94,
        risk_score=82,
        policy_version="p0.1.0",
    )
    assert decision.match_confidence == 0.94
    assert decision.risk_score == 82
    assert decision.to_dict()["effect"] == "openclaw_approval"


def test_detection_decision_accepts_optional_policy_evidence():
    decision = DetectionDecision(
        event_id="e1", timestamp="2026-01-01T00:00:00Z", action_type="chat_message",
        risk_level="safe", action="allow", reason="ok",
    )
    assert decision.policy_decision is None


def test_policy_effect_contract_rejects_unsupported_values():
    with pytest.raises(ValidationError):
        PolicyDecision(effect="allow", match_status="matched")
    with pytest.raises(ValidationError):
        PolicyRule(id="r1", version="p0.1.0", effect="partial_grant")


def test_old_detection_decision_payload_deserializes_without_policy_evidence():
    decision = DetectionDecision.model_validate({
        "event_id": "legacy-1", "timestamp": "2026-01-01T00:00:00Z",
        "action_type": "chat_message", "risk_level": "safe",
        "action": "allow", "reason": "legacy",
    })
    assert decision.policy_decision is None
