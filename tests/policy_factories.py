from openclaw_guard.models import BehaviorEvent
from openclaw_guard.policy.models import (
    AuthorizationTrace, CapabilityGrant, ContextRef, CoverageResult, DataRef,
    OperationRef, PermissionRef, PrincipalRef, ProvenanceRef, ResourceRef,
)


def permission(family: str, *, scope: str = "unknown", classification: str = "internal") -> PermissionRef:
    return PermissionRef(family=family, scope=scope, classification=classification)


def grant(family: str, *, scope: str = "unknown") -> CapabilityGrant:
    return CapabilityGrant(family=family, scope=scope, permissions=[permission(family, scope=scope)])


def make_event(action_type: str, *, target_paths: list[str] | None = None,
               network_targets: list[str] | None = None) -> BehaviorEvent:
    return BehaviorEvent(
        event_id="factory-event",
        timestamp="2026-01-01T00:00:00Z",
        action_type=action_type,
        process_name="test",
        pid=None,
        user=None,
        target_paths=target_paths or [],
        network_targets=network_targets or [],
    )


def trace_for_message(*, recipient_zone: str = "internal", recipient_count: int | None = 2,
                      classification: str = "internal", purpose: str = "meeting_notice") -> AuthorizationTrace:
    ids = [f"person-{i}" for i in range(recipient_count or 0)]
    return AuthorizationTrace(
        trace_id="trace-message",
        principal=PrincipalRef(id="agent-1", type="agent", trust="verified"),
        operation=OperationRef(family="message.send", tool_id="feishu.im.send"),
        resource=ResourceRef(type="recipient", ids=ids, scope="external" if recipient_zone == "external" else "workspace"),
        coverage=CoverageResult(status="complete" if recipient_count is not None else "partial"),
        data=DataRef(classification=classification, quantity=recipient_count or 0),
        context=ContextRef(recipient_zone=recipient_zone, purpose=purpose),
        provenance=ProvenanceRef(source="test", trust="verified"),
    )
