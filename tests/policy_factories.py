from openclaw_guard.models import BehaviorEvent
from openclaw_guard.policy.models import CapabilityGrant, PermissionRef


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
