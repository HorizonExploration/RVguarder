from datetime import datetime, timezone, timedelta

from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.policy.models import CapabilityGrant, PermissionRef
from openclaw_guard.policy.permission_diff import PermissionClosure, PermissionDiff


def permission(family, *, scope="unknown", classification="internal"):
    return PermissionRef(family=family, scope=scope, classification=classification)


def grant(family, *, scope="unknown", expires_at=None, constraints=None):
    return CapabilityGrant(family=family, scope=scope, expires_at=expires_at,
                           constraints=constraints or {}, permissions=[permission(family, scope=scope)])


def bundle(relations=None):
    loaded = PolicyBundle.load("policies/permissions")
    loaded.relations = relations or []
    return loaded


def test_read_grant_does_not_imply_export_or_share():
    closure = PermissionClosure(bundle())
    effective = closure.close([grant("document.read", scope="own")])
    result = PermissionDiff.compute(effective, [permission("document.export", scope="own")], [])
    assert result.requested_delta == [permission("document.export", scope="own")]


def test_implies_relation_adds_only_explicit_target():
    closure = PermissionClosure(bundle([{"effect": "implies", "source": "document.write", "target": "document.read"}]))
    assert permission("document.read", scope="workspace") in closure.close([grant("document.write", scope="workspace")])


def test_requested_permission_already_granted_is_redundant():
    granted = permission("calendar.read", scope="own")
    result = PermissionDiff.compute(frozenset({granted}), [granted], [granted])
    assert result.redundant_permissions == [granted]
    assert result.requested_delta == []


def test_workspace_to_external_scope_is_expansion():
    result = PermissionDiff.compute(
        frozenset({permission("file.read", scope="workspace")}),
        [permission("file.read", scope="external")],
        [permission("file.read", scope="workspace")],
    )
    assert "scope_expansion" in result.hard_violations
    assert result.scope_expansions == [permission("file.read", scope="external")]


def test_expired_and_revoked_grants_are_excluded_and_reported():
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    closure = PermissionClosure(bundle())
    effective = closure.close([
        grant("document.read", scope="own", expires_at=past),
        grant("calendar.read", scope="own", constraints={"revoked": True}),
    ])
    assert not effective
    assert len(closure.expired_grants) == 2
    result = PermissionDiff.compute(effective, [], [])
    assert len(result.expired_grants) == 2


def test_excessive_requested_permission_is_outside_required_trace():
    requested = [permission("document.read", scope="workspace"), permission("document.write", scope="workspace")]
    result = PermissionDiff.compute(frozenset(), requested, [permission("document.read", scope="workspace")])
    assert result.requested_delta == requested
    assert result.excessive_permissions == [requested[1]]
