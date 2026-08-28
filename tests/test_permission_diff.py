from datetime import datetime, timezone, timedelta
from dataclasses import replace
from pathlib import Path

from openclaw_guard.models import BehaviorEvent
from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.policy.engine import AuthorizationPolicyEngine
from openclaw_guard.policy.models import CapabilityGrant, PermissionRef
from openclaw_guard.policy.permission_diff import PermissionClosure, PermissionDiff
import pytest


def permission(family, *, scope="unknown", classification="internal"):
    return PermissionRef(family=family, scope=scope, classification=classification)


def grant(family, *, scope="unknown", expires_at=None, constraints=None):
    return CapabilityGrant(family=family, scope=scope, expires_at=expires_at,
                           constraints=constraints or {}, permissions=[permission(family, scope=scope)])


def bundle(relations=None):
    loaded = PolicyBundle.load("policies/permissions")
    return replace(loaded, relations=tuple(relations or []))


def test_read_grant_does_not_imply_export_or_share():
    closure = PermissionClosure(bundle())
    effective = closure.close([grant("document.read", scope="own")])
    result = PermissionDiff.compute(effective, [permission("document.export", scope="own")], [])
    assert result.requested_delta == [permission("document.export", scope="own")]


def test_implies_relation_adds_only_explicit_target():
    closure = PermissionClosure(bundle([{"effect": "implies", "source": "document.write", "target": "document.read"}]))
    assert permission("document.read", scope="workspace") in closure.close([grant("document.write", scope="workspace")])


def test_implied_permission_preserves_least_privilege_dimensions():
    closure = PermissionClosure(bundle([{"effect": "implies", "source": "document.write", "target": "document.read"}]))
    source = PermissionRef(
        family="document.write",
        resource_type="document",
        resource_ids=("doc-1",),
        scope="workspace",
        classification="sensitive",
        field_scope=("title",),
        purpose="meeting_summary",
        ttl_seconds=300,
    )
    derived = next(item for item in closure.close([CapabilityGrant(family="document.write", permissions=[source])])
                   if item.family == "document.read")
    assert derived.resource_type == source.resource_type
    assert derived.resource_ids == source.resource_ids
    assert derived.field_scope == source.field_scope
    assert derived.purpose == source.purpose
    assert derived.ttl_seconds == source.ttl_seconds


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


def test_broader_grant_does_not_cover_narrower_request():
    granted = permission("file.read", scope="outside")
    requested = permission("file.read", scope="workspace")
    result = PermissionDiff.compute(frozenset({granted}), [requested], [requested])
    assert result.requested_delta == [requested]
    assert result.redundant_permissions == []


def test_permission_ref_is_immutable_and_hash_safe():
    value = permission("file.read", scope="workspace")
    permissions = frozenset({value})
    with pytest.raises((TypeError, ValueError)):
        value.scope = "external"
    assert value in permissions


@pytest.mark.parametrize("dimension", [
    "classification", "resource_type", "resource_ids", "field_scope", "purpose", "ttl_seconds",
])
def test_least_privilege_marks_every_dimension_expansion_excessive(dimension):
    required = PermissionRef(
        family="document.read",
        resource_type="document",
        resource_ids=("doc-1",),
        scope="workspace",
        classification="internal",
        field_scope=("title",),
        purpose="meeting_summary",
        ttl_seconds=300,
    )
    values = {
        "classification": "secret",
        "resource_type": "table",
        "resource_ids": ("doc-2",),
        "field_scope": ("title", "body"),
        "purpose": "export",
        "ttl_seconds": 600,
    }
    requested = required.model_copy(update={dimension: values[dimension]})

    result = PermissionDiff.compute(frozenset(), [requested], [required])

    assert result.excessive_permissions == [requested]


def test_unknown_required_scope_is_not_a_wildcard():
    requested = permission("document.read", scope="external")
    required = permission("document.read", scope="unknown")

    result = PermissionDiff.compute(frozenset(), [requested], [required])

    assert result.excessive_permissions == [requested]


def test_explicit_required_resource_and_purpose_mismatches_are_excessive():
    requested = PermissionRef(
        family="document.read",
        resource_type="document",
        resource_ids=("doc-1",),
        scope="workspace",
        purpose="meeting_summary",
    )
    required = PermissionRef(
        family="document.read",
        resource_type="document",
        resource_ids=("doc-2",),
        scope="workspace",
        purpose="other_purpose",
    )

    result = PermissionDiff.compute(frozenset(), [requested], [required])

    assert result.excessive_permissions == [requested]


@pytest.mark.parametrize(
    ("dimension", "missing"),
    [("field_scope", ()), ("purpose", "")],
)
def test_missing_request_bound_is_excessive_against_explicit_required_trace(dimension, missing):
    required = PermissionRef(
        family="document.read",
        resource_type="document",
        resource_ids=("doc-1",),
        scope="workspace",
        field_scope=("title",),
        purpose="meeting_summary",
    )
    requested = required.model_copy(update={dimension: missing})

    result = PermissionDiff.compute(frozenset(), [requested], [required])

    assert result.excessive_permissions == [requested]


def test_explicitly_unbounded_legacy_trace_keeps_dimension_wildcards():
    required = PermissionRef(
        family="message.send",
        resource_type="recipient",
        scope="outside",
    )
    requested = required.model_copy(update={
        "field_scope": ("address",),
        "purpose": "meeting_notice",
    })

    result = PermissionDiff.compute(frozenset(), [requested], [required])

    assert result.excessive_permissions == []


def test_engine_p_after_contains_permission_implication_closure():
    loaded = bundle([{
        "id": "test-implies-write-read",
        "version": "1.0.0",
        "effect": "implies",
        "requires": ["document.write"],
        "source": "document.write",
        "target": "document.read",
        "rollback_state": "previous",
        "positive_examples": [],
        "negative_examples": [],
    }])
    engine = AuthorizationPolicyEngine(Path("policies/permissions"))
    engine.bundle = loaded
    engine.policy_evaluator.bundle = loaded
    engine.permission_closure = PermissionClosure(loaded)

    event = BehaviorEvent(
        event_id="p-after-closure",
        timestamp="2026-01-01T00:00:00Z",
        action_type="file_write",
        process_name="openclaw",
        pid=None,
        user="u1",
        metadata={
            "requested_permissions": [{
                "family": "document.write",
                "resource_type": "document",
                "resource_ids": ["doc-1"],
                "scope": "workspace",
            }],
            "required_trace": [{
                "family": "document.write",
                "resource_type": "document",
                "resource_ids": ["doc-1"],
                "scope": "workspace",
            }],
        },
    )

    decision = engine.evaluate(event)

    assert {permission.family for permission in decision.p_after} >= {
        "document.write", "document.read",
    }
