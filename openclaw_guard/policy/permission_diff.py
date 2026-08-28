"""Permission closure and deterministic least-privilege comparisons."""
from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any, Iterable

from .catalog import PolicyBundle
from .models import CapabilityGrant, PermissionRef


_SCOPE_RANK = {"unknown": -1, "own": 0, "workspace": 1, "outside": 2,
               "external": 3, "bulk": 4}
_CLASS_RANK = {"public": 0, "internal": 1, "sensitive": 2, "secret": 3}


@dataclass
class PermissionDiffResult:
    requested_delta: list[PermissionRef] = field(default_factory=list)
    redundant_permissions: list[PermissionRef] = field(default_factory=list)
    excessive_permissions: list[PermissionRef] = field(default_factory=list)
    scope_expansions: list[PermissionRef] = field(default_factory=list)
    expired_grants: list[Any] = field(default_factory=list)
    hard_violations: list[str] = field(default_factory=list)
    coverage_gaps: list[str] = field(default_factory=list)


class _EffectivePermissions(frozenset[PermissionRef]):
    """A frozenset retaining discarded-grant provenance for the diff stage."""

    def __new__(cls, values: Iterable[PermissionRef], expired_grants: list[CapabilityGrant]):
        instance = super().__new__(cls, values)
        instance.expired_grants = list(expired_grants)
        return instance


class PermissionClosure:
    """Compute the bounded transitive implication closure of capability grants."""

    def __init__(self, bundle: PolicyBundle):
        self.bundle = bundle
        self.expired_grants: list[CapabilityGrant] = []

    def close(self, grants: list[CapabilityGrant]) -> frozenset[PermissionRef]:
        self.expired_grants = []
        effective: set[PermissionRef] = set()
        pending: list[PermissionRef] = []
        for grant in grants:
            if _inactive(grant):
                self.expired_grants.append(grant)
                continue
            direct = list(grant.permissions)
            if not direct and grant.family:
                direct = [PermissionRef(family=grant.family, scope=grant.scope)]
            pending.extend(direct)
            pending.extend(_nested_permissions(grant.constraints))
        edges = _implication_edges(self.bundle.relations)
        while pending:
            current = pending.pop()
            if current in effective:
                continue
            effective.add(current)
            for source, target in edges:
                if source == current.family:
                    # Implication changes the operation family, not the
                    # authority dimensions. Preserve resource/field/purpose
                    # and TTL evidence so closure remains least-privilege
                    # comparable.
                    pending.append(current.model_copy(update={
                        "family": target,
                    }))
        return _EffectivePermissions(effective, self.expired_grants)


class PermissionDiff:
    @staticmethod
    def compute(effective: frozenset[PermissionRef], requested: list[PermissionRef],
                required_trace: list[PermissionRef]) -> PermissionDiffResult:
        result = PermissionDiffResult()
        result.expired_grants = list(getattr(effective, "expired_grants", []))
        for item in requested:
            if _covered(item, effective):
                result.redundant_permissions.append(item)
            else:
                result.requested_delta.append(item)

        for item in requested:
            if not _covered_by_required(item, required_trace):
                result.excessive_permissions.append(item)

        if any(item.scope == "unknown" for item in required_trace):
            result.coverage_gaps.append("required_trace.scope")

        for item in requested:
            if any(req.family == item.family and _broader(item.scope, req.scope)
                   for req in required_trace):
                result.scope_expansions.append(item)
        # A request which crosses a trust boundary is a hard least-privilege violation.
        if result.scope_expansions:
            result.hard_violations.append("scope_expansion")
        return result


def _covered(candidate: PermissionRef, available: Iterable[PermissionRef]) -> bool:
    return any(candidate.family == item.family
               and _resource_covers(item, candidate)
               and _scope_covers(item.scope, candidate.scope)
               and _classification_covers(item.classification, candidate.classification)
               and _fields_covers(item, candidate)
               for item in available)


def _covered_by_required(candidate: PermissionRef, required: Iterable[PermissionRef]) -> bool:
    return any(candidate.family == item.family
               and _required_resource_covers(item, candidate)
               and _required_scope_covers(item.scope, candidate.scope)
               and _classification_covers(item.classification, candidate.classification)
               and _fields_covers(item, candidate)
               for item in required)


def _resource_covers(granted: PermissionRef, requested: PermissionRef) -> bool:
    """Compare resource type/IDs without treating unknown grants as precise."""
    if granted.resource_type != requested.resource_type:
        return not requested.resource_type and not granted.resource_type
    if not requested.resource_ids:
        return True
    return bool(granted.resource_ids) and granted.resource_ids == requested.resource_ids


def _required_resource_covers(required: PermissionRef, requested: PermissionRef) -> bool:
    if required.resource_type != requested.resource_type:
        return False
    if required.resource_ids and tuple(required.resource_ids) != tuple(requested.resource_ids):
        return False
    return True


def _fields_covers(granted: PermissionRef, requested: PermissionRef) -> bool:
    if requested.field_scope and granted.field_scope != requested.field_scope:
        return False
    # Legacy trace records may intentionally omit purpose; that omission is
    # a bounded wildcard for the operation's known resource/scope template.
    if granted.purpose and requested.purpose and granted.purpose != requested.purpose:
        return False
    # TTL is an authorization boundary.  An absent or different TTL is not
    # evidence that the request is within the required trace.  This is
    # intentionally strict for both grants and required traces; callers can
    # issue a new, explicitly bounded grant instead of inheriting an unknown
    # lifetime.
    if granted.ttl_seconds != requested.ttl_seconds:
        return False
    return True


def _scope_covers(granted: str, requested: str) -> bool:
    # Scope boundaries are not interchangeable.  Only an explicit implication
    # edge may derive another permission, and closure preserves this scope.
    return granted == requested


def _required_scope_covers(required: str, requested: str) -> bool:
    """Unknown trace scope is insufficient evidence for any authorization."""
    return required != "unknown" and requested != "unknown" and required == requested


def _broader(scope: str, than: str) -> bool:
    return than != "unknown" and scope != than and _SCOPE_RANK.get(scope, -1) > _SCOPE_RANK.get(than, -1)


def _classification_covers(granted: str, requested: str) -> bool:
    return granted == requested or _CLASS_RANK.get(granted, -1) >= _CLASS_RANK.get(requested, -1)


def _implication_edges(relations: Iterable[dict[str, Any]]) -> list[tuple[str, str]]:
    edges: list[tuple[str, str]] = []
    for relation in relations:
        if str(relation.get("effect", relation.get("type", ""))).lower() != "implies":
            continue
        source = relation.get("source", relation.get("from"))
        target = relation.get("target", relation.get("to"))
        implies = relation.get("implies")
        if (not source or not target) and isinstance(implies, list) and len(implies) >= 2:
            source, target = implies[0], implies[1]
        if isinstance(source, str) and isinstance(target, str) and source and target:
            edges.append((source, target))
    return edges


def _nested_permissions(value: Any) -> list[PermissionRef]:
    found: list[PermissionRef] = []
    if isinstance(value, PermissionRef):
        return [value]
    if isinstance(value, CapabilityGrant):
        return list(value.permissions) or [PermissionRef(family=value.family, scope=value.scope)]
    if isinstance(value, dict):
        if isinstance(value.get("family"), str):
            found.append(PermissionRef(
                family=value["family"],
                resource_type=str(value.get("resource_type", "")),
                resource_ids=tuple(value.get("resource_ids", ())) if isinstance(value.get("resource_ids", ()), (list, tuple)) else (),
                scope=str(value.get("scope", "unknown")),
                classification=str(value.get("classification", "internal")),
                field_scope=tuple(value.get("field_scope", ())) if isinstance(value.get("field_scope", ()), (list, tuple)) else (),
                purpose=str(value.get("purpose", "")),
                ttl_seconds=value.get("ttl_seconds"),
                grant_mode=str(value.get("grant_mode", "direct")),
            ))
        for key in ("inherited_roles", "active_capabilities", "delegated_capabilities", "permissions", "grants"):
            found.extend(_nested_permissions(value.get(key, [])))
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            found.extend(_nested_permissions(item))
    return found


def _inactive(grant: CapabilityGrant) -> bool:
    if grant.constraints.get("revoked") is True or grant.constraints.get("revoked_at"):
        return True
    if str(grant.constraints.get("status", "")).lower() in {"revoked", "expired", "inactive"}:
        return True
    if not grant.expires_at:
        return False
    try:
        value = grant.expires_at.replace("Z", "+00:00")
        expiry = datetime.fromisoformat(value)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return expiry <= datetime.now(timezone.utc)
    except (TypeError, ValueError):
        return False
