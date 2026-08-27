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
                    pending.append(PermissionRef(family=target, scope=current.scope,
                                                 classification=current.classification))
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

        for item in result.requested_delta:
            if not _covered_by_required(item, required_trace):
                result.excessive_permissions.append(item)

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
               and _scope_covers(item.scope, candidate.scope)
               and _classification_covers(item.classification, candidate.classification)
               for item in available)


def _covered_by_required(candidate: PermissionRef, required: Iterable[PermissionRef]) -> bool:
    return any(candidate.family == item.family
               and _scope_covers(item.scope, candidate.scope)
               and _classification_covers(item.classification, candidate.classification)
               for item in required)


def _scope_covers(granted: str, requested: str) -> bool:
    # Scope boundaries are not interchangeable.  Only an explicit implication
    # edge may derive another permission, and closure preserves this scope.
    return granted == requested


def _broader(scope: str, than: str) -> bool:
    return scope != than and _SCOPE_RANK.get(scope, -1) > _SCOPE_RANK.get(than, -1)


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
            found.append(PermissionRef(family=value["family"], scope=str(value.get("scope", "unknown")),
                                       classification=str(value.get("classification", "internal"))))
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
