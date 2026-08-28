"""Sparse evaluation of permission combination (hyperedge) relations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable
from collections.abc import Mapping

from .catalog import PolicyBundle
from .models import AuthorizationTrace, PermissionRef


@dataclass(frozen=True)
class ComboViolation:
    relation_id: str
    permissions: tuple[str, ...]
    conditions: dict[str, Any]
    severity: int
    effect: str
    evidence: dict[str, Any]


_ID_ALIASES = {
    "secret-egress": "COMBO-SECRET-EGRESS-001",
    "export-sensitive-recipient": "COMBO-EXPORT-SENSITIVE-001",
    "config-audit": "COMBO-CONFIG-AUDIT-001",
    "credential-process": "COMBO-CREDENTIAL-PROCESS-001",
    "file-persistence": "COMBO-FILE-PERSISTENCE-001",
}
_CONDITION_ENDPOINTS = {
    "external_target", "external_recipient", "sensitive_data", "persistence_location",
}
_SEVERITY = {"block": 100, "openclaw_approval": 80, "clarify_then_retry": 50, "auto_allow_audit": 20}


class RiskGraph:
    """An indexed relation graph; evaluation visits only edges seeded by present families."""

    def __init__(self, relations: Iterable[dict[str, Any]]):
        self.relations = tuple(relations)
        frequencies: dict[str, int] = {}
        for relation in self.relations:
            if _relation_type(relation) not in {"toxic_with", "conflicts"}:
                continue
            for endpoint in relation.get("requires", ()):
                if endpoint not in _CONDITION_ENDPOINTS:
                    frequencies[endpoint] = frequencies.get(endpoint, 0) + 1
        self._index: dict[str, tuple[dict[str, Any], ...]] = {}
        for relation in self.relations:
            if _relation_type(relation) not in {"toxic_with", "conflicts"}:
                continue
            families = [x for x in relation.get("requires", ()) if x not in _CONDITION_ENDPOINTS]
            if not families:
                continue
            seed = min(families, key=lambda family: frequencies.get(family, 0))
            self._index.setdefault(seed, ())
            self._index[seed] = self._index[seed] + (relation,)

    @classmethod
    def from_bundle(cls, bundle: PolicyBundle) -> "RiskGraph":
        return cls(bundle.relations)

    def evaluate(
        self,
        *,
        effective: frozenset[PermissionRef],
        requested_delta: list[PermissionRef],
        trace: AuthorizationTrace,
    ) -> list[ComboViolation]:
        permissions = set(effective) | set(requested_delta)
        families = {permission.family for permission in permissions}
        violations: list[ComboViolation] = []
        seen: set[str] = set()
        for family in families:
            for relation in self._index.get(family, ()):
                relation_id = _ID_ALIASES.get(relation.get("id", ""), relation.get("id", ""))
                if relation_id in seen or not self._matches(relation, permissions, trace):
                    continue
                seen.add(relation_id)
                conditions = dict(relation.get("conditions", {}))
                evidence = self._evidence(relation, permissions, trace)
                violations.append(ComboViolation(
                    relation_id=relation_id,
                    permissions=tuple(relation.get("requires", ())),
                    conditions=conditions,
                    severity=int(relation.get("severity", _SEVERITY.get(relation.get("effect", ""), 0))),
                    effect=relation.get("effect", "openclaw_approval"),
                    evidence=evidence,
                ))
        return violations

    @staticmethod
    def _matches(relation: dict[str, Any], permissions: set[PermissionRef], trace: AuthorizationTrace) -> bool:
        required = relation.get("requires", ())
        families = {permission.family for permission in permissions}
        for endpoint in required:
            if endpoint in _CONDITION_ENDPOINTS:
                if not _condition_endpoint(endpoint, permissions, trace):
                    return False
            elif endpoint not in families:
                return False
        return _conditions_match(relation.get("conditions", {}), trace, permissions)

    @staticmethod
    def _evidence(relation: dict[str, Any], permissions: set[PermissionRef], trace: AuthorizationTrace) -> dict[str, Any]:
        relation_type = _relation_type(relation)
        return {
            "trace_id": trace.trace_id,
            "relation_version": relation.get("version", ""),
            "relation_type": relation_type,
            "matched_permissions": sorted({permission.family for permission in permissions}),
            "principal_id": trace.principal.id,
            "capability_lineage": list(trace.capability_lineage),
            "operation": trace.operation.family,
            "resource_scope": trace.resource.scope,
            "data_classification": trace.data.classification,
            "recipient_zone": trace.context.recipient_zone,
            **dict(relation.get("evidence", {})),
        }


def _condition_endpoint(endpoint: str, permissions: set[PermissionRef], trace: AuthorizationTrace) -> bool:
    if endpoint in {"external_target", "external_recipient"}:
        return trace.resource.scope == "external" or trace.context.recipient_zone == "external" or any(p.scope == "external" for p in permissions)
    if endpoint == "sensitive_data":
        return trace.data.classification in {"sensitive", "secret"} or any(p.classification in {"sensitive", "secret"} for p in permissions)
    if endpoint == "persistence_location":
        return trace.resource.scope in {"outside", "external"} or any(token in trace.operation.family.lower() for token in ("write", "persist", "save"))
    return False


def _relation_type(relation: dict[str, Any]) -> str:
    """Return the explicit relation kind, retaining old records as toxic edges."""
    return str(relation.get("type", relation.get("relation", "toxic_with"))).lower()


def _conditions_match(conditions: dict[str, Any], trace: AuthorizationTrace, permissions: set[PermissionRef]) -> bool:
    for field, requirement in conditions.items():
        value = {
            "quantity": trace.data.quantity,
            "classification": trace.data.classification,
            "data_classification": trace.data.classification,
            "external_target": trace.resource.scope == "external" or trace.context.recipient_zone == "external",
            "recipient_zone": trace.context.recipient_zone,
            "principal_lineage": trace.capability_lineage,
        }.get(field)
        if isinstance(requirement, Mapping):
            if "gte" in requirement and (value is None or value < requirement["gte"]):
                return False
            if "lte" in requirement and (value is None or value > requirement["lte"]):
                return False
            if "in" in requirement and value not in requirement["in"]:
                return False
            if "contains" in requirement and requirement["contains"] not in (value or []):
                return False
        elif value != requirement:
            return False
    return True
