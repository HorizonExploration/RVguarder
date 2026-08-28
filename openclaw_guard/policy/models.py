"""Pydantic models for normalized permission records and authorization evidence."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import ConfigDict, Field

from openclaw_guard.models import GuardBaseModel


class PrincipalRef(GuardBaseModel):
    id: str
    type: Literal["human", "agent", "skill", "service"]
    trust: Literal["verified", "unknown"] = "unknown"


class OperationRef(GuardBaseModel):
    family: str
    tool_id: str = ""
    arguments: dict[str, Any] = Field(default_factory=dict)
    aliases: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)


class ResourceRef(GuardBaseModel):
    type: str
    ids: list[str] = Field(default_factory=list)
    scope: Literal["workspace", "outside", "external", "unknown"] = "unknown"


class DataRef(GuardBaseModel):
    classification: Literal["public", "internal", "sensitive", "secret"] = "internal"
    quantity: int = 0


class ContextRef(GuardBaseModel):
    recipient_zone: Literal["internal", "external", "unknown"] = "unknown"
    purpose: str = ""


class ProvenanceRef(GuardBaseModel):
    source: str = "unknown"
    trust: str = "unknown"


class CoverageResult(GuardBaseModel):
    status: Literal["complete", "partial", "unknown", "conflict"]
    matched_rules: list[str] = Field(default_factory=list)
    missing_features: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)


class AuthorizationTrace(GuardBaseModel):
    trace_id: str
    principal: PrincipalRef
    operation: OperationRef
    resource: ResourceRef
    coverage: CoverageResult
    sequence: int = 0
    agent_id: str | None = None
    session_id: str | None = None
    goal_id: str | None = None
    capability_lineage: list[str] = Field(default_factory=list)
    data: DataRef = Field(default_factory=DataRef)
    context: ContextRef = Field(default_factory=ContextRef)
    provenance: ProvenanceRef = Field(default_factory=ProvenanceRef)
    confidence: dict[str, float] = Field(default_factory=dict)
    legacy_steps: list[dict[str, Any]] = Field(default_factory=list)


class PermissionRef(GuardBaseModel):
    model_config = ConfigDict(frozen=True)
    family: str
    # The dimensions below make least-privilege comparisons explicit.  They
    # intentionally use tuples so a PermissionRef remains hashable/frozen and
    # can safely participate in closure sets and replay evidence.
    resource_type: str = ""
    resource_ids: tuple[str, ...] = ()
    scope: str = "unknown"
    classification: str = "internal"
    field_scope: tuple[str, ...] = ()
    purpose: str = ""
    ttl_seconds: int | None = None
    grant_mode: Literal["direct", "inherited", "delegated", "temporary"] = "direct"


class CapabilityGrant(GuardBaseModel):
    family: str
    scope: str = "unknown"
    grant_id: str | None = None
    principal_id: str | None = None
    permissions: list[PermissionRef] = Field(default_factory=list)
    constraints: dict[str, Any] = Field(default_factory=dict)
    expires_at: str | None = None
    owner_id: str | None = None
    delegated_by: str | None = None
    delegates: list[str] = Field(default_factory=list)


class MatchCandidate(GuardBaseModel):
    rule_id: str = ""
    score: float = 0.0
    status: Literal["matched", "partial", "unknown", "conflict"] = "unknown"
    matched: bool = False
    reasons: list[str] = Field(default_factory=list)
    missing_features: list[str] = Field(default_factory=list)


class PolicyDecision(GuardBaseModel):
    effect: Literal[
        "auto_allow_audit", "clarify_then_retry", "openclaw_approval", "block",
    ]
    match_status: Literal["matched", "partial", "unknown", "conflict"]
    match_confidence: float = 0.0
    risk_score: int = 0
    selected_rule_ids: list[str] = Field(default_factory=list)
    candidate_rule_ids: list[str] = Field(default_factory=list)
    missing_features: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    requested_delta: list[PermissionRef] = Field(default_factory=list)
    redundant_permissions: list[PermissionRef] = Field(default_factory=list)
    excessive_permissions: list[PermissionRef] = Field(default_factory=list)
    scope_expansions: list[PermissionRef] = Field(default_factory=list)
    hard_violations: list[str] = Field(default_factory=list)
    effective_permissions: list[PermissionRef] = Field(default_factory=list)
    p_after: list[PermissionRef] = Field(default_factory=list)
    combo_violations: list[str] = Field(default_factory=list)
    grant_source: str = ""
    policy_version: str = ""
    replay_hash: str = ""


class PolicyRule(GuardBaseModel):
    id: str
    version: str
    effect: Literal[
        "auto_allow_audit", "clarify_then_retry", "openclaw_approval", "block",
    ]
    priority: int = 0
    match: dict[str, Any] = Field(default_factory=dict)
    required_fields: list[str] = Field(default_factory=list)
    negative_conditions: list[dict[str, Any]] = Field(default_factory=list)
    obligations: list[str] = Field(default_factory=list)
    source: str = ""
    test_vectors: list[str] = Field(default_factory=list)
    rollback_state: str = ""
    positive_examples: list[dict[str, Any]] = Field(default_factory=list)
    negative_examples: list[dict[str, Any]] = Field(default_factory=list)
