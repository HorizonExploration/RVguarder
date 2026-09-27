"""Pydantic models for normalized permission records and authorization evidence."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import ConfigDict, Field, StrictBool, StrictFloat, StrictInt, StrictStr

from openclaw_guard.models import GuardBaseModel


class _FrozenList(list[Any]):
    """List-compatible immutable container used inside loaded policy records."""

    def _immutable(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("policy records are immutable")

    __setitem__ = __delitem__ = __iadd__ = __imul__ = _immutable
    append = clear = extend = insert = pop = remove = reverse = sort = _immutable


class _FrozenDict(dict[str, Any]):
    """Dict-compatible immutable container that remains Pydantic serializable."""

    def _immutable(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("policy records are immutable")

    __setitem__ = __delitem__ = __ior__ = _immutable
    clear = pop = popitem = setdefault = update = _immutable


def _deep_freeze(value: Any) -> Any:
    """Recursively freeze JSON-shaped policy fields without losing JSON support."""
    if isinstance(value, dict):
        return _FrozenDict({key: _deep_freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return _FrozenList(_deep_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_deep_freeze(item) for item in value)
    return value


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
    scope: Literal["workspace", "managed_project", "outside", "external", "unknown"] = "unknown"


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


class SecurityFactEvidence(GuardBaseModel):
    value: StrictBool | StrictInt | StrictFloat | StrictStr
    source: Literal["deterministic", "llm", "local"]
    trust: Literal["verified", "suggested"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str = ""


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
    security_facts: dict[str, SecurityFactEvidence] = Field(default_factory=dict)
    rv_steps: list[dict[str, Any]] = Field(default_factory=list)


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
    evidence_trust: Literal["verified", "suggested", "mixed", "none"] = "none"


class PolicyDecision(GuardBaseModel):
    effect: Literal[
        "auto_allow_audit", "openclaw_approval", "block",
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
    grant_validation_gaps: list[str] = Field(default_factory=list)
    policy_version: str = ""
    replay_hash: str = ""


class PolicyRule(GuardBaseModel):
    model_config = ConfigDict(frozen=True)
    id: str
    version: str
    effect: Literal[
        "auto_allow_audit", "openclaw_approval", "block",
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
    legacy_rule_ids: list[str] = Field(default_factory=list)
    # Rules with strict predicates must not elevate on a missing predicate;
    # the evaluator still reports the missing feature for fail-closed review.
    partial_behavior: Literal["candidate", "ignore"] = "candidate"

    def model_post_init(self, __context: Any) -> None:
        """Freeze nested rule data after Pydantic has validated the record."""
        for field_name in (
            "match", "required_fields", "negative_conditions", "obligations",
            "test_vectors", "positive_examples", "negative_examples", "legacy_rule_ids",
        ):
            object.__setattr__(self, field_name, _deep_freeze(getattr(self, field_name)))
