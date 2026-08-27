"""Typed permission knowledge-base and authorization models."""

from .models import (
    AuthorizationTrace,
    CapabilityGrant,
    ContextRef,
    CoverageResult,
    DataRef,
    MatchCandidate,
    OperationRef,
    PermissionRef,
    PolicyDecision,
    PolicyRule,
    PrincipalRef,
    ProvenanceRef,
    ResourceRef,
)
from .evaluator import PolicyEvaluator

__all__ = [
    "AuthorizationTrace", "CapabilityGrant", "ContextRef", "CoverageResult",
    "DataRef", "MatchCandidate", "OperationRef", "PermissionRef",
    "PolicyDecision", "PolicyRule", "PrincipalRef", "ProvenanceRef", "ResourceRef",
    "PolicyEvaluator",
]
