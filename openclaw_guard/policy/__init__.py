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

__all__ = [
    "AuthorizationTrace", "CapabilityGrant", "ContextRef", "CoverageResult",
    "DataRef", "MatchCandidate", "OperationRef", "PermissionRef",
    "PolicyDecision", "PolicyRule", "PrincipalRef", "ProvenanceRef", "ResourceRef",
]
