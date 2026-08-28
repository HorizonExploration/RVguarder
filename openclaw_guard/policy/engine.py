"""Deterministic PMKB authorization orchestration for enriched behavior events."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from openclaw_guard.models import BehaviorEvent
from openclaw_guard.policy.catalog import PolicyBundle, default_policy_root
from openclaw_guard.policy.evaluator import PolicyEvaluator
from openclaw_guard.policy.models import AuthorizationTrace, CapabilityGrant, PermissionRef, PolicyDecision
from openclaw_guard.policy.permission_diff import PermissionClosure, PermissionDiff
from openclaw_guard.policy.risk_graph import RiskGraph
from openclaw_guard.policy.trace import TraceCompiler
from openclaw_guard.utils import sha256_text


_EFFECT_RANK = {
    "auto_allow_audit": 0,
    "clarify_then_retry": 1,
    "openclaw_approval": 2,
    "block": 3,
}
_BRIDGED_TOOL_ALIASES = {"shell", "exec", "command", "bash", "run", "execute"}


class AuthorizationPolicyEngine:
    """Evaluate local PMKB policy without invoking an LLM or network service."""

    def __init__(self, policy_root: Path | None = None) -> None:
        self.policy_root = Path(policy_root) if policy_root is not None else default_policy_root()
        self.bundle = PolicyBundle.load(self.policy_root)
        self.trace_compiler = TraceCompiler(self.bundle)
        self.policy_evaluator = PolicyEvaluator(self.bundle)
        self.permission_closure = PermissionClosure(self.bundle)
        self.permission_diff = PermissionDiff()
        self.risk_graph = RiskGraph.from_bundle(self.bundle)

    def compile_trace(self, event: BehaviorEvent, *, source_message: str = "") -> AuthorizationTrace:
        """Compile the event's already-enriched semantic context into PMKB evidence."""
        semantic = event.metadata.get("semantic")
        rv_trace = event.metadata.get("rv_trace")
        return self.trace_compiler.compile(
            event,
            semantic=semantic if isinstance(semantic, dict) else {},
            rv_trace=rv_trace if isinstance(rv_trace, list) else [],
            source_message=source_message,
        )

    def evaluate(self, event: BehaviorEvent, *, source_message: str = "") -> PolicyDecision:
        """Evaluate one event with its grants, least-privilege delta, and risk graph."""
        trace = self._trace_for(event, source_message=source_message)
        grants, grant_source = self._grants_for(event, trace.principal.id)
        grant_gaps = list(event.metadata.get("grant_validation_gaps") or [])
        event.metadata["grant_source"] = grant_source
        effective = self.permission_closure.close(grants)
        requested = self._requested_permissions(event, trace)
        required_trace = self._required_trace_permissions(event, trace)
        diff = self.permission_diff.compute(effective, requested, required_trace)
        # Evaluate toxic combinations against the authority that would exist
        # after this request, including any explicit implication edges.  A
        # plain set union would omit permissions derived from the requested
        # operation and could hide a downstream combination risk.
        p_after = self.permission_closure.close(
            self._permission_grants(set(effective) | set(requested))
        )
        violations = self.risk_graph.evaluate(
            effective=p_after,
            requested_delta=diff.requested_delta,
            trace=trace,
        )

        evaluated = self.policy_evaluator.evaluate(trace)
        effects = [evaluated.effect, *(item.effect for item in violations)]
        # Least-privilege evidence is a security gate, not advisory telemetry:
        # a request outside the required trace must reach the sole OpenClaw
        # approval owner even when the operation itself has an allow template.
        if diff.excessive_permissions or diff.coverage_gaps:
            effects.append("openclaw_approval")
        if grant_gaps:
            effects.append("openclaw_approval")
        if diff.hard_violations:
            effects.append("block")
        effect = max(effects, key=lambda candidate: _EFFECT_RANK[candidate])
        missing_features = list(dict.fromkeys([
            *evaluated.missing_features,
            *trace.coverage.gaps,
            *diff.coverage_gaps,
            *(f"grant:{item}" for item in grant_gaps),
            *( ["tool_mapping"] if self._raw_tool_is_unmapped(event) else [] ),
        ]))
        decision = evaluated.model_copy(update={
            "effect": effect,
            "risk_score": max([evaluated.risk_score, *(item.severity for item in violations)], default=evaluated.risk_score),
            "missing_features": missing_features,
            "requested_delta": diff.requested_delta,
            "redundant_permissions": diff.redundant_permissions,
            "excessive_permissions": diff.excessive_permissions,
            "scope_expansions": diff.scope_expansions,
            "hard_violations": diff.hard_violations,
            "effective_permissions": sorted(effective, key=repr),
            "p_after": sorted(p_after, key=repr),
            "combo_violations": [item.relation_id for item in violations],
            "grant_source": grant_source,
            "grant_validation_gaps": grant_gaps,
        })
        decision.replay_hash = sha256_text(json.dumps({
            "trace": trace.model_dump(mode="json"),
            "decision": decision.model_dump(mode="json", exclude={"replay_hash"}),
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return decision

    @staticmethod
    def _permission_grants(permissions: set[PermissionRef]) -> list[CapabilityGrant]:
        """Represent already-normalized permissions as closure inputs."""
        return [
            CapabilityGrant(family=permission.family, scope=permission.scope,
                            permissions=[permission])
            for permission in permissions
        ]

    def _requested_permissions(self, event: BehaviorEvent, trace: AuthorizationTrace) -> list[PermissionRef]:
        raw = event.metadata.get("requested_permissions")
        if isinstance(raw, list):
            parsed = _permission_refs(raw)
            if parsed:
                return parsed
        return [_permission_from_trace(trace)]

    def _required_trace_permissions(self, event: BehaviorEvent, trace: AuthorizationTrace) -> list[PermissionRef]:
        raw = event.metadata.get("required_trace")
        if isinstance(raw, list):
            parsed = _permission_refs(raw)
            if parsed:
                return parsed
        # Versioned P0 traces are executable data, not documentation only.
        evaluated = self.policy_evaluator.evaluate(trace)
        # Only traces for rules that actually apply to the normalized request
        # define the least-privilege boundary.  Keeping every candidate trace
        # would mix mutually exclusive scope variants (for example workspace
        # and outside file writes) and falsely report a scope expansion.
        rule_ids = set(evaluated.selected_rule_ids or evaluated.candidate_rule_ids)
        parsed: list[PermissionRef] = []
        for item in self.bundle.traces:
            if item.get("rule_id") not in rule_ids:
                continue
            parsed.extend(_permission_refs(item.get("required_permissions", [])))
        return parsed or [_permission_from_trace(trace)]

    def _raw_tool_is_unmapped(self, event: BehaviorEvent) -> bool:
        """Retain an explicit coverage gap when action inference masks an unknown tool."""
        tool_name = str(event.metadata.get("tool_name") or event.api_name or "")
        return bool(
            tool_name
            and tool_name.lower() not in _BRIDGED_TOOL_ALIASES
            and self.bundle.operation_for_tool(tool_name, {}).family == "unknown_tool"
        )

    def _trace_for(self, event: BehaviorEvent, *, source_message: str) -> AuthorizationTrace:
        """Use the pipeline's compiled trace when valid, otherwise compile locally."""
        serialized = event.metadata.get("authorization_trace")
        if isinstance(serialized, dict):
            try:
                return AuthorizationTrace.model_validate(serialized)
            except Exception:
                pass
        trace = self.compile_trace(event, source_message=source_message)
        event.metadata["authorization_trace"] = trace.model_dump()
        return trace

    @staticmethod
    def _grants_for(event: BehaviorEvent, principal_id: str) -> tuple[list[CapabilityGrant], str]:
        """Normalize grants from event metadata, defaulting explicitly to no grant."""
        raw_grants = event.metadata.get("current_permissions")
        if not isinstance(raw_grants, list):
            if "current_permissions" in event.metadata:
                event.metadata["grant_validation_gaps"] = ["current_permissions.invalid"]
            else:
                event.metadata["grant_validation_gaps"] = []
            return [], "empty_default"
        grants: list[CapabilityGrant] = []
        validation_gaps: list[str] = []
        for item in raw_grants:
            try:
                grant = item if isinstance(item, CapabilityGrant) else CapabilityGrant.model_validate(item)
                if grant.principal_id and grant.principal_id != principal_id:
                    continue
                gaps = _validate_grant_for_principal(grant, principal_id)
                if gaps:
                    label = grant.grant_id or grant.family or "unnamed"
                    validation_gaps.extend(f"{label}:{item}" for item in gaps)
                    continue
                grants.append(grant)
            except Exception:
                validation_gaps.append("grant.malformed")
                continue
        event.metadata["grant_validation_gaps"] = list(dict.fromkeys(validation_gaps))
        return grants, "event_metadata"


_SCOPE_RANK = {"own": 0, "workspace": 1, "outside": 2, "external": 3, "bulk": 4}


def _validate_grant_for_principal(grant: CapabilityGrant, principal_id: str) -> list[str]:
    """Validate ownership and delegation evidence before a grant enters closure.

    Direct grants retain the historical compact shape used by the local policy
    tests.  Delegated grants require an explicit owner/issuer/delegate chain,
    a known bounded scope, and both a positive permission TTL and grant expiry;
    unsupported or incomplete chains are rejected and surfaced as an approval
    gap instead of being treated as an empty, safe grant.
    """
    constraints = grant.constraints if isinstance(grant.constraints, dict) else {}
    permissions = list(grant.permissions)
    declared_mode = str(constraints.get("grant_mode") or "").lower()
    delegated = (
        declared_mode == "delegated"
        or bool(grant.delegated_by)
        or bool(grant.delegates)
        or any(permission.grant_mode == "delegated" for permission in permissions)
    )
    gaps: list[str] = []
    if not delegated:
        if grant.owner_id and grant.owner_id != principal_id:
            gaps.append("owner_mismatch")
        return gaps

    if not grant.owner_id:
        gaps.append("owner_missing")
    if not grant.delegated_by:
        gaps.append("issuer_missing")
    elif grant.delegated_by == principal_id:
        gaps.append("issuer_self_delegation")
    elif grant.owner_id and grant.delegated_by != grant.owner_id and constraints.get("issuer_can_delegate") is not True:
        gaps.append("issuer_not_owner")

    delegates = grant.delegates
    if not isinstance(delegates, list):
        gaps.append("delegate_list_invalid")
    elif grant.principal_id != principal_id and principal_id not in delegates:
        gaps.append("delegate_not_authorized")

    if grant.scope == "unknown":
        gaps.append("scope_unknown")
    configured_scope = constraints.get("scope")
    if configured_scope is not None and configured_scope != grant.scope:
        gaps.append("scope_mismatch")
    allowed_scopes = constraints.get("allowed_scopes")
    if allowed_scopes is not None and (
        not isinstance(allowed_scopes, list)
        or any(permission.scope not in allowed_scopes for permission in permissions)
    ):
        gaps.append("scope_not_allowed")
    if grant.scope != "unknown":
        grant_rank = _SCOPE_RANK.get(grant.scope, -1)
        if grant_rank < 0:
            gaps.append("scope_invalid")
        for permission in permissions:
            if permission.scope == "unknown":
                gaps.append("permission_scope_unknown")
            elif _SCOPE_RANK.get(permission.scope, -1) > grant_rank:
                gaps.append("permission_scope_expansion")

    if not permissions:
        gaps.append("permissions_missing")
    for permission in permissions:
        if permission.grant_mode != "delegated":
            gaps.append("permission_mode_mismatch")
        if permission.ttl_seconds is None or permission.ttl_seconds <= 0:
            gaps.append("permission_ttl_missing")
        max_ttl = constraints.get("max_ttl_seconds")
        if isinstance(max_ttl, int) and permission.ttl_seconds is not None and permission.ttl_seconds > max_ttl:
            gaps.append("permission_ttl_exceeded")

    if not grant.expires_at:
        gaps.append("expiry_missing")
    else:
        try:
            expiry = datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry <= datetime.now(timezone.utc):
                gaps.append("expired")
        except (TypeError, ValueError):
            gaps.append("expiry_invalid")
    return list(dict.fromkeys(gaps))


def _permission_from_trace(trace: AuthorizationTrace) -> PermissionRef:
    return PermissionRef(
        family=trace.operation.family,
        resource_type=trace.resource.type,
        resource_ids=tuple(trace.resource.ids),
        scope=trace.resource.scope,
        classification=trace.data.classification,
        purpose=trace.context.purpose,
    )


def _permission_refs(raw: object) -> list[PermissionRef]:
    if not isinstance(raw, list):
        return []
    result: list[PermissionRef] = []
    for item in raw:
        try:
            result.append(item if isinstance(item, PermissionRef) else PermissionRef.model_validate(item))
        except Exception:
            continue
    return result
