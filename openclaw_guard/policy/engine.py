"""Deterministic PMKB authorization orchestration for enriched behavior events."""

from __future__ import annotations

import json
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
        event.metadata["grant_source"] = grant_source
        effective = self.permission_closure.close(grants)
        requested = self._requested_permissions(event, trace)
        required_trace = self._required_trace_permissions(event, trace)
        diff = self.permission_diff.compute(effective, requested, required_trace)
        violations = self.risk_graph.evaluate(
            effective=effective,
            requested_delta=diff.requested_delta,
            trace=trace,
        )

        evaluated = self.policy_evaluator.evaluate(trace)
        effects = [evaluated.effect, *(item.effect for item in violations)]
        if diff.hard_violations:
            effects.append("block")
        effect = max(effects, key=lambda candidate: _EFFECT_RANK[candidate])
        missing_features = list(dict.fromkeys([
            *evaluated.missing_features,
            *trace.coverage.gaps,
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
            "p_after": sorted(set(effective) | set(diff.requested_delta), key=repr),
            "combo_violations": [item.relation_id for item in violations],
            "grant_source": grant_source,
        })
        decision.replay_hash = sha256_text(json.dumps({
            "trace": trace.model_dump(mode="json"),
            "decision": decision.model_dump(mode="json", exclude={"replay_hash"}),
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return decision

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
        rule_ids = set(self.policy_evaluator.evaluate(trace).candidate_rule_ids)
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
            return [], "empty_default"
        grants: list[CapabilityGrant] = []
        for item in raw_grants:
            try:
                grant = item if isinstance(item, CapabilityGrant) else CapabilityGrant.model_validate(item)
                if grant.principal_id and grant.principal_id != principal_id:
                    continue
                if grant.owner_id and grant.owner_id != principal_id:
                    continue
                grants.append(grant)
            except Exception:
                continue
        return grants, "event_metadata"


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
