"""跨会话主体的授权证据状态。"""

from __future__ import annotations

import time as _time
from typing import Any

from openclaw_guard.policy.catalog import PolicyBundle, default_policy_root
from openclaw_guard.policy.models import AuthorizationTrace, PermissionRef, PolicyDecision
from openclaw_guard.policy.risk_graph import RiskGraph


class PrincipalSecurityState:
    """Bounded authorization evidence retained across sessions for one identity.

    The identity key is the complete ``(principal_id, agent_id,
    capability_lineage)`` tuple.  Session and goal identifiers are retained as
    evidence only: a goal can partition work but cannot prove that two records
    belong to the same principal capability.
    """

    _DEFAULT_TTL_SECONDS = 300
    _MAX_SENSITIVE_EVENTS = 32

    def __init__(
        self,
        principal_id: str,
        agent_id: str,
        capability_lineage: tuple[str, ...],
        *,
        ttl_seconds: int | None = _DEFAULT_TTL_SECONDS,
    ) -> None:
        self.principal_id = principal_id
        self.agent_id = agent_id
        self.capability_lineage = tuple(capability_lineage)
        self.ttl_seconds = ttl_seconds
        self.effective_grants: set[PermissionRef] = set()
        self.sensitive_data_lineage: list[dict[str, Any]] = []
        self.revocations: set[str] = set()
        self.sequence = 0
        self._grant_observed_at: dict[PermissionRef, float] = {}
        self._last_seen_at = _time.monotonic()
        self._risk_graph = RiskGraph.from_bundle(PolicyBundle.load(default_policy_root()))

    @property
    def last_seen_at(self) -> float:
        """Return the monotonic time of the most recent state activity."""
        return self._last_seen_at

    def record(self, trace: AuthorizationTrace, decision: PolicyDecision) -> str | None:
        """Record normalized evidence and escalate an observed toxic chain.

        Inconclusive or mismatched identity evidence is never treated as safe;
        it preserves an existing block and otherwise routes through OpenClaw
        approval.  Allowed operations become effective grants only after the
        risk check, so a request awaiting approval does not expand authority.
        """
        effect = self.evaluate(trace, decision)
        if effect is not None:
            return effect
        self._last_seen_at = _time.monotonic()
        self.sequence = max(self.sequence + 1, trace.sequence)
        if trace.operation.family in {"capability.revoke", "capability.expire"}:
            self.revoke(*trace.capability_lineage)
            return None
        requested = PermissionRef(
            family=trace.operation.family,
            resource_type=trace.resource.type,
            resource_ids=tuple(trace.resource.ids),
            scope=trace.resource.scope,
            classification=trace.data.classification,
            purpose=trace.context.purpose,
        )
        if decision.effect == "auto_allow_audit":
            self.effective_grants.add(requested)
            self._grant_observed_at[requested] = _time.time()
            self._record_sensitive_lineage(trace)
        return None

    def evaluate(self, trace: AuthorizationTrace, decision: PolicyDecision) -> str | None:
        """Evaluate a requested operation against committed principal evidence.

        This method never expands grants or lineage, so it is safe on the
        before-tool-call path.  ``record`` is reserved for successful tools.
        """
        self._expire_old()
        if not isinstance(trace, AuthorizationTrace) or not isinstance(decision, PolicyDecision):
            raise TypeError("PrincipalSecurityState accepts normalized policy evidence only")
        if not self._matches_identity(trace):
            return self._inconclusive_effect(decision)

        if trace.operation.family in {"capability.revoke", "capability.expire"}:
            return "block" if decision.effect == "block" else None
        if self.revocations.intersection(trace.capability_lineage):
            return self._inconclusive_effect(decision)

        requested = PermissionRef(
            family=trace.operation.family,
            resource_type=trace.resource.type,
            resource_ids=tuple(trace.resource.ids),
            scope=trace.resource.scope,
            classification=trace.data.classification,
            purpose=trace.context.purpose,
        )
        violations = self._risk_graph.evaluate(
            effective=frozenset(self.effective_grants),
            requested_delta=[requested],
            trace=trace,
        )
        if violations:
            return "block" if any(item.effect == "block" for item in violations) else "openclaw_approval"
        if decision.effect == "block":
            return "block"
        return None

    def revoke(self, *grant_ids: str) -> None:
        """Revoke lineage grants and remove authority learned from them."""
        self.revocations.update(grant_id for grant_id in grant_ids if grant_id)
        if self.revocations.intersection(self.capability_lineage):
            self.effective_grants.clear()
            self._grant_observed_at.clear()
            self.sensitive_data_lineage.clear()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible principal-state snapshot."""
        self._expire_old()
        return {
            "principal_id": self.principal_id,
            "agent_id": self.agent_id,
            "capability_lineage": list(self.capability_lineage),
            "ttl_seconds": self.ttl_seconds,
            "sequence": self.sequence,
            "effective_grants": [grant.model_dump(mode="json") for grant in sorted(self.effective_grants, key=repr)],
            "sensitive_data_lineage": list(self.sensitive_data_lineage),
            "revocations": sorted(self.revocations),
            "grant_observed_at": [
                {"grant": grant.model_dump(mode="json"), "observed_at": observed_at}
                for grant, observed_at in self._grant_observed_at.items()
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PrincipalSecurityState:
        """Restore a principal-state snapshot, tolerating old or partial data."""
        lineage = data.get("capability_lineage", [])
        state = cls(
            str(data.get("principal_id", "")),
            str(data.get("agent_id", "")),
            tuple(item for item in lineage if isinstance(item, str)) if isinstance(lineage, list) else (),
            ttl_seconds=data.get("ttl_seconds", cls._DEFAULT_TTL_SECONDS),
        )
        state.sequence = int(data.get("sequence", 0) or 0)
        state.revocations = {item for item in data.get("revocations", []) if isinstance(item, str)}
        raw_sensitive = data.get("sensitive_data_lineage", [])
        if isinstance(raw_sensitive, list):
            state.sensitive_data_lineage = [item for item in raw_sensitive if isinstance(item, dict)][-cls._MAX_SENSITIVE_EVENTS:]
        raw_grants = data.get("grant_observed_at", [])
        if isinstance(raw_grants, list):
            for item in raw_grants:
                if not isinstance(item, dict) or not isinstance(item.get("grant"), dict):
                    continue
                try:
                    grant = PermissionRef.model_validate(item["grant"])
                    state.effective_grants.add(grant)
                    state._grant_observed_at[grant] = float(item.get("observed_at", 0))
                except (TypeError, ValueError):
                    continue
        else:
            for item in data.get("effective_grants", []):
                if isinstance(item, dict):
                    try:
                        grant = PermissionRef.model_validate(item)
                        state.effective_grants.add(grant)
                        state._grant_observed_at[grant] = _time.time()
                    except (TypeError, ValueError):
                        continue
        state._expire_old()
        return state

    def _matches_identity(self, trace: AuthorizationTrace) -> bool:
        """Require every state-key component on normalized evidence to match."""
        return bool(
            self.principal_id
            and self.agent_id
            and self.capability_lineage
            and trace.principal.id
            and trace.agent_id
            and trace.capability_lineage
            and trace.principal.id == self.principal_id
            and trace.agent_id == self.agent_id
            and tuple(trace.capability_lineage) == self.capability_lineage
        )

    @staticmethod
    def _inconclusive_effect(decision: PolicyDecision) -> str:
        """Map incomplete evidence to a non-safe policy route."""
        return "block" if decision.effect == "block" else "openclaw_approval"

    def _record_sensitive_lineage(self, trace: AuthorizationTrace) -> None:
        """Retain bounded sensitive-data provenance for approved capabilities."""
        if trace.data.classification not in {"sensitive", "secret"}:
            return
        self.sensitive_data_lineage.append({
            "trace_id": trace.trace_id,
            "classification": trace.data.classification,
            "session_id": trace.session_id,
            "goal_id": trace.goal_id,
            "sequence": self.sequence,
            "observed_at": _time.time(),
        })
        del self.sensitive_data_lineage[:-self._MAX_SENSITIVE_EVENTS]

    def _expire_old(self) -> None:
        """Expire grants and lineage evidence outside the configured TTL."""
        if self.ttl_seconds is None:
            return
        cutoff = _time.time() - self.ttl_seconds
        for grant, observed_at in tuple(self._grant_observed_at.items()):
            if observed_at < cutoff:
                self._grant_observed_at.pop(grant, None)
                self.effective_grants.discard(grant)
        self.sensitive_data_lineage[:] = [
            item for item in self.sensitive_data_lineage
            if float(item.get("observed_at", 0)) >= cutoff
        ]
