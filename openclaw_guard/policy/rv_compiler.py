"""Compile PMKB policy records into symbolic RV monitor specifications."""

from __future__ import annotations

import re

from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.rv.rv_dsl import ChainRule, MonitorSpec, PolicyGuard, Ruleset, StepRequirement


_VERDICT_FOR_EFFECT = {
    "auto_allow_audit": "ok",
    "clarify_then_retry": "ask",
    "openclaw_approval": "ask",
    "block": "block",
}


class PermissionAutomatonCompiler:
    """Turn versioned PMKB rules into auditable symbolic RV monitors.

    The generated guards project the evaluator's authoritative outcome rather
    than duplicating predicate, closure, or risk-graph code.  It keeps the
    policy source of truth singular and gives runtime verification a stable
    state-machine representation with source IDs for audit and rollback.
    """

    def __init__(self, bundle: PolicyBundle) -> None:
        self.bundle = bundle

    def compile_ruleset(self) -> Ruleset:
        monitors = [self._rule_monitor(rule.id, rule.effect) for rule in self.bundle.rules]
        monitors.extend(
            self._relation_monitor(str(item["id"]), str(item["effect"]))
            for item in self.bundle.relations
            if str(item.get("effect")) in _VERDICT_FOR_EFFECT
        )
        return Ruleset(version=1, monitors=monitors, source_nl=f"PMKB {self.bundle.version}")

    @staticmethod
    def _safe_name(value: str) -> str:
        return re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_")

    def _rule_monitor(self, rule_id: str, effect: str) -> MonitorSpec:
        name = f"PMKBRule_{self._safe_name(rule_id)}"
        return MonitorSpec(
            name=name,
            initial="idle",
            scope="session",
            source="pmkb",
            source_ids=[rule_id],
            rules=[ChainRule(
                id=f"pmkb-rule-{rule_id}",
                **{"from": "*", "to": "matched"},
                verdict=_VERDICT_FOR_EFFECT[effect],
                origin="pmkb",
                source_nl=f"PMKB rule {rule_id}",
                when=StepRequirement(policy=PolicyGuard(
                    rule_ids_any_of=[rule_id], effects_any_of=[effect],
                    match_statuses=["matched", "partial"],
                )),
            )],
        )

    def _relation_monitor(self, relation_id: str, effect: str) -> MonitorSpec:
        name = f"PMKBRelation_{self._safe_name(relation_id)}"
        return MonitorSpec(
            name=name,
            initial="idle",
            scope="principal",
            source="pmkb",
            source_ids=[relation_id],
            rules=[ChainRule(
                id=f"pmkb-relation-{relation_id}",
                **{"from": "*", "to": "violated"},
                verdict=_VERDICT_FOR_EFFECT[effect],
                origin="pmkb",
                source_nl=f"PMKB permission relation {relation_id}",
                when=StepRequirement(policy=PolicyGuard(
                    combo_violations_any_of=[relation_id], effects_any_of=[effect],
                    match_statuses=["matched", "partial"],
                )),
            )],
        )
