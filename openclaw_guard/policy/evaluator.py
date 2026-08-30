"""Deterministic, coverage-aware evaluation of authorization traces."""
from __future__ import annotations

from typing import Any

from .catalog import PolicyBundle
from .models import AuthorizationTrace, MatchCandidate, PolicyDecision, PolicyRule


_EFFECT_RANK = {"auto_allow_audit": 0, "clarify_then_retry": 1,
               "openclaw_approval": 2, "block": 3}
_CLASS_RANK = {"public": 0, "internal": 1, "sensitive": 2, "secret": 3}


class PolicyEvaluator:
    def __init__(self, bundle: PolicyBundle):
        self.bundle = bundle

    def match_rule(self, rule: PolicyRule, trace: AuthorizationTrace) -> MatchCandidate:
        match = rule.match
        operation = str(match.get("operation", ""))
        wildcard = operation == "*"
        exact = wildcard or operation == trace.operation.family
        alias = operation != "" and (
            operation in trace.operation.aliases
            or trace.operation.family in match.get("aliases", [])
            or self._catalog_alias_match(operation, trace.operation.family)
        )
        if not exact and not alias:
            return MatchCandidate(rule_id=rule.id, status="unknown", reasons=["operation_mismatch"])

        # Compatibility records are independent legacy detections.  A different
        # action or absent semantic labels is non-applicability, not a conflict.
        legacy_actions = match.get("legacy_action_types")
        if legacy_actions and trace.operation.arguments.get("action_type") not in legacy_actions:
            return MatchCandidate(rule_id=rule.id, status="unknown", reasons=["legacy_action_mismatch"])
        legacy_labels = match.get("legacy_labels_all")
        if legacy_labels and not self._equals(self._value("legacy_labels_all", trace), legacy_labels):
            return MatchCandidate(rule_id=rule.id, status="unknown", reasons=["legacy_labels_mismatch"])

        missing: list[str] = []
        for field in rule.required_fields:
            if not self._field_present(field, trace):
                missing.append(self._feature_name(field))
                if field == "recipient" and trace.context.recipient_zone == "unknown":
                    missing.append("context.recipient_zone")
        # Coverage evidence is additive: never throw away compiler-reported gaps.
        missing.extend(x for x in trace.coverage.missing_features if x not in missing)
        reasons = ["operation_wildcard" if wildcard else ("operation_exact" if exact else "operation_alias")]
        predicate_count = 0
        predicate_matches = 0
        conflict = False
        for field, expected in match.items():
            if field in {"operation", "aliases"}:
                continue
            predicate_count += 1
            actual = self._value(field, trace)
            if actual is None:
                missing.append(self._feature_name(field))
            elif self._equals(actual, expected):
                predicate_matches += 1
                reasons.append(f"{field}_exact")
            else:
                conflict = True
                reasons.append(f"{field}_mismatch")
        for condition in rule.negative_conditions:
            field, expected = condition.get("field"), condition.get("equals")
            actual = self._value(str(field), trace)
            if actual is not None and self._equals(actual, expected):
                conflict = True
                reasons.append(f"negative_{field}")
        missing = list(dict.fromkeys(missing))
        if conflict:
            status = "conflict"
        elif missing:
            status = "partial"
        else:
            status = "matched"
        # Compiler coverage uncertainty is authoritative, even with no listed gaps.
        if trace.coverage.status == "conflict":
            status = "conflict"
        elif trace.coverage.status == "unknown":
            status = "unknown"
        elif trace.coverage.status == "partial" and status == "matched":
            status = "partial"
        action = 1.0 if exact else 0.5
        completeness = 1.0 if not rule.required_fields else max(0.0, 1 - len(missing) / len(rule.required_fields))
        specificity = predicate_matches / predicate_count if predicate_count else 1.0
        provenance = 1.0 if trace.provenance.trust == "verified" else 0.5
        score = round(0.40 * action + 0.25 * completeness + 0.20 * specificity + 0.15 * provenance, 6)
        return MatchCandidate(rule_id=rule.id, score=score, status=status,
                              matched=status == "matched", reasons=reasons,
                              missing_features=missing)

    def _catalog_alias_match(self, rule_operation: str, trace_family: str) -> bool:
        """Resolve either direction of a canonical/alias operation relationship."""
        for operation in self.bundle.operations:
            if operation.family == rule_operation and trace_family in operation.aliases:
                return True
            if operation.family == trace_family and rule_operation in operation.aliases:
                return True
        return False

    def evaluate(self, trace: AuthorizationTrace) -> PolicyDecision:
        rules = self.bundle.rules_for_operation(trace.operation.family)
        # Native PMKB records remain authoritative for a mapped operation.  The
        # legacy records are a compatibility fallback for an operation that
        # lacks a native PMKB rule; this preserves existing calibrated P0
        # decisions while making every legacy rule usable on uncovered tools.
        if trace.operation.arguments.get("action_type") and not rules:
            rules = [*rules, *self.bundle.legacy_rules()]
        candidates = [self.match_rule(rule, trace) for rule in rules]
        applicable = [c for c in candidates if c.status in {"matched", "partial"}]
        missing = list(dict.fromkeys(trace.coverage.missing_features + [x for c in candidates for x in c.missing_features]))
        conflicts = list(trace.coverage.conflicts)
        if any(c.status == "conflict" for c in candidates):
            conflicts.append("rule_conflict")

        # Safety invariants for high-impact, externally directed data movement.
        high_impact = (trace.data.classification in {"sensitive", "secret"}
                       or trace.context.recipient_zone in {"external", "unknown"})
        selected: list[str] = []
        synthetic_block = high_impact and trace.data.classification == "secret" and trace.context.recipient_zone == "external"
        if synthetic_block:
            certain = not missing and trace.coverage.status == "complete"
            effect = "block" if certain else "openclaw_approval"
            status = "matched" if certain else (trace.coverage.status if trace.coverage.status != "complete" else "partial")
        elif applicable:
            strongest = max(applicable, key=lambda c: (_EFFECT_RANK[self._rule_effect(c.rule_id)], c.score))
            effect = self._rule_effect(strongest.rule_id)
            status = "matched" if all(c.status == "matched" for c in applicable) else "partial"
            selected = [c.rule_id for c in applicable
                        if _EFFECT_RANK[self._rule_effect(c.rule_id)] == _EFFECT_RANK[effect]]
            # Internal, small, classified messages are the calibrated low-impact exception.
            if (trace.operation.family == "message.send" and trace.context.recipient_zone == "internal"
                    and trace.data.classification in {"public", "internal"} and trace.data.quantity <= 10
                    and not missing and effect != "block"):
                effect = "auto_allow_audit"
        else:
            effect, status = "openclaw_approval", "unknown"
        if trace.coverage.status in {"unknown", "conflict"}:
            status = trace.coverage.status
            if effect == "auto_allow_audit":
                effect = "openclaw_approval"
        if (status == "partial" and not high_impact and len(missing) <= 2
                and _EFFECT_RANK[effect] < _EFFECT_RANK["clarify_then_retry"]):
            effect = "clarify_then_retry"
        return PolicyDecision(effect=effect, match_status=status,
                              match_confidence=max((c.score for c in applicable), default=0.0),
                              risk_score=self._risk_score(trace), selected_rule_ids=selected,
                              candidate_rule_ids=[c.rule_id for c in candidates],
                              missing_features=missing, conflicts=list(dict.fromkeys(conflicts)),
                              policy_version=self.bundle.version)

    def _rule_effect(self, rule_id: str) -> str:
        return next(rule.effect for rule in self.bundle.rules if rule.id == rule_id)

    @staticmethod
    def _feature_name(field: str) -> str:
        return {"recipient": "resource.recipient", "principal": "principal.id", "resource": "resource.id"}.get(field, field if "." in field else f"context.{field}")

    @classmethod
    def _field_present(cls, field: str, trace: AuthorizationTrace) -> bool:
        if field == "resource": return bool(trace.resource.ids)
        if field == "recipient": return bool(trace.resource.ids) and trace.context.recipient_zone != "unknown"
        if field == "principal": return bool(trace.principal.id and trace.principal.id != "unknown")
        return cls._value(field, trace) is not None

    @staticmethod
    def _value(field: str, trace: AuthorizationTrace) -> Any:
        if field.startswith("context."): return getattr(trace.context, field.split(".", 1)[1], None)
        if field.startswith("resource."): return getattr(trace.resource, field.split(".", 1)[1], None)
        if field.startswith("data."): return getattr(trace.data, field.split(".", 1)[1], None)
        if field.startswith("operation.arguments."):
            return trace.operation.arguments.get(field.split(".", 2)[2])
        if field.startswith("operation."): return getattr(trace.operation, field.split(".", 1)[1], None)
        if field in {"legacy_action_type", "legacy_action_types"}:
            return trace.operation.arguments.get("action_type")
        if field == "legacy_labels_all":
            return [str(label) for step in trace.legacy_steps for label in step.get("props", [])]
        return {"scope": trace.resource.scope, "classification": trace.data.classification,
                "quantity": trace.data.quantity, "recipient_zone": trace.context.recipient_zone,
                "purpose": trace.context.purpose}.get(field)

    @staticmethod
    def _equals(actual: Any, expected: Any) -> bool:
        if isinstance(expected, dict):
            if "gte" in expected and (actual is None or actual < expected["gte"]):
                return False
            if "lte" in expected and (actual is None or actual > expected["lte"]):
                return False
            if "in" in expected and actual not in expected["in"]:
                return False
            return True
        if isinstance(expected, list) and isinstance(actual, list): return set(expected).issubset(set(actual))
        if isinstance(expected, list): return actual in expected
        if isinstance(actual, list): return expected in actual
        return actual == expected

    @staticmethod
    def _risk_score(trace: AuthorizationTrace) -> int:
        score = _CLASS_RANK[trace.data.classification] * 20
        if trace.context.recipient_zone == "external": score += 30
        if trace.operation.family in {"secret.read", "credential.read", "process.execute"}: score += 30
        return min(100, score)
