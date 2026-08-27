"""Versioned, dependency-free permission knowledge-base loader."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import OperationRef, PolicyRule


class PolicyBundleError(ValueError):
    """Raised when a permission bundle is malformed (including its JSON path)."""


@dataclass(frozen=True)
class _Operation:
    family: str
    tool_ids: tuple[str, ...]
    aliases: tuple[str, ...] = ()


@dataclass
class PolicyBundle:
    operations: list[_Operation]
    rules: list[PolicyRule]
    traces: list[dict[str, Any]]
    relations: list[dict[str, Any]]
    vectors: list[dict[str, Any]]

    @classmethod
    def load(cls, root: Path) -> "PolicyBundle":
        root = Path(root)
        def read(relative: str) -> Any:
            path = root / relative
            try:
                with path.open(encoding="utf-8") as stream:
                    return json.load(stream)
            except (OSError, json.JSONDecodeError) as exc:
                raise PolicyBundleError(f"{relative}: {exc}") from exc

        schema = read("schema/permissions.schema.json")
        if not isinstance(schema, dict):
            raise PolicyBundleError("schema/permissions.schema.json: $ must be an object")
        if not isinstance(schema.get("version"), str) or not schema["version"]:
            raise PolicyBundleError("schema/permissions.schema.json: $.version")
        catalog = read("catalog/operation-catalog.json")
        raw_operations = _array(catalog, "operations", "catalog/operation-catalog.json")
        operations: list[_Operation] = []
        families: set[str] = set()
        for i, item in enumerate(raw_operations):
            _object(item, f"catalog/operation-catalog.json: $.operations[{i}]")
            family = _string(item, "family", f"catalog/operation-catalog.json: $.operations[{i}]")
            tools = item.get("tool_ids", item.get("tools"))
            if not isinstance(tools, list) or not all(isinstance(x, str) and x for x in tools):
                raise PolicyBundleError(f"catalog/operation-catalog.json: $.operations[{i}].tool_ids")
            aliases = item.get("aliases", [])
            if not isinstance(aliases, list) or not all(isinstance(x, str) for x in aliases):
                raise PolicyBundleError(f"catalog/operation-catalog.json: $.operations[{i}].aliases")
            if family in families:
                raise PolicyBundleError(f"catalog/operation-catalog.json: duplicate family {family}")
            families.add(family)
            operations.append(_Operation(family, tuple(tools), tuple(aliases)))

        raw_rules = _array(read("rules/p0-office.json"), "rules", "rules/p0-office.json")
        rules: list[PolicyRule] = []
        rule_ids: set[str] = set()
        for i, item in enumerate(raw_rules):
            path = f"rules/p0-office.json: $.rules[{i}]"
            _object(item, path)
            required = ("id", "version", "effect", "priority", "match", "required_fields",
                        "negative_conditions", "obligations", "source", "test_vectors")
            for field in required:
                if field not in item:
                    raise PolicyBundleError(f"{path}.{field}")
            if item["id"] in rule_ids:
                raise PolicyBundleError(f"{path}: duplicate rule id {item['id']}")
            if not isinstance(item["version"], str) or not item["version"]:
                raise PolicyBundleError(f"{path}.version")
            if item["effect"] not in {"auto_allow_audit", "clarify_then_retry", "openclaw_approval", "block"}:
                raise PolicyBundleError(f"{path}.effect: unknown effect {item['effect']}")
            try:
                rules.append(PolicyRule.model_validate(item))
            except Exception as exc:
                raise PolicyBundleError(f"{path}: {exc}") from exc
            rule_ids.add(item["id"])

        traces = _array(read("traces/p0-office.json"), "traces", "traces/p0-office.json")
        relations = _array(read("relations/p0-combinations.json"), "relations", "relations/p0-combinations.json")
        vectors = _array(read("tests/p0-vectors.json"), "vectors", "tests/p0-vectors.json")
        for i, trace in enumerate(traces):
            path = f"traces/p0-office.json: $.traces[{i}]"
            _object(trace, path)
            for field in ("id", "rule_id"):
                if not isinstance(trace.get(field), str) or not trace[field]:
                    raise PolicyBundleError(f"{path}.{field}")
            if trace["rule_id"] not in rule_ids:
                raise PolicyBundleError(f"{path}.rule_id: unknown rule {trace['rule_id']}")
        for i, relation in enumerate(relations):
            path = f"relations/p0-combinations.json: $.relations[{i}]"
            _object(relation, path)
            for field in ("id", "version", "effect", "requires"):
                if not isinstance(relation.get(field), str if field != "requires" else list) or (not relation[field] if field != "requires" else False):
                    raise PolicyBundleError(f"{path}.{field}")
            if relation["effect"] not in {"auto_allow_audit", "clarify_then_retry", "openclaw_approval", "block"}:
                raise PolicyBundleError(f"{path}.effect: unknown effect {relation['effect']}")
            endpoints = relation["requires"]
            if not all(isinstance(endpoint, str) and endpoint for endpoint in endpoints):
                raise PolicyBundleError(f"{path}.requires")
            for endpoint in endpoints:
                if endpoint not in families and endpoint not in {"external_target", "external_recipient", "sensitive_data", "audit.modify", "persistence_location"}:
                    raise PolicyBundleError(f"relations/p0-combinations.json: unknown endpoint {endpoint}")
        for i, vector in enumerate(vectors):
            if not isinstance(vector, dict):
                raise PolicyBundleError(f"tests/p0-vectors.json: $.vectors[{i}]")
            path = f"tests/p0-vectors.json: $.vectors[{i}]"
            for field in ("id", "expected_effect", "rule_id"):
                if not isinstance(vector.get(field), str) or not vector[field]:
                    raise PolicyBundleError(f"{path}.{field}")
            if vector["rule_id"] not in rule_ids:
                raise PolicyBundleError(f"{path}.rule_id")
        return cls(operations, rules, traces, relations, vectors)

    def operation_for_tool(self, tool_id: str, params: dict[str, Any]) -> OperationRef:
        for operation in self.operations:
            if tool_id in operation.tool_ids:
                return OperationRef(family=operation.family, tool_id=tool_id, arguments=params, aliases=list(operation.aliases))
        for operation in self.operations:
            if tool_id in operation.aliases:
                return OperationRef(family=operation.family, tool_id=tool_id, arguments=params, aliases=list(operation.aliases))
        return OperationRef(family="unknown_tool", tool_id=tool_id, arguments=params, gaps=["tool_mapping"])

    def rules_for_operation(self, family: str) -> list[PolicyRule]:
        exact = [rule for rule in self.rules if rule.match.get("operation") == family]
        if exact:
            return exact
        return [rule for rule in self.rules if family in rule.match.get("aliases", [])]

    def p0_vectors(self) -> list[dict[str, Any]]:
        return list(self.vectors)


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyBundleError(f"{path} must be an object")
    return value


def _array(value: Any, field: str, path: str) -> list[Any]:
    value = _object(value, path)
    if not isinstance(value.get(field), list):
        raise PolicyBundleError(f"{path}: $.{field} must be an array")
    return value[field]


def _string(value: dict[str, Any], field: str, path: str) -> str:
    if not isinstance(value.get(field), str) or not value[field]:
        raise PolicyBundleError(f"{path}.{field} must be a non-empty string")
    return value[field]
