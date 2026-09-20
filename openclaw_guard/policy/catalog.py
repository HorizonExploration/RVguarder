"""Versioned, dependency-free permission knowledge-base loader."""
from __future__ import annotations

import json
from importlib import resources
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any
from collections.abc import Mapping

from .models import OperationRef, PolicyRule


class PolicyBundleError(ValueError):
    """Raised when a permission bundle is malformed (including its JSON path)."""


class _FrozenList(list):
    """List-compatible immutable JSON sequence for backwards-compatible equality."""

    def _immutable(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("policy records are immutable")

    __setitem__ = __delitem__ = __iadd__ = __imul__ = _immutable
    append = clear = extend = insert = pop = remove = reverse = sort = _immutable


def default_policy_root() -> Path:
    """Resolve the bundled PMKB independently of the process working directory."""
    checkout = Path(__file__).resolve().parents[2] / "policies" / "permissions"
    if (checkout / "schema/permissions.schema.json").exists():
        return checkout
    packaged = resources.files("openclaw_guard.policy.data.permissions")
    return Path(str(packaged))


@dataclass(frozen=True)
class _Operation:
    family: str
    tool_ids: tuple[str, ...]
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyBundle:
    operations: tuple[_Operation, ...]
    rules: tuple[PolicyRule, ...]
    traces: tuple[dict[str, Any], ...]
    relations: tuple[dict[str, Any], ...]
    vectors: tuple[dict[str, Any], ...]
    version: str = ""
    migrations: tuple[dict[str, Any], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "operations", tuple(self.operations))
        object.__setattr__(self, "rules", tuple(self.rules))
        object.__setattr__(self, "traces", tuple(_freeze_record(item) for item in self.traces))
        object.__setattr__(self, "relations", tuple(_freeze_record(item) for item in self.relations))
        object.__setattr__(self, "vectors", tuple(_freeze_record(item) for item in self.vectors))
        object.__setattr__(self, "migrations", tuple(_freeze_record(item) for item in self.migrations))

    @classmethod
    def load(cls, root: Path | None = None) -> "PolicyBundle":
        root = Path(root) if root is not None else default_policy_root()
        def read(relative: str) -> Any:
            path = root / relative
            try:
                with path.open(encoding="utf-8") as stream:
                    return json.load(stream)
            except (OSError, json.JSONDecodeError) as exc:
                raise PolicyBundleError(f"{relative}: {exc}") from exc

        def read_many(section: str, field: str) -> tuple[list[tuple[str, Any]], list[Any]]:
            paths = sorted((root / section).glob("*.json"))
            if not paths:
                raise PolicyBundleError(f"{section}: no JSON components")
            documents: list[tuple[str, Any]] = []
            records: list[Any] = []
            for path in paths:
                relative = path.relative_to(root).as_posix()
                document = read(relative)
                _version(document, relative)
                documents.append((relative, document))
                records.extend(_array(document, field, relative))
            return documents, records

        schema = read("schema/permissions.schema.json")
        if not isinstance(schema, dict):
            raise PolicyBundleError("schema/permissions.schema.json: $ must be an object")
        bundle_version = _version(schema, "schema/permissions.schema.json")
        if "type" in schema and schema.get("type") != "policy-bundle":
            raise PolicyBundleError("schema/permissions.schema.json: $.type")
        required_sections = schema.get("required")
        if required_sections is not None and required_sections != ["operations", "rules", "traces", "relations", "vectors"]:
            raise PolicyBundleError("schema/permissions.schema.json: $.required")
        catalog = read("catalog/operation-catalog.json")
        _version(catalog, "catalog/operation-catalog.json")
        raw_operations = _array(catalog, "operations", "catalog/operation-catalog.json")
        operations: list[_Operation] = []
        families: set[str] = set()
        operation_tokens: set[str] = set()
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
            tokens = [*tools, *aliases]
            if len(set(tokens)) != len(tokens) or operation_tokens.intersection(tokens):
                raise PolicyBundleError(f"catalog/operation-catalog.json: duplicate tool or alias in {family}")
            families.add(family)
            operation_tokens.update(tokens)
            operations.append(_Operation(family, tuple(tools), tuple(aliases)))

        rules_docs, raw_rules = read_many("rules", "rules")
        rules: list[PolicyRule] = []
        rule_ids: set[str] = set()
        seen_rule_ids: set[str] = set()
        for item in raw_rules:
            if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"] in rule_ids:
                raise PolicyBundleError(f"rules/p0-office.json: duplicate rule id {item['id']}")
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                rule_ids.add(item["id"])
        rule_ids.clear()
        for i, item in enumerate(raw_rules):
            path = f"rules/p0-office.json: $.rules[{i}]"
            _object(item, path)
            if item.get("id") in seen_rule_ids:
                raise PolicyBundleError(f"{path}: duplicate rule id {item['id']}")
            required = ("id", "version", "effect", "priority", "match", "required_fields",
                        "negative_conditions", "obligations", "source", "test_vectors",
                        "rollback_state", "positive_examples", "negative_examples")
            for field in required:
                if field not in item:
                    raise PolicyBundleError(f"{path}.{field}")
            if not isinstance(item["version"], str) or not item["version"]:
                raise PolicyBundleError(f"{path}.version")
            if item["effect"] not in {"auto_allow_audit", "openclaw_approval", "block"}:
                raise PolicyBundleError(f"{path}.effect: unknown effect {item['effect']}")
            try:
                rules.append(PolicyRule.model_validate(item))
            except Exception as exc:
                raise PolicyBundleError(f"{path}: {exc}") from exc
            rule_ids.add(item["id"])
            seen_rule_ids.add(item["id"])

        for rule in rules:
            operation = rule.match.get("operation")
            if operation and operation not in families:
                raise PolicyBundleError(f"rules/p0-office.json: unknown operation {operation}")

        traces_docs, traces = read_many("traces", "traces")
        relations_docs, relations = read_many("relations", "relations")
        vectors_docs, vectors = read_many("tests", "vectors")
        migration_docs, migrations = read_many("migrations", "migrations")
        trace_ids: set[str] = set()
        for i, trace in enumerate(traces):
            path = f"traces/p0-office.json: $.traces[{i}]"
            _object(trace, path)
            for field in ("id", "version", "rule_id", "required_permissions", "rollback_state", "positive_examples", "negative_examples"):
                if not isinstance(trace.get(field), str) or not trace[field]:
                    if field in {"positive_examples", "negative_examples"} and isinstance(trace.get(field), list):
                        continue
                    if field == "required_permissions" and isinstance(trace.get(field), list):
                        continue
                    raise PolicyBundleError(f"{path}.{field}")
            if trace["id"] in trace_ids:
                raise PolicyBundleError(f"{path}: duplicate trace id {trace['id']}")
            trace_ids.add(trace["id"])
            if trace["rule_id"] not in rule_ids:
                raise PolicyBundleError(f"{path}.rule_id: unknown rule {trace['rule_id']}")
            if not all(isinstance(item, dict) and isinstance(item.get("family"), str) and item["family"] for item in trace["required_permissions"]):
                raise PolicyBundleError(f"{path}.required_permissions")
        relation_ids: set[str] = set()
        for i, relation in enumerate(relations):
            path = f"relations/p0-combinations.json: $.relations[{i}]"
            _object(relation, path)
            for field in ("id", "version", "effect", "requires", "source", "rollback_state", "positive_examples", "negative_examples"):
                if not isinstance(relation.get(field), str if field != "requires" else list) or (not relation[field]):
                    if field in {"positive_examples", "negative_examples"} and isinstance(relation.get(field), list):
                        continue
                    raise PolicyBundleError(f"{path}.{field}")
            if relation["id"] in relation_ids:
                raise PolicyBundleError(f"{path}: duplicate relation id {relation['id']}")
            relation_ids.add(relation["id"])
            if relation["effect"] not in {"auto_allow_audit", "openclaw_approval", "block", "implies"}:
                raise PolicyBundleError(f"{path}.effect: unknown effect {relation['effect']}")
            endpoints = relation["requires"]
            if not all(isinstance(endpoint, str) and endpoint for endpoint in endpoints):
                raise PolicyBundleError(f"{path}.requires")
            for endpoint in endpoints:
                if endpoint not in families and endpoint not in {"external_target", "external_recipient", "sensitive_data", "audit.modify", "persistence_location"}:
                    raise PolicyBundleError(f"relations/p0-combinations.json: unknown endpoint {endpoint}")
        vector_ids: set[str] = set()
        for i, vector in enumerate(vectors):
            if not isinstance(vector, dict):
                raise PolicyBundleError(f"tests/p0-vectors.json: $.vectors[{i}]")
            path = f"tests/p0-vectors.json: $.vectors[{i}]"
            for field in ("id", "expected_effect", "rule_id", "version", "category"):
                if not isinstance(vector.get(field), str) or not vector[field]:
                    raise PolicyBundleError(f"{path}.{field}")
            if vector["id"] in vector_ids:
                raise PolicyBundleError(f"{path}: duplicate vector id {vector['id']}")
            vector_ids.add(vector["id"])
            if vector["rule_id"] not in rule_ids:
                raise PolicyBundleError(f"{path}.rule_id")
            if vector["expected_effect"] not in {"auto_allow_audit", "openclaw_approval", "block"}:
                raise PolicyBundleError(f"{path}.expected_effect: unknown effect {vector['expected_effect']}")
            operation = vector.get("operation")
            if (operation and vector["category"] != "unknown"
                    and operation not in families
                    and not any(operation in item.aliases for item in operations)):
                raise PolicyBundleError(f"{path}.operation: unknown operation {operation}")
        for rule in rules:
            for vector_id in rule.test_vectors:
                if vector_id not in vector_ids:
                    raise PolicyBundleError(f"rules: {rule.id}.test_vectors: unknown vector {vector_id}")

        migration_legacy_ids: set[str] = set()
        migration_owner_ids: set[str] = set()
        rules_by_id = {rule.id: rule for rule in rules}
        for i, migration in enumerate(migrations):
            path = f"migrations: $.migrations[{i}]"
            _object(migration, path)
            legacy_id = _string(migration, "legacy_rule_id", path)
            owner_id = _string(migration, "native_rule_id", path)
            if legacy_id in migration_legacy_ids:
                raise PolicyBundleError(f"{path}: duplicate legacy_rule_id {legacy_id}")
            if owner_id in migration_owner_ids:
                raise PolicyBundleError(f"{path}: duplicate native_rule_id {owner_id}")
            owner = rules_by_id.get(owner_id)
            if owner is None:
                raise PolicyBundleError(f"{path}.native_rule_id: unknown rule {owner_id}")
            if legacy_id not in owner.legacy_rule_ids:
                raise PolicyBundleError(f"{path}: owner {owner_id} missing legacy_rule_ids {legacy_id}")
            migration_legacy_ids.add(legacy_id)
            migration_owner_ids.add(owner_id)
        component_versions = {
            "catalog/operation-catalog.json": _version(catalog, "catalog/operation-catalog.json"),
            **{name: _version(doc, name) for name, doc in rules_docs},
            **{name: _version(doc, name) for name, doc in traces_docs},
            **{name: _version(doc, name) for name, doc in relations_docs},
            **{name: _version(doc, name) for name, doc in vectors_docs},
            **{name: _version(doc, name) for name, doc in migration_docs},
        }
        if any(version != bundle_version for version in component_versions.values()):
            raise PolicyBundleError(f"policy bundle version mismatch: schema={bundle_version}, components={component_versions}")
        return cls(
            tuple(operations), tuple(rules), tuple(traces), tuple(relations),
            tuple(vectors), bundle_version, tuple(migrations),
        )

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
        # Callers use vectors as test input and may annotate them; return a
        # detached mutable copy so a test cannot alter the loaded policy.
        return [_thaw_record(vector) for vector in self.vectors]


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


def _version(value: Any, path: str) -> str:
    value = _object(value, path)
    if not isinstance(value.get("version"), str) or not value["version"]:
        raise PolicyBundleError(f"{path}: $.version")
    return value["version"]


def _freeze_record(value: Any) -> Any:
    """Recursively freeze JSON policy records kept by a loaded bundle."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_record(item) for key, item in value.items()})
    if isinstance(value, list):
        return _FrozenList(_freeze_record(item) for item in value)
    return value


def _thaw_record(value: Any) -> Any:
    """Convert an immutable policy record into a detached JSON-like value."""
    if isinstance(value, Mapping):
        return {key: _thaw_record(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_thaw_record(item) for item in value]
    if isinstance(value, tuple):
        return [_thaw_record(item) for item in value]
    return value
