from __future__ import annotations

from pathlib import Path

from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.policy.evaluator import PolicyEvaluator
from openclaw_guard.policy.models import (
    AuthorizationTrace,
    ContextRef,
    CoverageResult,
    DataRef,
    OperationRef,
    PrincipalRef,
    ResourceRef,
    SecurityFactEvidence,
)


ROOT = Path(__file__).parents[1] / "policies" / "permissions"


def _trace(vector: dict) -> AuthorizationTrace:
    facts = {
        name: SecurityFactEvidence(
            value=value,
            source="deterministic",
            trust="verified",
            confidence=1.0,
            evidence="migration replay vector",
        )
        for name, value in vector.get("facts", {}).items()
    }
    scope = vector.get("scope", "workspace")
    recipient_zone = vector.get("recipient_zone", "internal")
    return AuthorizationTrace(
        trace_id=vector["id"],
        principal=PrincipalRef(id="migration-audit", type="human", trust="verified"),
        operation=OperationRef(
            family=vector["operation"],
            tool_id="migration.replay",
            arguments=vector.get("arguments", {}),
        ),
        resource=ResourceRef(type="migration", ids=["fixture"], scope=scope),
        coverage=CoverageResult(status="complete"),
        data=DataRef(
            classification=vector.get("classification", "internal"),
            quantity=vector.get("quantity", 1),
        ),
        context=ContextRef(recipient_zone=recipient_zone),
        security_facts=facts,
    )


def test_pmkb_12_has_no_runtime_legacy_rules_and_adds_skill_operation() -> None:
    bundle = PolicyBundle.load(ROOT)

    assert bundle.version == "1.2.0"
    assert all(not rule.id.startswith("LEGACY-") for rule in bundle.rules)
    assert bundle.operation_for_tool("skill.run", {}).family == "skill.execute"
    assert bundle.operation_for_tool("session.cookie.read", {}).family == "session.token.read"
    assert bundle.operation_for_tool("oauth.scope.grant", {}).family == "identity.permission.grant"
    assert bundle.operation_for_tool("audit.disable", {}).family == "audit.modify"
    assert {
        "P1-NETWORK-EGRESS", "P1-SESSION-TOKEN-READ", "P1-PERMISSION-GRANT", "P1-AUDIT-MODIFY",
    } <= {rule.id for rule in bundle.rules}


def test_every_historical_rule_has_one_native_owner() -> None:
    bundle = PolicyBundle.load(ROOT)
    rules = {rule.id: rule for rule in bundle.rules}

    assert len(bundle.migrations) == 47
    assert len({item["legacy_rule_id"] for item in bundle.migrations}) == 47
    assert len({item["native_rule_id"] for item in bundle.migrations}) == 47
    for item in bundle.migrations:
        owner = rules[item["native_rule_id"]]
        assert item["legacy_rule_id"] in owner.legacy_rule_ids


def test_each_migration_has_positive_and_near_miss_replay_vectors() -> None:
    bundle = PolicyBundle.load(ROOT)
    evaluator = PolicyEvaluator(bundle)
    migration_vectors = [
        vector for vector in bundle.p0_vectors()
        if vector["category"].startswith("migration-")
    ]

    assert len(migration_vectors) == 94
    for migration in bundle.migrations:
        vectors = [
            vector for vector in migration_vectors
            if vector["legacy_rule_id"] == migration["legacy_rule_id"]
        ]
        assert {vector["category"] for vector in vectors} == {
            "migration-positive",
            "migration-near-miss",
        }
        owner = next(rule for rule in bundle.rules if rule.id == migration["native_rule_id"])
        for vector in vectors:
            candidate = evaluator.match_rule(owner, _trace(vector))
            expected = "matched" if vector["category"] == "migration-positive" else "conflict"
            assert candidate.status == expected, vector["id"]


def test_each_native_owner_has_a_least_privilege_trace() -> None:
    bundle = PolicyBundle.load(ROOT)
    traced_rules = {trace["rule_id"] for trace in bundle.traces}

    assert {item["native_rule_id"] for item in bundle.migrations} <= traced_rules


def test_source_and_packaged_pmkb_components_have_identical_file_sets() -> None:
    source = ROOT
    packaged = Path(__file__).parents[1] / "openclaw_guard" / "policy" / "data" / "permissions"
    sections = ("rules", "traces", "relations", "tests", "migrations")

    for section in sections:
        source_files = sorted((source / section).glob("*.json"))
        packaged_files = sorted((packaged / section).glob("*.json"))
        assert [path.name for path in source_files] == [path.name for path in packaged_files]
        for source_file, packaged_file in zip(source_files, packaged_files, strict=True):
            assert source_file.read_bytes() == packaged_file.read_bytes()
