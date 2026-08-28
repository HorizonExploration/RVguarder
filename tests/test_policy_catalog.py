from pathlib import Path
import json
import shutil
import re
from dataclasses import FrozenInstanceError

import pytest

from openclaw_guard.policy.catalog import PolicyBundle, PolicyBundleError


ROOT = Path("policies/permissions")


def test_catalog_maps_feishu_like_domains_to_atomic_operations():
    bundle = PolicyBundle.load(ROOT)
    assert bundle.operation_for_tool("feishu.docs.read", {}).family == "document.read"
    assert bundle.operation_for_tool("feishu.im.send", {}).family == "message.send"
    assert bundle.operation_for_tool("feishu.bitable.export", {}).family == "data.export"


def test_catalog_keeps_unknown_tool_as_explicit_gap():
    operation = PolicyBundle.load(ROOT).operation_for_tool("new.tool", {})
    assert operation.family == "unknown_tool"
    assert operation.gaps == ["tool_mapping"]


def test_catalog_rejects_duplicate_rule_ids(tmp_path):
    (tmp_path / "schema").mkdir()
    (tmp_path / "catalog").mkdir()
    (tmp_path / "rules").mkdir()
    (tmp_path / "traces").mkdir()
    (tmp_path / "relations").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "schema/permissions.schema.json").write_text('{"version":"1"}')
    (tmp_path / "catalog/operation-catalog.json").write_text('{"version":"1", "operations": []}')
    rule = {"id":"same", "version":"1", "effect":"block", "priority":1,
            "match":{}, "required_fields":[], "negative_conditions":[], "obligations":[],
            "source":"x", "test_vectors":[]}
    (tmp_path / "rules/p0-office.json").write_text('{"version":"1", "rules": [' + str(rule).replace("'", '"') + ',' + str(rule).replace("'", '"') + ']}')
    (tmp_path / "traces/p0-office.json").write_text('{"traces": []}')
    (tmp_path / "relations/p0-combinations.json").write_text('{"relations": []}')
    (tmp_path / "tests/p0-vectors.json").write_text('{"vectors": []}')
    with pytest.raises(PolicyBundleError, match="duplicate.*same"):
        PolicyBundle.load(tmp_path)


def test_rules_prefer_exact_operation_index_to_aliases():
    bundle = PolicyBundle.load(ROOT)
    assert [rule.id for rule in bundle.rules_for_operation("message.send")] == ["EX-10", "P0-MESSAGE-SEND"]


def test_legacy_detection_rules_are_exposed_to_the_policy_bundle():
    bundle = PolicyBundle.load(ROOT)
    legacy = bundle.legacy_rules()

    assert len(legacy) == 47
    assert {rule.legacy_rule_ids[0] for rule in legacy} >= {"CMD-001", "NET-005", "CFG-002", "GEN-006"}
    assert [rule.id for rule in bundle.rules_for_operation("data.query")] == ["EX-19"]
    assert [rule.id for rule in bundle.rules_for_operation("file.bulk_transfer")] == ["EX-27"]


def test_p0_vectors_reference_real_rules():
    bundle = PolicyBundle.load(ROOT)
    ids = {rule.id for rule in bundle.rules}
    assert bundle.p0_vectors()
    assert all(vector["rule_id"] in ids for vector in bundle.p0_vectors())


def _bundle_copy(tmp_path):
    shutil.copytree(ROOT, tmp_path / "permissions")
    return tmp_path / "permissions"


@pytest.mark.parametrize("relative,payload,field", [
    ("schema/permissions.schema.json", {"version": ""}, "version"),
    ("traces/p0-office.json", {"version": "1", "traces": [{}]}, "traces[0].id"),
    ("relations/p0-combinations.json", {"version": "1", "relations": [{"id": "x", "requires": [1]}]}, "relations[0].version"),
    ("tests/p0-vectors.json", {"version": "1", "vectors": [{"id": "x"}]}, "vectors[0].expected_effect"),
])
def test_loader_rejects_malformed_contracts(tmp_path, relative, payload, field):
    root = _bundle_copy(tmp_path)
    (root / relative).write_text(json.dumps(payload))
    with pytest.raises(PolicyBundleError, match=re.escape(field)):
        PolicyBundle.load(root)


def test_required_relations_use_canonical_operation_endpoints():
    bundle = PolicyBundle.load(ROOT)
    relations = {item["id"]: item["requires"] for item in bundle.relations}
    assert ["credential.read", "process.execute"] == relations["credential-process"]
    assert ["data.export", "external_recipient", "sensitive_data"] == relations["export-sensitive-recipient"]
    assert bundle.operation_for_tool("feishu.bitable.export", {}).family == "data.export"


@pytest.mark.parametrize("relative,field", [
    ("catalog/operation-catalog.json", "version"),
    ("rules/p0-office.json", "version"),
    ("traces/p0-office.json", "version"),
    ("relations/p0-combinations.json", "version"),
    ("tests/p0-vectors.json", "version"),
])
def test_loader_requires_top_level_versions(tmp_path, relative, field):
    root = _bundle_copy(tmp_path)
    payload = json.loads((root / relative).read_text())
    payload.pop("version")
    (root / relative).write_text(json.dumps(payload))
    with pytest.raises(PolicyBundleError, match=re.escape(f"$.{field}")):
        PolicyBundle.load(root)


def test_loader_rejects_empty_relation_requirements(tmp_path):
    root = _bundle_copy(tmp_path)
    payload = json.loads((root / "relations/p0-combinations.json").read_text())
    payload["relations"][0]["requires"] = []
    (root / "relations/p0-combinations.json").write_text(json.dumps(payload))
    with pytest.raises(PolicyBundleError, match=re.escape("relations[0].requires")):
        PolicyBundle.load(root)


def test_policy_vectors_are_defensive_copies():
    bundle = PolicyBundle.load(ROOT)
    vectors = bundle.p0_vectors()
    vectors[0]["id"] = "tampered"

    assert bundle.p0_vectors()[0]["id"] != "tampered"


def test_loaded_relation_records_are_immutable():
    bundle = PolicyBundle.load(ROOT)

    with pytest.raises(TypeError):
        bundle.relations[0]["requires"] = []


def test_loaded_bundle_rules_and_nested_match_data_are_immutable():
    bundle = PolicyBundle.load(ROOT)

    with pytest.raises(FrozenInstanceError):
        bundle.version = "tampered"
    with pytest.raises(FrozenInstanceError):
        bundle.rules = ()
    with pytest.raises((TypeError, ValueError)):
        bundle.rules[0].effect = "block"
    with pytest.raises(TypeError):
        bundle.rules[0].match["operation"] = "tampered"
    with pytest.raises(TypeError):
        bundle.rules[0].match["aliases"].append("tampered")
    with pytest.raises(TypeError):
        bundle.rules[0].required_fields.append("tampered")

    assert [rule.id for rule in bundle.rules_for_operation("message.send")] == [
        "EX-10", "P0-MESSAGE-SEND",
    ]
