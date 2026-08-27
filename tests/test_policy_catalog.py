from pathlib import Path

import pytest

from openclaw_guard.policy.catalog import PolicyBundle, PolicyBundleError


ROOT = Path("policies/permissions")


def test_catalog_maps_feishu_like_domains_to_atomic_operations():
    bundle = PolicyBundle.load(ROOT)
    assert bundle.operation_for_tool("feishu.docs.read", {}).family == "document.read"
    assert bundle.operation_for_tool("feishu.im.send", {}).family == "message.send"
    assert bundle.operation_for_tool("feishu.bitable.export", {}).family == "table.export"


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
    (tmp_path / "schema/permissions.schema.json").write_text("{}")
    (tmp_path / "catalog/operation-catalog.json").write_text('{"operations": []}')
    rule = {"id":"same", "version":"1", "effect":"block", "priority":1,
            "match":{}, "required_fields":[], "negative_conditions":[], "obligations":[],
            "source":"x", "test_vectors":[]}
    (tmp_path / "rules/p0-office.json").write_text('{"rules": [' + str(rule).replace("'", '"') + ',' + str(rule).replace("'", '"') + ']}')
    (tmp_path / "traces/p0-office.json").write_text('{"traces": []}')
    (tmp_path / "relations/p0-combinations.json").write_text('{"relations": []}')
    (tmp_path / "tests/p0-vectors.json").write_text('{"vectors": []}')
    with pytest.raises(PolicyBundleError, match="duplicate.*same"):
        PolicyBundle.load(tmp_path)


def test_rules_prefer_exact_operation_index_to_aliases():
    bundle = PolicyBundle.load(ROOT)
    assert [rule.id for rule in bundle.rules_for_operation("document.write")] == ["EX-10"]
    assert [rule.id for rule in bundle.rules_for_operation("data.export")] == ["EX-27"]


def test_p0_vectors_reference_real_rules():
    bundle = PolicyBundle.load(ROOT)
    ids = {rule.id for rule in bundle.rules}
    assert bundle.p0_vectors()
    assert all(vector["rule_id"] in ids for vector in bundle.p0_vectors())
