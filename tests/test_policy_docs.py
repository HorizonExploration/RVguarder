import json
import re
from pathlib import Path

from openclaw_guard.policy.catalog import PolicyBundle


ROOT = Path(__file__).parents[1]
POLICY_ROOT = ROOT / "policies" / "permissions"


def read_doc(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_docs_name_p0_rules_and_effect_routes():
    text = read_doc("docs/semantic/method.md")
    for token in (
        "Authorization Trace",
        "EX-10",
        "EX-19",
        "EX-27",
        "auto_allow_audit",
        "clarify_then_retry",
        "openclaw_approval",
        "policy_version",
    ):
        assert token in text


def test_docs_preserve_openclaw_single_approval_owner():
    text = read_doc("docs/features/runtime-hook.md")
    assert "OpenClaw" in text and "唯一审批" in text


def test_current_architecture_documents_describe_pmkb_semantic_and_rv_layers():
    architecture = read_doc("docs/architecture/permission-kb-runtime-architecture.md")
    readme = read_doc("README.md")
    for token in (
        "PolicyBundle",
        "TraceCompiler",
        "PermissionClosure",
        "PermissionDiff",
        "RiskGraph",
        "PrincipalSecurityState",
        "openclaw_approval",
        "session_id",
            "513 passed",
    ):
        assert token in architecture
    for token in ("PMKB", "Authorization Trace", "SemanticEnhancer", "ChainRule DSL"):
        assert token in readme


def test_runtime_hook_docs_match_once_only_resolution_contract():
    runtime_hook = read_doc("docs/features/runtime-hook.md")
    spec = read_doc("docs/archive/specs/2026-08-27-openclaw-rvguarder-five-phase-upgrade-design.md")
    assert "允许一次" in runtime_hook and "拒绝" in runtime_hook
    assert "始终允许" not in runtime_hook
    assert "当前生成插件只向 OpenClaw 暴露" in spec
    assert "Guard resolver 明确拒绝该值" in spec


def test_policy_docs_cover_catalog_scopes_trace_and_precedence():
    text = "\n".join(
        read_doc(path)
        for path in (
            "docs/semantic/method.md",
            "docs/semantic/office-scenario-matrix.md",
            "docs/api/http.md",
            "docs/features/runtime-hook.md",
            "docs/ops/roadmap.md",
        )
    )
    for token in (
        "Feishu",
        "PMKB",
        "IM",
        "directory",
        "document/wiki/drive",
        "sheets/bitables",
        "calendar/meeting",
        "workflow/approval",
        "event/network",
        "app/config",
        "personal-office",
        "principal",
        "capability_lineage",
        "hard-block",
        "versioned",
        "rollback",
    ):
        assert token in text


def test_api_docs_expose_read_only_guard_evidence_fields_and_timing():
    text = read_doc("docs/api/http.md")
    for token in (
        "policy_decision",
        "effect",
        "match_status",
        "missing_features",
        "requested_delta",
        "excessive_permissions",
        "combo_violations",
        "policy_version",
        "evaluation_ms",
        "p95_ms",
        "read-only",
    ):
        assert token in text


def test_policy_decision_examples_match_serialized_contract():
    method = read_doc("docs/semantic/method.md")
    api = read_doc("docs/api/http.md")
    method_section = method.split("### 18.1 Authorization Trace", 1)[1]
    method_example = json.loads(
        re.search(r"```json\n(\{.*?\})\n```", method_section, re.DOTALL).group(1)
    )
    api_example = json.loads(
        re.search(r"```json\n(\{\n  \"policy_decision\".*?\n\})\n```", api, re.DOTALL).group(1)
    )["policy_decision"]
    allowed_statuses = {"matched", "partial", "unknown", "conflict"}
    assert method_example["match_status"] in allowed_statuses
    assert api_example["match_status"] in allowed_statuses
    assert "timing" not in method_example
    assert "timing" not in api_example
    for field in ("requested_delta", "redundant_permissions", "excessive_permissions"):
        assert all(isinstance(item, dict) for item in api_example[field])
        for item in api_example[field]:
            assert set(("family", "scope", "classification")) <= item.keys()


def test_docs_define_p0_metrics_bounded_validation_and_rollback():
    text = read_doc("docs/ops/roadmap.md")
    for token in (
        "complete coverage",
        "85%",
        "unknown",
        "10%",
        "99%",
        "98%",
        "40%",
        "60%",
        "50 ms",
        "有限样本",
        "20",
        "previous catalog",
        "audit records",
    ):
        assert token in text


def test_documented_p0_operations_match_canonical_policy_bundle():
    bundle = PolicyBundle.load(POLICY_ROOT)
    rules = {rule.id: rule for rule in bundle.rules}
    expected = {
        "EX-10": {"message.send", "broadcast"},
        "EX-19": {"data.query", "data.export"},
        "EX-27": {"file.bulk_transfer"},
    }
    matrix = read_doc("docs/semantic/office-scenario-matrix.md")
    method = read_doc("docs/semantic/method.md")
    vectors = {vector["rule_id"]: vector for vector in bundle.p0_vectors()}
    for rule_id, operations in expected.items():
        rule = rules[rule_id]
        canonical = {rule.match["operation"], *rule.match.get("aliases", [])}
        assert canonical & operations
        assert vectors[rule_id]["operation"] in canonical
        assert rule_id in matrix and rule_id in method
        row = matrix[matrix.index(f"| `{rule_id}`") : matrix.index("\n", matrix.index(f"| `{rule_id}`"))]
        assert any(operation in row for operation in operations)
