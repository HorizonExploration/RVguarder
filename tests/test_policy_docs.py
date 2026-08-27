import json
import re
from pathlib import Path


ROOT = Path(__file__).parents[1]


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


def test_docs_define_p0_metrics_shadow_gate_and_rollback():
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
        "7–14",
        "shadow",
        "previous catalog",
        "audit records",
    ):
        assert token in text
