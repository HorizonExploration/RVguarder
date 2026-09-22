from __future__ import annotations

from pathlib import Path
import json

from testlab.office_value.runner import (
    MODES,
    _safe_params,
    load_scenarios,
    run_scenario,
    run_trust_scope_checks,
    summarize_results,
)
from testlab.office_value.report import render_markdown


def test_office_value_fixture_has_balanced_case_families_and_required_evidence():
    scenarios = load_scenarios()

    assert len(scenarios) == 24
    assert {item["variant"] for item in scenarios} == {"benign", "attack"}
    assert len([item for item in scenarios if item["variant"] == "benign"]) == 12
    assert len([item for item in scenarios if item["variant"] == "attack"]) == 12
    assert {item["workflow"] for item in scenarios} == {
        "feishu_daily_report",
        "meeting_preparation",
        "document_processing",
        "routine_command",
    }
    for scenario in scenarios:
        assert scenario["scenario_id"]
        assert scenario["case_source"]
        assert scenario["events"]
        assert scenario["expected_terminal"] in {"complete", "intervened"}
        assert isinstance(scenario["expected"], dict)
        for event in scenario["events"]:
            assert event["toolName"]
            assert isinstance(event.get("params"), dict)
            assert event.get("sessionId")


def test_runner_exposes_three_comparable_modes_and_evidence(tmp_path: Path):
    scenarios = load_scenarios()
    selected = [
        next(item for item in scenarios if item["variant"] == "benign"),
        next(item for item in scenarios if item["variant"] == "attack"),
    ]

    results = [run_scenario(item, mode, root=tmp_path / mode) for item in selected for mode in MODES]

    assert len(results) == 6
    assert {item["mode"] for item in results} == set(MODES)
    assert {item["scenario_id"] for item in results} == {item["scenario_id"] for item in selected}
    for result in results:
        assert result["calls"]
        assert result["duration_ms"] >= 0
        for call in result["calls"]:
            assert call["tool_name"]
            assert call["action"] in {"allow", "require_approval", "block"}
            assert isinstance(call["evidence"], dict)


def test_summary_reports_value_metrics_without_collapsing_mode_comparison():
    scenarios = load_scenarios()
    results = [run_scenario(scenarios[0], mode) for mode in MODES]

    summary = summarize_results(results)

    assert set(summary["modes"]) == set(MODES)
    for mode in MODES:
        metrics = summary["metrics"][mode]
        assert {
            "silent_unsafe_allow",
            "intervention_coverage",
            "benign_completion",
            "false_hard_block",
            "approval_burden",
            "latency_ms",
            "evidence_completeness",
            "expected_outcome_match",
        } <= metrics.keys()
        assert 0 <= metrics["latency_ms"]["p95"]


def test_exact_approval_trust_scope_rejects_changed_contexts():
    checks = run_trust_scope_checks()

    assert checks["exact_repeat"] == "allow"
    assert checks["changed_cwd"] == "require_approval"
    assert checks["changed_principal"] == "require_approval"
    assert checks["sensitive_target"] in {"require_approval", "block"}
    assert checks["destructive_command"] in {"require_approval", "block"}
    assert checks["symlink_escape"] in {"require_approval", "block"}


def test_full_guard_upgrades_two_cross_step_chains(tmp_path: Path):
    scenarios = load_scenarios()
    selected = [
        next(item for item in scenarios if item["scenario_id"] == "DOC-A02"),
        next(item for item in scenarios if item["scenario_id"] == "CMD-A03"),
    ]
    results = [
        run_scenario(item, mode, root=tmp_path / f"{item['scenario_id']}-{mode}")
        for item in selected
        for mode in ("pmkb_only", "full_guard")
    ]

    upgrades = summarize_results(results)["full_guard_upgrades_vs_pmkb"]

    assert {item["scenario_id"] for item in upgrades} == {"DOC-A02", "CMD-A03"}


def test_markdown_report_keeps_comparison_and_safety_disclaimer(tmp_path: Path):
    scenarios = load_scenarios()
    report = {"results": [run_scenario(scenarios[0], mode, root=tmp_path / mode) for mode in MODES]}
    report["summary"] = summarize_results(report["results"])

    markdown = render_markdown(report)

    assert "pass_through" in markdown
    assert "pmkb_only" in markdown
    assert "full_guard" in markdown
    assert "不会执行真实工具" in markdown


def test_raw_parameter_redaction_is_recursive_and_covers_embedded_values():
    safe = _safe_params(
        {
            "nested": {"token": "nested-secret"},
            "items": [{"authorization": "Bearer nested-secret"}],
            "text": "api_key=nested-secret",
        }
    )

    serialized = str(safe)
    assert "nested-secret" not in serialized
    assert safe["nested"]["token"] == "[REDACTED]"
    assert safe["items"][0]["authorization"] == "[REDACTED]"


def test_replay_resolves_pending_approval_before_committing_after_hook(tmp_path: Path):
    scenario = next(item for item in load_scenarios() if item["scenario_id"] == "FR-B03")

    result = run_scenario(scenario, "full_guard", root=tmp_path / "approval")
    pending = next(call for call in result["calls"] if call["action"] == "require_approval")

    assert pending["evidence"]["approval_resolution"] == "allow-once"
    assert pending["after"]["ok"] is True
    assert pending["after"]["action"]["status"] == "executed"


def test_exported_replay_row_does_not_echo_fixture_secret_or_raw_after_payload(tmp_path: Path):
    scenario = next(item for item in load_scenarios() if item["scenario_id"] == "FR-A01")

    result = run_scenario(scenario, "full_guard", root=tmp_path / "redaction")
    serialized = json.dumps(result, ensure_ascii=False)

    assert "FAKE-KEY-123" not in serialized
    assert "raw_payload" not in serialized
