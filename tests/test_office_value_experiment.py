from __future__ import annotations

import json
from pathlib import Path

from testlab.office_value.report import render_html, write_report_bundle
from testlab.office_value.runner import (
    APPROVAL_PERSONAS,
    MODES,
    _safe_params,
    load_scenarios,
    run_experiment,
    run_scenario,
    run_trust_scope_checks,
    summarize_results,
)


def test_incident_matrix_is_balanced_and_explicitly_mapped():
    payload = load_scenarios()

    assert payload["schema_version"] == 2
    assert {item["incident_id"] for item in payload["incidents"]} == {
        "DSH-2026-853",
        "PRAISON-2026-55532",
        "MCP-SHELL-2026-55580",
    }
    scenarios = payload["scenarios"]
    assert len(scenarios) == 15
    assert len([item for item in scenarios if item["variant"] == "benign"]) == 6
    assert len([item for item in scenarios if item["variant"] == "attack"]) == 9
    assert {item["split"] for item in scenarios} == {"calibration", "holdout"}
    for scenario in scenarios:
        assert scenario["incident_id"]
        assert scenario["scenario_id"]
        assert scenario["events"]
        for event in scenario["events"]:
            assert event["hook_payload"]["toolName"]
            assert event["hook_payload"]["sessionId"]
            assert isinstance(event["hook_payload"].get("params"), dict)
            assert isinstance(event["effect"], dict)
            assert isinstance(event["oracle"], dict)


def test_modes_and_personas_are_comparable(tmp_path: Path):
    scenarios = load_scenarios()["scenarios"]
    selected = [
        next(item for item in scenarios if item["scenario_id"] == "DSH-B01"),
        next(item for item in scenarios if item["scenario_id"] == "DSH-A01"),
    ]
    results = [
        run_scenario(item, mode, approval_persona=persona, root=tmp_path / f"{mode}-{persona}")
        for item in selected
        for mode in MODES
        for persona in APPROVAL_PERSONAS
    ]

    assert len(results) == 12
    assert {item["mode"] for item in results} == set(MODES)
    assert {item["approval_persona"] for item in results} == set(APPROVAL_PERSONAS)
    for result in results:
        assert result["calls"]
        assert result["duration_ms"] >= 0
        assert "attack_goal_achieved" in result
        for call in result["calls"]:
            assert call["tool_name"]
            assert call["action"] in {"allow", "require_approval", "block"}
            assert isinstance(call["evidence"], dict)


def test_full_guard_is_hermetic_and_stops_dsh_chain(tmp_path: Path):
    scenario = next(item for item in load_scenarios()["scenarios"] if item["scenario_id"] == "DSH-A01")
    result = run_scenario(scenario, "full_guard", approval_persona="approval_all", root=tmp_path / "dsh")

    assert result["attack_goal_achieved"] is False
    assert result["sandbox"]["external_sink_count"] == 0
    assert result["containment_step"] is not None
    assert result["effect_applied"] < result["effect_attempted"]
    assert all(call["effect_applied"] is False for call in result["calls"] if call["action"] == "block")


def test_pmkb_only_exposes_dsh_chain_but_full_guard_contains_it(tmp_path: Path):
    scenario = next(item for item in load_scenarios()["scenarios"] if item["scenario_id"] == "DSH-A01")
    pmkb = run_scenario(scenario, "pmkb_only", approval_persona="approval_all", root=tmp_path / "pmkb")
    full = run_scenario(scenario, "full_guard", approval_persona="approval_all", root=tmp_path / "full")

    assert pmkb["attack_goal_achieved"] is True
    assert full["attack_goal_achieved"] is False
    assert full["containment_step"] is not None


def test_praison_chain_crosses_sessions_and_is_contained(tmp_path: Path):
    scenario = next(item for item in load_scenarios()["scenarios"] if item["scenario_id"] == "PRAISON-A01")
    pmkb = run_scenario(scenario, "pmkb_only", approval_persona="approval_all", root=tmp_path / "pmkb")
    full = run_scenario(scenario, "full_guard", approval_persona="approval_all", root=tmp_path / "full")

    assert len({event["hook_payload"]["sessionId"] for event in scenario["events"]}) >= 2
    assert pmkb["attack_goal_achieved"] is True
    assert full["attack_goal_achieved"] is False
    assert full["restart_count"] >= 1


def test_summary_groups_by_mode_and_persona_without_overwriting_repeats(tmp_path: Path):
    scenarios = load_scenarios()["scenarios"][:2]
    report = run_experiment(
        scenarios=scenarios,
        mode="all",
        approval_persona="all",
        repeats=2,
        root=tmp_path / "matrix",
    )
    summary = report["summary"]

    assert set(summary["modes"]) == set(MODES)
    assert set(summary["approval_personas"]) == set(APPROVAL_PERSONAS)
    for mode in MODES:
        for persona in APPROVAL_PERSONAS:
            metrics = summary["metrics"][mode][persona]
            assert {
                "attack_goal_success",
                "containment_rate",
                "benign_completion",
                "false_hard_block",
                "approval_burden",
                "latency_ms",
                "evidence_completeness",
                "external_effects",
            } <= metrics.keys()


def test_report_has_sources_safety_boundary_and_html_bundle(tmp_path: Path):
    scenarios = load_scenarios()["scenarios"][:2]
    report = run_experiment(scenarios=scenarios, mode="full_guard", approval_persona="all", root=tmp_path / "run")
    html = render_html(report)

    assert "DSH-2026-853" in html
    assert "approval_all" in html
    assert "attack_goal_success" in html
    assert "不会启动 shell" in html
    assert "report.html" not in html

    paths = write_report_bundle(report, tmp_path / "bundle")
    assert Path(paths["html"]).exists()
    assert Path(paths["summary"]).exists()
    assert Path(paths["raw"]).exists()
    assert json.loads(Path(paths["summary"]).read_text(encoding="utf-8"))["schema_version"] == 2


def test_oracle_is_not_a_policy_input_and_canary_is_redacted(tmp_path: Path):
    source = next(item for item in load_scenarios()["scenarios"] if item["scenario_id"] == "PRAISON-A01")
    altered = json.loads(json.dumps(source))
    altered["oracle"] = {"attack_goal": "none", "expected": "completed"}
    altered["events"][0]["oracle"] = {"expected": "safe"}
    original = run_scenario(source, "full_guard", approval_persona="approval_all", root=tmp_path / "original")
    replay = run_scenario(altered, "full_guard", approval_persona="approval_all", root=tmp_path / "altered")
    assert [call["guard_action"] for call in original["calls"]] == [call["guard_action"] for call in replay["calls"]]
    assert "FAKE-OFFICE-KEY" not in json.dumps(original, ensure_ascii=False)
    shell_source = next(item for item in load_scenarios()["scenarios"] if item["scenario_id"] == "MCP-SHELL-A01")
    shell_result = run_scenario(shell_source, "full_guard", approval_persona="approval_all", root=tmp_path / "shell")
    serialized = json.dumps(shell_result, ensure_ascii=False)
    assert "cat " not in serialized
    assert "credential output" not in serialized


def test_effect_failure_is_reported_without_success_after_commit(tmp_path: Path):
    source = next(item for item in load_scenarios()["scenarios"] if item["scenario_id"] == "DSH-B01")
    broken = json.loads(json.dumps(source))
    broken["events"][0]["effect"] = {"kind": "read", "path": "${ROOT}/office-workspace/missing.txt"}
    result = run_scenario(broken, "full_guard", approval_persona="approval_all", root=tmp_path / "broken")
    assert result["effect_attempted"] == 1
    assert result["effect_applied"] == 0
    assert result["calls"][0]["after"]["ok"] is True
    assert result["calls"][0]["after"]["error"] == "sandbox_effect_failed"


def test_reusing_a_root_starts_a_fresh_replay(tmp_path: Path):
    scenario = next(item for item in load_scenarios()["scenarios"] if item["scenario_id"] == "DSH-B02")
    first = run_scenario(scenario, "full_guard", approval_persona="approval_all", root=tmp_path / "reused")
    second = run_scenario(scenario, "full_guard", approval_persona="approval_all", root=tmp_path / "reused")
    assert all(call["after"]["ok"] for call in first["calls"] if call["after"])
    assert all(call["after"]["ok"] for call in second["calls"] if call["after"])


def test_exact_approval_trust_scope_and_redaction_regressions():
    checks = run_trust_scope_checks()
    assert checks["exact_repeat"] == "allow"
    assert checks["changed_cwd"] == "require_approval"
    assert checks["changed_principal"] == "require_approval"
    assert checks["sensitive_target"] in {"require_approval", "block"}
    assert checks["destructive_command"] in {"require_approval", "block"}
    assert checks["symlink_escape"] in {"require_approval", "block"}

    safe = _safe_params(
        {
            "nested": {"token": "nested-secret"},
            "items": [{"authorization": "Bearer nested-secret"}],
            "text": "api_key=nested-secret",
        }
    )
    assert "nested-secret" not in str(safe)
    assert safe["nested"]["token"] == "[REDACTED]"
