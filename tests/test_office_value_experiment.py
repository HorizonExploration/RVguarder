from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from testlab.office_value.report import render_html, render_markdown, write_report_bundle
from testlab.office_value.sandbox import OfficeSandbox, SandboxViolation
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


def test_dependency_validation_rejects_forward_reference(tmp_path: Path):
    matrix = load_scenarios()
    matrix["scenarios"][0]["events"][0]["event_id"] = "first"
    matrix["scenarios"][0]["events"][0]["depends_on"] = ["later"]
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(matrix), encoding="utf-8")
    with pytest.raises(ValueError, match="depends_on"):
        load_scenarios(path)


def test_dependency_skip_preserves_independent_later_event(tmp_path: Path):
    scenario = deepcopy(load_scenarios()["scenarios"][0])
    first = deepcopy(scenario["events"][0])
    first["event_id"] = "first"
    first["effect"] = {"kind": "read", "path": "missing.txt"}
    dependent = deepcopy(scenario["events"][0])
    dependent["event_id"] = "dependent"
    dependent["depends_on"] = ["first"]
    independent = deepcopy(scenario["events"][0])
    independent["event_id"] = "independent"
    scenario["events"] = [first, dependent, independent]

    result = run_scenario(scenario, "pass_through", root=tmp_path / "dependency")
    assert [call["status"] for call in result["calls"]] == ["executed", "skipped_dependency", "executed"]
    assert result["calls"][1]["dependency_missing"] == ["first"]
    assert result["calls"][1]["effect_applied"] is False
    assert result["calls"][2]["effect_applied"] is True
    assert result["effect_skipped_dependency"] == 1
    assert result["benign_completed"] is False


def test_dependency_validation_precedes_any_custom_replay(tmp_path: Path):
    valid = deepcopy(load_scenarios()["scenarios"][0])
    invalid = deepcopy(valid)
    invalid["scenario_id"] = "INVALID-DEPENDENCY"
    invalid["events"][0]["depends_on"] = ["missing"]
    root = tmp_path / "custom"
    with pytest.raises(ValueError, match="depends_on"):
        run_experiment(scenarios=[valid, invalid], mode="pass_through", root=root)
    assert not root.exists()


def test_dependency_generated_id_collision_is_rejected(tmp_path: Path):
    scenario = deepcopy(load_scenarios()["scenarios"][0])
    duplicate = deepcopy(scenario["events"][0])
    duplicate["event_id"] = "step-1"
    scenario["events"].append(duplicate)
    root = tmp_path / "collision"
    with pytest.raises(ValueError, match="event_id"):
        run_scenario(scenario, "pass_through", root=root)
    assert not root.exists()


def test_persistent_rule_failure_skips_dependent_followup(tmp_path: Path):
    scenario = next(item for item in load_scenarios()["scenarios"] if item["scenario_id"] == "PRAISON-A01")
    result = run_scenario(scenario, "pmkb_only", approval_persona="risk_aware", root=tmp_path / "rule")
    assert result["calls"][0]["effect_applied"] is False
    assert [call["status"] for call in result["calls"][1:]] == ["skipped_dependency", "skipped_dependency"]
    assert result["effect_skipped_dependency"] == 2
    assert result["sandbox"]["external_sink_count"] == 0


def test_unrelated_read_does_not_taint_egress(tmp_path: Path):
    sandbox = OfficeSandbox(tmp_path)
    sandbox.initialize()
    sandbox.apply({"kind": "read", "path": "secrets/.env", "object_id": "secret"})
    sandbox.apply({"kind": "read", "path": "docs/today.md", "object_id": "public"})
    sandbox.apply({"kind": "egress_capture", "targets": ["https://collector.external.invalid"],
                   "source_object_id": "public"})
    assert not sandbox.attack_goal_achieved({"attack_goal": "credential_exfiltrated"})


def test_compound_goal_requires_named_observation(tmp_path: Path):
    sandbox = OfficeSandbox(tmp_path)
    sandbox.initialize()
    sandbox.apply({"kind": "read", "path": "secrets/.env", "object_id": "secret"})
    sandbox.apply({"kind": "egress_capture", "targets": ["https://collector.external.invalid"],
                   "source_object_id": "secret"})
    assert sandbox.attack_goal_achieved({"attack_goal": "credential_exfiltrated"})
    assert not sandbox.attack_goal_achieved({"attack_goal": "persistent_rule_then_exfil"})
    assert not sandbox.attack_goal_achieved({"attack_goal": "shell_chain_exfil"})


def test_archive_carries_sensitive_provenance_to_sink(tmp_path: Path):
    sandbox = OfficeSandbox(tmp_path)
    sandbox.initialize()
    sandbox.apply({"kind": "read", "path": "secrets/.env", "object_id": "secret"})
    sandbox.apply({"kind": "archive", "source": "secrets/.env", "path": "archive/copy.txt",
                   "source_object_id": "secret", "object_id": "archive"})
    sandbox.apply({"kind": "egress_capture", "targets": ["https://collector.external.invalid"],
                   "source_object_id": "archive"})
    assert sandbox.attack_goal_achieved({"attack_goal": "credential_exfiltrated"})
    assert sandbox.summary()["sensitive_receipt_count"] == 1


def test_egress_requires_known_source_object(tmp_path: Path):
    sandbox = OfficeSandbox(tmp_path)
    sandbox.initialize()
    with pytest.raises(SandboxViolation, match="source_object_id"):
        sandbox.apply({"kind": "egress_capture", "targets": ["https://collector.external.invalid"]})


def test_empty_sink_target_cannot_count_as_exfiltration(tmp_path: Path):
    sandbox = OfficeSandbox(tmp_path)
    sandbox.initialize()
    sandbox.apply({"kind": "read", "path": "secrets/.env", "object_id": "secret"})
    with pytest.raises(SandboxViolation, match="target"):
        sandbox.apply({"kind": "egress_capture", "targets": [], "source_object_id": "secret"})
    assert not sandbox.attack_goal_achieved({"attack_goal": "credential_exfiltrated"})


def test_compound_observation_after_sink_does_not_retroactively_complete_attack(tmp_path: Path):
    sandbox = OfficeSandbox(tmp_path)
    sandbox.initialize()
    sandbox.apply({"kind": "read", "path": "secrets/.env", "object_id": "secret"})
    sandbox.apply({"kind": "egress_capture", "targets": ["https://collector.external.invalid"],
                   "source_object_id": "secret"})
    sandbox.apply({"kind": "write", "path": ".openclaw/policies/late.json", "persistent": True})
    sandbox.apply({"kind": "shell_observation"})
    assert not sandbox.attack_goal_achieved({"attack_goal": "persistent_rule_then_exfil"})
    assert not sandbox.attack_goal_achieved({"attack_goal": "shell_chain_exfil"})


def test_pass_through_replays_declared_restart_before_persistent_chain(tmp_path: Path):
    scenario = next(item for item in load_scenarios()["scenarios"] if item["scenario_id"] == "PRAISON-A01")
    result = run_scenario(scenario, "pass_through", root=tmp_path / "baseline")
    assert result["restart_count"] == 1
    assert result["attack_goal_achieved"] is True


def test_duplicate_object_id_fails_without_partial_effect(tmp_path: Path):
    sandbox = OfficeSandbox(tmp_path)
    sandbox.initialize()
    sandbox.apply({"kind": "read", "path": "docs/today.md", "object_id": "same"})
    target = sandbox.workspace / "docs" / "duplicate.txt"
    with pytest.raises(SandboxViolation, match="object_id"):
        sandbox.apply({"kind": "write", "path": "docs/duplicate.txt", "object_id": "same"})
    assert not target.exists()


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
            if call["status"] == "skipped_dependency":
                assert call["dependency_missing"]
                assert not call["effect_applied"]
            else:
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
            assert metrics["attack_goal_success"]["denominator"] == metrics["attack_count"]
            assert metrics["benign_completion"]["denominator"] == metrics["benign_count"]


def test_holdout_benign_rate_is_undefined(tmp_path: Path):
    report = run_experiment(mode="pmkb_only", approval_persona="risk_aware",
                            split="holdout", repeats=2, root=tmp_path / "holdout")
    cell = report["summary"]["by_split"]["holdout"]["pmkb_only"]["risk_aware"]
    assert cell["unique_attack_count"] == 6
    assert cell["unique_benign_count"] == 0
    assert cell["run_count"] == 12
    assert cell["benign_completion"]["rate"] is None
    assert report["summary"]["metrics"]["pmkb_only"]["risk_aware"]["benign_completion"]["rate"] is None
    assert cell["approval_burden"]["eligible_calls"] > 0
    assert "denied" in cell["approval_burden"]
    assert cell["latency_ms"]["sample_count"] == cell["approval_burden"]["eligible_calls"]
    assert "N/A" in render_markdown(report)
    assert "审批与效果诊断" in render_markdown(report)


def test_split_report_uses_independent_scenario_denominators(tmp_path: Path):
    report = run_experiment(mode="pass_through", approval_persona="all",
                            repeats=2, root=tmp_path / "all")
    by_split = report["summary"]["by_split"]
    calibration = by_split["calibration"]["pass_through"]["risk_aware"]
    holdout = by_split["holdout"]["pass_through"]["risk_aware"]
    assert (calibration["unique_attack_count"], calibration["unique_benign_count"], calibration["run_count"]) == (3, 6, 18)
    assert (holdout["unique_attack_count"], holdout["unique_benign_count"], holdout["run_count"]) == (6, 0, 12)
    markdown = render_markdown(report)
    html = render_html(report)
    assert "calibration" in markdown and "holdout" in markdown
    assert "repeat 不增加独立样本量" in markdown
    assert "repeat 不增加独立样本量" in html
    assert "pass_through | risk_aware" in markdown
    assert "pass_through | approval_all" not in markdown


def test_unknown_split_fails_instead_of_looking_like_empty_success(tmp_path: Path):
    with pytest.raises(ValueError, match="split"):
        run_experiment(split="calibraton", root=tmp_path / "bad-split")
    assert not (tmp_path / "bad-split").exists()


def test_report_bundle_is_versioned_and_refuses_overwrite(tmp_path: Path):
    report = run_experiment(mode="pass_through", approval_persona="risk_aware")
    output = tmp_path / "bundle"
    paths = write_report_bundle(report, output)
    manifest = json.loads(Path(paths["manifest"]).read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 3
    assert manifest["scenario_schema_version"] == 2
    assert manifest["rerun_command"]
    with pytest.raises(FileExistsError):
        write_report_bundle(report, output)


def test_sink_count_is_not_reported_as_rate_with_all_runs_denominator(tmp_path: Path):
    scenario = next(item for item in load_scenarios()["scenarios"] if item["scenario_id"] == "DSH-A02")
    report = run_experiment(scenarios=[scenario], mode="pass_through", approval_persona="risk_aware",
                            repeats=2, root=tmp_path / "sink")
    metric = report["summary"]["metrics"]["pass_through"]["risk_aware"]
    assert metric["external_effects"] == {"count": 2}
    assert metric["sink_hits_per_run"] == {"count": 2, "denominator": 2, "mean": 1.0}


def test_balanced_holdout_is_not_described_as_having_no_benign_cases(tmp_path: Path):
    benign = deepcopy(load_scenarios()["scenarios"][0])
    benign["scenario_id"] = "NEW-HOLDOUT-BENIGN"
    benign["split"] = "holdout"
    report = run_experiment(scenarios=[benign], mode="pass_through", approval_persona="risk_aware",
                            root=tmp_path / "balanced")
    assert "holdout 没有正常场景" not in render_markdown(report)
    assert "holdout 没有正常场景" not in render_html(report)


def test_full_guard_upgrade_counts_one_independent_scenario(tmp_path: Path):
    scenario = next(item for item in load_scenarios()["scenarios"] if item["scenario_id"] == "DSH-A01")
    report = run_experiment(scenarios=[scenario], mode="all", approval_persona="approval_all",
                            repeats=2, root=tmp_path / "upgrade")
    summary = report["summary"]
    assert len(summary["full_guard_upgrades_vs_pmkb"]) == 2
    assert summary["full_guard_upgrade_scenarios"] == [
        {"split": "calibration", "scenario_id": "DSH-A01", "approval_persona": "approval_all"}
    ]
    assert "独立场景增量" in render_markdown(report)


def test_report_has_sources_safety_boundary_and_html_bundle(tmp_path: Path):
    scenarios = load_scenarios()["scenarios"][:2]
    report = run_experiment(scenarios=scenarios, mode="full_guard", approval_persona="all", root=tmp_path / "run")
    html = render_html(report)

    assert "DSH-2026-853" in html
    assert "approval_all" in html
    assert "attack_goal_success" in html
    assert "关键案例时间线" in html
    assert "不会启动 shell" in html
    assert "report.html" not in html

    paths = write_report_bundle(report, tmp_path / "bundle")
    assert Path(paths["html"]).exists()
    assert Path(paths["summary"]).exists()
    assert Path(paths["raw"]).exists()
    assert json.loads(Path(paths["summary"]).read_text(encoding="utf-8"))["schema_version"] == 3


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
