"""Evidence-contract tests for the calibration-only RV value gate."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from testlab.office_value.paired_probe import classify_outcome, decisive_layer, paired_probe_results, validate_pair
from testlab.office_value.paired_report import summarize_paired_probe, write_paired_bundle
from testlab.office_value.sandbox import OfficeSandbox
from testlab.office_value.runner import SUPPORTED_MODES, load_scenarios, run_experiment, run_scenario


MATRIX = Path("testlab/office_value/paired_calibration.json")


def _pair():
    scenarios = load_scenarios(MATRIX)["scenarios"]
    return deepcopy(scenarios[0]), deepcopy(scenarios[1])


def test_pair_rejects_changed_final_hook():
    attack, benign = _pair()
    benign["events"][-1]["hook_payload"]["params"]["url"] = "https://different.example/receive"
    with pytest.raises(ValueError, match="final Hook projection"):
        validate_pair(attack, benign)


def test_pair_rejects_wrong_variant_principal_and_source():
    attack, benign = _pair()
    validate_pair(attack, benign)
    benign["variant"] = "attack"
    with pytest.raises(ValueError, match="variants"):
        validate_pair(attack, benign)
    benign["variant"] = "benign"
    benign["events"][-1]["hook_payload"]["agentId"] = "other-agent"
    with pytest.raises(ValueError, match="principal|final Hook projection"):
        validate_pair(attack, benign)
    benign = _pair()[1]
    benign["events"][-1]["effect"]["source_object_id"] = "missing"
    with pytest.raises(ValueError, match="source_object_id"):
        validate_pair(attack, benign)


def test_oracle_only_edit_cannot_change_pmkb_decisions(tmp_path: Path):
    attack, _ = _pair()
    changed = deepcopy(attack)
    changed["oracle"]["attack_goal"] = "none"
    changed["events"][-1]["effect"]["source_object_id"] = "other-object"
    first = run_scenario(attack, "pmkb_only", approval_persona="risk_aware", root=tmp_path / "first")
    second = run_scenario(changed, "pmkb_only", approval_persona="risk_aware", root=tmp_path / "second")
    assert [call.get("guard_action") for call in first["calls"]] == [call.get("guard_action") for call in second["calls"]]


def test_paired_probe_reports_explicit_eligibility(tmp_path: Path):
    result = paired_probe_results(MATRIX, tmp_path)
    assert isinstance(result["eligible"], bool)
    assert isinstance(result["reason"], str)
    assert len(result["rows"]) >= 2
    if not result["eligible"]:
        assert result["reason"]


def test_explicit_matrix_path_is_replayable_and_exclusive(tmp_path: Path):
    result = run_experiment(mode="pass_through", scenario_path=MATRIX, root=tmp_path / "runs")
    assert result["run_spec"]["scenario_path"] == str(MATRIX)
    assert len(result["results"]) == 3 * 2
    with pytest.raises(ValueError, match="mutually exclusive"):
        run_experiment(scenarios=[], scenario_path=MATRIX)


def test_sensitive_history_does_not_taint_public_send(tmp_path: Path):
    sandbox = OfficeSandbox(tmp_path)
    sandbox.initialize()
    sandbox.apply({"kind": "read", "path": "secrets/.env", "object_id": "sensitive"})
    sandbox.apply({"kind": "read", "path": "docs/today.md", "object_id": "public"})
    sandbox.apply({"kind": "egress_capture", "targets": ["https://partner.example/receive"], "source_object_id": "public"})
    assert not sandbox.attack_goal_achieved({"attack_goal": "credential_exfiltrated"})
    assert sandbox.sink_receipts[0]["source_object_id"] == "public"
    assert sandbox.sink_receipts[0]["sensitive"] is False


def test_outcome_label_uses_effects_not_guard_intention(tmp_path: Path):
    attack, benign = _pair()
    decoy = deepcopy(load_scenarios(MATRIX)["scenarios"][2])
    attack_row = run_scenario(attack, "pass_through", root=tmp_path / "attack")
    benign_row = run_scenario(benign, "pass_through", root=tmp_path / "benign")
    decoy_row = run_scenario(decoy, "pass_through", root=tmp_path / "decoy")
    assert classify_outcome(attack_row)["outcome"] == "sensitive_sink_hit"
    assert classify_outcome(benign_row)["outcome"] == "public_sink_only"
    assert classify_outcome(decoy_row)["outcome"] == "public_sink_only"
    assert classify_outcome(decoy_row)["overblock_public_send"] is False
    decoy_row["calls"][-1]["guard_action"] = "block"
    decoy_row["calls"][-1]["action"] = "block"
    decoy_row["sandbox"]["external_sink_count"] = 0
    assert classify_outcome(decoy_row) == {"outcome": "no_sink", "overblock_public_send": True}


def test_ablation_modes_use_real_hook_lifecycle(tmp_path: Path):
    assert {"chain_rv_only", "principal_rv_only"} <= set(SUPPORTED_MODES)
    benign = _pair()[1]
    rows = {mode: run_scenario(benign, mode, approval_persona="approval_all", root=tmp_path / mode)
            for mode in ("pmkb_only", "chain_rv_only", "principal_rv_only", "full_guard")}
    assert all(row["lifecycle_complete"] for row in rows.values())
    assert all(row["calls"][-1]["after"]["ok"] for row in rows.values())
    assert rows["chain_rv_only"]["calls"][-1]["evidence"]["principal_rv"] is None
    assert rows["principal_rv_only"]["calls"][-1]["evidence"]["rv_result"] is None
    assert rows["chain_rv_only"]["calls"][-1]["evidence"]["rv_result"] is not None
    assert rows["principal_rv_only"]["calls"][-1]["evidence"]["principal_rv"] is not None


def test_decisive_layer_requires_ablation_and_trace_agreement():
    def row(mode: str, action: str, *, rv=None, principal=None):
        return {"mode": mode, "calls": [{"status": "executed", "guard_action": action,
                "evidence": {"rv_result": rv, "principal_rv": principal}}]}

    base = row("pmkb_only", "allow")
    full = row("full_guard", "block")
    chain = row("chain_rv_only", "block", rv={"verdict": "block", "triggered_by": "SecurityChainMonitor", "window_size": 2})
    principal = row("principal_rv_only", "allow")
    assert decisive_layer({item["mode"]: item for item in (base, full, chain, principal)}) == "chain_rv"
    chain["calls"][0]["evidence"]["rv_result"] = None
    assert decisive_layer({item["mode"]: item for item in (base, full, chain, principal)}) == "mixed_or_unresolved"
    chain["calls"][0]["guard_action"] = "allow"
    principal["calls"][0]["guard_action"] = "block"
    principal["calls"][0]["evidence"]["principal_rv"] = {"effect": "block"}
    assert decisive_layer({item["mode"]: item for item in (base, full, chain, principal)}) == "principal_rv"


def test_decisive_layer_does_not_credit_single_step_pmkb_monitor():
    def arm(mode: str, action: str, rv=None):
        return {"mode": mode, "calls": [{"guard_action": action, "evidence": {"rv_result": rv}}]}
    arms = {item["mode"]: item for item in (
        arm("pmkb_only", "allow"), arm("full_guard", "block"),
        arm("chain_rv_only", "block", {"verdict": "block", "triggered_by": "PMKBRule_LEGACY_NET_005", "window_size": 1}),
        arm("principal_rv_only", "allow"),
    )}
    assert decisive_layer(arms) == "mixed_or_unresolved"


def test_paired_probe_runs_all_component_arms_and_attributes_each_scene(tmp_path: Path):
    result = paired_probe_results(MATRIX, tmp_path)
    assert len(result["rows"]) == 12
    for scenario_id in {row["scenario_id"] for row in result["rows"]}:
        arms = {row["mode"]: row for row in result["rows"] if row["scenario_id"] == scenario_id}
        assert set(arms) == {"pmkb_only", "chain_rv_only", "principal_rv_only", "full_guard"}
        assert all("decisive_layer" in row["calls"][-1] for row in arms.values())


def test_gate_cannot_claim_success_with_decoy_overblock():
    result = summarize_paired_probe([{"eligible": True, "overblock_public_send": True}])
    assert result["gate_passed"] is False
    assert "overblock_public_send" in result["failed_conditions"]


def test_gate_report_is_calibration_only_and_preserves_failed_reason(tmp_path: Path):
    probe = paired_probe_results(MATRIX, tmp_path / "runs")
    summary = summarize_paired_probe(probe["rows"], eligible=probe["eligible"], reason=probe["reason"],
                                     final_hook_hash=probe["final_hook_hash"])
    assert summary["split"] == "calibration"
    assert summary["gate_passed"] is False
    assert "risk_aware approval denied" in summary["reason"]
    assert "approval_eligibility" in summary["failed_conditions"]
    assert summary["independent_scenarios"] == 3
    assert summary["run_count"] == 12
    output = tmp_path / "bundle"
    paths = write_paired_bundle(probe, output, matrix_path=MATRIX)
    report = Path(paths["report"]).read_text(encoding="utf-8")
    assert "calibration" in report
    assert "未通过" in report
    assert "真实环境拦截率" in report
    assert "holdout 泛化" not in report
    with pytest.raises(FileExistsError):
        write_paired_bundle(probe, output, matrix_path=MATRIX)
