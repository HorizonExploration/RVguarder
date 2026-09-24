"""Evidence-contract tests for the calibration-only RV value gate."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from testlab.office_value.paired_probe import classify_outcome, paired_probe_results, validate_pair
from testlab.office_value.sandbox import OfficeSandbox
from testlab.office_value.runner import load_scenarios, run_experiment, run_scenario


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
