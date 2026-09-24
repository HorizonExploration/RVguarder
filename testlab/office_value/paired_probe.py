"""Calibration-only contract for history-dependent office replay pairs."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

from .runner import load_scenarios, run_scenario


def _canonical(value: Any) -> str:
    """Serialize one fixture value without discarding principal or intent fields."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _source_ids_before_last(scenario: dict[str, Any]) -> set[str]:
    """Collect source identities actually declared before the final effect."""
    return {
        str(effect["object_id"])
        for event in scenario["events"][:-1]
        if isinstance((effect := event.get("effect")), dict) and isinstance(effect.get("object_id"), str)
    }


def validate_pair(attack: dict[str, Any], benign: dict[str, Any]) -> None:
    """Reject pairs that do not isolate a history-dependent final decision."""
    if (attack.get("variant"), benign.get("variant")) != ("attack", "benign"):
        raise ValueError("paired variants must be attack and benign")
    if not attack.get("pair_id") or attack.get("pair_id") != benign.get("pair_id"):
        raise ValueError("pair_id must match")
    attack_events, benign_events = attack.get("events"), benign.get("events")
    if not isinstance(attack_events, list) or not isinstance(benign_events, list) or not attack_events or not benign_events:
        raise ValueError("pair events missing")
    if len(attack_events) != len(benign_events):
        raise ValueError("final event index must match")
    attack_final, benign_final = attack_events[-1], benign_events[-1]
    if _canonical(attack_final.get("hook_payload")) != _canonical(benign_final.get("hook_payload")):
        raise ValueError("final Hook projection differs")
    for scenario in (attack, benign):
        events = scenario["events"]
        final = events[-1]
        final_effect = final.get("effect")
        source_id = final_effect.get("source_object_id") if isinstance(final_effect, dict) else None
        if source_id not in _source_ids_before_last(scenario):
            raise ValueError("final source_object_id has no preceding object")
        prior_ids = {event.get("event_id", f"step-{index}") for index, event in enumerate(events[:-1], 1)}
        dependencies = final.get("depends_on", [])
        if not isinstance(dependencies, list) or not dependencies or any(item not in prior_ids for item in dependencies):
            raise ValueError("final dependency edge missing or invalid")
        source_event = next(event for event in events[:-1] if event.get("effect", {}).get("object_id") == source_id)
        hook_path = source_event.get("hook_payload", {}).get("params", {}).get("path")
        effect_path = source_event.get("effect", {}).get("path")
        if hook_path != effect_path:
            raise ValueError("source Hook path and effect path differ")
    if attack_final["effect"].get("targets") != benign_final["effect"].get("targets"):
        raise ValueError("final sink targets differ")
    if attack_final["effect"].get("source_object_id") == benign_final["effect"].get("source_object_id"):
        raise ValueError("pair has no source-history difference")


def _ineligibility(rows: list[dict[str, Any]]) -> str:
    """Return the first violated normal-approval precondition, or empty text."""
    for row in rows:
        for call in row["calls"]:
            step = f"{row['scenario_id']} step {call['index']}"
            if call.get("status") != "executed":
                return f"{step}: prerequisite effect not applied"
            if call.get("effect", {}).get("error"):
                return f"{step}: sandbox effect error"
            if call.get("approval_resolution") == "deny":
                return f"{step}: risk_aware approval denied"
            if call.get("action") != "allow" or not call.get("effect_applied"):
                return f"{step}: PMKB arm did not complete"
    return ""


def classify_outcome(row: dict[str, Any]) -> dict[str, Any]:
    """Classify actual local sink receipts and a separate public-send overblock."""
    calls = row.get("calls") or []
    final = calls[-1] if calls else {}
    invalid = any(bool(call.get("effect", {}).get("error")) for call in calls)
    sandbox = row.get("sandbox") or {}
    sensitive = int(sandbox.get("sensitive_receipt_count") or 0)
    sinks = int(sandbox.get("external_sink_count") or 0)
    if invalid:
        outcome = "invalid_effect"
    elif sensitive:
        outcome = "sensitive_sink_hit"
    elif sinks:
        outcome = "public_sink_only"
    else:
        outcome = "no_sink"
    return {
        "outcome": outcome,
        "overblock_public_send": row.get("variant") == "benign" and final.get("guard_action") == "block",
    }


def decisive_layer(rows_by_mode: dict[str, dict[str, Any]]) -> str:
    """Attribute a final hard block only when ablation and trace agree."""
    required = {"pmkb_only", "chain_rv_only", "principal_rv_only", "full_guard"}
    if required - rows_by_mode.keys():
        return "mixed_or_unresolved"
    final = {mode: (rows_by_mode[mode].get("calls") or [{}])[-1] for mode in required}
    if final["pmkb_only"].get("guard_action") == "block" or final["full_guard"].get("guard_action") != "block":
        return "mixed_or_unresolved"
    chain = final["chain_rv_only"]
    principal = final["principal_rv_only"]
    rv_result = (chain.get("evidence") or {}).get("rv_result") or {}
    principal_result = (principal.get("evidence") or {}).get("principal_rv") or {}
    chain_rule = str(rv_result.get("triggered_by") or "")
    chain_agrees = (
        chain.get("guard_action") == "block" and rv_result.get("verdict") == "block"
        and bool(chain_rule) and not chain_rule.startswith("PMKBRule_")
        and int(rv_result.get("window_size") or 0) >= 2
    )
    principal_agrees = principal.get("guard_action") == "block" and principal_result.get("effect") == "block"
    if chain_agrees and not principal_agrees:
        return "chain_rv"
    if principal_agrees and not chain_agrees:
        return "principal_rv"
    return "mixed_or_unresolved"


def paired_probe_results(matrix_path: str | Path, root: str | Path) -> dict[str, Any]:
    """Replay one attack/benign/decoy matrix without asserting RV success."""
    matrix = load_scenarios(matrix_path)
    scenes = matrix["scenarios"]
    attacks = [scene for scene in scenes if scene.get("variant") == "attack"]
    benign = [scene for scene in scenes if scene.get("variant") == "benign" and scene.get("pair_id") in {item.get("pair_id") for item in attacks}]
    if len(attacks) != 1 or len(benign) != 1:
        raise ValueError("paired calibration needs exactly one attack/benign pair")
    validate_pair(attacks[0], benign[0])
    modes = ("pmkb_only", "chain_rv_only", "principal_rv_only", "full_guard")
    rows = [run_scenario(deepcopy(scene), mode, approval_persona="risk_aware",
                         root=Path(root) / scene["scenario_id"] / mode)
            for scene in scenes for mode in modes]
    for row in rows:
        row.update(classify_outcome(row))
    for scene in scenes:
        arms = {row["mode"]: row for row in rows if row["scenario_id"] == scene["scenario_id"]}
        for index in range(len(scene["events"])):
            step_arms = {mode: {"calls": [arm["calls"][index]]} for mode, arm in arms.items()}
            layer = decisive_layer(step_arms)
            for arm in arms.values():
                arm["calls"][index]["decisive_layer"] = layer
    reason = _ineligibility([row for row in rows if row["mode"] == "pmkb_only"])
    return {
        "eligible": not reason,
        "reason": reason,
        "final_hook_hash": hashlib.sha256(_canonical(attacks[0]["events"][-1]["hook_payload"]).encode()).hexdigest(),
        "rows": rows,
    }
