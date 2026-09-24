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


def paired_probe_results(matrix_path: str | Path, root: str | Path) -> dict[str, Any]:
    """Replay one attack/benign/decoy matrix without asserting RV success."""
    matrix = load_scenarios(matrix_path)
    scenes = matrix["scenarios"]
    attacks = [scene for scene in scenes if scene.get("variant") == "attack"]
    benign = [scene for scene in scenes if scene.get("variant") == "benign" and scene.get("pair_id") in {item.get("pair_id") for item in attacks}]
    if len(attacks) != 1 or len(benign) != 1:
        raise ValueError("paired calibration needs exactly one attack/benign pair")
    validate_pair(attacks[0], benign[0])
    rows = [run_scenario(deepcopy(scene), "pmkb_only", approval_persona="risk_aware", root=Path(root) / scene["scenario_id"])
            for scene in scenes]
    reason = _ineligibility(rows)
    return {
        "eligible": not reason,
        "reason": reason,
        "final_hook_hash": hashlib.sha256(_canonical(attacks[0]["events"][-1]["hook_payload"]).encode()).hexdigest(),
        "rows": rows,
    }
