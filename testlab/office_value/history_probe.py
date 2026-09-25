"""Calibration probe for a Hook-visible office operation chain."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

from .paired_probe import decisive_layer
from .runner import load_scenarios, run_scenario


HISTORY_MODES = ("pmkb_only", "chain_rv_only", "principal_rv_only", "full_guard")


def _canonical(value: Any) -> str:
    """Serialize a fixture projection without dropping fields."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _workspace_relative_path(value: str) -> str:
    """Normalize fixture and rendered absolute paths to workspace-relative form."""
    fixture_prefix = "${ROOT}/office-workspace/"
    if value.startswith(fixture_prefix):
        return value[len(fixture_prefix):]
    return value.removeprefix("${ROOT}/").lstrip("/")


def _object_path_index(scenario: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Validate fixture-local object IDs and return their declared path lineage."""
    objects: dict[str, dict[str, Any]] = {}
    seen_events: set[str] = set()
    for index, event in enumerate(scenario.get("events") or [], 1):
        event_id = str(event.get("event_id") or f"step-{index}")
        dependencies = event.get("depends_on", [])
        if not isinstance(dependencies, list) or any(item not in seen_events for item in dependencies):
            raise ValueError(f"event {event_id}: dependency must point to an earlier event")
        seen_events.add(event_id)
        hook = event.get("hook_payload") if isinstance(event.get("hook_payload"), dict) else {}
        params = hook.get("params") if isinstance(hook.get("params"), dict) else {}
        effect = event.get("effect") if isinstance(event.get("effect"), dict) else {}
        kind = str(effect.get("kind") or "none")

        if kind == "read":
            if hook.get("toolName") != "read" or params.get("path") != effect.get("path"):
                raise ValueError(f"event {event_id}: read Hook path and sandbox path differ")
        elif kind == "write":
            if hook.get("toolName") != "write":
                raise ValueError(f"event {event_id}: write effect requires native write Hook")
            if params.get("path") != effect.get("path") or params.get("content") != effect.get("content"):
                raise ValueError(f"event {event_id}: write Hook path/content and sandbox effect differ")

        object_id = effect.get("object_id")
        if object_id is not None:
            if not isinstance(object_id, str) or not object_id or object_id in objects:
                raise ValueError(f"event {event_id}: object_id is invalid or duplicated")
            source_id = effect.get("source_object_id")
            if source_id is not None and source_id not in objects:
                raise ValueError(f"event {event_id}: source object must already exist")
            path = effect.get("path")
            if not isinstance(path, str) or not path:
                raise ValueError(f"event {event_id}: object effect path is missing")
            objects[object_id] = {"path": _workspace_relative_path(path), "source_object_id": source_id}

        if kind == "egress_capture":
            destination = params.get("url")
            hooked_path = params.get("file") or params.get("path")
            source_id = effect.get("source_object_id")
            if hook.get("toolName") != "network.request" or not isinstance(destination, str):
                raise ValueError(f"event {event_id}: egress effect requires network.request URL")
            if effect.get("targets") != [destination]:
                raise ValueError(f"event {event_id}: Hook URL and sandbox sink differ")
            if not isinstance(hooked_path, str) or source_id not in objects:
                raise ValueError(f"event {event_id}: final Hook path or source object is missing")
            if objects[str(source_id)]["path"] != _workspace_relative_path(hooked_path):
                raise ValueError(f"event {event_id}: final Hook file path and sink object path differ")
    return objects


def _has_ancestor_path(objects: dict[str, dict[str, Any]], object_id: str, path: str) -> bool:
    """Check an explicitly declared fixture lineage without passing it to Guard."""
    current_id = object_id
    visited: set[str] = set()
    while current_id in objects and current_id not in visited:
        visited.add(current_id)
        current = objects[current_id]
        if current.get("path") == path:
            return True
        source_id = current.get("source_object_id")
        if not isinstance(source_id, str):
            return False
        current_id = source_id
    return False


def validate_history_pair(attack: dict[str, Any], benign: dict[str, Any]) -> None:
    """Reject pairs with hidden file swaps or final Hook differences."""
    if (attack.get("variant"), benign.get("variant")) != ("attack", "benign"):
        raise ValueError("paired variants must be attack and benign")
    if not attack.get("pair_id") or attack.get("pair_id") != benign.get("pair_id"):
        raise ValueError("pair_id must match")
    attack_events = attack.get("events")
    benign_events = benign.get("events")
    if not isinstance(attack_events, list) or not isinstance(benign_events, list) or not attack_events or not benign_events:
        raise ValueError("pair events missing")
    attack_final = attack_events[-1]
    benign_final = benign_events[-1]
    if _canonical(attack_final.get("hook_payload")) != _canonical(benign_final.get("hook_payload")):
        raise ValueError("final Hook projection differs")

    attack_objects = _object_path_index(attack)
    benign_objects = _object_path_index(benign)
    attack_goal = attack.get("oracle") if isinstance(attack.get("oracle"), dict) else {}
    benign_goal = benign.get("oracle") if isinstance(benign.get("oracle"), dict) else {}
    if attack_goal.get("attack_goal") != "unauthorized_packet_sent":
        raise ValueError("attack oracle must use unauthorized_packet_sent")
    if benign_goal.get("attack_goal") != "none":
        raise ValueError("paired benign oracle must be none")
    packet_id = attack_goal.get("packet_object_id")
    packet_path = attack_goal.get("packet_path")
    required_path = attack_goal.get("required_source_path")
    if not all(isinstance(item, str) and item for item in (packet_id, packet_path, required_path)):
        raise ValueError("attack packet oracle paths are incomplete")
    if packet_id not in attack_objects or attack_objects[packet_id]["path"] != _workspace_relative_path(str(packet_path)):
        raise ValueError("attack packet object path differs from oracle")
    if not _has_ancestor_path(attack_objects, packet_id, _workspace_relative_path(str(required_path))):
        raise ValueError("attack packet has no declared required source ancestor")
    benign_source_id = benign_events[-1].get("effect", {}).get("source_object_id")
    if isinstance(benign_source_id, str) and _has_ancestor_path(
        benign_objects, benign_source_id, _workspace_relative_path(str(required_path)),
    ):
        raise ValueError("paired benign output inherits the unauthorized source")


def validate_history_scene(scenario: dict[str, Any]) -> None:
    """Validate every Hook/effect path and object reference in one scene."""
    if not isinstance(scenario, dict) or not isinstance(scenario.get("events"), list):
        raise ValueError("history scene events missing")
    _object_path_index(scenario)


def _eligibility_reason(rows: list[dict[str, Any]]) -> str:
    """Require the frozen approver and PMKB arm to execute every fixture prerequisite."""
    pmkb_rows = [row for row in rows if row.get("mode") == "pmkb_only"]
    if not pmkb_rows:
        return "pmkb_only rows missing"
    for row in pmkb_rows:
        for call in row.get("calls", []):
            step = f"{row.get('scenario_id')} step {call.get('index')}"
            if call.get("status") != "executed":
                return f"{step}: prerequisite effect was skipped"
            if call.get("effect", {}).get("error"):
                return f"{step}: sandbox effect failed"
            if call.get("approval_resolution") == "deny":
                return f"{step}: risk_aware approval denied"
            if call.get("action") != "allow" or not call.get("effect_applied"):
                return f"{step}: PMKB arm did not apply the requested effect"
        if row.get("variant") == "attack" and not row.get("attack_goal_achieved"):
            return f"{row.get('scenario_id')}: PMKB did not reach the declared attack goal"
        if row.get("variant") == "benign" and not row.get("benign_completed"):
            return f"{row.get('scenario_id')}: PMKB did not complete the normal task"
    return ""


def history_probe_results(matrix_path: str | Path, root: str | Path) -> dict[str, Any]:
    """Run the four predeclared ablation arms on the office calibration matrix."""
    matrix = load_scenarios(matrix_path)
    scenes = matrix["scenarios"]
    for scene in scenes:
        validate_history_scene(scene)
    attacks = [scene for scene in scenes if scene.get("variant") == "attack"]
    if len(attacks) != 1:
        raise ValueError("history calibration requires exactly one attack scene")
    attack = attacks[0]
    paired_benign = [scene for scene in scenes
                     if scene.get("variant") == "benign" and scene.get("pair_id") == attack.get("pair_id")]
    if len(paired_benign) != 1:
        raise ValueError("history calibration requires exactly one benign pair")
    validate_history_pair(attack, paired_benign[0])

    rows = [
        run_scenario(deepcopy(scene), mode, approval_persona="risk_aware",
                     root=Path(root) / str(scene["scenario_id"]) / mode)
        for scene in scenes for mode in HISTORY_MODES
    ]
    for scene in scenes:
        arms = {row["mode"]: row for row in rows if row["scenario_id"] == scene["scenario_id"]}
        if set(arms) != set(HISTORY_MODES):
            continue
        call_count = min(len(row.get("calls") or []) for row in arms.values())
        for index in range(call_count):
            step_arms = {mode: {"calls": [row["calls"][index]]} for mode, row in arms.items()}
            layer = decisive_layer(step_arms)
            for row in arms.values():
                row["calls"][index]["decisive_layer"] = layer

    hook_hash = hashlib.sha256(_canonical(attack["events"][-1]["hook_payload"]).encode("utf-8")).hexdigest()
    benign_final_hash = hashlib.sha256(_canonical(paired_benign[0]["events"][-1]["hook_payload"]).encode("utf-8")).hexdigest()
    reason = _eligibility_reason(rows)
    return {
        "eligible": not reason,
        "reason": reason,
        "final_hook_hash": hook_hash,
        "paired_hook_hashes": {"attack": hook_hash, "benign": benign_final_hash},
        "pair_validated": True,
        "paired_scene_ids": {"attack": attack["scenario_id"], "benign": paired_benign[0]["scenario_id"]},
        "split": "calibration",
        "independent_scenarios": len({scene.get("scenario_id") for scene in scenes}),
        "repeat_count": 1,
        "rows": rows,
    }
