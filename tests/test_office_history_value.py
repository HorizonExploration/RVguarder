from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from testlab.office_value.runner import run_scenario


def _two_read_scene() -> dict:
    events = []
    for index, name in enumerate(("today.md", "meeting-notes.md"), 1):
        relative_path = f"${{ROOT}}/office-workspace/docs/{name}"
        events.append({
            "hook_payload": {
                "toolName": "read",
                "params": {"path": relative_path},
                "sessionId": "one-session",
                "agentId": "office-agent",
                "toolCallId": f"read-{index}",
            },
            "effect": {"kind": "read", "path": relative_path, "object_id": f"doc-{index}"},
            "oracle": {"expected": "source_read"},
        })
    return {
        "scenario_id": "STEP-IDS",
        "incident_id": "OFFICE-PAIR-001",
        "split": "calibration",
        "workflow": "meeting_followup",
        "variant": "benign",
        "oracle": {"attack_goal": "none"},
        "events": events,
    }


def test_hook_rv_steps_are_call_scoped_and_stable_across_modes(tmp_path: Path) -> None:
    scene = _two_read_scene()
    original_payloads = deepcopy([event["hook_payload"] for event in scene["events"]])

    rows = [
        run_scenario(scene, mode, approval_persona="risk_aware", root=tmp_path / mode)
        for mode in ("chain_rv_only", "full_guard")
    ]

    ids_by_mode = [
        [call["evidence"]["rv_step_ids"] for call in row["calls"] if call["status"] == "executed"]
        for row in rows
    ]
    for ids in ids_by_mode:
        assert len(ids) == 2
        assert all(len(step_ids) == 1 for step_ids in ids)
        assert ids[0][0] != ids[1][0]
    assert ids_by_mode[0] == ids_by_mode[1]
    assert [event["hook_payload"] for event in scene["events"]] == original_payloads
