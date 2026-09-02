from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from openclaw_guard import api
from openclaw_guard.services import build_services


class ApprovalSyncTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        project = Path(self.tmp.name) / "OpenclawGuard"
        project.mkdir()
        config_path = project / "openclaw.json"
        config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
        self.services = build_services(project, config_path=config_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _pending_hook(self) -> dict:
        result = self.services.handle_before_tool_call(
            {
                "toolName": "shell_exec",
                "params": {"command": "rm -f /tmp/guard-sync-test"},
                "runId": "run-sync-1",
                "toolCallId": "tool-sync-1",
                "sessionId": "session-sync-1",
            }
        )
        self.assertEqual(result["action"], "require_approval")
        return result["action_record"]

    def test_hook_action_cannot_be_approved_from_guard_api(self) -> None:
        action = self._pending_hook()
        payload, status = api.approve_action(
            self.services,
            {"action_id": action["action_id"], "confirmation_text": ""},
        )
        self.assertEqual(status, 409)
        self.assertEqual(payload["error_code"], "hook_approval_owned_by_openclaw")

    def test_resolution_is_idempotent_and_returns_sync_metadata(self) -> None:
        action = self._pending_hook()
        payload, status = api.resolve_hook_approval(
            self.services,
            {"actionId": action["action_id"], "decision": "allow-once"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(payload["accepted"])
        self.assertEqual(payload["decision_state"], "allowed")
        first_seq = payload["event_seq"]

        payload2, status2 = api.resolve_hook_approval(
            self.services,
            {"actionId": action["action_id"], "decision": "allow-once"},
        )
        self.assertEqual(status2, 200)
        self.assertEqual(payload2["event_seq"], first_seq)
        self.assertEqual(self.services.action_service.get_action(action["action_id"])["status"], "approved")

    def test_resolution_conflict_is_recorded_without_overwriting_decision(self) -> None:
        action = self._pending_hook()
        first, _ = api.resolve_hook_approval(
            self.services,
            {"actionId": action["action_id"], "decision": "allow-once"},
        )
        conflict, status = api.resolve_hook_approval(
            self.services,
            {"actionId": action["action_id"], "decision": "deny"},
        )
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error_code"], "resolution_conflict")
        current = self.services.action_service.get_action(action["action_id"])
        self.assertEqual(current["status"], "approved")
        self.assertEqual(current["sync_state"], "conflict")

    def test_late_resolution_does_not_mutate_non_pending_action(self) -> None:
        """执行中或已结束的 Hook 动作拒绝乱序回调且保留原状态。"""
        execution_states = {
            "executing": "running",
            "executed": "executed",
            "blocked": "not_started",
            "rejected": "not_started",
        }
        for status, execution_state in execution_states.items():
            with self.subTest(status=status):
                action = self._pending_hook()
                action_model = self.services._find_action(action["action_id"])
                assert action_model is not None
                action_model.status = status
                action_model.decision_state = "allowed" if status in {"executing", "executed"} else "denied"
                action_model.execution_state = execution_state
                action_model.sync_state = "local_only"
                action_model.resolution = {}
                self.services._save_all(self.services._replace_action(action_model))
                before = deepcopy(self.services.action_service.get_action(action["action_id"]))

                payload, response_status = api.resolve_hook_approval(
                    self.services,
                    {"actionId": action["action_id"], "decision": "allow-once"},
                )

                self.assertEqual(response_status, 409)
                self.assertEqual(payload["error_code"], "resolution_conflict")
                after = self.services.action_service.get_action(action["action_id"])
                self.assertEqual(after, before)

    def test_stale_hook_approval_is_expired_after_openclaw_timeout(self) -> None:
        action = self._pending_hook()
        action_model = self.services._find_action(action["action_id"])
        assert action_model is not None
        action_model.created_at = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        self.services._save_all(self.services._replace_action(action_model))

        expired = self.services.action_service.expire_pending_hook_actions()

        self.assertEqual(expired, 1)
        current = self.services.action_service.get_action(action["action_id"])
        assert current is not None
        self.assertEqual(current["status"], "failed")
        self.assertEqual(current["execution_result"]["error_code"], "approval_timeout")

    def test_summary_expires_stale_hook_and_publishes_timeout_event(self) -> None:
        action = self._pending_hook()
        action_model = self.services._find_action(action["action_id"])
        assert action_model is not None
        action_model.created_at = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        self.services._save_all(self.services._replace_action(action_model))
        before_seq = self.services.events.latest_seq

        summary = self.services.summary(compact=True)

        self.assertEqual(summary["actions"]["counts"]["pending"], 0)
        events = self.services.events.since(before_seq)
        self.assertEqual([item["type"] for item in events], ["action.timeout"])
        self.assertEqual(events[0]["action_id"], action["action_id"])
        current = self.services.action_service.get_action(action["action_id"])
        assert current is not None
        self.assertEqual(current["last_event_seq"], events[0]["seq"])

    def test_event_bus_supports_cursor_replay(self) -> None:
        first = self.services.events.publish("action.resolved", {"action_id": "a1"})
        self.services.events.publish("action.updated", {"action_id": "a1"})
        events = self.services.events.since(first["seq"])
        self.assertEqual([item["type"] for item in events], ["action.updated"])


if __name__ == "__main__":
    unittest.main()
