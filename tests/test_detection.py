from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openclaw_guard.detection import DetectionEngine, builtin_rules
from openclaw_guard.manager import build_manager


class DetectionTests(unittest.TestCase):
    def test_builtin_rules_count_is_47(self) -> None:
        self.assertEqual(len(builtin_rules()), 47)

    def test_rm_rf_is_blocked(self) -> None:
        engine = DetectionEngine()
        from openclaw_guard.behavior import BehaviorCollectorManager

        event = BehaviorCollectorManager().ingest(
            {"action_type": "command_exec", "command": "rm -rf /tmp/demo", "process_name": "openclaw", "user": "tester"}
        )
        decision = engine.evaluate(event)
        self.assertEqual(decision.action, "block")

    def test_outside_workspace_delete_enters_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text("{}", encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            payload = manager.ingest_event(
                {
                    "action_type": "file_delete",
                    "process_name": "openclaw",
                    "user": "tester",
                    "target_paths": ["/Users/dynooob/secret.txt"],
                    "raw_user_intent": "删除 /Users/dynooob/secret.txt",
                    "metadata": {"outside_workspace": True},
                },
                "删除 /Users/dynooob/secret.txt",
            )
            self.assertEqual(payload["status"], "pending_approval")

