from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openclaw_guard.engine.behavior import BehaviorCollectorManager
from openclaw_guard.manager import build_manager
from openclaw_guard.policy.engine import AuthorizationPolicyEngine


class PolicyDecisionAdapterTests(unittest.TestCase):
    def test_frozen_legacy_record_count_is_47(self) -> None:
        engine = AuthorizationPolicyEngine()
        self.assertEqual(len(engine.bundle.legacy_rules()), 47)

    def test_rm_rf_is_blocked_by_pmkb(self) -> None:
        event = BehaviorCollectorManager().ingest(
            {"action_type": "command_exec", "command": "rm -rf /tmp/demo", "process_name": "openclaw", "user": "tester"}
        )
        event.metadata["semantic"] = {"labels": ["command_rm_rf"]}
        event.metadata["rv_trace"] = [{"props": ["command_rm_rf"]}]
        decision = AuthorizationPolicyEngine().decide(event)
        self.assertEqual(decision.action, "block")
        self.assertIn("LEGACY-CMD-001", decision.rule_ids)

    def test_outside_workspace_delete_enters_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            with patch.object(manager.audit_store, "append", return_value={}):
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
