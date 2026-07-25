from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openclaw_guard.engine.behavior import BehaviorCollectorManager
from openclaw_guard.engine.whitelist import WhitelistEngine, default_police_whitelist
from openclaw_guard.storage.audit_store import AuditStore


class WhitelistAuditTests(unittest.TestCase):
    def test_whitelist_matches_path_command_and_network(self) -> None:
        engine = WhitelistEngine(default_police_whitelist())
        event = BehaviorCollectorManager().ingest(
            {
                "action_type": "network_egress",
                "process_name": "openclaw",
                "user": "tester",
                "command": "cat /tmp/openclaw-case.txt",
                "target_paths": ["/tmp/openclaw-case.txt"],
                "network_targets": ["http://127.0.0.1:19001"],
            }
        )
        matches = engine.evaluate(event)
        self.assertTrue(any(item.startswith("file:") for item in matches))
        self.assertTrue(any(item.startswith("network:") for item in matches))

    def test_audit_store_chain_and_exports_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = AuditStore(root / "audit.db", root / "audit.jsonl")
            store.append("event", {"action": "scan"})
            store.append("event", {"action": "block"})
            verification = store.verify_chain()
            exports = store.export(root / "exports")
            self.assertTrue(verification["ok"])
            self.assertTrue(Path(exports["json"]).exists())
            self.assertTrue(Path(exports["csv"]).exists())

    def test_audit_store_query_order_is_stable_when_timestamps_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = AuditStore(root / "audit.db", root / "audit.jsonl")
            with patch("openclaw_guard.storage.audit_store.utc_now_iso", return_value="2026-04-06T00:00:00+00:00"):
                store.append("event", {"action": "first"})
                store.append("event", {"action": "second"})
            rows = store.query(limit=2)
            self.assertEqual(rows[0]["payload"]["action"], "second")
            self.assertEqual(rows[1]["payload"]["action"], "first")
            self.assertTrue(store.verify_chain()["ok"])
