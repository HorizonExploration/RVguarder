from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from openclaw_guard.manager import build_manager


class FrontendRvContractTests(unittest.TestCase):
    def test_action_contains_pipeline_timings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            action = manager.ingest_event(
                {
                    "action_type": "command_exec",
                    "command": "ls",
                    "raw_user_intent": "列出目录",
                },
                source_message="列出目录",
                auto_execute=False,
            )
            meta = (action.get("event") or {}).get("metadata") or {}
            timings = meta.get("pipeline_timings_ms") or {}
            for key in ("semantic_ms", "detection_ms", "rv_ms", "controller_ms", "total_ms"):
                self.assertIn(key, timings)
                self.assertIsInstance(timings[key], (int, float))

    def test_summary_does_not_expose_channel_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(
                json.dumps(
                    {
                        "models": {"providers": {}},
                        "channels": {"feishu": {"enabled": True, "appId": "ID", "appSecret": "SECRET"}},
                        "skills": {"demo-skill": {"enabled": True, "description": "demo", "permissions": ["net"]}},
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            manager = build_manager(project, config_path=config_path)
            summary = manager.summary()
            payload = json.dumps(summary, ensure_ascii=False)
            self.assertNotIn("SECRET", payload)
            for item in summary.get("skills", {}).get("items", []):
                self.assertNotIn("raw", item)
            for item in summary.get("channels", {}).get("items", []):
                self.assertNotIn("raw", item)

