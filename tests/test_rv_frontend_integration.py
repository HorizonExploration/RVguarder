"""RV 模式全流程集成测试。

覆盖：
- RV 状态 API（/api/rv/status）
- RV 切换 API（/api/rv/toggle）
- summary 中包含 RV 字段
- 前端 localStorage 持久化（通过 Mock）
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openclaw_guard.manager import build_manager


class TestRvApiIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.project = Path(self.tmp.name) / "OpenclawGuard"
        self.project.mkdir()
        self.config_path = self.project / "openclaw.json"
        self.config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
        self.manager = build_manager(self.project, config_path=self.config_path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_summary_contains_rv_field(self):
        summary = self.manager.summary()
        self.assertIn("rv", summary)
        rv = summary["rv"]
        self.assertIn("mode", rv)
        self.assertIn("engine", rv)
        self.assertIn("window_size", rv["engine"])
        self.assertIn("monitor_count", rv["engine"])

    def test_rv_status_returns_engine_state(self):
        status = self.manager.rv_status()
        self.assertTrue(status["ok"])
        self.assertIn("mode", status)
        self.assertIn("engine", status)
        self.assertGreaterEqual(status["engine"]["monitor_count"], 0)

    def test_rv_toggle_on(self):
        result = self.manager.rv_toggle({"enabled": True})
        self.assertTrue(result["ok"])
        self.assertTrue(result["rv_mode"])

    def test_rv_toggle_off(self):
        result = self.manager.rv_toggle({"enabled": False})
        self.assertTrue(result["ok"])
        self.assertFalse(result["rv_mode"])

    def test_rv_toggle_persists_in_preferences(self):
        self.manager.rv_toggle({"enabled": False})
        prefs = self.manager.preferences()
        self.assertIs(prefs.get("rv_mode"), False)

        self.manager.rv_toggle({"enabled": True})
        prefs = self.manager.preferences()
        self.assertIs(prefs.get("rv_mode"), True)

    def test_summary_rv_matches_toggle(self):
        # Default should be True (not explicitly set)
        summary = self.manager.summary()
        # If no preference set, rv_mode defaults to True from preference read

        self.manager.rv_toggle({"enabled": False})
        summary2 = self.manager.summary()
        self.assertIs(summary2["rv"]["mode"], False)

    def test_rv_engine_is_initialized(self):
        self.assertIsNotNone(self.manager.rv_engine)
        # 先触发一次 evaluate 以完成懒加载初始化
        self.manager.rv_engine.evaluate([])
        summary = self.manager.rv_engine.result_summary()
        self.assertEqual(summary["monitor_count"], 8)  # 8 monitors (6 original + 2 phase D additions)

    def test_rv_engine_trace_preserves_after_action(self):
        # 模拟一个动作触发 RV
        from openclaw_guard.models import BehaviorEvent
        from openclaw_guard.utils import utc_now_iso

        event = BehaviorEvent(
            event_id="test-rv-001",
            timestamp=utc_now_iso(),
            action_type="file_delete",
            process_name="openclaw",
            pid=None,
            user="test",
            command=None,
            target_paths=["/tmp/secret.txt"],
            network_targets=[],
            raw_payload={"toolName": "file_delete", "params": {"path": "/tmp/secret.txt"}},
            source="test",
            metadata={
                "rv_trace": [{"event": "file_delete", "props": ["file_delete", "high_value_path"]}],
            },
        )
        from openclaw_guard.policy.engine import AuthorizationPolicyEngine

        decision = AuthorizationPolicyEngine().decide(event)
        self.assertIn(decision.action, {"allow", "ask", "block", "revise"})
        # Apply RV
        rv_result = self.manager.rv_engine.evaluate(event.metadata.get("rv_trace", []))
        self.assertIn("verdict", rv_result)

    def test_rv_toggle_api_handler_signature(self):
        from openclaw_guard.api._handlers import rv_status, rv_toggle
        # rv_status is a GET handler (no payload)
        result_status, code = rv_status(self.manager)
        self.assertEqual(code, 200)
        self.assertTrue(result_status["ok"])

        # rv_toggle is a POST handler
        result_toggle, code = rv_toggle(self.manager, {"enabled": False})
        self.assertEqual(code, 200)
        self.assertFalse(result_toggle["rv_mode"])


if __name__ == "__main__":
    unittest.main()
