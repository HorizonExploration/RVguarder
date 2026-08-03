"""GuardServices 容器与 build_services 工厂的单元测试。

覆盖：
- build_services() 工厂（急热懒冷组件）
- GuardServices.__init__ 中的 runtime_hook 急切执行
- rv_status / rv_toggle / cleanup_rv_session
- _classify_runtime_failure / _dedupe_messages / _auto_complete_previous_actions
- export_audit / recent_logs
- skills / channels CRUD
- doctor / refresh_runtime_target
- GuardServices 基础容器（非 OpenclawGuardManager 子类）上的适配器解析
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from openclaw_guard.models import ControlledAction
from openclaw_guard.services import GuardServices, build_services
from openclaw_guard.integrations.openclaw_adapter import OpenClawRelayError


class BuildServicesTests(unittest.TestCase):
    """build_services 工厂测试。"""

    def test_build_services_returns_guard_services(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            services = build_services(project, config_path=config_path)
            self.assertIsInstance(services, GuardServices)

    def test_build_services_eager_hot_path_components(self) -> None:
        """热路径组件在构建时已初始化（非 LazyProxy）。"""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            services = build_services(project, config_path=config_path)

            from openclaw_guard.engine.behavior import BehaviorCollectorManager
            from openclaw_guard.engine.detection import DetectionEngine
            from openclaw_guard.engine.control import GuardController
            from openclaw_guard.engine.whitelist import WhitelistEngine
            from openclaw_guard.storage.audit_store import AuditStore
            from openclaw_guard.core.action_service import ActionService

            self.assertIsInstance(services.collectors, BehaviorCollectorManager)
            self.assertIsInstance(services.detector, DetectionEngine)
            self.assertIsInstance(services.controller, GuardController)
            self.assertIsInstance(services.whitelist, WhitelistEngine)
            self.assertIsInstance(services.audit_store, AuditStore)
            self.assertIsInstance(services.action_service, ActionService)

    def test_build_services_eagerly_materializes_runtime_hook(self) -> None:
        """runtime_hook 在构建时急切执行 —— 插件文件写入磁盘。"""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            services = build_services(project, config_path=config_path)

            # runtime_hook 已执行 — installed/plugin_valid 应为 True
            self.assertTrue(services.runtime_hook["installed"])
            self.assertTrue(services.runtime_hook["plugin_valid"])

    def test_build_services_paths_are_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            services = build_services(project, config_path=config_path)

            self.assertTrue(services.actions_path.name.endswith("controlled-actions.json"))
            self.assertTrue(services.log_path.name.endswith("guard.log"))
            self.assertTrue(services.preferences_path.name.endswith("preferences.json"))
            self.assertIsNotNone(services.conversation_path)


class GuardServicesRvTests(unittest.TestCase):
    """rv_status / rv_toggle / cleanup_rv_session 测试。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        project = Path(self.tmp.name) / "OpenclawGuard"
        project.mkdir()
        config_path = project / "openclaw.json"
        config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
        self.services = build_services(project, config_path=config_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_rv_status_returns_dict(self) -> None:
        result = self.services.rv_status()
        self.assertTrue(result["ok"])
        self.assertIn("mode", result)
        self.assertIn("engine", result)
        self.assertIn("session_count", result)

    def test_rv_toggle_updates_preferences(self) -> None:
        result = self.services.rv_toggle({"enabled": False})
        self.assertFalse(result["rv_mode"])
        prefs = self.services.preferences()
        self.assertFalse(prefs["rv_mode"])

        result = self.services.rv_toggle({"enabled": True})
        self.assertTrue(result["rv_mode"])

    def test_cleanup_rv_session(self) -> None:
        result = self.services.cleanup_rv_session("test_session")
        self.assertTrue(result["ok"])
        self.assertEqual(result["session_key"], "test_session")


class GuardServicesClassifyTests(unittest.TestCase):
    """_classify_runtime_failure 测试。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        project = Path(self.tmp.name) / "OpenclawGuard"
        project.mkdir()
        config_path = project / "openclaw.json"
        config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
        self.services = build_services(project, config_path=config_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_rate_limit_classification(self) -> None:
        code, msg = self.services._classify_runtime_failure("429 Too Many Requests")
        self.assertEqual(code, "provider_rate_limited")

        code, msg = self.services._classify_runtime_failure("余额不足，请充值")
        self.assertEqual(code, "provider_rate_limited")

    def test_auth_failure_classification(self) -> None:
        code, msg = self.services._classify_runtime_failure("authentication failed")
        self.assertEqual(code, "provider_auth_failed")

        code, msg = self.services._classify_runtime_failure("invalid api key")
        self.assertEqual(code, "provider_auth_failed")

    def test_generic_failure_classification(self) -> None:
        code, msg = self.services._classify_runtime_failure("something went wrong")
        self.assertEqual(code, "runtime_execution_failed")


class GuardServicesDedupeTests(unittest.TestCase):
    """_dedupe_messages 测试。"""

    def test_dedupe_removes_duplicates(self) -> None:
        msgs = [
            {"role": "user", "content": "hello", "timestamp": "t1"},
            {"role": "user", "content": "hello", "timestamp": "t1"},
            {"role": "assistant", "content": "hi", "timestamp": "t2"},
        ]
        result = GuardServices._dedupe_messages(msgs)
        self.assertEqual(len(result), 2)

    def test_dedupe_keeps_different_content(self) -> None:
        msgs = [
            {"role": "user", "content": "a", "timestamp": "t1"},
            {"role": "user", "content": "b", "timestamp": "t1"},
        ]
        result = GuardServices._dedupe_messages(msgs)
        self.assertEqual(len(result), 2)


class GuardServicesSkillsChannelsTests(unittest.TestCase):
    """skills / channels CRUD 测试。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        project = Path(self.tmp.name) / "OpenclawGuard"
        project.mkdir()
        config_path = project / "openclaw.json"
        config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
        self.services = build_services(project, config_path=config_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_upsert_and_delete_skill(self) -> None:
        result = self.services.upsert_skill("test-skill", {"enabled": True, "description": "A test skill"})
        self.assertTrue(result["ok"])
        self.assertIn("items", result["skills"])

        result = self.services.delete_skill("test-skill")
        self.assertTrue(result["ok"])

    def test_upsert_skill_empty_name_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.services.upsert_skill("  ", {})

    def test_upsert_and_delete_channel(self) -> None:
        result = self.services.upsert_channel("test-channel", {"enabled": True, "target": "https://example.com"})
        self.assertTrue(result["ok"])
        self.assertIn("items", result["channels"])

        result = self.services.delete_channel("test-channel")
        self.assertTrue(result["ok"])

    def test_upsert_channel_empty_name_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.services.upsert_channel("  ", {})


class GuardServicesDoctorTests(unittest.TestCase):
    """doctor() 诊断测试。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        project = Path(self.tmp.name) / "OpenclawGuard"
        project.mkdir()
        config_path = project / "openclaw.json"
        config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
        self.services = build_services(project, config_path=config_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_doctor_returns_sections(self) -> None:
        result = self.services.doctor()
        self.assertIn("paths", result)
        self.assertIn("target", result)
        self.assertIn("runtime_hook", result)
        self.assertIn("summary", result)

    def test_doctor_paths_exist(self) -> None:
        result = self.services.doctor()
        self.assertTrue(result["paths"]["runtime_dir_exists"])
        self.assertTrue(result["paths"]["audit_dir_exists"])


class GuardServicesExportAuditTests(unittest.TestCase):
    """export_audit 测试。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        project = Path(self.tmp.name) / "OpenclawGuard"
        project.mkdir()
        config_path = project / "openclaw.json"
        config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
        self.services = build_services(project, config_path=config_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_export_audit_returns_files(self) -> None:
        result = self.services.export_audit()
        self.assertIsInstance(result, dict)
        # 应该至少包含一个导出文件路径
        self.assertTrue(len(result) > 0)


class GuardServicesAdapterResolutionTests(unittest.TestCase):
    """验证 GuardServices 基类正确解析适配器函数。

    与 OpenclawGuardManager 子类（解析自 openclaw_guard.manager）不同，
    基类从 openclaw_guard.services 命名空间解析适配器。
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        project = Path(self.tmp.name) / "OpenclawGuard"
        project.mkdir()
        config_path = project / "openclaw.json"
        config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
        self.services = build_services(project, config_path=config_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_chat_status_uses_services_adapter(self) -> None:
        with patch("openclaw_guard.services.get_chat_status") as mock_get:
            mock_get.return_value = MagicMock(connected=False, available_models=[])
            status = self.services.chat_status()
            mock_get.assert_called_once()
            self.assertFalse(status.connected)

    def test_new_chat_uses_services_adapter(self) -> None:
        with patch("openclaw_guard.services.reset_chat_session") as mock_reset:
            mock_reset.return_value = {"ok": True}
            result = self.services.new_chat()
            mock_reset.assert_called_once()
            self.assertTrue(result["ok"])
            self.assertIn("messages", result)

    def test_chat_history_uses_services_adapter(self) -> None:
        with patch("openclaw_guard.services.get_chat_history") as mock_hist:
            mock_hist.return_value = []
            result = self.services.chat_history()
            mock_hist.assert_called_once()
            self.assertEqual(result, [])

    def test_hook_status_uses_services_adapter(self) -> None:
        with patch("openclaw_guard.services.inspect_guard_plugin") as mock_inspect, patch(
            "openclaw_guard.services.get_guard_hook_status"
        ) as mock_hook:
            mock_inspect.return_value = {"ok": True, "found": False, "status": "not_installed"}
            mock_hook.side_effect = OpenClawRelayError("gateway_unreachable", "test")
            status = self.services.hook_status()
            mock_inspect.assert_called_once()
            self.assertIsInstance(status, dict)


if __name__ == "__main__":
    unittest.main()
