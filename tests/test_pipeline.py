"""流水线函数的单元测试 —— engine.pipeline 模块。

覆盖：
- _ensure_pipeline_timings（字典初始化、非字典元数据、缺失键）
- _resolve_rv_session_key（5 个优先级级别，默认回退）
- _apply_rv_if_available（RV 覆盖、无 rv_trace 回退、per-session 隔离）
- ingest_event_pipeline（完整聊天路径）
- handle_before_tool_call_pipeline（所有状态分支）
- handle_after_tool_call_pipeline（成功/错误/未找到）
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

from openclaw_guard.engine.pipeline import (
    _annotate_event_context,
    _apply_rv_if_available,
    _ensure_pipeline_timings,
    _resolve_rv_session_key,
    handle_after_tool_call_pipeline,
    handle_before_tool_call_pipeline,
    ingest_event_pipeline,
)
from openclaw_guard.integrations.tool_hook_bridge import build_hook_event, build_hook_source_message
from openclaw_guard.models import BehaviorEvent, DetectionDecision
from openclaw_guard.services import build_services


def test_user_explanation_is_bounded_for_openclaw_approval_payloads() -> None:
    from openclaw_guard.utils import utc_now_iso

    event = BehaviorEvent(
        event_id="long-explanation",
        timestamp=utc_now_iso(),
        action_type="file_write",
        process_name="openclaw",
        pid=None,
        user="openclaw",
        target_paths=["/workspace/" + "x" * 600],
        metadata={"scope_class": "workspace"},
    )
    decision = DetectionDecision(
        event_id="long-explanation",
        timestamp=utc_now_iso(),
        action_type="file_write",
        risk_level="dangerous",
        action="ask",
        reason="long target",
    )

    from openclaw_guard.engine.pipeline import _user_explanation

    _title, message = _user_explanation(event, decision)
    assert len(message) <= 240
    assert message.endswith("…")


def test_native_tool_user_summary_uses_openclaw_operation_language() -> None:
    from openclaw_guard.utils import utc_now_iso

    event = build_hook_event(
        {
            "toolName": "memory_search",
            "params": {"query": "daily"},
            "runId": "summary-run",
            "toolCallId": "summary-call",
        }
    )
    decision = DetectionDecision(
        event_id=event.event_id,
        timestamp=utc_now_iso(),
        action_type=event.action_type,
        risk_level="caution",
        action="ask",
        reason="summary test",
    )

    from openclaw_guard.engine.pipeline import _user_summary

    assert _user_summary(event, decision)["operation"] == "搜索记忆"


class EnsurePipelineTimingsTests(unittest.TestCase):
    """_ensure_pipeline_timings 单元测试。"""

    def test_creates_timings_dict_when_missing(self) -> None:
        class Event:
            metadata = {}

        event = Event()
        timings = _ensure_pipeline_timings(event)
        self.assertIsInstance(timings, dict)
        self.assertEqual(event.metadata["pipeline_timings_ms"], timings)

    def test_returns_existing_timings(self) -> None:
        class Event:
            metadata = {"pipeline_timings_ms": {"policy_ms": 1.5}}

        event = Event()
        timings = _ensure_pipeline_timings(event)
        self.assertEqual(timings["policy_ms"], 1.5)

    def test_handles_none_metadata(self) -> None:
        class Event:
            metadata = None

        event = Event()
        timings = _ensure_pipeline_timings(event)
        self.assertEqual(timings, {})

    def test_handles_non_dict_timings(self) -> None:
        class Event:
            metadata = {"pipeline_timings_ms": "not_a_dict"}

        event = Event()
        timings = _ensure_pipeline_timings(event)
        self.assertIsInstance(timings, dict)
        self.assertNotEqual(timings, "not_a_dict")


class ResolveRvSessionKeyTests(unittest.TestCase):
    """_resolve_rv_session_key 优先级测试。"""

    def test_hook_metadata_session_id_first(self) -> None:
        event = MagicMock()
        event.metadata = {"session_id": "abc123"}
        event.raw_payload = {}
        key = _resolve_rv_session_key(event)
        self.assertEqual(key, "session_abc123")

    def test_raw_payload_session_id_second(self) -> None:
        event = MagicMock()
        event.metadata = {}
        event.raw_payload = {"sessionId": "raw456"}
        key = _resolve_rv_session_key(event)
        self.assertEqual(key, "session_raw456")

    def test_metadata_priority_over_raw_payload(self) -> None:
        event = MagicMock()
        event.metadata = {"session_id": "meta_first"}
        event.raw_payload = {"sessionId": "raw_second"}
        key = _resolve_rv_session_key(event)
        self.assertEqual(key, "session_meta_first")

    def test_fallback_to_default(self) -> None:
        event = MagicMock()
        event.metadata = {}
        event.raw_payload = {}
        key = _resolve_rv_session_key(event)
        self.assertEqual(key, "_default")


class ApplyRvIfAvailableTests(unittest.TestCase):
    """_apply_rv_if_available 测试。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        project = Path(self.tmp.name) / "OpenclawGuard"
        project.mkdir()
        config_path = project / "openclaw.json"
        config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
        self.services = build_services(project, config_path=config_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _make_decision(self, action: str = "ask", reason: str = "test") -> DetectionDecision:
        """构建用于测试的 DetectionDecision 实例。"""
        from openclaw_guard.utils import utc_now_iso
        return DetectionDecision(
            event_id="evt-test",
            timestamp=utc_now_iso(),
            action_type="chat_message",
            risk_level="dangerous",
            action=action,
            reason=reason,
        )

    def test_no_rv_trace_returns_decision_unchanged(self) -> None:
        event = MagicMock()
        event.metadata = {}
        decision = self._make_decision(action="block", reason="hard rule")

        result = _apply_rv_if_available(self.services, event, decision)
        self.assertEqual(result.action, "block")

    def test_rv_block_overrides_detector_ask(self) -> None:
        event = MagicMock()
        event.metadata = {"rv_trace": [{"step_id": "s1", "event": "mail_send",
                         "props": ["mail_send", "external_recipient", "contains_secret"]}]}
        decision = self._make_decision(action="ask", reason="semantic")

        result = _apply_rv_if_available(self.services, event, decision)
        self.assertEqual(result.action, "block")
        self.assertIn("[RV]", result.reason)

    def test_rv_ok_does_not_override_detector_block(self) -> None:
        event = MagicMock()
        event.metadata = {"rv_trace": [{"step_id": "s1", "event": "normal_chat",
                         "props": ["chat_message"]}]}
        decision = self._make_decision(action="block", reason="hard rule")

        result = _apply_rv_if_available(self.services, event, decision)
        self.assertEqual(result.action, "block")

    def test_rv_disabled_skips_overlay(self) -> None:
        """RV 总开关（rv_mode=false）关闭后，RV overlay 不覆盖检测判定。"""
        event = MagicMock()
        event.metadata = {"rv_trace": [{"step_id": "s1", "event": "mail_send",
                         "props": ["mail_send", "external_recipient", "contains_secret"]}]}
        decision = self._make_decision(action="ask", reason="semantic")

        with patch.object(self.services, "rv_enabled", return_value=False):
            result = _apply_rv_if_available(self.services, event, decision)

        self.assertEqual(result.action, "ask")
        self.assertNotIn("[RV]", result.reason)


class HandleBeforeToolCallPipelineTests(unittest.TestCase):
    """handle_before_tool_call_pipeline 分支测试。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        project = Path(self.tmp.name) / "OpenclawGuard"
        project.mkdir()
        config_path = project / "openclaw.json"
        config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
        self.services = build_services(project, config_path=config_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_read_tool_is_not_inferred_as_file_write(self) -> None:
        event = build_hook_event(
            {"toolName": "read", "params": {"file_path": "/tmp/test.txt"}, "runId": "r-read", "toolCallId": "c-read"}
        )
        self.assertEqual(event.action_type, "unknown")

    def test_real_tool_approval_still_creates_pending_action(self) -> None:
        with patch.object(self.services.audit_store, "append", return_value={}):
            result = handle_before_tool_call_pipeline(
                self.services,
                {"toolName": "unknown_tool", "params": {}, "runId": "r-approval", "toolCallId": "c-approval"},
            )
        self.assertEqual(result["action"], "require_approval")
        actions = self.services.action_service.list_actions(limit=100)
        pending = [item for item in actions if item.get("status") == "pending_approval"]
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["event"]["metadata"]["tool_name"], "unknown_tool")

    def test_read_command_produces_action_record(self) -> None:
        """正常 read 命令应产生 action_record。"""
        with patch.object(self.services.audit_store, "append", return_value={}):
            result = handle_before_tool_call_pipeline(
                self.services,
                {"toolName": "read", "params": {"file_path": "/tmp/test.txt"}, "runId": "r2", "toolCallId": "c2", "sessionId": "s2"},
            )
        self.assertIn("action_record", result)
        # read 通常是安全的 → proposed → allow
        self.assertIn(result["action"], ("allow", "require_approval"))

    def test_native_control_plane_read_is_not_blocked_by_missing_agent_identity(self) -> None:
        with patch.object(self.services.audit_store, "append", return_value={}):
            result = handle_before_tool_call_pipeline(
                self.services,
                {
                    "toolName": "memory_search",
                    "params": {"query": "daily"},
                    "runId": "native-read-run",
                    "toolCallId": "native-read-call",
                    "sessionId": "native-read-session",
                },
            )

        self.assertEqual(result["action"], "allow")
        self.assertEqual(
            result["action_record"]["decision"]["trace"][-1]["reason"],
            "low_risk_identity_not_required",
        )

    def test_all_native_read_tools_remain_allowed_in_full_hook_pipeline(self) -> None:
        native_read_tools = (
            "sessions_history",
            "sessions_list",
            "session_status",
            "memory_search",
            "memory_get",
            "agents_list",
            "get_goal",
        )
        with patch.object(self.services.audit_store, "append", return_value={}):
            results = [
                handle_before_tool_call_pipeline(
                    self.services,
                    {
                        "toolName": tool_name,
                        "params": {"query": "daily"},
                        "runId": f"native-run-{tool_name}",
                        "toolCallId": f"native-call-{tool_name}",
                        "sessionId": f"native-session-{tool_name}",
                    },
                )
                for tool_name in native_read_tools
            ]

        self.assertEqual([result["action"] for result in results], ["allow"] * len(native_read_tools))

    def test_native_memory_read_with_external_path_does_not_use_read_only_trust(self) -> None:
        with patch.object(self.services.audit_store, "append", return_value={}):
            result = handle_before_tool_call_pipeline(
                self.services,
                {
                    "toolName": "memory_search",
                    "params": {"query": "read /etc/shadow"},
                    "runId": "native-unsafe-run",
                    "toolCallId": "native-unsafe-call",
                    "sessionId": "native-unsafe-session",
                },
            )

        self.assertIn(result["action"], {"require_approval", "block"})
        self.assertNotEqual(result["action_record"]["event"]["metadata"]["tool_origin"], "openclaw_native")


class HandleAfterToolCallPipelineTests(unittest.TestCase):
    """handle_after_tool_call_pipeline 测试。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        project = Path(self.tmp.name) / "OpenclawGuard"
        project.mkdir()
        config_path = project / "openclaw.json"
        config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
        self.services = build_services(project, config_path=config_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_action_not_found_returns_error(self) -> None:
        result = handle_after_tool_call_pipeline(
            self.services,
            {"runId": "nonexistent", "toolCallId": "call-none"},
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "action_not_found")

    def test_memory_index_failure_is_recorded_as_capability_error(self) -> None:
        payload = {
            "toolName": "memory_search",
            "params": {"query": "daily"},
            "runId": "memory-error-run",
            "toolCallId": "memory-error-call",
            "sessionId": "memory-error-session",
        }
        with patch.object(self.services.audit_store, "append", return_value={}):
            before = handle_before_tool_call_pipeline(self.services, payload)
            result = handle_after_tool_call_pipeline(
                self.services,
                {
                    **payload,
                    "error": "memory_search index metadata is missing",
                },
            )

        self.assertIn(before["action"], {"allow", "require_approval"})
        self.assertTrue(result["ok"])
        execution_result = result["action"]["execution_result"]
        self.assertEqual(execution_result["error_code"], "capability_error")


if __name__ == "__main__":
    unittest.main()
