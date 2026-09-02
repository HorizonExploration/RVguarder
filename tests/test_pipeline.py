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
    _apply_session_escalation,
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


class ApplySessionEscalationTests(unittest.TestCase):
    """_apply_session_escalation 测试（阶段 F 会话升级 + revise 干预）。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        project = Path(self.tmp.name) / "OpenclawGuard"
        project.mkdir()
        config_path = project / "openclaw.json"
        config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
        self.services = build_services(project, config_path=config_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _event(self) -> MagicMock:
        event = MagicMock()
        event.metadata = {}
        event.raw_payload = {}
        return event

    def test_repeated_escalation_emits_revise(self) -> None:
        """连续 escalate 产生修正建议，但不能降低原有 escalate 严重度。"""
        from openclaw_guard.utils import utc_now_iso

        def make_decision() -> DetectionDecision:
            return DetectionDecision(
                event_id="evt-revise",
                timestamp=utc_now_iso(),
                action_type="command_exec",
                risk_level="dangerous",
                action="escalate",
                reason="repeated escalation",
            )

        first = _apply_session_escalation(self.services, self._event(), make_decision())
        self.assertEqual(first.action, "escalate")

        second = _apply_session_escalation(self.services, self._event(), make_decision())
        self.assertEqual(second.action, "escalate")
        self.assertIsNotNone(second.revision_hint)
        self.assertIn("repeated escalation", second.revision_hint)

    def test_revision_hint_is_preserved_for_non_escalated_action(self) -> None:
        """会话建议可以把同级 ask 提升为 revise。"""
        from openclaw_guard.utils import utc_now_iso

        def make_decision(action: str) -> DetectionDecision:
            return DetectionDecision(
                event_id="evt-revise-ask",
                timestamp=utc_now_iso(),
                action_type="command_exec",
                risk_level="dangerous",
                action=action,
                reason="revision candidate",
            )

        _apply_session_escalation(self.services, self._event(), make_decision("block"))
        _apply_session_escalation(self.services, self._event(), make_decision("block"))
        result = _apply_session_escalation(self.services, self._event(), make_decision("ask"))

        self.assertEqual(result.action, "revise")
        self.assertIsNotNone(result.revision_hint)

    def test_critical_session_does_not_revise_safe_allow(self) -> None:
        """会话达到 critical 后，当前安全读取仍应保持 allow。"""
        from openclaw_guard.utils import utc_now_iso

        def make_decision(action: str, risk_level: str) -> DetectionDecision:
            return DetectionDecision(
                event_id="evt-safe-after-critical",
                timestamp=utc_now_iso(),
                action_type="file_read",
                risk_level=risk_level,
                action=action,
                reason="session regression",
            )

        for _ in range(3):
            _apply_session_escalation(
                self.services,
                self._event(),
                make_decision("block", "blocked"),
            )

        result = _apply_session_escalation(
            self.services,
            self._event(),
            make_decision("allow", "safe"),
        )

        self.assertEqual(result.action, "allow")
        self.assertIsNotNone(result.revision_hint)

    def test_block_upgrade_is_applied_before_revision_hint(self) -> None:
        """record() 返回 block 时，critical hint 不能提前返回 revise。"""
        from openclaw_guard.utils import utc_now_iso

        def make_decision() -> DetectionDecision:
            return DetectionDecision(
                event_id="evt-block-upgrade",
                timestamp=utc_now_iso(),
                action_type="command_exec",
                risk_level="dangerous",
                action="escalate",
                reason="repeated escalation",
            )

        for action in ("block", "block", "escalate", "escalate"):
            current = make_decision().model_copy(update={"action": action})
            _apply_session_escalation(self.services, self._event(), current)

        result = _apply_session_escalation(self.services, self._event(), make_decision())

        self.assertEqual(result.action, "block")
        self.assertIsNotNone(result.revision_hint)


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

    def test_before_prompt_build_always_allows(self) -> None:
        """before_prompt_build 意图预警禁止触发阻塞审批。"""
        with patch.object(self.services.audit_store, "append", return_value={}):
            result = handle_before_tool_call_pipeline(
                self.services,
                {"toolName": "before_prompt_build", "params": {}, "runId": "r1", "toolCallId": "c1", "sessionId": "s1"},
            )
        self.assertEqual(result["action"], "allow")
        self.assertNotIn("action_record", result)
        actions = self.services.action_service.list_actions(limit=100)
        self.assertFalse(
            any(item.get("event", {}).get("metadata", {}).get("tool_name") == "before_prompt_build" for item in actions)
        )

    def test_before_prompt_build_is_not_command_action(self) -> None:
        event = build_hook_event(
            {"toolName": "before_prompt_build", "params": {}, "runId": "r-pre", "toolCallId": "c-pre"}
        )
        self.assertEqual(event.action_type, "unknown")
        self.assertIn("预检查", build_hook_source_message(event))

    def test_read_tool_is_not_inferred_as_file_write(self) -> None:
        event = build_hook_event(
            {"toolName": "read", "params": {"file_path": "/tmp/test.txt"}, "runId": "r-read", "toolCallId": "c-read"}
        )
        self.assertEqual(event.action_type, "file_read")

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

    def test_default_hook_path_keeps_escalation_after_repeated_blocks(self) -> None:
        """默认 Hook 会话层不得用 revise 覆盖 block 或 escalate。"""
        from openclaw_guard.utils import utc_now_iso

        actions = iter(("block", "block", "escalate"))

        def policy_decision(event: BehaviorEvent, *, source_message: str = "") -> DetectionDecision:
            del source_message
            action = next(actions)
            return DetectionDecision(
                event_id=event.event_id,
                timestamp=utc_now_iso(),
                action_type=event.action_type,
                risk_level="blocked" if action == "block" else "dangerous",
                action=action,
                reason=f"hook fixture {action}",
            )

        payload_base = {
            "toolName": "session_fixture_tool",
            "params": {},
            "sessionId": "session-monotonic",
            "sessionKey": "agent:agent-hook-e2e:main",
            "agentId": "agent-hook-e2e",
        }
        with patch.object(self.services.policy_engine, "decide", side_effect=policy_decision):
            results = [
                handle_before_tool_call_pipeline(
                    self.services,
                    {
                        **payload_base,
                        "runId": f"run-{index}",
                        "toolCallId": f"call-{index}",
                    },
                )
                for index in range(3)
            ]

        self.assertEqual(
            [result["action_record"]["decision"]["action"] for result in results],
            ["block", "block", "block"],
        )
        self.assertEqual([result["action"] for result in results], ["block", "block", "block"])
        self.assertIsNotNone(results[2]["action_record"]["decision"]["revision_hint"])

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
