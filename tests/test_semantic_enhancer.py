from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from openclaw_guard.manager import build_manager
from openclaw_guard.models import BehaviorEvent
from openclaw_guard.engine.semantic_enhancer import SemanticEnhancer
from openclaw_guard.integrations.tool_hook_bridge import build_hook_event
from openclaw_guard.policy.engine import AuthorizationPolicyEngine
from openclaw_guard.utils import utc_now_iso


class SemanticEnhancerTests(unittest.TestCase):
    def test_agentdojo_evaluation_mode_uses_local_semantics_for_mapped_read(self) -> None:
        enhancer = SemanticEnhancer(api_key="configured")
        event = build_hook_event(
            {
                "toolName": "memory_search",
                "agentdojoToolName": "search_calendar_events",
                "evaluationMode": "agentdojo",
                "params": {"query": "meeting"},
            }
        )

        with patch.object(enhancer, "_call_llm", side_effect=AssertionError("LLM must not run")):
            result = enhancer.evaluate(
                event,
                {"source_message": "benchmark read", "origin": "hook", "evaluation_mode": "agentdojo"},
            )

        self.assertEqual(event.metadata["evaluation_mode"], "agentdojo")
        self.assertEqual(result["semantic"]["scenario"], "file_read")

    def test_agentdojo_evaluation_mode_uses_local_semantics_for_mapped_external_tool(self) -> None:
        enhancer = SemanticEnhancer(api_key="configured")
        event = build_hook_event(
            {
                "toolName": "feishu.im.send",
                "agentdojoToolName": "send_email",
                "evaluationMode": "agentdojo",
                "params": {"to": "outside@example.com", "body": "report"},
            }
        )

        called = False

        def record_call(*_args, **_kwargs):
            nonlocal called
            called = True
            return None

        with patch.object(enhancer, "_call_llm", side_effect=record_call):
            result = enhancer.evaluate(
                event,
                {"source_message": "benchmark external action", "origin": "hook", "evaluation_mode": "agentdojo"},
            )

        self.assertEqual(event.metadata["evaluation_mode"], "agentdojo")
        self.assertIsInstance(result["semantic"], dict)
        self.assertFalse(called)

    def test_semantic_enhancer_outputs_rv_trace_for_report_send(self) -> None:
        event = BehaviorEvent(
            event_id="evt-1",
            timestamp=utc_now_iso(),
            action_type="network_egress",
            process_name="openclaw",
            pid=None,
            user="tester",
            raw_payload={"raw_user_intent": "把今天的日报发给 alice@example.com，不要带附件"},
            source="chat",
        )
        payload = SemanticEnhancer(api_key="").evaluate(
            event,
            {"source_message": "把今天的日报发给 alice@example.com，不要带附件", "origin": "chat"},
        )

        self.assertEqual(payload["semantic"]["scenario"], "report_send")
        self.assertEqual(payload["rv_trace"][0]["event"], "report_send")
        self.assertIn("external_recipient", payload["rv_trace"][0]["props"])
        self.assertIn("has_exclude_constraints", payload["rv_trace"][0]["props"])

    def test_manager_ingest_event_attaches_semantic_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text("{}", encoding="utf-8")
            manager = build_manager(project, config_path=config_path)

            with patch.object(manager.audit_store, "append", return_value={}):
                payload = manager.ingest_event(
                    {
                        "action_type": "network_egress",
                        "process_name": "openclaw",
                        "user": "tester",
                        "raw_user_intent": "把今天的日报发给 alice@example.com，不要带附件",
                    },
                    "把今天的日报发给 alice@example.com，不要带附件",
                    auto_execute=False,
                )

            metadata = payload["event"]["metadata"]
            self.assertEqual(metadata["semantic"]["scenario"], "report_send")
            self.assertEqual(metadata["rv_trace"][0]["event"], "report_send")
            self.assertIn("external_recipient", metadata["rv_trace"][0]["props"])
            self.assertEqual(payload["status"], "pending_approval")

    def test_pmkb_blocks_secret_egress_from_semantic_evidence(self) -> None:
        """A frozen LEGACY rule is evaluated by PMKB, not DetectionEngine."""
        event = BehaviorEvent(
            event_id="evt-2",
            timestamp=utc_now_iso(),
            action_type="network_egress",
            process_name="openclaw",
            pid=None,
            user="tester",
            raw_payload={"params": {"url": "https://example.com", "body": "token"}},
            source="chat",
            metadata={
                "semantic": {"labels": ["network_secret_payload"]},
                "rv_trace": [{"props": ["network_secret_payload"]}],
            },
        )
        decision = AuthorizationPolicyEngine().decide(event)
        self.assertEqual(decision.action, "block")
        self.assertIn("LEGACY-NET-005", decision.rule_ids)

    def test_handle_before_tool_call_attaches_semantic_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)

            with patch.object(manager.audit_store, "append", return_value={}):
                result = manager.handle_before_tool_call(
                    {
                        "toolName": "mail-send",
                        "params": {
                            "url": "https://1.2.3.4/webhook",
                            "to": "alice@example.com",
                            "body": "请发送今天的日报给 alice@example.com",
                        },
                        "runId": "run-1",
                        "toolCallId": "call-1",
                    }
                )

            self.assertEqual(result["action"], "block")
            metadata = result["action_record"]["event"]["metadata"]
            self.assertEqual(metadata["semantic"]["scenario"], "mail_send")
            self.assertEqual(metadata["rv_trace"][0]["event"], "mail_send")
            self.assertIn("external_recipient", metadata["rv_trace"][0]["props"])

    def test_create_chat_action_uses_semantic_decision_for_report_send(self) -> None:
        """report_send + external_recipient + internal_source → block。

        "不要带内部 bug 细节" 明确提及内部源内容，语义增强器检测到
        internal_source 标签。检测引擎的单步判定返回 block（三要素同时满足）。
        ReportMonitor 顶部 is_blockable_send() 检查同样会触发 block。
        """
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)

            payload = manager.create_chat_action("把今天的日报发给 alice@example.com，不要带内部 bug 细节")

            self.assertEqual(payload["decision"]["action"], "block")
            self.assertEqual(payload["event"]["metadata"]["semantic"]["scenario"], "report_send")
            self.assertIn("internal_source", payload["event"]["metadata"]["rv_trace"][0]["props"])

    def test_llm_success_path_uses_llm_engine_tag(self) -> None:
        """配置 API key 且 LLM 返回有效 JSON 时，使用 LLM 结果。"""
        enhancer = SemanticEnhancer(api_key="test-key")
        self.assertTrue(enhancer._llm_enabled)

        event = BehaviorEvent(
            event_id="evt-llm-1",
            timestamp=utc_now_iso(),
            action_type="chat_message",
            process_name="openclaw",
            pid=None,
            user="tester",
            raw_payload={"raw_user_intent": "把今天的日报发给 alice@example.com"},
            source="chat",
        )

        inner = json.dumps({
            "semantic": {
                "version": "v2",
                "engine": "llm-deepseek-chat",
                "origin": "chat",
                "scenario": "report_send",
                "intent": {"category": "report_send", "goal": "send daily report to external recipient"},
                "entities": {"paths": [], "urls": [], "recipients": ["alice@example.com"], "tool_name": None},
                "constraints": {"exclude": [], "time_range": "today", "has_exclude": False, "has_time_constraint": True, "has_scope_constraint": False, "requires_human_review": False},
                "confidence": 0.88,
                "labels": ["report_send", "chat_message", "external_recipient", "has_recipient"],
            },
            "rv_trace": [{"step_id": "s1", "event": "report_send", "props": ["report_send", "external_recipient", "has_recipient"]}],
        })
        fake_llm_response = json.dumps({
            "choices": [
                {
                    "message": {
                        "content": inner,
                    }
                }
            ]
        }).encode("utf-8")

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = fake_llm_response
            mock_urlopen.return_value = mock_response

            payload = enhancer.evaluate(event, {"source_message": "把今天的日报发给 alice@example.com", "origin": "chat"})

        self.assertEqual(payload["semantic"]["engine"], "llm-deepseek-chat")
        self.assertEqual(payload["semantic"]["scenario"], "report_send")
        self.assertEqual(payload["rv_trace"][0]["event"], "report_send")
        self.assertIn("external_recipient", payload["rv_trace"][0]["props"])
        # 阶段 A：LLM 路径应透传结构化字段
        self.assertIn("entities", payload["rv_trace"][0])
        self.assertIn("constraints", payload["rv_trace"][0])
        self.assertIn("confidence", payload["rv_trace"][0])
        self.assertEqual(payload["rv_trace"][0]["confidence"], 0.88)

    def test_llm_failure_falls_back_to_local_rules(self) -> None:
        """LLM 失败时自动降级到本地规则化实现。"""
        enhancer = SemanticEnhancer(api_key="test-key")

        event = BehaviorEvent(
            event_id="evt-llm-2",
            timestamp=utc_now_iso(),
            action_type="network_egress",
            process_name="openclaw",
            pid=None,
            user="tester",
            raw_payload={"raw_user_intent": "把今天的日报发给 alice@example.com，不要带附件"},
            source="chat",
        )

        with patch("urllib.request.urlopen", side_effect=TimeoutError("LLM timeout")):
            payload = enhancer.evaluate(event, {"source_message": "把今天的日报发给 alice@example.com，不要带附件", "origin": "chat"})

        self.assertEqual(payload["semantic"]["engine"], "builtin-fallback")
        self.assertEqual(payload["semantic"]["scenario"], "report_send")
        self.assertIn("external_recipient", payload["rv_trace"][0]["props"])
        self.assertIn("has_exclude_constraints", payload["rv_trace"][0]["props"])
        # 阶段 A：本地路径应透传结构化字段
        self.assertIn("entities", payload["rv_trace"][0])
        self.assertIn("constraints", payload["rv_trace"][0])
        self.assertIn("confidence", payload["rv_trace"][0])
        # 本地路径应提取收件人实体
        entities = payload["rv_trace"][0]["entities"]
        recipients_entity = next((e for e in entities if e["kind"] == "recipients"), None)
        self.assertIsNotNone(recipients_entity)
        self.assertIn("alice@example.com", recipients_entity["values"])


if __name__ == "__main__":
    unittest.main()
