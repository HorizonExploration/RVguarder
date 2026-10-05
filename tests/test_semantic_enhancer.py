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
            self.assertEqual(metadata["semantic_match"]["version"], "v3")
            self.assertEqual(metadata["semantic_audit"]["llm_status"], "disabled")
            self.assertEqual(metadata["rv_trace"][0]["event"], "tool_call")
            self.assertEqual(metadata["semantic_rv_trace"][0]["event"], "report_send")
            self.assertIn("external_recipient", metadata["rv_trace"][0]["props"])
            self.assertEqual(payload["status"], "pending_approval")

    def test_free_form_semantic_label_cannot_hard_block_incomplete_egress(self) -> None:
        """Unverified legacy labels cannot replace complete structured evidence."""
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
        self.assertEqual(decision.action, "ask")

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
            self.assertEqual(metadata["rv_trace"][0]["event"], "tool_call")
            self.assertEqual(metadata["semantic_rv_trace"][0]["event"], "mail_send")
            self.assertIn("external_recipient", metadata["rv_trace"][0]["props"])

    def test_chat_intent_does_not_create_a_tool_execution(self) -> None:
        """聊天里的发送意图不能当作已经发生或即将执行的工具调用。"""
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)

            payload = manager.create_chat_action("把今天的日报发给 alice@example.com，不要带内部 bug 细节")

            self.assertEqual(payload["decision"]["action"], "allow")
            self.assertEqual(payload["event"]["metadata"]["semantic"]["scenario"], "report_send")
            self.assertEqual(payload["event"]["metadata"]["rv_trace"], [])
            self.assertIn("internal_source", payload["event"]["metadata"]["semantic_rv_trace"][0]["props"])

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
            "version": "v3",
            "engine": "deepseek-chat",
            "operation_candidates": [{
                "family": "message.send",
                "confidence": 0.88,
                "evidence": "send intent",
            }],
            "facts": {
                "channel.external": {
                    "value": True,
                    "source": "llm",
                    "trust": "suggested",
                    "confidence": 0.84,
                    "evidence": "external destination",
                }
            },
            "entities": {"recipient_zone": "external"},
            "constraints": {},
            "uncertainties": [],
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
        self.assertEqual(payload["semantic"]["scenario"], "message.send")
        self.assertEqual(payload["rv_trace"][0]["event"], "message.send")
        self.assertIn("channel.external", payload["rv_trace"][0]["props"])
        # 阶段 A：LLM 路径应透传结构化字段
        self.assertIn("entities", payload["rv_trace"][0])
        self.assertIn("constraints", payload["rv_trace"][0])
        self.assertIn("confidence", payload["rv_trace"][0])
        self.assertEqual(payload["rv_trace"][0]["confidence"], 0.88)
        self.assertEqual(payload["semantic_match"]["facts"]["channel.external"]["trust"], "suggested")

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

    def test_llm_request_fits_hook_latency_budget(self) -> None:
        enhancer = SemanticEnhancer(api_key="test-key")
        event = BehaviorEvent(
            event_id="evt-llm-budget",
            timestamp=utc_now_iso(),
            action_type="chat_message",
            process_name="openclaw",
            pid=None,
            user="tester",
            raw_payload={"raw_user_intent": "读取项目状态"},
            source="chat",
        )
        response = MagicMock()
        response.read.return_value = json.dumps({
            "choices": [{"message": {"content": json.dumps({
                "semantic": {"scenario": "chat_message", "intent": {"goal": "读取项目状态"}},
                "rv_trace": [{"step_id": "s1", "event": "chat_message", "props": ["chat_message"]}],
            })}}]
        }).encode("utf-8")
        with patch("urllib.request.urlopen", return_value=response) as mock_urlopen:
            enhancer.evaluate(event, {"source_message": "读取项目状态", "origin": "chat"})

        request = mock_urlopen.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        assert payload["max_tokens"] == 4096
        assert mock_urlopen.call_args.kwargs["timeout"] <= 1.5


if __name__ == "__main__":
    unittest.main()
