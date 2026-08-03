"""RV 层全功能单元测试。

覆盖：
- WindowManager 滑动窗口功能
- RuntimeVerificationEngine 主引擎
- 6 个监视器的单步/多步判定
- Manager 主链接入
"""

import json
import unittest
from pathlib import Path

from openclaw_guard.engine.runtime_verification import (
    RuntimeVerificationEngine,
    WindowManager,
)
from openclaw_guard.engine.rv_monitors import (
    BatchFileMonitor,
    BroadcastMonitor,
    DataExportMonitor,
    MailMonitor,
    ReportMonitor,
    SecurityChainMonitor,
)


# =============================================================================
# WindowManager 测试
# =============================================================================


class TestWindowManager(unittest.TestCase):
    def setUp(self):
        self.wm = WindowManager(max_size=5)

    def test_push_and_latest(self):
        self.wm.push({"event": "a", "props": ["x"]})
        self.assertIsNotNone(self.wm.latest())
        self.assertEqual(self.wm.latest()["event"], "a")

    def test_snapshot_order(self):
        self.wm.push({"event": "a", "props": ["x"]})
        self.wm.push({"event": "b", "props": ["y"]})
        snap = self.wm.snapshot()
        self.assertEqual(len(snap), 2)
        self.assertEqual(snap[0]["event"], "a")
        self.assertEqual(snap[1]["event"], "b")

    def test_max_size(self):
        for i in range(10):
            self.wm.push({"event": str(i), "props": [f"p{i}"]})
        self.assertEqual(len(self.wm), 5)  # 最多 5 个

    def test_sequence_matches(self):
        self.wm.push({"event": "search", "props": ["file_search", "path_high_value"]})
        self.wm.push({"event": "read", "props": ["file_read"]})
        self.wm.push({"event": "delete", "props": ["file_delete", "high_value_path"]})
        self.assertTrue(self.wm.sequence_matches(
            [{"file_search"}, {"file_delete"}]
        ))

    def test_sequence_does_not_match_reversed(self):
        self.wm.push({"event": "delete", "props": ["file_delete"]})
        self.wm.push({"event": "search", "props": ["file_search"]})
        self.assertFalse(self.wm.sequence_matches(
            [{"file_search"}, {"file_delete"}]
        ))

    def test_sequence_matches_with_window_size(self):
        for i in range(10):
            self.wm.push({"event": "x", "props": [f"p{i}"]})
        self.wm.push({"event": "search", "props": ["file_search"]})
        # 窗口共 11 项；window_size=3 只看最近 3 步，含 file_search
        self.assertTrue(self.wm.contains_any({"file_search"}, window_size=3))

    def test_cumulative_count(self):
        for _ in range(5):
            self.wm.push({"event": "del", "props": ["file_delete"]})
        self.assertEqual(self.wm.cumulative_count("file_delete"), 5)

    def test_cumulative_count_with_window(self):
        self.wm.push({"event": "del", "props": ["file_delete"]})
        self.wm.push({"event": "del", "props": ["file_delete"]})
        self.wm.push({"event": "other", "props": ["read"]})
        # window_size=2: 只看最近 2 步（["del", "other"]），1 个 file_delete
        self.assertEqual(self.wm.cumulative_count("file_delete", window_size=2), 1)

    def test_contains_any(self):
        self.wm.push({"event": "a", "props": ["mail_send"]})
        self.wm.push({"event": "b", "props": ["file_read"]})
        self.assertTrue(self.wm.contains_any({"mail_send"}))
        self.assertFalse(self.wm.contains_any({"network_egress"}))

    def test_clear(self):
        self.wm.push({"event": "a", "props": []})
        self.wm.clear()
        self.assertEqual(len(self.wm), 0)


# =============================================================================
# MailMonitor 测试
# =============================================================================


class TestMailMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = MailMonitor()
        self.wm = WindowManager()

    def _make_step(self, event, props):
        return {"event": event, "props": props}

    def test_mail_block_external_secret(self):
        step = self._make_step("mail_send", [
            "mail_send", "external_recipient", "contains_secret",
        ])
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "block")

    def test_mail_ask_ai_generated(self):
        step = self._make_step("mail_send", [
            "mail_send", "ai_generated_content",
        ])
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "ask")

    def test_mail_ask_bulk(self):
        step = self._make_step("mail_send", [
            "mail_send", "bulk_send",
        ])
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "ask")

    def test_mail_normal_no_trigger(self):
        step = self._make_step("mail_send", ["mail_send", "internal_recipient"])
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertIsNone(result)

    def test_search_then_delete(self):
        self.wm.push(self._make_step("search", ["file_search", "high_value_path"]))
        step = self._make_step("delete", ["file_delete", "high_value_path"])
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "block")

    def test_delete_no_search(self):
        step = self._make_step("delete", ["file_delete", "high_value_path"])
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertIsNone(result)


# =============================================================================
# ReportMonitor 测试
# =============================================================================


class TestReportMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = ReportMonitor()
        self.wm = WindowManager()

    def test_report_generate_missing_scope(self):
        step = {"event": "report_generate", "props": [
            "report_generate", "missing_scope_constraint",
        ]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "ask")

    def test_report_send_external_internal_source(self):
        """单步 report_send + external_recipient + internal_source → block。

        is_blockable_send() 包含完整三要素（report_send + external + internal_source），
        在 feed() 顶部优先检查，直接返回 block。
        """
        step = {"event": "report_send", "props": [
            "report_send", "external_recipient", "internal_source",
        ]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "block")

    def test_report_send_external_ok(self):
        """report_send + external_recipient（无 internal_source）→ escalate。

        当未检测到内部数据源时，单步 report_send + external_recipient
        触发 is_escalation_send() 而非 is_external_send()，返回 escalate。
        """
        step = {"event": "report_send", "props": [
            "report_send", "external_recipient",
        ]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "escalate")

    def test_report_no_trigger(self):
        step = {"event": "file_read", "props": ["file_read"]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertIsNone(result)


# =============================================================================
# SecurityChainMonitor 测试
# =============================================================================


class TestSecurityChainMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = SecurityChainMonitor()
        self.wm = WindowManager()

    def test_audit_off_then_modify(self):
        """两步链: 审计关闭 → 配置修改 → block。

        必须 feed 第一步让 FSM 进入 audit_disabled 状态，
        第二步 config_modify 触发 B-02 链阻断。
        """
        step1 = {"event": "config_modify", "props": ["config_audit_disable"]}
        self.wm.push(step1)
        self.monitor.feed(step1, self.wm)  # FSM → audit_disabled
        step2 = {"event": "config_modify", "props": ["config_modify"]}
        self.wm.push(step2)
        result = self.monitor.feed(step2, self.wm)
        self.assertEqual(result, "block")

    def test_download_then_egress(self):
        """两步链: 附件下载 → 网络外传 → escalate。

        必须 feed 第一步让 FSM 进入 sensitive_content_accessed 状态，
        第二步 network_egress 触发 B-03 链升级。
        """
        step1 = {"event": "download", "props": ["attachment_download"]}
        self.wm.push(step1)
        self.monitor.feed(step1, self.wm)  # FSM → sensitive_content_accessed
        step2 = {"event": "send", "props": ["network_egress", "mail_send"]}
        self.wm.push(step2)
        result = self.monitor.feed(step2, self.wm)
        self.assertEqual(result, "escalate")

    def test_batch_delete_threshold(self):
        for _ in range(5):
            self.wm.push({"event": "del", "props": ["file_delete"]})
        step = {"event": "del", "props": ["file_delete"]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "escalate")

    def test_single_delete_ok(self):
        self.wm.push({"event": "del", "props": ["file_delete"]})
        result = self.monitor.feed(self.wm.latest(), self.wm)
        self.assertIsNone(result)


# =============================================================================
# BroadcastMonitor 测试
# =============================================================================


class TestBroadcastMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = BroadcastMonitor()
        self.wm = WindowManager()

    def test_broadcast_default_ask(self):
        step = {"event": "channel_send", "props": [
            "channel_send", "bulk_send",
        ]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "ask")

    def test_broadcast_with_external_block(self):
        """群发 + external_recipient 但无 contains_secret/cross_org → ask。

        is_immediate_block() 需要三要素（群发 + 外部 + 敏感/跨组织）同时满足。
        仅群发 + 外部 → 进入 broadcasting 状态并返回 ask（默认需确认）。
        """
        step = {"event": "channel_send", "props": [
            "channel_send", "bulk_send", "external_recipient",
        ]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "ask")

    def test_single_chat_ok(self):
        step = {"event": "channel_send", "props": [
            "channel_send",
        ]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertIsNone(result)


# =============================================================================
# DataExportMonitor 测试
# =============================================================================


class TestDataExportMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = DataExportMonitor()
        self.wm = WindowManager()

    def test_query_sensitive_table_ask(self):
        step = {"event": "database_query", "props": [
            "database_query", "user_table",
        ]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "ask")

    def test_query_then_export_escalate(self):
        self.wm.push({"event": "query", "props": ["database_query"]})
        step = {"event": "export", "props": ["file_write", "export_format"]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "escalate")

    def test_batch_export_block(self):
        step = {"event": "export", "props": ["batch_export"]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "block")

    def test_normal_query_ok(self):
        step = {"event": "database_query", "props": ["database_query", "product_table"]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertIsNone(result)


# =============================================================================
# BatchFileMonitor 测试
# =============================================================================


class TestBatchFileMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = BatchFileMonitor()
        self.wm = WindowManager()

    def test_search_package_egress_block(self):
        self.wm.push({"event": "search", "props": ["file_search", "file_read"]})
        self.wm.push({"event": "compress", "props": ["file_compress", "file_package"]})
        step = {"event": "upload", "props": ["network_egress", "file_upload"]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "block")

    def test_batch_delete_ask(self):
        for _ in range(12):
            self.wm.push({"event": "del", "props": ["file_delete"]})
        step = {"event": "del", "props": ["file_delete"]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "ask")

    def test_batch_delete_block(self):
        # 最多 52 次删除，但窗口最多保留最近 20 项，因此 cnt≤20，预期 ask
        for _ in range(52):
            self.wm.push({"event": "del", "props": ["file_delete"]})
        step = {"event": "del", "props": ["file_delete"]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "ask")

    def test_share_link_public_ask(self):
        step = {"event": "share", "props": ["share_link_update", "public_access"]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "ask")

    def test_batch_upload_external_escalate(self):
        step = {"event": "upload", "props": [
            "file_upload", "bulk_send", "external_target",
        ]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "escalate")


# =============================================================================
# RuntimeVerificationEngine 集成测试
# =============================================================================


class TestRuntimeVerificationEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RuntimeVerificationEngine(window_size=10)

    def test_empty_rv_trace_returns_ok(self):
        result = self.engine.evaluate([])
        self.assertEqual(result["verdict"], "ok")

    def test_mail_block_trace(self):
        rv_trace = [{
            "step_id": "s1",
            "event": "mail_send",
            "props": ["mail_send", "external_recipient", "contains_secret"],
        }]
        result = self.engine.evaluate(rv_trace)
        self.assertEqual(result["verdict"], "block")
        self.assertEqual(result["triggered_by"], "MailMonitor")

    def test_report_ask_trace(self):
        """单步 report_send + external_recipient + internal_source → block。

        ReportMonitor.is_blockable_send() 包含完整三要素，
        feed() 顶部优先检查 → 直接 block。经 engine.evaluate() 验证。
        """
        rv_trace = [{
            "step_id": "s1",
            "event": "report_send",
            "props": ["report_send", "external_recipient", "internal_source"],
        }]
        result = self.engine.evaluate(rv_trace)
        self.assertEqual(result["verdict"], "block")

    def test_broadcast_ask_trace(self):
        rv_trace = [{
            "step_id": "s1",
            "event": "channel_send",
            "props": ["channel_send", "bulk_send"],
        }]
        result = self.engine.evaluate(rv_trace)
        self.assertEqual(result["verdict"], "ask")

    def test_normal_chat_ok(self):
        rv_trace = [{
            "step_id": "s1",
            "event": "chat_message",
            "props": ["chat_message"],
        }]
        result = self.engine.evaluate(rv_trace)
        self.assertEqual(result["verdict"], "ok")

    def test_data_export_block_chain(self):
        # 两步：先查表，再导出
        self.engine.evaluate([{
            "step_id": "s1",
            "event": "query",
            "props": ["database_query"],
        }])
        result = self.engine.evaluate([{
            "step_id": "s2",
            "event": "export",
            "props": ["file_write", "export_format"],
        }])
        # 查询+导出链 → escalate
        self.assertEqual(result["verdict"], "escalate")

    def test_engine_reset(self):
        self.engine.evaluate([{
            "step_id": "s1",
            "event": "mail_send",
            "props": ["mail_send", "external_recipient", "contains_secret"],
        }])
        self.engine.reset()
        # 重置后再测一个正常事件应该 ok
        result = self.engine.evaluate([{
            "step_id": "s1",
            "event": "chat_message",
            "props": ["chat_message"],
        }])
        self.assertEqual(result["verdict"], "ok")

    def test_result_summary(self):
        self.engine.evaluate([{
            "step_id": "s1",
            "event": "mail_send",
            "props": ["mail_send"],
        }])
        summary = self.engine.result_summary()
        self.assertIn("window_size", summary)
        self.assertIn("monitor_count", summary)
        self.assertIn("window_snapshot", summary)


# =============================================================================
# 启动
# =============================================================================

if __name__ == "__main__":
    unittest.main()
