"""
RV 层 FSM 状态转移与跨步链式检测测试。

覆盖：
- 6 个监视器的 FSM 状态转移正确性
- 链式攻击检测（状态驱动决策）
- 无链前序的单步判定（不应误报）
- Per-session 窗口隔离
- WindowManager TTL 过期
- 监视器 reset
"""

import unittest
from openclaw_guard.engine.rv_monitors import (
    BatchFileMonitor,
    BroadcastMonitor,
    DataExportMonitor,
    MailMonitor,
    ReportMonitor,
    SecurityChainMonitor,
)
from openclaw_guard.engine.runtime_verification import (
    RuntimeVerificationEngine,
    WindowManager,
)


# =============================================================================
# MailMonitor — 外部来源 → 敏感数据 → 外发攻击链
# =============================================================================


class TestMailMonitorFSM(unittest.TestCase):
    def setUp(self):
        self.wm = WindowManager(max_size=5)

    def _step(self, event, props):
        return {"event": event, "props": props}

    def test_initial_state(self):
        m = MailMonitor()
        self.assertEqual(m.current_state, "idle")

    def test_external_source_transition(self):
        m = MailMonitor()
        r = m.feed(self._step("file_read", ["attachment_open", "channel_external"]), self.wm)
        self.assertIsNone(r)
        self.assertEqual(m.current_state, "external_source_read")

    def test_external_then_sensitive_transition(self):
        m = MailMonitor()
        m.feed(self._step("file_read", ["attachment_open"]), self.wm)
        r = m.feed(self._step("file_read", ["contains_secret"]), self.wm)
        self.assertIsNone(r)
        self.assertEqual(m.current_state, "sensitive_data_extracted")

    def test_full_chain_blocks(self):
        """外部来源 → 敏感数据 → 邮件外发 = block"""
        m = MailMonitor()
        m.feed(self._step("file_read", ["attachment_open", "channel_external"]), self.wm)
        m.feed(self._step("file_read", ["contains_secret"]), self.wm)
        r = m.feed(self._step("mail_send", ["mail_send", "external_recipient"]), self.wm)
        self.assertEqual(r, "block")
        self.assertEqual(m.current_state, "blocked")

    def test_no_chain_mail_asks(self):
        """无外部来源+敏感数据链前序 = ask（不阻断）"""
        m = MailMonitor()
        r = m.feed(self._step("mail_send", ["mail_send", "external_recipient"]), self.wm)
        self.assertEqual(r, "ask")

    def test_internal_mail_no_chain(self):
        """内部收件人 + 无链前序 = 放行"""
        m = MailMonitor()
        r = m.feed(self._step("mail_send", ["mail_send", "internal_recipient"]), self.wm)
        self.assertIsNone(r)

    def test_mail_with_sensitive_in_idle_asks(self):
        """idle 状态下直接发含敏感邮件 → block（外部+敏感同在一步，FSM 状态追踪之后 Phase 2 判定）"""
        m = MailMonitor()
        r = m.feed(self._step("mail_send", ["mail_send", "contains_secret", "external_recipient"]), self.wm)
        # 同一步同时含 contains_secret + external_recipient → 经状态追踪后进入 sensitive_data_extracted → blocked
        self.assertEqual(r, "block")

    def test_sensitive_direct_transition(self):
        """直接检测到敏感数据 → 进入 sensitive_data_extracted"""
        m = MailMonitor()
        r = m.feed(self._step("file_read", ["contains_secret", "path_high_value"]), self.wm)
        self.assertIsNone(r)
        self.assertEqual(m.current_state, "sensitive_data_extracted")

    def test_escalation_bulk_send(self):
        """群发 + 外部收件人 → escalate"""
        m = MailMonitor()
        r = m.feed(self._step("mail_send", ["mail_send", "bulk_send", "external_recipient"]), self.wm)
        self.assertEqual(r, "escalate")

    def test_ai_generated_needs_approval(self):
        """AI 生成内容 + 无人审阅 → ask"""
        m = MailMonitor()
        r = m.feed(self._step("mail_send", ["mail_send", "ai_generated_content"]), self.wm)
        self.assertEqual(r, "ask")

    def test_reset_returns_idle(self):
        m = MailMonitor()
        m.feed(self._step("file_read", ["attachment_open"]), self.wm)
        m.reset()
        self.assertEqual(m.current_state, "idle")


# =============================================================================
# ReportMonitor — 内部源 → 报告生成 → 外部发送攻击链
# =============================================================================


class TestReportMonitorFSM(unittest.TestCase):
    def setUp(self):
        self.wm = WindowManager(max_size=5)

    def _step(self, event, props):
        return {"event": event, "props": props}

    def test_initial_state(self):
        rm = ReportMonitor()
        self.assertEqual(rm.current_state, "idle")

    def test_internal_source_transition(self):
        rm = ReportMonitor()
        r = rm.feed(self._step("file_read", ["internal_source"]), self.wm)
        self.assertIsNone(r)
        self.assertEqual(rm.current_state, "source_aggregating")

    def test_source_then_report_transition(self):
        rm = ReportMonitor()
        rm.feed(self._step("file_read", ["internal_source"]), self.wm)
        r = rm.feed(self._step("report_generate", ["report_generate"]), self.wm)
        self.assertIsNone(r)
        self.assertEqual(rm.current_state, "report_ready")

    def test_full_chain_blocks(self):
        """内部源 → 生成报告 → 外部发送 = block"""
        rm = ReportMonitor()
        rm.feed(self._step("file_read", ["internal_source"]), self.wm)
        rm.feed(self._step("report_generate", ["report_generate"]), self.wm)
        r = rm.feed(self._step("report_send", ["report_send", "external_recipient", "internal_source"]), self.wm)
        self.assertEqual(r, "block")
        self.assertEqual(rm.current_state, "blocked")

    def test_missing_scope_asks(self):
        rm = ReportMonitor()
        r = rm.feed(self._step("report_generate", ["report_generate", "missing_scope_constraint"]), self.wm)
        self.assertEqual(r, "ask")

    def test_no_chain_report_send(self):
        """无链前序 → external 仅 escalate"""
        rm = ReportMonitor()
        r = rm.feed(self._step("report_send", ["report_send", "external_recipient"]), self.wm)
        self.assertIn(r, ("escalate", "ask"))

    def test_valid_report_no_missing_scope(self):
        rm = ReportMonitor()
        r = rm.feed(self._step("report_generate", ["report_generate"]), self.wm)
        self.assertIsNone(r)

    def test_reset(self):
        rm = ReportMonitor()
        rm.feed(self._step("file_read", ["internal_source"]), self.wm)
        rm.reset()
        self.assertEqual(rm.current_state, "idle")


# =============================================================================
# SecurityChainMonitor — 5 条通用链式风险
# =============================================================================


class TestSecurityChainMonitorFSM(unittest.TestCase):
    def setUp(self):
        self.wm = WindowManager(max_size=10)

    def _step(self, event, props):
        return {"event": event, "props": props}

    def test_initial_state(self):
        sc = SecurityChainMonitor()
        self.assertEqual(sc.current_state, "idle")

    def test_b01_high_value_search_then_delete(self):
        sc = SecurityChainMonitor()
        sc.feed(self._step("search", ["file_search", "high_value_path"]), self.wm)
        self.assertEqual(sc.current_state, "high_value_searched")
        r = sc.feed(self._step("delete", ["file_delete", "high_value_path"]), self.wm)
        self.assertEqual(r, "block")
        self.assertEqual(sc.current_state, "blocked")

    def test_b02_audit_disable_then_modify(self):
        sc = SecurityChainMonitor()
        sc.feed(self._step("config", ["config_audit_disable"]), self.wm)
        self.assertEqual(sc.current_state, "audit_disabled")
        r = sc.feed(self._step("config", ["config_modify"]), self.wm)
        self.assertEqual(r, "block")
        self.assertEqual(sc.current_state, "blocked")

    def test_b03_sensitive_access_then_egress(self):
        sc = SecurityChainMonitor()
        sc.feed(self._step("read", ["file_read", "contains_secret"]), self.wm)
        self.assertEqual(sc.current_state, "sensitive_content_accessed")
        r = sc.feed(self._step("send", ["network_egress", "mail_send"]), self.wm)
        self.assertEqual(r, "escalate")

    def test_b04_credentials_then_ssh(self):
        sc = SecurityChainMonitor()
        sc.feed(self._step("read", ["path_sensitive_creds"]), self.wm)
        self.assertEqual(sc.current_state, "credentials_accessed")
        r = sc.feed(self._step("connect", ["network_egress", "ssh"]), self.wm)
        self.assertEqual(r, "escalate")

    def test_b05_batch_delete(self):
        sc = SecurityChainMonitor()
        for _ in range(5):
            wm_local = WindowManager(max_size=10)
            sc.feed(self._step("del", ["file_delete"]), wm_local)
        # 累积足够时触发 escalate
        wm_final = WindowManager(max_size=10)
        for _ in range(6):
            wm_final.push(self._step("del", ["file_delete"]))
        r = sc.feed(self._step("del", ["file_delete"]), wm_final)
        self.assertEqual(r, "escalate")

    def test_single_delete_no_alert(self):
        sc = SecurityChainMonitor()
        wm_local = WindowManager(max_size=10)
        r = sc.feed(self._step("del", ["file_delete"]), wm_local)
        self.assertIsNone(r)

    def test_reset(self):
        sc = SecurityChainMonitor()
        sc.feed(self._step("config", ["config_audit_disable"]), self.wm)
        sc.reset()
        self.assertEqual(sc.current_state, "idle")


# =============================================================================
# BroadcastMonitor — 单聊 → 群发 → 外部 → 阻断
# =============================================================================


class TestBroadcastMonitorFSM(unittest.TestCase):
    def setUp(self):
        self.wm = WindowManager(max_size=5)

    def _step(self, event, props):
        return {"event": event, "props": props}

    def test_initial_state(self):
        bc = BroadcastMonitor()
        self.assertEqual(bc.current_state, "idle")

    def test_single_chat_ok(self):
        bc = BroadcastMonitor()
        r = bc.feed(self._step("msg", ["channel_send"]), self.wm)
        self.assertIsNone(r)

    def test_broadcast_default_ask(self):
        bc = BroadcastMonitor()
        r = bc.feed(self._step("msg", ["channel_send", "bulk_send"]), self.wm)
        self.assertEqual(r, "ask")
        self.assertEqual(bc.current_state, "broadcasting")

    def test_broadcast_external_block(self):
        bc = BroadcastMonitor()
        bc.feed(self._step("msg", ["channel_send", "bulk_send"]), self.wm)
        r = bc.feed(self._step("msg", ["channel_send", "bulk_send", "external_recipient", "cross_org"]), self.wm)
        self.assertEqual(r, "block")
        self.assertEqual(bc.current_state, "blocked")

    def test_immediate_block(self):
        bc = BroadcastMonitor()
        r = bc.feed(self._step("msg", ["channel_send", "bulk_send", "external_recipient", "contains_secret"]), self.wm)
        self.assertEqual(r, "block")
        self.assertEqual(bc.current_state, "blocked")

    def test_reset(self):
        bc = BroadcastMonitor()
        bc.feed(self._step("msg", ["channel_send", "bulk_send"]), self.wm)
        bc.reset()
        self.assertEqual(bc.current_state, "idle")


# =============================================================================
# DataExportMonitor — 查询敏感表 → 导出 → 外传
# =============================================================================


class TestDataExportMonitorFSM(unittest.TestCase):
    def setUp(self):
        self.wm = WindowManager(max_size=10)

    def _step(self, event, props):
        return {"event": event, "props": props}

    def test_initial_state(self):
        de = DataExportMonitor()
        self.assertEqual(de.current_state, "idle")

    def test_query_sensitive_table_ask(self):
        de = DataExportMonitor()
        r = de.feed(self._step("query", ["database_query", "user_table"]), self.wm)
        self.assertEqual(r, "ask")
        self.assertEqual(de.current_state, "query_sensitive")

    def test_query_then_export_escalate(self):
        de = DataExportMonitor()
        de.feed(self._step("query", ["database_query", "user_table"]), self.wm)
        r = de.feed(self._step("export", ["file_write", "export_format"]), self.wm)
        self.assertEqual(r, "escalate")
        self.assertEqual(de.current_state, "escalated")

    def test_batch_export_block(self):
        de = DataExportMonitor()
        r = de.feed(self._step("export", ["batch_export"]), self.wm)
        self.assertEqual(r, "block")
        self.assertEqual(de.current_state, "blocked")

    def test_normal_query_ok(self):
        de = DataExportMonitor()
        r = de.feed(self._step("query", ["database_query", "product_table"]), self.wm)
        self.assertIsNone(r)

    def test_reset(self):
        de = DataExportMonitor()
        de.feed(self._step("query", ["database_query", "user_table"]), self.wm)
        de.reset()
        self.assertEqual(de.current_state, "idle")


# =============================================================================
# BatchFileMonitor — 搜索 → 打包 → 外传三步链 + 批量删除
# =============================================================================


class TestBatchFileMonitorFSM(unittest.TestCase):
    def setUp(self):
        self.wm = WindowManager(max_size=5)

    def _step(self, event, props):
        return {"event": event, "props": props}

    def test_initial_state(self):
        bf = BatchFileMonitor()
        self.assertEqual(bf.current_state, "idle")

    def test_search_transition(self):
        bf = BatchFileMonitor()
        r = bf.feed(self._step("search", ["file_search", "file_read"]), self.wm)
        self.assertIsNone(r)
        self.assertEqual(bf.current_state, "searching")

    def test_search_then_package_transition(self):
        bf = BatchFileMonitor()
        bf.feed(self._step("search", ["file_search"]), self.wm)
        r = bf.feed(self._step("compress", ["file_compress", "file_package"]), self.wm)
        self.assertIsNone(r)
        self.assertEqual(bf.current_state, "packaging")

    def test_three_step_chain_block(self):
        bf = BatchFileMonitor()
        bf.feed(self._step("search", ["file_search", "file_read"]), self.wm)
        bf.feed(self._step("compress", ["file_compress", "file_package"]), self.wm)
        r = bf.feed(self._step("upload", ["network_egress", "file_upload"]), self.wm)
        self.assertEqual(r, "block")
        self.assertEqual(bf.current_state, "blocked")

    def test_share_link_public_ask(self):
        bf = BatchFileMonitor()
        r = bf.feed(self._step("share", ["share_link_update", "public_access"]), self.wm)
        self.assertEqual(r, "ask")

    def test_share_link_password_removed_ask(self):
        bf = BatchFileMonitor()
        r = bf.feed(self._step("share", ["share_link_update", "password_removed"]), self.wm)
        self.assertEqual(r, "ask")

    def test_batch_upload_external_escalate(self):
        bf = BatchFileMonitor()
        r = bf.feed(self._step("upload", ["file_upload", "bulk_send", "external_target"]), self.wm)
        self.assertEqual(r, "escalate")

    def test_batch_delete_ask(self):
        bf = BatchFileMonitor()
        wm_local = WindowManager(max_size=20)
        for _ in range(11):
            wm_local.push(self._step("del", ["file_delete"]))
        r = bf.feed(self._step("del", ["file_delete"]), wm_local)
        self.assertEqual(r, "ask")

    def test_batch_delete_block(self):
        bf = BatchFileMonitor()
        wm_local = WindowManager(max_size=60)
        for _ in range(55):
            wm_local.push(self._step("del", ["file_delete"]))
        r = bf.feed(self._step("del", ["file_delete"]), wm_local)
        self.assertEqual(r, "block")

    def test_reset(self):
        bf = BatchFileMonitor()
        bf.feed(self._step("search", ["file_search"]), self.wm)
        bf.reset()
        self.assertEqual(bf.current_state, "idle")


# =============================================================================
# RuntimeVerificationEngine — Per-session 隔离 + 摘要
# =============================================================================


class TestRuntimeVerificationEngine(unittest.TestCase):
    def test_empty_trace_ok(self):
        eng = RuntimeVerificationEngine()
        r = eng.evaluate([])
        self.assertEqual(r["verdict"], "ok")

    def test_mail_block_trace(self):
        eng = RuntimeVerificationEngine(window_size=10)
        r = eng.evaluate([{
            "step_id": "s1", "event": "mail_send",
            "props": ["mail_send", "external_recipient", "contains_secret"],
        }])
        # RuntimeVerificationEngine 会遍历 6 个监视器——MailMonitor 应该判定 block
        self.assertIn(r["verdict"], ("block", "escalate", "ask"))
        self.assertNotEqual(r["verdict"], "ok")

    def test_session_isolation_prevents_cross_session_contamination(self):
        """session_A 的攻击链不应影响 session_B 的正常操作。"""
        eng = RuntimeVerificationEngine(window_size=10)
        eng.evaluate([{
            "step_id": "s1", "event": "file_read",
            "props": ["file_read", "contains_secret"],
        }], session_key="session_A")
        r = eng.evaluate([{
            "step_id": "s1", "event": "mail_send",
            "props": ["mail_send", "external_recipient"],
        }], session_key="session_B")
        self.assertNotEqual(r["verdict"], "block")

    def test_same_session_maintains_chain_context(self):
        """同一会话应保持攻击链上下文。"""
        eng = RuntimeVerificationEngine(window_size=10)
        eng.evaluate([{
            "step_id": "s1", "event": "file_read",
            "props": ["attachment_open", "channel_external"],
        }], session_key="session_chain")
        eng.evaluate([{
            "step_id": "s2", "event": "file_read",
            "props": ["contains_secret"],
        }], session_key="session_chain")
        r = eng.evaluate([{
            "step_id": "s3", "event": "mail_send",
            "props": ["mail_send", "external_recipient"],
        }], session_key="session_chain")
        self.assertEqual(r["verdict"], "block")

    def test_result_summary_contains_monitor_states(self):
        eng = RuntimeVerificationEngine(window_size=10)
        eng.evaluate([{"step_id": "s1", "event": "mail_send", "props": ["mail_send"]}])
        summary = eng.result_summary()
        self.assertIn("monitor_states", summary)
        for name in ["MailMonitor", "ReportMonitor", "SecurityChainMonitor",
                     "BroadcastMonitor", "DataExportMonitor", "BatchFileMonitor"]:
            self.assertIn(name, summary["monitor_states"])

    def test_engine_release_session(self):
        eng = RuntimeVerificationEngine(window_size=10)
        eng.evaluate([{"step_id": "s1", "event": "mail_send", "props": ["mail_send"]}],
                     session_key="temp_sess")
        eng.release_session("temp_sess")
        self.assertEqual(eng.session_count(), 0)

    def test_engine_reset(self):
        eng = RuntimeVerificationEngine(window_size=10)
        eng.evaluate([{"step_id": "s1", "event": "mail_send", "props": ["mail_send", "external_recipient", "contains_secret"]}])
        eng.reset()
        r = eng.evaluate([{"step_id": "s1", "event": "chat_message", "props": ["chat_message"]}])
        self.assertEqual(r["verdict"], "ok")


# =============================================================================
# WindowManager — TTL 过期
# =============================================================================


class TestWindowManager(unittest.TestCase):
    def test_ttl_expires_old_entries(self):
        wm = WindowManager(max_size=10, ttl_seconds=0.01)
        wm.push({"event": "old", "props": ["old"]})
        import time
        time.sleep(0.05)
        wm.push({"event": "new", "props": ["new"]})
        for step in wm.snapshot():
            self.assertNotEqual(step["event"], "old")

    def test_no_ttl_keeps_all(self):
        wm = WindowManager(max_size=10)
        wm.push({"event": "old", "props": ["old"]})
        wm.push({"event": "new", "props": ["new"]})
        self.assertEqual(len(wm), 2)

    def test_serialization_roundtrip(self):
        wm = WindowManager(max_size=10)
        wm.push({"event": "read", "props": ["file_read"]})
        wm.push({"event": "delete", "props": ["file_delete"]})
        data = wm.to_dict()
        restored = WindowManager.from_dict(data)
        self.assertEqual(len(restored), 2)
        self.assertEqual(restored.latest()["event"], "delete")

    def test_steps_with_label(self):
        wm = WindowManager(max_size=10)
        wm.push({"event": "a", "props": ["file_read"]})
        wm.push({"event": "b", "props": ["file_write"]})
        wm.push({"event": "c", "props": ["file_read", "contains_secret"]})
        matches = wm.steps_with_label("file_read")
        self.assertEqual(len(matches), 2)


if __name__ == "__main__":
    unittest.main()
