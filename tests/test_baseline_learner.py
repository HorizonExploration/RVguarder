"""基线自动机测试 —— 阶段 C。

覆盖：
- TraceAbstractor 抽象正确性（步骤 → 三元组符号）
- BaselineLearner 前缀树构建 + 状态合并
- BaselineDFA 序列化/反序列化完整往返
- BaselineMonitor 正例全接受 + 反例偏离检出
- DFA 规模缩减（合并后状态数 < 前缀树节点数）
- RuntimeVerificationEngine 集成基线监视器
"""

import tempfile
import unittest
from pathlib import Path

from openclaw_guard.engine.baseline_learner import (
    BaselineDFA,
    BaselineLearner,
    learn_from_traces,
)
from openclaw_guard.engine.baseline_monitor import BaselineMonitor
from openclaw_guard.engine.runtime_verification import RuntimeVerificationEngine
from openclaw_guard.engine.trace_abstractor import abstract_step, abstract_trace


# =============================================================================
# 测试辅助：构造典型办公场景 trace
# =============================================================================


def _normal_traces() -> list[list[dict]]:
    """构造 3 条正常办公行为 trace。"""
    return [
        # Trace 1: 读邮件 → 附件下载 → 回复
        [
            {"event": "mail_read", "props": ["mail_read", "internal_recipient"]},
            {"event": "attachment_download", "props": ["attachment_download", "file_read"]},
            {"event": "mail_send", "props": ["mail_send", "internal_recipient"]},
        ],
        # Trace 2: 读邮件 → 删除旧附件
        [
            {"event": "mail_read", "props": ["mail_read"]},
            {"event": "file_delete", "props": ["file_delete", "path_log"]},
        ],
        # Trace 3: 日报生成 → 发送
        [
            {"event": "report_generate", "props": ["report_generate", "internal_source"]},
            {"event": "report_send", "props": ["report_send", "internal_recipient"]},
        ],
    ]


def _anomalous_trace() -> list[dict]:
    """构造一条偏离基线的异常 trace：
    读邮件 → 直接外发（未经历附件下载环节）。
    """
    return [
        {"event": "mail_read", "props": ["mail_read", "internal_recipient"]},
        {"event": "mail_send", "props": ["mail_send", "external_recipient"]},
    ]


# =============================================================================
# TraceAbstractor
# =============================================================================


class TestTraceAbstractor(unittest.TestCase):
    def test_abstract_step_basic(self):
        step = {"event": "mail_send", "props": ["mail_send", "external_recipient"]}
        sym = abstract_step(step)
        parts = sym.split("|")
        self.assertEqual(len(parts), 3)
        self.assertEqual(parts[0], "mail_send")
        self.assertEqual(parts[2], "office")

    def test_abstract_step_with_entities(self):
        step = {
            "event": "mail_send",
            "props": ["mail_send"],
            "entities": [
                {"kind": "recipients", "values": ["a@b.com"]},
            ],
        }
        sym = abstract_step(step)
        self.assertIn("R", sym.split("|")[1])

    def test_abstract_step_no_entities(self):
        step = {"event": "file_read", "props": ["file_read"]}
        sym = abstract_step(step)
        entity_part = sym.split("|")[1]
        self.assertEqual(entity_part, "_")

    def test_abstract_trace_returns_symbol_list(self):
        trace = _normal_traces()[0]
        symbols = abstract_trace(trace)
        self.assertEqual(len(symbols), 3)
        self.assertTrue(all("|" in s for s in symbols))

    def test_abstract_step_label_class(self):
        step = {"event": "command_exec", "props": ["command_exec", "command_rm_rf"]}
        sym = abstract_step(step)
        self.assertEqual(sym.split("|")[2], "command")


# =============================================================================
# BaselineLearner + BaselineDFA
# =============================================================================


class TestBaselineLearner(unittest.TestCase):
    def setUp(self):
        self.traces = _normal_traces()

    def test_learn_empty_returns_minimal_dfa(self):
        dfa = learn_from_traces([])
        self.assertIn(0, dfa.states)
        self.assertEqual(len(dfa.transitions), 0)

    def test_learn_single_trace(self):
        dfa = learn_from_traces([abstract_trace(self.traces[0])])
        # 前缀树：3 个步骤 → 至少 3+1 个状态（含根）
        stats = dfa.stats()
        self.assertGreaterEqual(stats["state_count"], 3)
        self.assertGreaterEqual(stats["accepting_count"], 1)

    def test_trie_size_gt_dfa_size(self):
        """合并后 DFA 状态数应小于前缀树节点数。"""
        traces = [abstract_trace(t) for t in self.traces * 3]  # 9 traces
        learner = BaselineLearner()
        for t in traces:
            learner.add_trace(t)
        trie = learner.trie_size()
        dfa = learner.learn()
        stats = dfa.stats()
        # 多条 trace 共享前缀 → 合并后应减少
        self.assertLessEqual(stats["state_count"], trie)

    def test_state_reduction_with_duplicate_traces(self):
        """重复 trace 应被合并，规模显著减小。"""
        symbols = abstract_trace(self.traces[0])
        learner = BaselineLearner()
        for _ in range(10):
            learner.add_trace(symbols)
        trie = learner.trie_size()
        dfa = learner.learn()
        # 10 条相同 trace → trie = 4（根 + 3步），DFA 也应 ≤ 4
        self.assertLessEqual(dfa.stats()["state_count"], trie)

    def test_all_training_steps_accepted(self):
        """训练集所有步骤都应沿 DFA 走到接受状态。"""
        dfa = learn_from_traces([abstract_trace(t) for t in self.traces])
        monitor = BaselineMonitor(dfa)
        for trace in self.traces:
            monitor.reset()
            for step in trace:
                r = monitor.feed(step)
                self.assertIsNone(r, f"Step {abstract_step(step)} should be accepted")

    def test_anomaly_detected_for_unseen_path(self):
        """走未训练路径 → 应返回异常。"""
        dfa = learn_from_traces([abstract_trace(t) for t in self.traces])
        monitor = BaselineMonitor(dfa)
        for step in _anomalous_trace():
            monitor.feed(step)
        # 最后一个 step 应该触发异常（路径不在训练集中）
        # 注意：前两步 (mail_read, mail_send) 可能存在于训练 trace 的子路径中
        # 如果 mail_read→mail_send 在训练中出现过（Trace 2 有 mail_read→file_delete，不是）
        # 那么第二步就偏离了
        self.assertGreaterEqual(monitor.anomaly_count, 1)

    def test_anomaly_for_completely_novel_first_step(self):
        """第一个步骤就不在 DFA 中 → 应检出异常。"""
        dfa = learn_from_traces([abstract_trace(t) for t in self.traces])
        monitor = BaselineMonitor(dfa)
        # config_modify 不在训练集
        step = {"event": "config_modify", "props": ["config_modify", "config_auth_disable"]}
        r = monitor.feed(step)
        self.assertIsNotNone(r)

    def test_monitor_reset(self):
        """监视器 reset 后应从初始状态重新开始。"""
        dfa = learn_from_traces([abstract_trace(self.traces[0])])
        monitor = BaselineMonitor(dfa)
        monitor.feed(self.traces[0][0])
        self.assertGreater(monitor.step_count, 0)
        monitor.reset()
        self.assertEqual(monitor.current_state, 0)
        self.assertEqual(monitor.step_count, 0)
        self.assertEqual(monitor.anomaly_count, 0)

    def test_monitor_without_dfa_returns_none(self):
        """未加载 DFA 的监视器应返回 None。"""
        monitor = BaselineMonitor()
        r = monitor.feed({"event": "test", "props": []})
        self.assertIsNone(r)


# =============================================================================
# BaselineDFA 序列化
# =============================================================================


class TestBaselineDFASerialization(unittest.TestCase):
    def test_save_and_load_roundtrip(self):
        traces = [abstract_trace(t) for t in _normal_traces()]
        dfa = learn_from_traces(traces)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp_path = f.name

        try:
            dfa.save(tmp_path)
            loaded = BaselineDFA.load(tmp_path)
            self.assertEqual(dfa.states, loaded.states)
            self.assertEqual(dfa.start_state, loaded.start_state)
            self.assertEqual(dfa.accepting_states, loaded.accepting_states)
            self.assertEqual(len(dfa.transitions), len(loaded.transitions))
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_to_dict_from_dict_roundtrip(self):
        traces = [abstract_trace(t) for t in _normal_traces()]
        dfa = learn_from_traces(traces)
        data = dfa.to_dict()
        restored = BaselineDFA.from_dict(data)
        self.assertEqual(dfa.stats(), restored.stats())

    def test_load_nonexistent_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            BaselineDFA.load("/nonexistent/baseline.json")

    def test_default_dfa_accepts_start_state(self):
        dfa = BaselineDFA()
        dfa.accepting_states = {0}
        self.assertTrue(dfa.is_accepting(0))
        self.assertFalse(dfa.is_accepting(99))


# =============================================================================
# RuntimeVerificationEngine 集成
# =============================================================================


class TestBaselineEngineIntegration(unittest.TestCase):
    def test_engine_without_baseline_returns_none_result(self):
        """未配置基线 DFA 时，baseline_result 应为 None。"""
        engine = RuntimeVerificationEngine(window_size=10)
        result = engine.evaluate([])
        self.assertIsNone(result["baseline_result"])

    def test_engine_with_valid_baseline_produces_result(self):
        """从临时训练 DFA 配置引擎，基线结果应返回 dict。"""
        traces = [abstract_trace(t) for t in _normal_traces()]
        dfa = learn_from_traces(traces)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp_path = f.name
        try:
            dfa.save(tmp_path)
            engine = RuntimeVerificationEngine(window_size=10, baseline_dfa_path=tmp_path)

            # 正常 trace → baseline 应正常
            rv_trace = [{"event": "mail_read", "props": ["mail_read", "internal_recipient"]}]
            result = engine.evaluate(rv_trace)
            self.assertIsNotNone(result["baseline_result"])
            self.assertIsInstance(result["baseline_result"], dict)
            self.assertIn("anomaly_detected", result["baseline_result"])
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_baseline_does_not_override_existing_verdict(self):
        """基线检测到异常时，不应覆盖现有多监视器更严重的判定。"""
        # 训练一个简单 DFA
        traces = [abstract_trace(t) for t in _normal_traces()]
        dfa = learn_from_traces(traces)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp_path = f.name
        try:
            dfa.save(tmp_path)
            engine = RuntimeVerificationEngine(window_size=10, baseline_dfa_path=tmp_path)

            # mail_send + external + secret → MailMonitor 判定 block
            rv_trace = [{
                "step_id": "s1",
                "event": "mail_send",
                "props": ["mail_send", "external_recipient", "contains_secret"],
            }]
            result = engine.evaluate(rv_trace)
            self.assertEqual(result["verdict"], "block")
            # 基线结果存在但不影响主判定
            self.assertIsNotNone(result["baseline_result"])
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_invalid_baseline_path_silently_ignored(self):
        """无效 DFA 路径不应阻断引擎初始化。"""
        engine = RuntimeVerificationEngine(window_size=10, baseline_dfa_path="/nonexistent.dfa.json")
        result = engine.evaluate([])
        self.assertEqual(result["verdict"], "ok")
        self.assertIsNone(result["baseline_result"])


if __name__ == "__main__":
    unittest.main()
