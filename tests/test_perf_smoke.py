"""性能冒烟基准测试。

覆盖 RV 热路径三个纯内存组件的延迟基线（审计报告 4.2 补记）：
- ConstraintEngine.evaluate_steps()（约束推理，含 IR 结构化转换）
- RuntimeVerificationEngine.evaluate()（RV 窗口判定）
- SessionSafetyState.record()（会话状态累计）

阈值刻意宽松（10 倍余量），防止 CI 环境抖动误报；
超阈值说明出现明显性能劣化，需要人工复核。
项目硬约束参考：detection < 1ms、rv < 5ms、摘要接口 <= 10ms。
"""

import time
import unittest

from openclaw_guard.rv.constraints import ConstraintEngine, migrated_constraint_rules
from openclaw_guard.rv.runtime_verification import RuntimeVerificationEngine
from openclaw_guard.spec.session_state import SessionSafetyState

# 宽松冒烟阈值（平均/次，毫秒）
CONSTRAINT_ENGINE_MAX_MS = 50.0
RV_ENGINE_MAX_MS = 50.0
SESSION_1000_RECORDS_MAX_MS = 200.0

LOOPS = 100


def _make_rv_trace(steps: int) -> list[dict]:
    """构造含 steps 个步骤的 rv_trace（含链式外发场景，触发 MailMonitor）。"""
    trace = [{
        "step_id": "s1",
        "event": "mail_read",
        "props": ["mail_read", "external_source", "contains_secret"],
        "entities": [],
        "constraints": [],
    }]
    for i in range(2, steps + 1):
        trace.append({
            "step_id": f"s{i}",
            "event": "mail_send",
            "props": ["mail_send", "external_recipient", "contains_secret"],
            "entities": [{"kind": "recipients", "values": [f"ext{i}@example.com"]}],
            "constraints": [{"kind": "time_range", "value": "today"}],
        })
    return trace


def _make_constraint_trace(steps: int) -> list[dict]:
    """构造含 steps 个 IR 步骤的 rv_trace（命中 CMD-001/NET-005 等多条规则）。"""
    trace = []
    for i in range(steps):
        trace.append({
            "step_id": f"s{i}",
            "event": "command_exec",
            "props": ["command_exec", "command_rm_rf"] if i % 2 == 0 else ["command_exec", "command_sudo"],
            "entities": [],
            "constraints": [],
            "confidence": 0.9,
        })
    return trace


class TestPerfSmoke(unittest.TestCase):
    def test_constraint_engine_latency(self):
        """约束引擎：20 步 IR 平均判定延迟 < 50ms。"""
        engine = ConstraintEngine(migrated_constraint_rules())
        trace = _make_constraint_trace(20)

        engine.evaluate_steps(trace)  # 预热
        start = time.perf_counter()
        for _ in range(LOOPS):
            engine.evaluate_steps(trace)
        elapsed = (time.perf_counter() - start) / LOOPS * 1000.0

        self.assertLess(elapsed, CONSTRAINT_ENGINE_MAX_MS,
                        f"约束引擎平均 {elapsed:.2f}ms 超过阈值 {CONSTRAINT_ENGINE_MAX_MS}ms")

    def test_rv_engine_latency(self):
        """RV 引擎：链式外发 rv_trace 平均判定延迟 < 50ms。"""
        engine = RuntimeVerificationEngine(window_size=10)
        trace = _make_rv_trace(6)

        engine.evaluate(trace)  # 预热
        start = time.perf_counter()
        for _ in range(LOOPS):
            engine.evaluate(trace)
        elapsed = (time.perf_counter() - start) / LOOPS * 1000.0

        self.assertLess(elapsed, RV_ENGINE_MAX_MS,
                        f"RV 引擎平均 {elapsed:.2f}ms 超过阈值 {RV_ENGINE_MAX_MS}ms")

    def test_session_state_latency(self):
        """会话状态：1000 次 record 总耗时 < 200ms。"""
        state = SessionSafetyState("perf-session")
        start = time.perf_counter()
        for i in range(1000):
            state.record("escalate" if i % 3 == 0 else "ask")
        elapsed = (time.perf_counter() - start) * 1000.0

        self.assertLess(elapsed, SESSION_1000_RECORDS_MAX_MS,
                        f"会话状态 1000 次耗时 {elapsed:.2f}ms 超过阈值 {SESSION_1000_RECORDS_MAX_MS}ms")


if __name__ == "__main__":
    unittest.main()
