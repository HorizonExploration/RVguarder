"""性能冒烟基准测试。

覆盖 RV 热路径的延迟基线（审计报告 4.2 补记）：
- RuntimeVerificationEngine.preview()（执行前自动机判定）

阈值刻意宽松（10 倍余量），防止 CI 环境抖动误报；
超阈值说明出现明显性能劣化，需要人工复核。
项目硬约束参考：detection < 1ms、rv < 5ms、摘要接口 <= 10ms。
"""

import time
import unittest

from openclaw_guard.rv.runtime_verification import RuntimeVerificationEngine

# 宽松冒烟阈值（平均/次，毫秒）
RV_ENGINE_MAX_MS = 50.0

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


class TestPerfSmoke(unittest.TestCase):
    def test_rv_engine_latency(self):
        """RV 预判：链式外发 rv_trace 平均判定延迟 < 50ms。"""
        engine = RuntimeVerificationEngine(window_size=10)
        trace = _make_rv_trace(6)

        engine.preview(trace)  # 预热
        start = time.perf_counter()
        for _ in range(LOOPS):
            engine.preview(trace)
        elapsed = (time.perf_counter() - start) / LOOPS * 1000.0

        self.assertLess(elapsed, RV_ENGINE_MAX_MS,
                        f"RV 引擎平均 {elapsed:.2f}ms 超过阈值 {RV_ENGINE_MAX_MS}ms")


if __name__ == "__main__":
    unittest.main()
