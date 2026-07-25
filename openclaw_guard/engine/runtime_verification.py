"""
运行时验证核心引擎 —— 滑动窗口管理器 + RV 主引擎。

基于 transitions FSM 库，为所有办公场景监视器提供：
- 滑动上下文窗口（WindowManager）
- 多步序列匹配
- 累积统计
- 主引擎编排（RuntimeVerificationEngine）
"""

from __future__ import annotations

from collections import deque
from typing import Any

from openclaw_guard.utils import utc_now_iso


class WindowManager:
    """滑动窗口管理器。

    维护最近 N 步的 rv_trace 轨迹，提供：
    - 窗口快照与最近一步查询
    - 序列模式匹配（给定标签序列是否在窗口中成立）
    - 累积计数器（统计指定标签的出现次数）
    - 存在性检查（窗口中是否存在某标签）

    Thread-safe 约束：外部调用方保证串行访问。
    """

    def __init__(self, max_size: int = 10) -> None:
        self._buffer: deque[dict[str, Any]] = deque(maxlen=max_size)

    def push(self, step: dict[str, Any]) -> None:
        """追加一个事件步到窗口尾部。"""
        step["_ts"] = utc_now_iso()
        self._buffer.append(step)

    def snapshot(self) -> list[dict[str, Any]]:
        """获取当前窗口的完整快照（从旧到新）。"""
        return list(self._buffer)

    def latest(self) -> dict[str, Any] | None:
        """获取最近一步事件。"""
        return self._buffer[-1] if self._buffer else None

    def sequence_matches(
        self,
        pattern: list[set[str]],
        window_size: int | None = None,
    ) -> bool:
        """检查窗口中是否存在指定的标签序列。

        例：sequence_matches([{"file_search"}, {"file_delete"}])
        表示"先出现 file_search 标签，后出现 file_delete 标签"。

        Args:
            pattern: 标签集合列表，顺序敏感
            window_size: 仅在最近 N 步内检查，默认全窗口

        Returns:
            序列是否匹配
        """
        recent = list(self._buffer)
        if window_size and window_size < len(recent):
            recent = recent[-window_size:]

        pi = 0
        for step in recent:
            props = set(step.get("props", []))
            if pi < len(pattern) and pattern[pi].issubset(props):
                pi += 1
        return pi == len(pattern)

    def cumulative_count(self, label: str, window_size: int | None = None) -> int:
        """统计窗口中指定标签的总出现次数。

        Args:
            label: 目标标签名
            window_size: 统计范围，默认全窗口

        Returns:
            出现次数
        """
        recent = list(self._buffer)
        if window_size and window_size < len(recent):
            recent = recent[-window_size:]
        return sum(1 for step in recent if label in step.get("props", []))

    def contains_any(self, labels: set[str], window_size: int | None = None) -> bool:
        """检查窗口中是否存在至少包含一个指定标签的事件步。"""
        recent = list(self._buffer)
        if window_size and window_size < len(recent):
            recent = recent[-window_size:]
        for step in recent:
            if labels & set(step.get("props", [])):
                return True
        return False

    def clear(self) -> None:
        """清空窗口。"""
        self._buffer.clear()

    def __len__(self) -> int:
        return len(self._buffer)


class RuntimeVerificationEngine:
    """运行时验证主引擎。

    统筹所有办公场景 FSM 监视器 + 滑动窗口 + 判定融合。
    消费语义层产出的 rv_trace，产出 RV 判定结果。
    """

    def __init__(self, window_size: int = 10) -> None:
        self.window = WindowManager(max_size=window_size)
        self._monitors: list = []

    # ---- 懒加载初始化监视器 ----

    def _lazy_init_monitors(self) -> None:
        if not self._monitors:
            from openclaw_guard.engine.rv_monitors import (
                BatchFileMonitor,
                BroadcastMonitor,
                DataExportMonitor,
                MailMonitor,
                ReportMonitor,
                SecurityChainMonitor,
            )
            self._monitors = [
                MailMonitor(),
                ReportMonitor(),
                SecurityChainMonitor(),
                BroadcastMonitor(),
                DataExportMonitor(),
                BatchFileMonitor(),
            ]

    # ---- 核心方法 ----

    def evaluate(
        self,
        rv_trace: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """执行在线运行时验证。

        对语义层产出的 rv_trace 执行：
        1. 将新事件步推入滑动窗口
        2. 依次过所有监视器的 FSM
        3. 取最高风险等级的判定作为最终结果

        Args:
            rv_trace: 语义层产出的步骤列表

        Returns:
            {
                "verdict": "ok" | "ask" | "block" | "escalate",
                "triggered_by": str | None,   # 触发规则的监视器名
                "reason": str | None,
                "window_size": int,
            }
        """
        self._lazy_init_monitors()

        # 1) 将新步推入窗口
        for step in rv_trace:
            self.window.push(step)

        # 2) 遍历监视器收集判定
        severity_map: dict[str, int] = {
            "block": 4, "escalate": 3, "ask": 2, "ok": 1,
        }
        final = "ok"
        triggered_by: str | None = None
        reason: str | None = None

        for monitor in self._monitors:
            for step in rv_trace:
                try:
                    result = monitor.feed(step, self.window)
                except Exception:
                    continue
                if result and severity_map.get(result, 0) > severity_map.get(final, 0):
                    final = result
                    triggered_by = monitor.__class__.__name__
                    reason = f"{monitor.__class__.__name__}: {result}"

        return {
            "verdict": final,
            "triggered_by": triggered_by,
            "reason": reason,
            "window_size": len(self.window),
        }

    def result_summary(self) -> dict[str, Any]:
        """返回当前窗口的摘要信息，供前端展示。"""
        return {
            "window_size": len(self.window),
            "monitor_count": len(self._monitors),
            "window_snapshot": [
                {
                    "event": s.get("event"),
                    "props": s.get("props", [])[:6],
                }
                for s in self.window.snapshot()
            ],
        }

    def reset(self) -> None:
        """重置所有监视器的 FSM 状态和滑动窗口。"""
        self.window.clear()
        for m in self._monitors:
            try:
                m.reset()
            except Exception:
                pass
