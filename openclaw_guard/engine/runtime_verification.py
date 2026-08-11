"""
运行时验证核心引擎 —— 滑动窗口管理器 + RV 主引擎。

基于 transitions FSM 库，为所有安全监视器提供：
- 带时间过期的滑动上下文窗口（WindowManager）
- 多步序列匹配
- 累积统计
- Per-session 会话隔离
- 状态序列化/反序列化
- 主引擎编排（RuntimeVerificationEngine）

设计原则：
- 监视器（Monitors）通过 FSM 状态记忆追踪跨步攻击链
- WindowManager 提供统计增强（累积计数、序列匹配、窗口查询）
- Engine 负责 per-session 窗口隔离和判定融合
"""

from __future__ import annotations

import os
import time as _time
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
    - 时间过期（基于 TTL 的自动清理）
    - 序列化/反序列化（支持持久化）
    - 按标签检索（steps_with_label）

    Thread-safe 约束：外部调用方保证串行访问。
    """

    def __init__(self, max_size: int = 10, ttl_seconds: int | None = 300) -> None:
        self._buffer: deque[dict[str, Any]] = deque(maxlen=max_size)
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds

    # ── 写入 ──

    def push(self, step: dict[str, Any]) -> None:
        """追加一个事件步到窗口尾部。自动处理时间过期。"""
        step["_ts"] = utc_now_iso()
        step["_ts_epoch"] = _time.time()
        self._buffer.append(step)
        if self._ttl_seconds is not None:
            self._expire_old()

    # ── 时间过期 ──

    def _expire_old(self) -> int:
        """移除超过 TTL 的步骤。返回移除的数量。"""
        if self._ttl_seconds is None or not self._buffer:
            return 0
        cutoff = _time.time() - self._ttl_seconds
        removed = 0
        while self._buffer and self._buffer[0].get("_ts_epoch", 0) < cutoff:
            self._buffer.popleft()
            removed += 1
        return removed

    def set_ttl(self, ttl_seconds: int | None) -> None:
        """动态更新 TTL 并立即清理过期条目。"""
        self._ttl_seconds = ttl_seconds
        if ttl_seconds is not None:
            self._expire_old()

    def age_of_oldest(self) -> float | None:
        """返回最老步骤的年龄（秒），用于 FSM 判定。窗口为空返回 None。"""
        if not self._buffer:
            return None
        oldest_epoch = self._buffer[0].get("_ts_epoch", 0)
        if oldest_epoch == 0:
            return None
        return _time.time() - oldest_epoch

    # ── 快照与查询 ──

    def snapshot(self) -> list[dict[str, Any]]:
        """获取当前窗口的完整快照（从旧到新）。"""
        self._expire_old()
        return list(self._buffer)

    def latest(self) -> dict[str, Any] | None:
        """获取最近一步事件。"""
        return self._buffer[-1] if self._buffer else None

    def steps_with_label(self, label: str, window_size: int | None = None) -> list[dict[str, Any]]:
        """返回窗口中包含指定标签的所有步骤。

        Args:
            label: 目标标签名
            window_size: 仅在最近 N 步内检查，默认全窗口

        Returns:
            匹配步骤列表（从旧到新）
        """
        recent = self.snapshot()
        if window_size and window_size < len(recent):
            recent = recent[-window_size:]
        return [s for s in recent if label in set(s.get("props", []))]

    # ── 序列匹配 ──

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
        recent = self.snapshot()
        if window_size and window_size < len(recent):
            recent = recent[-window_size:]

        pi = 0
        for step in recent:
            props = set(step.get("props", []))
            if pi < len(pattern) and pattern[pi].issubset(props):
                pi += 1
        return pi == len(pattern)

    # ── 累积计数 ──

    def cumulative_count(self, label: str, window_size: int | None = None) -> int:
        """统计窗口中指定标签的总出现次数。

        Args:
            label: 目标标签名
            window_size: 统计范围，默认全窗口

        Returns:
            出现次数
        """
        recent = self.snapshot()
        if window_size and window_size < len(recent):
            recent = recent[-window_size:]
        return sum(1 for step in recent if label in step.get("props", []))

    # ── 存在性检查 ──

    def contains_any(self, labels: set[str], window_size: int | None = None) -> bool:
        """检查窗口中是否存在至少包含一个指定标签的事件步。"""
        recent = self.snapshot()
        if window_size and window_size < len(recent):
            recent = recent[-window_size:]
        for step in recent:
            if labels & set(step.get("props", [])):
                return True
        return False

    # ── 序列化 ──

    def to_dict(self) -> dict[str, Any]:
        """序列化窗口状态供持久化。"""
        return {
            "max_size": self._max_size,
            "ttl_seconds": self._ttl_seconds,
            "buffer": list(self._buffer),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WindowManager:
        """从序列化数据恢复窗口。

        恢复后的窗口保留原始时间戳，但会基于当前时间重新检查过期。
        """
        wm = cls(
            max_size=data.get("max_size", 10),
            ttl_seconds=data.get("ttl_seconds"),
        )
        buffer_data = data.get("buffer", [])
        if isinstance(buffer_data, list):
            for item in buffer_data:
                if isinstance(item, dict):
                    # 保留原始时间戳用于审计
                    wm._buffer.append(item)
        # 立即过期旧条目
        if wm._ttl_seconds is not None:
            wm._expire_old()
        return wm

    # ── 管理 ──

    def clear(self) -> None:
        """清空窗口。"""
        self._buffer.clear()

    def __len__(self) -> int:
        return len(self._buffer)


class RuntimeVerificationEngine:
    """运行时验证主引擎 —— Per-session 窗口隔离。

    统筹所有安全监视器 + 滑动窗口 + 判定融合。
    消费语义层产出的 rv_trace，产出 RV 判定结果。

    Per-session 设计：
    - evaluate() 接受 session_key 参数
    - 不同 session 拥有独立的 WindowManager 和 Monitor 实例
    - "_default" session 保持向后兼容
    """

    def __init__(
        self,
        window_size: int = 10,
        window_ttl_seconds: int | None = 300,
        rule_mode: str | None = None,
        baseline_dfa_path: str | None = None,
    ) -> None:
        self._window_size = window_size
        self._window_ttl = window_ttl_seconds
        self._rule_mode = self._normalize_rule_mode(
            rule_mode or os.getenv("OPENCLAW_RV_RULE_MODE")
        )
        # 默认共享窗口（向后兼容）
        self.window = WindowManager(max_size=window_size, ttl_seconds=window_ttl_seconds)
        # Per-session 隔离存储
        self._session_windows: dict[str, WindowManager] = {}
        self._session_monitors: dict[str, list] = {}
        self._fsm_monitors_template: list | None = None
        self._spec_monitors_template: list | None = None
        self._spec_ruleset: Any | None = None
        # 基线自动机监视器（阶段 C）
        self._baseline_monitor: Any | None = None
        self._init_baseline_monitor(baseline_dfa_path)

    # ── 懒加载初始化监视器模板 ──

    def _normalize_rule_mode(self, value: str | None) -> str:
        if not value:
            return "dsl"
        v = str(value).strip().lower()
        if v in {"dsl", "spec", "spec-driven", "spec_driven"}:
            return "dsl"
        if v in {"fsm", "handwritten", "hand-written"}:
            return "fsm"
        return "dsl"

    def _init_baseline_monitor(self, dfa_path: str | None) -> None:
        """懒加载基线 DFA 监视器。"""
        path = dfa_path or os.getenv("OPENCLAW_RV_BASELINE_DFA_PATH")
        if not path:
            return
        try:
            from openclaw_guard.engine.baseline_learner import BaselineDFA
            from openclaw_guard.engine.baseline_monitor import BaselineMonitor

            dfa = BaselineDFA.load(path)
            self._baseline_monitor = BaselineMonitor(dfa)
        except Exception:
            pass  # DFA 加载失败时静默跳过，不影响正常引擎功能

    def rule_mode(self) -> str:
        return self._rule_mode

    def set_rule_mode(self, mode: str) -> None:
        new_mode = self._normalize_rule_mode(mode)
        if new_mode == self._rule_mode:
            return
        self._rule_mode = new_mode
        self._session_monitors.clear()
        self._fsm_monitors_template = None
        self._spec_monitors_template = None

    def _lazy_init_monitors(self) -> None:
        if self._rule_mode == "fsm":
            self._lazy_init_fsm_monitors()
        else:
            self._lazy_init_spec_monitors()

    def _lazy_init_fsm_monitors(self) -> None:
        if self._fsm_monitors_template is not None:
            return
        from openclaw_guard.engine.rv_monitors import (
            BatchFileMonitor,
            BroadcastMonitor,
            DataExportMonitor,
            MailMonitor,
            ReportMonitor,
            SecurityChainMonitor,
        )
        self._fsm_monitors_template = [
            MailMonitor(),
            ReportMonitor(),
            SecurityChainMonitor(),
            BroadcastMonitor(),
            DataExportMonitor(),
            BatchFileMonitor(),
        ]

    def _lazy_init_spec_monitors(self) -> None:
        if self._spec_monitors_template is not None:
            return
        from openclaw_guard.engine.rv_dsl import compile_monitors, load_ruleset

        if self._spec_ruleset is None:
            rules_path = os.getenv("OPENCLAW_RV_RULES_PATH")
            self._spec_ruleset = load_ruleset(rules_path) if rules_path else load_ruleset()
        self._spec_monitors_template = compile_monitors(self._spec_ruleset)

    def _create_monitors(self) -> list:
        """基于模板创建新的监视器实例。"""
        self._lazy_init_monitors()
        if self._rule_mode == "fsm":
            from openclaw_guard.engine.rv_monitors import (
                BatchFileMonitor,
                BroadcastMonitor,
                DataExportMonitor,
                MailMonitor,
                ReportMonitor,
                SecurityChainMonitor,
            )
            return [
                MailMonitor(),
                ReportMonitor(),
                SecurityChainMonitor(),
                BroadcastMonitor(),
                DataExportMonitor(),
                BatchFileMonitor(),
            ]
        from openclaw_guard.engine.rv_dsl import compile_monitors

        return compile_monitors(self._spec_ruleset)

    # ── 核心方法 ──

    def evaluate(
        self,
        rv_trace: list[dict[str, Any]],
        session_key: str = "_default",
    ) -> dict[str, Any]:
        """执行在线运行时验证。

        对语义层产出的 rv_trace 执行：
        1. 将新事件步推入 per-session 滑动窗口
        2. 依次过所有监视器的 FSM
        3. 取最高风险等级的判定作为最终结果

        Args:
            rv_trace: 语义层产出的步骤列表
            session_key: 会话标识（用于 per-session 窗口隔离）
                         默认 "_default" 保持向后兼容

        Returns:
            {
                "verdict": "ok" | "ask" | "block" | "escalate",
                "triggered_by": str | None,   # 触发规则的监视器名
                "reason": str | None,
                "window_size": int,
                "session_key": str,
            }
        """
        # 获取 per-session 资源
        window = self._get_session_window(session_key)
        monitors = self._get_session_monitors(session_key)

        # 1) 将新步推入窗口
        for step in rv_trace:
            window.push(step)

        # 2) 遍历监视器收集判定
        severity_map: dict[str, int] = {
            "block": 4, "escalate": 3, "ask": 2, "ok": 1,
        }
        final = "ok"
        triggered_by: str | None = None
        reason: str | None = None
        monitor_timings: dict[str, float] = {}

        for monitor in monitors:
            m_start = _time.perf_counter()
            for step in rv_trace:
                try:
                    result = monitor.feed(step, window)
                except Exception:
                    result = None
                if result and severity_map.get(result, 0) > severity_map.get(final, 0):
                    final = result
                    triggered_by = monitor.__class__.__name__
                    reason = f"{monitor.__class__.__name__}: {result}"
            monitor_timings[monitor.__class__.__name__] = round(
                (_time.perf_counter() - m_start) * 1000.0, 4
            )

        return {
            "verdict": final,
            "triggered_by": triggered_by,
            "reason": reason,
            "window_size": len(window),
            "session_key": session_key,
            "rule_mode": self._rule_mode,
            "monitor_timings_ms": monitor_timings,
            "baseline_result": self._run_baseline(rv_trace, severity_map, final),
        }

    def _run_baseline(
        self,
        rv_trace: list[dict[str, Any]],
        severity_map: dict[str, int],
        current_verdict: str,
    ) -> dict[str, Any] | None:
        """运行基线监视器并返回结果。

        基线判定作为独立信号，不覆盖现有监视器的判定。
        仅当基线检测到异常且 severity 高于当前 verdict 时才升级。
        """
        if self._baseline_monitor is None:
            return None

        bm = self._baseline_monitor
        bm_result: str | None = None
        for step in rv_trace:
            r = bm.feed(step)
            if r and severity_map.get(r, 0) > severity_map.get(bm_result or "ok", 0):
                bm_result = r

        return {
            "anomaly_detected": bm_result is not None,
            "verdict": bm_result or "ok",
            "current_state": bm.current_state,
            "anomaly_count": bm.anomaly_count,
            "step_count": bm.step_count,
        }

    # ── Session 管理 ──

    def _get_session_window(self, session_key: str) -> WindowManager:
        """获取或创建 per-session 窗口。"""
        if session_key == "_default":
            return self.window
        if session_key not in self._session_windows:
            self._session_windows[session_key] = WindowManager(
                max_size=self._window_size,
                ttl_seconds=self._window_ttl,
            )
        return self._session_windows[session_key]

    def _get_session_monitors(self, session_key: str) -> list:
        """获取或创建 per-session 监视器实例。"""
        if session_key == "_default":
            self._lazy_init_monitors()
            if self._rule_mode == "fsm":
                return self._fsm_monitors_template  # type: ignore[return-value]
            return self._spec_monitors_template  # type: ignore[return-value]
        if session_key not in self._session_monitors:
            self._session_monitors[session_key] = self._create_monitors()
        return self._session_monitors[session_key]

    def release_session(self, session_key: str) -> None:
        """释放某个会话的 RV 状态（窗口 + 监视器）。"""
        self._session_windows.pop(session_key, None)
        self._session_monitors.pop(session_key, None)

    def session_count(self) -> int:
        """返回当前活跃的 per-session 数量（不含 _default）。"""
        return len(self._session_windows)

    # ── 序列化 ──

    def serialize_state(self) -> dict[str, Any]:
        """序列化所有窗口状态供持久化。"""
        state: dict[str, Any] = {
            "_window_size": self._window_size,
            "_window_ttl": self._window_ttl,
            "default_window": self.window.to_dict(),
            "session_windows": {
                k: w.to_dict() for k, w in self._session_windows.items()
            },
        }
        return state

    def deserialize_state(self, state: dict[str, Any]) -> None:
        """从序列化数据恢复所有窗口状态。"""
        if "default_window" in state:
            self.window = WindowManager.from_dict(state["default_window"])
        if "session_windows" in state:
            for k, data in state["session_windows"].items():
                if isinstance(data, dict):
                    self._session_windows[k] = WindowManager.from_dict(data)

    # ── 摘要 ──

    def result_summary(self, session_key: str = "_default") -> dict[str, Any]:
        """返回当前会话窗口的摘要信息，供前端展示。"""
        window = self._get_session_window(session_key)
        monitors = self._get_session_monitors(session_key)
        snap = window.snapshot()
        return {
            "window_size": len(window),
            "monitor_count": len(monitors),
            "rule_mode": self._rule_mode,
            "session_key": session_key,
            "monitor_states": {
                m.__class__.__name__: m.state_summary()
                for m in monitors
            },
            "window_snapshot": [
                {
                    "event": s.get("event"),
                    "props": s.get("props", [])[:6],
                }
                for s in snap
            ],
        }

    def reset(self, session_key: str | None = None) -> None:
        """重置监视器状态和滑动窗口。

        Args:
            session_key: 要重置的会话，None 表示重置所有
        """
        if session_key is not None:
            window = self._get_session_window(session_key)
            window.clear()
            for m in self._get_session_monitors(session_key):
                try:
                    m.reset()
                except Exception:
                    pass
        else:
            # 重置所有
            self.window.clear()
            self._lazy_init_monitors()
            monitors = (
                self._fsm_monitors_template
                if self._rule_mode == "fsm"
                else self._spec_monitors_template
            )
            if monitors:
                for m in monitors:
                    try:
                        m.reset()
                    except Exception:
                        pass
            for wm in self._session_windows.values():
                wm.clear()
            for monitors in self._session_monitors.values():
                for m in monitors:
                    try:
                        m.reset()
                    except Exception:
                        pass
