"""
baseline_monitor.py —— 阶段 C 基线行为监视器。

在运行时追踪会话行为序列，与已训练的基线 DFA 比对，
检测偏离正常模式的异常行为。

设计原则：
- 消费 rv_trace 步骤 + trace_abstractor 抽象
- 沿 DFA 转移推进状态，未定义转移 → 异常
- 判定结果作为独立信号输入 RV 引擎裁决层
- 支持从文件/字典加载预训练 DFA
"""

from __future__ import annotations

from typing import Any

from openclaw_guard.rv.baseline_learner import BaselineDFA
from openclaw_guard.rv.trace_abstractor import abstract_step


class BaselineMonitor:
    """基线偏离检测监视器。

    载入预训练的 BaselineDFA，运行时逐步比对：
    - 步骤能够沿 DFA 走到接受状态 → 正常（返回 None）
    - 步骤走到未定义转移 → 异常（返回 "ask" 或自定义决策）

    Usage:
        dfa = BaselineDFA.load("baseline.json")
        monitor = BaselineMonitor(dfa)
        for step in rv_trace:
            result = monitor.feed(step)
            if result:
                print(f"Anomaly detected: {result}")
    """

    def __init__(
        self,
        dfa: BaselineDFA | None = None,
        anomaly_decision: str = "ask",
    ) -> None:
        self._dfa = dfa
        self._current_state: int = 0
        self._anomaly_decision = anomaly_decision
        self._anomaly_count: int = 0
        self._step_count: int = 0

    @property
    def current_state(self) -> int:
        return self._current_state

    @property
    def anomaly_count(self) -> int:
        return self._anomaly_count

    @property
    def step_count(self) -> int:
        return self._step_count

    def load_dfa(self, dfa: BaselineDFA) -> None:
        """加载或替换基线 DFA。"""
        self._dfa = dfa
        self.reset()

    def feed(
        self,
        step: dict[str, Any],
        _window: Any = None,  # 兼容 Monitor 接口，不使用
    ) -> str | None:
        """输入一个 rv_trace 步骤，返回判定。

        Args:
            step: rv_trace 步骤（dict，含 event/props/entities 等）

        Returns:
            None 表示正常；否则返回决策字符串（如 "ask", "escalate"）
        """
        if self._dfa is None:
            return None

        self._step_count += 1
        symbol = abstract_step(step)

        # 沿 DFA 转移
        next_state = self._dfa.next_state(self._current_state, symbol)
        if next_state is None:
            # 未定义转移 → 偏离基线
            self._anomaly_count += 1
            return self._anomaly_decision

        self._current_state = next_state

        # 检查是否在非接受状态（理论上不应发生，因为所有学习到的状态都是接受状态）
        if not self._dfa.is_accepting(self._current_state):
            self._anomaly_count += 1
            return self._anomaly_decision

        return None

    def reset(self) -> None:
        """重置监视器状态到起始状态。"""
        self._current_state = 0 if self._dfa else 0
        self._anomaly_count = 0
        self._step_count = 0

    def status(self) -> dict[str, Any]:
        """返回监视器当前状态信息。"""
        return {
            "current_state": self._current_state,
            "anomaly_count": self._anomaly_count,
            "step_count": self._step_count,
            "dfa_loaded": self._dfa is not None,
        }
