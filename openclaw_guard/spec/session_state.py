"""
session_state.py —— 阶段 F：会话安全状态与干预升级。

管理每个会话的安全态势：
- 累计风险评分（加权求和的告警严重度）
- 状态桶（safe / warning / elevated / critical）
- escalate → block 自动升级阈值
- revision_hint 生成（revise 裁决时的修正建议）
"""

from __future__ import annotations

from typing import Any


class SessionSafetyState:
    """Per-session 安全状态追踪器。

    在阻断点之间累积安全告警，根据累计风险评分升级响应等级。
    """

    _RISK_THRESHOLDS: dict[str, int] = {
        "safe": 0,
        "warning": 3,
        "elevated": 7,
        "critical": 15,
    }
    _SEVERITY_TO_SCORE: dict[str, int] = {
        "block": 5,
        "escalate": 3,
        "ask": 1,
        "ok": 0,
    }
    _THRESHOLDS_ORDER = ["safe", "warning", "elevated", "critical"]

    def __init__(self, session_key: str = "_default") -> None:
        self.session_key = session_key
        self.total_score: int = 0
        self._state: str = "safe"
        self._escalation_history: list[dict[str, Any]] = []
        self._escalate_to_block_count: int = 0
        self._ask_to_escalate_count: int = 0

    @property
    def current_state(self) -> str:
        return self._state

    def record(self, verdict: str, reason: str | None = None) -> str | None:
        """记录一次判定，返回升级后的裁决（如有）。

        Args:
            verdict: 原始裁决（block / escalate / ask / ok）
            reason: 触发原因

        Returns:
            None 表示不升级；否则返回升级后的裁决字符串
        """
        score = self._SEVERITY_TO_SCORE.get(verdict, 0)
        self.total_score += score
        self._escalation_history.append({
            "verdict": verdict,
            "score": score,
            "reason": reason or "",
            "total_after": self.total_score,
        })

        # 状态桶变更
        new_state = self._compute_state()
        self._state = new_state

        # 连续 ask → escalate（spec F2）
        if verdict == "ask":
            self._ask_to_escalate_count += 1
            if self._ask_to_escalate_count >= 3:
                self._ask_to_escalate_count = 0
                return "escalate"
        else:
            self._ask_to_escalate_count = max(0, self._ask_to_escalate_count - 1)

        # 连续 escalate → 升级为 block
        if verdict == "escalate":
            self._escalate_to_block_count += 1
            if self._escalate_to_block_count >= 3:
                self._escalate_to_block_count = 0
                return "block"
        elif verdict == "block":
            self._escalate_to_block_count = 0
        else:
            self._escalate_to_block_count = max(0, self._escalate_to_block_count - 1)

        # escalate + 累计 elevated → 升级为 block
        if verdict == "escalate" and self._state in ("elevated", "critical"):
            return "block"

        return None

    def revision_hint(self) -> str | None:
        """生成 revise 裁决时的修正建议。

        Returns:
            修正建议字符串（如 "block: cumulative risk elevated"），或无建议返回 None
        """
        if self._state == "critical":
            return "block: cumulative risk critical — consider session termination"
        if self._escalate_to_block_count >= 2:
            return "block: repeated escalation — consider upgrading to block"
        if self.total_score >= 10:
            return "block: escalating risk score"
        return None

    def _compute_state(self) -> str:
        for level in reversed(self._THRESHOLDS_ORDER):
            if self.total_score >= self._RISK_THRESHOLDS[level]:
                return level
        return "safe"

    def reset(self) -> None:
        self.total_score = 0
        self._state = "safe"
        self._escalation_history.clear()
        self._escalate_to_block_count = 0
        self._ask_to_escalate_count = 0

    def status(self) -> dict[str, Any]:
        return {
            "session_key": self.session_key,
            "state": self._state,
            "total_score": self.total_score,
            "escalate_to_block_count": self._escalate_to_block_count,
            "ask_to_escalate_count": self._ask_to_escalate_count,
            "history_length": len(self._escalation_history),
        }
