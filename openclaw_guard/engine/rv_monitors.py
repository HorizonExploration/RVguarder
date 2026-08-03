"""
安全场景 RV 监视器定义。

每个监视器代表一个攻击链的安全 FSM（有限状态机），
通过 transitions 库实现**真正的跨步状态记忆驱动决策**。

设计原则：
- FSM 状态编码攻击链的演进阶段（如：外部来源读取 → 敏感数据提取 → 外传）
- self.state 在 feed() 中被**读取**来驱动分支逻辑（不再是纯记录性）
- WindowManager 提供统计增强（累积计数、序列匹配）辅助 FSM 决策
- 与 detection.py 分工：detection 处理单步风险，RV 处理链式风险

包含：
- MailMonitor: 外部来源 → 敏感数据 → 邮件外发攻击链
- ReportMonitor: 内部源 → 报告生成 → 外部发送攻击链
- SecurityChainMonitor: 5 条通用链式组合风险
- BroadcastMonitor: 单聊 → 群发 → 外部收件人攻击链
- DataExportMonitor: 查询敏感表 → 导出 → 外传攻击链
- BatchFileMonitor: 搜索 → 打包 → 外传三步链 + 批量删除
"""

from __future__ import annotations

import time as _time
from abc import ABC, abstractmethod
from typing import Any

from transitions import Machine

from openclaw_guard.engine.runtime_verification import WindowManager


# =============================================================================
# 1. 增强的基类
# =============================================================================


class BaseMonitor(ABC):
    """所有 RV 监视器的抽象基类。

    FSM 状态语义约定：
    - idle: 初始态，尚未检测到攻击链的起手事件
    - 中间态（如 external_source_read, sensitive_data_extracted）:
      攻击链的部分步骤已完成，正在追踪 Agent 行为轨迹
    - blocked / escalated: 终端态，攻击链被确认
    - ask_approval / awaiting_review: 终端态，需要人工介入

    子类必须实现：
    - feed(step, window) → str|None: 核心判定入口
    - reset(): 重置 FSM 回到 idle
    - current_state: 属性，返回当前 FSM 状态名
    - state_summary(): 返回监视器状态摘要
    """

    @abstractmethod
    def feed(self, step: dict[str, Any], window: WindowManager) -> str | None:
        """处理一个新的事件步。

        核心约定：必须在 feed() 中**读取 self.state** 来驱动决策逻辑。
        不能仅基于当前 props 做判定——必须结合 FSM 记录的跨步状态。

        Args:
            step: rv_trace 中的单步事件，含 event/props 字段
            window: 当前滑动窗口（可查询历史步与统计信息）

        Returns:
            "block" | "escalate" | "ask" | None（无判定，继续下一监视器）
        """
        ...

    def reset(self) -> None:
        """重置 FSM 状态为初始值。子类按需重写。"""

    @property
    @abstractmethod
    def current_state(self) -> str:
        """返回当前 FSM 状态名，用于审计与调试。"""
        ...

    @abstractmethod
    def state_summary(self) -> dict[str, Any]:
        """返回监视器状态摘要。

        Returns:
            {"state": str, "monitor": str, "props_snapshot": [...]}
        """
        ...

    def is_in_state(self, state: str) -> bool:
        """便捷方法：检查 FSM 是否处于某个状态。"""
        return self.current_state == state


# =============================================================================
# 2. MailMonitor —— 邮件钓鱼攻击链 FSM
# =============================================================================


class MailMonitor(BaseMonitor):
    """邮件发送安全监视器 —— 建模完整的外部来源攻击链。

    建模的攻击链：外部附件/来源 → 敏感数据提取 → 邮件外发给外部收件人

    FSM 状态图:
        idle
          ├─ external_source_read（读取外部来源内容）
          │   └─ sensitive_data_extracted（外部来源 + 敏感内容被提取）
          │       └─ blocked（外部收件人 + 敏感 = 阻断）
          ├─ escalated（群发 = 升级审批）
          ├─ ask_approval（AI 生成未审阅 = 要求确认）
          └─ reset_state → idle

    核心创新：sensitive_data_extracted 状态记录了「Agent 已从外部来源获取敏感数据」，
    后续 mail_send 时基于此状态决定 block/ask 级别。

    与 detection.py 分工：
    - detection.py: 处理单步显式硬阻断（如 CMD-001 rm -rf）
    - MailMonitor: 处理「外部来源 → 敏感 → 外发」链式攻击
    """

    states = [
        "idle",
        "external_source_read",       # 读取了外部来源内容
        "sensitive_data_extracted",   # 从外部来源提取了敏感数据
        "blocked",                    # 终端：已阻断
        "escalated",                  # 终端：升级审批
        "ask_approval",              # 终端：需要人工确认
    ]

    def __init__(self) -> None:
        self.machine = Machine(model=self, states=self.states, initial="idle")

        # 链式状态转移
        self.machine.add_transition(
            "to_external_source", "idle", "external_source_read",
            conditions=["is_external_source"],
        )
        self.machine.add_transition(
            "to_sensitive", "external_source_read", "sensitive_data_extracted",
            conditions=["is_sensitive_data"],
        )
        self.machine.add_transition(
            "to_sensitive_direct", "idle", "sensitive_data_extracted",
            conditions=["is_sensitive_data"],
        )
        # 终端转移
        self.machine.add_transition(
            "to_blocked", "sensitive_data_extracted", "blocked",
        )
        self.machine.add_transition(
            "to_escalated", "*", "escalated",
            conditions=["is_escalation"],
        )
        self.machine.add_transition(
            "to_ask", "*", "ask_approval",
            conditions=["needs_approval"],
        )
        self.machine.add_transition("reset_state", "*", "idle")

        self._current_props: set[str] = set()

    # ── Properties ──

    @property
    def current_state(self) -> str:
        return self.state  # transitions 注入的 state 属性

    def state_summary(self) -> dict[str, Any]:
        return {
            "state": self.current_state,
            "monitor": "MailMonitor",
            "props_snapshot": sorted(self._current_props),
        }

    # ── FSM 条件 ──

    def is_external_source(self) -> bool:
        """当前步是否来自外部来源（附件、外部渠道）。"""
        return bool(
            {"attachment_open", "channel_external", "external_source"}
            & self._current_props
        )

    def is_sensitive_data(self) -> bool:
        """当前步是否包含敏感数据。"""
        return (
            "contains_secret" in self._current_props
            or "path_high_value" in self._current_props
            or "hidden_content" in self._current_props
        )

    def is_escalation(self) -> bool:
        """当前步是否需要升级审批（群发、含敏感+外部）。"""
        return (
            "bulk_send" in self._current_props
            and "external_recipient" in self._current_props
        )

    def needs_approval(self) -> bool:
        """当前步是否需要人工确认。"""
        return (
            "bulk_send" in self._current_props
            or (
                "ai_generated_content" in self._current_props
                and "requires_human_review" not in self._current_props
            )
        )

    def has_external_recipient(self) -> bool:
        """是否有外部收件人。"""
        return "external_recipient" in self._current_props

    # ── 核心入口 ──

    def feed(self, step: dict[str, Any], window: WindowManager) -> str | None:
        self._current_props = set(step.get("props", []))
        ev = step.get("event", "")

        # === 阶段 1: 状态追踪（不 return，让 Phase 2 也执行） ===
        state_advanced = False
        if self.is_external_source():
            if self.is_in_state("idle"):
                self.to_external_source()
                state_advanced = True
            elif self.is_in_state("external_source_read") and self.is_sensitive_data():
                self.to_sensitive()
                state_advanced = True

        elif self.is_sensitive_data():
            if self.is_in_state("idle"):
                self.to_sensitive_direct()
                state_advanced = True
            elif self.is_in_state("external_source_read"):
                self.to_sensitive()
                state_advanced = True

        # 如果只有状态追踪（无外发动作），直接返回
        has_mail = "mail_send" in self._current_props or ev == "mail_send"
        if state_advanced and not has_mail:
            return None

        # === 阶段 2: 外发动作判定（基于 FSM 状态） ===
        if "mail_send" in self._current_props or ev == "mail_send":
            current = self.current_state  # ← 读取 FSM 状态

            if current == "sensitive_data_extracted":
                # 已确认「外部来源 + 敏感数据」链 → 严格判定
                if self.has_external_recipient():
                    self.to_blocked()
                    return "block"
                if self.is_escalation():
                    self.to_escalated()
                    return "escalate"
                if self.needs_approval():
                    self.to_ask()
                    return "ask"
                return "ask"

            elif current == "external_source_read":
                # 外部来源但未提取敏感数据 → 中等风险
                if self.has_external_recipient():
                    return "ask"
                return None

            elif current == "idle":
                # 无链式前序 → 基础判定
                if self.is_escalation():
                    self.to_escalated()
                    return "escalate"
                if self.needs_approval():
                    self.to_ask()
                    return "ask"
                if self.has_external_recipient():
                    return "ask"
                return None

            elif current in ("blocked", "escalated", "ask_approval"):
                # 从终端态接收新邮件事件 → 继续维持当前 risk 判定
                severity = {"blocked": "block", "escalated": "escalate", "ask_approval": "ask"}
                return severity.get(current)

        # === 阶段 3: 时间过期的状态回退 ===
        # 若长时间无新事件，将中间状态回退到 idle
        if self.is_in_state("external_source_read") or self.is_in_state("sensitive_data_extracted"):
            age = window.age_of_oldest()
            if age is not None and age > 300:  # 5 分钟无活动
                self.reset_state()
                return None

        # === 阶段 4: WindowManager 辅助链式检测 ===
        if "file_delete" in self._current_props and "high_value_path" in self._current_props:
            if window.contains_any({"file_search", "file_read"}, window_size=5):
                return "block"

        return None

    def reset(self) -> None:
        self.reset_state()
        self._current_props = set()


# =============================================================================
# 3. ReportMonitor —— 日报内部源泄漏链 FSM
# =============================================================================


class ReportMonitor(BaseMonitor):
    """日报生成/外发安全监视器 —— 建模内部数据源泄漏链。

    建模的攻击链：内部源数据聚合 → 生成报告 → 外部发送 → 数据泄漏

    FSM 状态图:
        idle
          ├─ source_aggregating（正在聚合内部数据源）
          │   └─ report_ready（报告已生成，含内部源）
          │       └─ blocked（内部源 + 外部发送 = 阻断）
          ├─ missing_scope（缺少范围约束 → ask）
          └─ reset_state → idle
    """

    states = [
        "idle",
        "source_aggregating",        # 正在从内部源聚合数据
        "report_ready",              # 报告已生成（含内部源标记）
        "blocked",                   # 终端：已阻断
        "escalated",                 # 终端：升级审批
        "asking",                    # 终端：需要确认
    ]

    def __init__(self) -> None:
        self.machine = Machine(model=self, states=self.states, initial="idle")

        self.machine.add_transition(
            "to_aggregating", "idle", "source_aggregating",
            conditions=["is_internal_source"],
        )
        self.machine.add_transition(
            "to_report_ready", ["idle", "source_aggregating"], "report_ready",
            conditions=["is_report_generated"],
        )
        self.machine.add_transition(
            "to_blocked", "report_ready", "blocked",
            conditions=["is_blockable_send"],
        )
        self.machine.add_transition(
            "to_escalated", "report_ready", "escalated",
            conditions=["is_escalation_send"],
        )
        self.machine.add_transition(
            "to_asking", "report_ready", "asking",
            conditions=["is_external_send"],
        )
        self.machine.add_transition(
            "to_ask_missing_scope", "*", "asking",
            conditions=["is_missing_scope"],
        )
        self.machine.add_transition("reset_state", "*", "idle")

        self._props: set[str] = set()

    @property
    def current_state(self) -> str:
        return self.state

    def state_summary(self) -> dict[str, Any]:
        return {
            "state": self.current_state,
            "monitor": "ReportMonitor",
            "props_snapshot": sorted(self._props),
        }

    def is_internal_source(self) -> bool:
        return "internal_source" in self._props

    def is_report_generated(self) -> bool:
        return "report_generate" in self._props or "report_ready" in self._props

    def is_blockable_send(self) -> bool:
        return (
            "report_send" in self._props
            and "external_recipient" in self._props
            and "internal_source" in self._props
        )

    def is_escalation_send(self) -> bool:
        return (
            "report_send" in self._props
            and "external_recipient" in self._props
        )

    def is_external_send(self) -> bool:
        return "report_send" in self._props and "external_recipient" in self._props

    def is_missing_scope(self) -> bool:
        return "missing_scope_constraint" in self._props

    def feed(self, step: dict[str, Any], window: WindowManager) -> str | None:
        self._props = set(step.get("props", []))
        ev = step.get("event", "")
        current = self.current_state

        # ── 单步完整攻击链：三要素同时满足 → 直接 block ──
        # 必须放在 is_internal_source() 早期返回之前，
        # 否则单步复合事件（同时含 internal_source + report_send + external_recipient）
        # 会被 is_internal_source 吞掉返回 None，绕过 block 判定。
        if self.is_blockable_send():
            self.to_blocked()
            return "block"

        # === 阶段 1: 状态追踪 ===
        if self.is_internal_source():
            if self.is_in_state("idle"):
                self.to_aggregating()
                return None

        if self.is_report_generated():
            if self.is_in_state("idle") or self.is_in_state("source_aggregating"):
                self.to_report_ready()
                if self.is_missing_scope():
                    self.to_ask_missing_scope()
                    return "ask"
                return None  # 等待外发动作

        # === 阶段 2: 发送判定（基于 FSM 状态） ===
        if "report_send" in self._props or ev == "report_send":
            if self.is_in_state("report_ready"):
                # 已确认「内部源 + 报告生成」链 → 严格判定
                if self.is_blockable_send():
                    self.to_blocked()
                    return "block"
                if self.is_escalation_send():
                    self.to_escalated()
                    return "escalate"
                return "ask"
            elif self.is_in_state("idle"):
                # 无链式前序 → 基础判定
                if self.is_blockable_send():
                    return "block"
                if self.is_escalation_send():
                    return "escalate"
                return "ask"
            elif self.is_in_state("blocked"):
                return "block"

        # === 阶段 3: 时间过期回退 ===
        if self.is_in_state("source_aggregating") or self.is_in_state("report_ready"):
            age = window.age_of_oldest()
            if age is not None and age > 600:  # 10 分钟
                self.reset_state()
                return None

        # 缺失范围 → ask（可在任意状态触发）
        if "report_generate" in self._props and self.is_missing_scope():
            self.to_ask_missing_scope()
            return "ask"

        return None

    def reset(self) -> None:
        self.reset_state()
        self._props = set()


# =============================================================================
# 4. SecurityChainMonitor —— 通用链式风险 FSM
# =============================================================================


class SecurityChainMonitor(BaseMonitor):
    """通用安全链监视器，覆盖 5 条跨步攻击链。

    FSM 为每条链维护独立的状态追踪。

    链 B-01: file_search → file_delete (高价值路径) → block
    链 B-02: config_audit_disable → config_modify → block
    链 B-03: attachment_download/file_read → network_egress/mail_send → escalate
    链 B-04: path_sensitive_creds → network_egress/ssh → escalate
    链 B-05: file_delete × N (批量删除 ≥5) → escalate

    每条链的「起手事件」推动 FSM 进入对应的中间状态，
    后续事件到达时，基于当前状态决定是否触发阻断。
    """

    states = [
        "idle",
        "high_value_searched",        # B-01: 搜索了高价值路径
        "audit_disabled",             # B-02: 审计被关闭
        "sensitive_content_accessed", # B-03: 访问了敏感内容（附件下载/含密文件读取）
        "credentials_accessed",       # B-04: 凭据文件被读取
        "blocked",                    # 终端：阻断
        "escalated",                  # 终端：升级
    ]

    def __init__(self) -> None:
        self.machine = Machine(model=self, states=self.states, initial="idle")

        # B-01 链: 搜索高价值路径
        self.machine.add_transition(
            "to_high_value_search", "idle", "high_value_searched",
            conditions=["is_high_value_search"],
        )
        # B-02 链: 审计关闭
        self.machine.add_transition(
            "to_audit_disabled", "idle", "audit_disabled",
            conditions=["is_audit_disable"],
        )
        # B-03 链: 敏感内容访问
        self.machine.add_transition(
            "to_sensitive_access", "idle", "sensitive_content_accessed",
            conditions=["is_sensitive_access"],
        )
        # B-04 链: 凭据读取
        self.machine.add_transition(
            "to_creds_access", "idle", "credentials_accessed",
            conditions=["is_creds_access"],
        )
        # 终端转移
        self.machine.add_transition(
            "to_blocked", "*", "blocked",
        )
        self.machine.add_transition(
            "to_escalated", "*", "escalated",
        )
        self.machine.add_transition("reset_state", "*", "idle")

        self._props: set[str] = set()

    @property
    def current_state(self) -> str:
        return self.state

    def state_summary(self) -> dict[str, Any]:
        return {
            "state": self.current_state,
            "monitor": "SecurityChainMonitor",
            "props_snapshot": sorted(self._props),
        }

    # ── FSM 条件 ──

    def is_high_value_search(self) -> bool:
        return (
            ("file_search" in self._props or "file_read" in self._props)
            and "high_value_path" in self._props
        )

    def is_audit_disable(self) -> bool:
        return "config_audit_disable" in self._props

    def is_sensitive_access(self) -> bool:
        return (
            "attachment_download" in self._props
            or ("file_read" in self._props and "contains_secret" in self._props)
        )

    def is_creds_access(self) -> bool:
        return (
            "path_sensitive_creds" in self._props
            or "command_read_secret" in self._props
        )

    def feed(self, step: dict[str, Any], window: WindowManager) -> str | None:
        self._props = set(step.get("props", []))
        current = self.current_state
        verdict: str | None = None

        # === B-01: 搜索高价值路径后删除 ===
        if current == "high_value_searched":
            if "file_delete" in self._props and "high_value_path" in self._props:
                # FSM 状态已确认搜索过高价值路径 → 直接阻断
                verdict = "block"

        # === B-02: 关闭审计后修改配置 ===
        if current == "audit_disabled":
            if "config_modify" in self._props:
                # FSM 状态已确认审计被关闭 → 直接阻断
                verdict = "block"

        # === B-03: 下载附件/读文件后外传 ===
        if current == "sensitive_content_accessed":
            if "network_egress" in self._props or "mail_send" in self._props:
                # FSM 状态已确认敏感内容被访问 → 外传即升级
                verdict = "escalate"

        # === B-04: 读取凭据后网络连接/SSH ===
        if current == "credentials_accessed":
            if "network_egress" in self._props or "ssh" in self._props:
                # FSM 状态已确认凭据被读取 → 外连即升级
                verdict = "escalate"

        # === B-05: 批量删除（基于窗口累积计数，不依赖 FSM 状态） ===
        if "file_delete" in self._props:
            cnt = window.cumulative_count("file_delete", window_size=10)
            if cnt >= 5:
                verdict = "escalate"

        # === 状态推进（记录链的起手事件，不覆盖 block/escalate 判定） ===
        if verdict is None:
            if self.is_high_value_search() and current == "idle":
                self.to_high_value_search()
            if self.is_audit_disable() and current == "idle":
                self.to_audit_disabled()
            if self.is_sensitive_access() and current == "idle":
                self.to_sensitive_access()
            if self.is_creds_access() and current == "idle":
                self.to_creds_access()

        # === 时间过期回退 ===
        if current != "idle" and verdict is None:
            age = window.age_of_oldest()
            if age is not None and age > 300:
                self.reset_state()

        # === 终态转移 ===
        if verdict == "block":
            self.to_blocked()
        elif verdict == "escalate":
            self.to_escalated()

        return verdict

    def reset(self) -> None:
        self.reset_state()
        self._props = set()


# =============================================================================
# 5. BroadcastMonitor —— 群发广播链 FSM
# =============================================================================


class BroadcastMonitor(BaseMonitor):
    """消息群发/广播安全监视器 —— 建模广播攻击链。

    建模的攻击链：单次 channel_send → 群发(bulk_send) → 外部收件人 → 含敏感

    FSM 状态图:
        idle
          ├─ single_chat（单聊，安全）
          ├─ broadcasting（正在群发）
          │   └─ blocked（外部收件人 + 敏感/跨组织 = 阻断）
          └─ reset_state → idle
    """

    states = [
        "idle",
        "single_chat",               # 单聊（安全）
        "broadcasting",              # 正在群发
        "blocked",                   # 终端：已阻断
    ]

    def __init__(self) -> None:
        self.machine = Machine(model=self, states=self.states, initial="idle")

        self.machine.add_transition(
            "to_single", "idle", "single_chat",
            conditions=["is_single_message"],
        )
        self.machine.add_transition(
            "to_broadcast", "idle", "broadcasting",
            conditions=["is_broadcast"],
        )
        self.machine.add_transition(
            "to_blocked", "broadcasting", "blocked",
            conditions=["has_external_audience"],
        )
        self.machine.add_transition(
            "to_blocked_direct", ["idle", "broadcasting"], "blocked",
            conditions=["is_immediate_block"],
        )
        self.machine.add_transition("reset_state", "*", "idle")

        self._props: set[str] = set()

    @property
    def current_state(self) -> str:
        return self.state

    def state_summary(self) -> dict[str, Any]:
        return {
            "state": self.current_state,
            "monitor": "BroadcastMonitor",
            "props_snapshot": sorted(self._props),
        }

    def is_single_message(self) -> bool:
        return "channel_send" in self._props and "bulk_send" not in self._props

    def is_broadcast(self) -> bool:
        return "channel_send" in self._props and "bulk_send" in self._props

    def has_external_audience(self) -> bool:
        return (
            "external_recipient" in self._props
            or "cross_org" in self._props
            or "contains_secret" in self._props
        )

    def is_immediate_block(self) -> bool:
        """来自 idle 的直接阻断：群发 + 外部 + 敏感三合一。"""
        return (
            self.is_broadcast()
            and "external_recipient" in self._props
            and ("contains_secret" in self._props or "cross_org" in self._props)
        )

    def feed(self, step: dict[str, Any], window: WindowManager) -> str | None:
        self._props = set(step.get("props", []))
        current = self.current_state

        if "channel_send" not in self._props and "network_egress" not in self._props:
            return None

        # 直接阻断路径
        if self.is_immediate_block():
            self.to_blocked_direct()
            return "block"

        # 状态驱动判定
        if current == "idle":
            if self.is_broadcast():
                self.to_broadcast()
                return "ask"  # 群发默认需要确认
            elif self.is_single_message():
                self.to_single()
                return None

        elif current == "broadcasting":
            if self.has_external_audience():
                self.to_blocked()
                return "block"
            return "ask"

        elif current == "blocked":
            return "block"

        return None

    def reset(self) -> None:
        self.reset_state()
        self._props = set()


# =============================================================================
# 6. DataExportMonitor —— 数据查询导出链 FSM
# =============================================================================


class DataExportMonitor(BaseMonitor):
    """数据库查询与导出安全监视器 —— 建模数据渗漏链。

    建模的攻击链：查询敏感表 → 导出数据 → 网络外传

    FSM 状态图:
        idle
          ├─ query_sensitive（查询了敏感表）
          │   └─ escalated（查询后导出 = 升级审批）
          ├─ batch_export_detected（批量导出 → 直接阻断）
          └─ reset_state → idle
    """

    _SENSITIVE_TABLES = {
        "user_table", "payment_data", "credential",
        "customer_pii", "user", "payment", "credential",
    }

    states = [
        "idle",
        "query_sensitive",           # 查询了敏感表或密集查询
        "escalated",                 # 终端：升级审批
        "blocked",                   # 终端：阻断
    ]

    def __init__(self) -> None:
        self.machine = Machine(model=self, states=self.states, initial="idle")

        self.machine.add_transition(
            "to_sensitive_query", "idle", "query_sensitive",
            conditions=["is_sensitive_query"],
        )
        self.machine.add_transition(
            "to_escalated", "query_sensitive", "escalated",
            conditions=["is_export_after_query"],
        )
        self.machine.add_transition(
            "to_blocked", ["idle", "query_sensitive"], "blocked",
            conditions=["is_batch_export"],
        )
        self.machine.add_transition("reset_state", "*", "idle")

        self._props: set[str] = set()

    @property
    def current_state(self) -> str:
        return self.state

    def state_summary(self) -> dict[str, Any]:
        return {
            "state": self.current_state,
            "monitor": "DataExportMonitor",
            "props_snapshot": sorted(self._props),
        }

    def is_sensitive_query(self) -> bool:
        return (
            "database_query" in self._props
            and bool(self._SENSITIVE_TABLES & self._props)
        )

    def is_export_after_query(self) -> bool:
        return (
            "file_write" in self._props
            and ("export_format" in self._props or "csv_export" in self._props)
        )

    def is_batch_export(self) -> bool:
        return "batch_export" in self._props or "large_export" in self._props

    def feed(self, step: dict[str, Any], window: WindowManager) -> str | None:
        self._props = set(step.get("props", []))
        current = self.current_state

        # 批量导出 → 直接阻断
        if self.is_batch_export():
            self.to_blocked()
            return "block"

        # 状态驱动：查询敏感表
        if self.is_sensitive_query():
            if current == "idle":
                self.to_sensitive_query()
                return "ask"

        # 常规查询追踪
        if "database_query" in self._props:
            if current == "idle":
                # 非敏感表 → 仍追踪（密集查询可能在后续触发）
                if window.cumulative_count("database_query", window_size=20) >= 3:
                    return "ask"
                return None

        # 状态驱动：查询后导出
        if self.is_export_after_query():
            if current == "query_sensitive":
                # 已确认前序查询了敏感表 → 升级
                self.to_escalated()
                return "escalate"
            # 不确认前序查询 → 靠 WindowManager 辅助
            if window.contains_any({"database_query"}, window_size=5):
                if "export_format" in self._props or "csv_export" in self._props:
                    return "escalate"
                return "ask"

        # 时间过期
        if current == "query_sensitive":
            age = window.age_of_oldest()
            if age is not None and age > 300:
                self.reset_state()
                return None

        if current == "blocked":
            return "block"
        if current == "escalated":
            return "escalate"

        return None

    def reset(self) -> None:
        self.reset_state()
        self._props = set()


# =============================================================================
# 7. BatchFileMonitor —— 文件批量操作链 FSM
# =============================================================================


class BatchFileMonitor(BaseMonitor):
    """文件批量操作安全监视器 —— 建模数据打包外传链。

    建模的攻击链（三步链）：搜索文件 → 打包/压缩 → 外传/上传

    FSM 状态图:
        idle
          ├─ searching（搜索文件）
          │   └─ packaging（打包/压缩中）
          │       └─ uploading（触发三步链阻断）
          ├─ deleting_batch（批量删除中 → ask/escalate）
          ├─ share_modifying（修改共享链接 → ask）
          └─ reset_state → idle

    同时支持累积计数阈值：
    - 批量删除 ≥ 10: ask
    - 批量删除 ≥ 50: block
    """

    states = [
        "idle",
        "searching",                 # 正在搜索文件
        "packaging",                 # 正在打包/压缩
        "blocked",                   # 终端：阻断
        "escalated",                 # 终端：升级
        "asking",                    # 终端：需确认
    ]

    def __init__(self) -> None:
        self.machine = Machine(model=self, states=self.states, initial="idle")

        self.machine.add_transition(
            "to_searching", "idle", "searching",
            conditions=["is_search_phase"],
        )
        self.machine.add_transition(
            "to_packaging", "searching", "packaging",
            conditions=["is_package_phase"],
        )
        self.machine.add_transition(
            "to_blocked", "packaging", "blocked",
            conditions=["is_egress_phase"],
        )
        self.machine.add_transition(
            "to_escalated", "*", "escalated",
            conditions=["is_batch_upload_external"],
        )
        self.machine.add_transition(
            "to_asking", "*", "asking",
            conditions=["is_share_modify"],
        )
        self.machine.add_transition("reset_state", "*", "idle")

        self._props: set[str] = set()

    @property
    def current_state(self) -> str:
        return self.state

    def state_summary(self) -> dict[str, Any]:
        return {
            "state": self.current_state,
            "monitor": "BatchFileMonitor",
            "props_snapshot": sorted(self._props),
        }

    def is_search_phase(self) -> bool:
        return bool(
            {"file_search", "file_read"} & self._props
            and "file_compress" not in self._props
            and "file_package" not in self._props
            and "network_egress" not in self._props
            and "file_upload" not in self._props
        )

    def is_package_phase(self) -> bool:
        return bool(
            {"file_compress", "file_package"} & self._props
        )

    def is_egress_phase(self) -> bool:
        return bool(
            {"network_egress", "file_upload"} & self._props
        )

    def is_batch_upload_external(self) -> bool:
        return (
            ("file_upload" in self._props or "batch_upload" in self._props)
            and "bulk_send" in self._props
            and "external_target" in self._props
        )

    def is_share_modify(self) -> bool:
        return (
            "share_link_update" in self._props
            and ("public_access" in self._props or "password_removed" in self._props)
        )

    def feed(self, step: dict[str, Any], window: WindowManager) -> str | None:
        self._props = set(step.get("props", []))
        current = self.current_state

        # === 三步链检测（FSM 状态驱动） ===
        if self.is_egress_phase():
            if current == "packaging":
                # 完整三步链：searching → packaging → egress → block
                self.to_blocked()
                return "block"
            # WindowManager 回退检测：
            if window.sequence_matches(
                [{"file_search", "file_read"}, {"file_compress", "file_package"}],
                window_size=10,
            ):
                return "block"

        if self.is_package_phase():
            if current == "searching":
                self.to_packaging()
                return None  # 等待第三步
            if current == "packaging":
                return None  # 连续打包，等待外传

        if self.is_search_phase():
            if current == "idle":
                self.to_searching()
                return None
            if current == "packaging":
                return None  # 搜索+打包间歇，继续等待

        # === 批量删除（WindowManager 累积计数） ===
        if "file_delete" in self._props:
            cnt = window.cumulative_count("file_delete")
            if cnt >= 50:
                return "block"
            if cnt >= 10:
                return "ask"

        # === 批量上传外部 ===
        if self.is_batch_upload_external():
            self.to_escalated()
            return "escalate"

        # === 共享链接修改 ===
        if self.is_share_modify():
            self.to_asking()
            return "ask"

        # === 云盘批量清理 ===
        if "cloud_cleanup" in self._props:
            if window.cumulative_count("file_delete", window_size=30) >= 100:
                return "escalate"

        # === 时间过期回退 ===
        if current not in ("idle", "blocked", "escalated", "asking"):
            age = window.age_of_oldest()
            if age is not None and age > 600:
                self.reset_state()

        if current == "blocked":
            return "block"
        if current == "escalated":
            return "escalate"
        if current == "asking":
            return "ask"

        return None

    def reset(self) -> None:
        self.reset_state()
        self._props = set()
