"""
办公场景 RV 监视器定义。

每个监视器代表一个业务场景的安全 FSM（有限状态机），
消费语义层产出的 rv_trace 事件步，返回 RV 判定。

包含：
- MailMonitor / ReportMonitor / SecurityChainMonitor（原 6 类场景）
- BroadcastMonitor / DataExportMonitor / BatchFileMonitor（P0 新增 3 类）
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from transitions import Machine

from openclaw_guard.engine.runtime_verification import WindowManager


# =============================================================================
# 1. 基类
# =============================================================================


class BaseMonitor(ABC):
    """所有 RV 监视器的抽象基类。"""

    @abstractmethod
    def feed(self, step: dict[str, Any], window: WindowManager) -> str | None:
        """处理一个新的事件步。

        Args:
            step: rv_trace 中的单步事件，含 event/props 字段
            window: 当前滑动窗口（可查询历史步）

        Returns:
            "block" | "ask" | "escalate" | None（无判定，继续下一监视器）
        """
        ...

    def reset(self) -> None:
        """重置 FSM 状态为初始值。子类按需重写。"""


# =============================================================================
# 2. 邮件场景监视器
# =============================================================================


class MailMonitor(BaseMonitor):
    """邮件发送安全监视器。

    FSM:
      idle → mailing（收到 mail_send 事件）
      mailing → blocked（外部收件人 + 敏感内容）
      mailing → ask_approval（群发或 AI 内容未审阅）

    多步链：
      file_search + high_value_path → file_delete → block
    """

    states = ["idle", "mailing", "blocked", "ask_approval"]

    def __init__(self) -> None:
        self.machine = Machine(model=self, states=self.states, initial="idle")
        self.machine.add_transition("start_mail", "idle", "mailing")
        self.machine.add_transition(
            "block_send", "mailing", "blocked",
            conditions=["has_external_secret"],
        )
        self.machine.add_transition(
            "ask_send", "mailing", "ask_approval",
            conditions=["needs_approval"],
        )
        self.machine.add_transition("reset_state", "*", "idle")
        self._current_props: set[str] = set()

    # ---- FSM 条件 ----

    def has_external_secret(self) -> bool:
        return (
            "external_recipient" in self._current_props
            and "contains_secret" in self._current_props
        )

    def needs_approval(self) -> bool:
        return (
            "bulk_send" in self._current_props
            or (
                "ai_generated_content" in self._current_props
                and "human_reviewed" not in self._current_props
            )
        )

    # ---- 核心入口 ----

    def feed(self, step: dict[str, Any], window: WindowManager) -> str | None:
        self._current_props = set(step.get("props", []))
        ev = step.get("event", "")

        # 单步：mail_send
        if "mail_send" in self._current_props or ev == "mail_send":
            self.start_mail()
            if self.has_external_secret():
                self.block_send()
                return "block"
            if self.needs_approval():
                self.ask_send()
                return "ask"
            return None

        # 多步链：搜索高价值文件后删除
        if "file_delete" in self._current_props and "high_value_path" in self._current_props:
            if window.contains_any({"file_search", "file_read"}, window_size=5):
                return "block"

        return None

    def reset(self) -> None:
        self.reset_state()


# =============================================================================
# 3. 日报场景监视器
# =============================================================================


class ReportMonitor(BaseMonitor):
    """日报生成/外发安全监视器。

    FSM:
      idle → generating（日报生成）
      generating → blocked（内部来源 + 外部发送）
      generating → sending_external（外部发送，需 ask）
    """

    states = ["idle", "generating", "sending_external", "blocked"]

    def __init__(self) -> None:
        self.machine = Machine(model=self, states=self.states, initial="idle")
        self.machine.add_transition("generate", "idle", "generating")
        self.machine.add_transition(
            "send_ext", ["idle", "generating"], "sending_external",
            conditions=["has_internal_source"],
        )
        self.machine.add_transition("block_send", "sending_external", "blocked")
        self.machine.add_transition("reset_state", "*", "idle")
        self._props: set[str] = set()

    def has_internal_source(self) -> bool:
        return "internal_source" in self._props

    def feed(self, step: dict[str, Any], window: WindowManager) -> str | None:
        self._props = set(step.get("props", []))
        ev = step.get("event", "")

        if "report_generate" in self._props or ev == "report_generate":
            self.generate()
            if "missing_scope_constraint" in self._props:
                return "ask"
            return None

        if "report_send" in self._props or ev == "report_send":
            self.send_ext()
            if self.has_internal_source() and "external_recipient" in self._props:
                self.block_send()
                return "block"
            if "external_recipient" in self._props:
                return "ask"
            return None

        return None

    def reset(self) -> None:
        self.reset_state()


# =============================================================================
# 4. 链式组合风险监视器
# =============================================================================


class SecurityChainMonitor(BaseMonitor):
    """链式组合风险监视器。

    覆盖原 6 类特殊场景中的链式风险：
    - 搜索敏感路径后删除 → block
    - 关闭审计后改配置 → block
    - 下载附件后外传 → escalate
    - 批量删除超出阈值 → escalate
    - 读取凭据后网络连接 → escalate（越权提升）
    """

    def feed(self, step: dict[str, Any], window: WindowManager) -> str | None:
        props = set(step.get("props", []))

        # B-01: 搜索敏感路径后删除
        if "file_delete" in props and "high_value_path" in props:
            if window.contains_any({"file_search", "file_read"}, window_size=5):
                return "block"

        # B-02: 关闭审计后改配置
        if "config_modify" in props:
            if window.contains_any({"config_audit_disable"}, window_size=10):
                return "block"

        # B-03: 下载附件后外传
        if "network_egress" in props or "mail_send" in props:
            if window.contains_any(
                {"attachment_download", "file_read", "contains_secret"},
                window_size=8,
            ):
                return "escalate"

        # B-04: 越权提升（读取敏感凭据后网络连接）
        if "network_egress" in props or "ssh" in props:
            if window.contains_any(
                {"path_sensitive_creds", "command_read_secret"},
                window_size=10,
            ):
                return "escalate"

        # B-05: 批量删除超阈值
        if "file_delete" in props:
            cnt = window.cumulative_count("file_delete", window_size=10)
            if cnt >= 5:
                return "escalate"

        return None


# =============================================================================
# 5. P0 新增：消息群发/广播监视器
# =============================================================================


class BroadcastMonitor(BaseMonitor):
    """消息群发/广播安全监视器。

    FSM:
      idle → single_chat（单聊，安全）
      idle → broadcast（群发/广播，需审批）
      broadcast → blocked（含外部成员/敏感内容）
      broadcast → need_approval（默认，需确认发送清单）

    适用场景：EX-10 消息群发、EX-11 文件分享到群聊、SR-04 会议通知群发。
    """

    states = ["idle", "single_chat", "broadcast", "blocked"]

    def __init__(self) -> None:
        self.machine = Machine(model=self, states=self.states, initial="idle")
        self.machine.add_transition("to_broadcast", "*", "broadcast",
            conditions=["is_broadcast"])
        self.machine.add_transition("to_single", "*", "single_chat",
            conditions=["is_single_message"])
        self.machine.add_transition("block_bc", "broadcast", "blocked",
            conditions=["has_external_audience"])
        self.machine.add_transition("reset_state", "*", "idle")
        self._props: set[str] = set()

    def is_broadcast(self) -> bool:
        return "channel_send" in self._props and "bulk_send" in self._props

    def is_single_message(self) -> bool:
        return "channel_send" in self._props and not self.is_broadcast()

    def has_external_audience(self) -> bool:
        return (
            "external_recipient" in self._props
            or "cross_org" in self._props
            or "contains_secret" in self._props
        )

    def feed(self, step: dict[str, Any], window: WindowManager) -> str | None:
        self._props = set(step.get("props", []))
        ev = step.get("event", "")

        if "channel_send" not in self._props and "network_egress" not in self._props:
            return None

        if self.is_broadcast():
            self.to_broadcast()
            if self.has_external_audience():
                self.block_bc()
                return "block"
            return "ask"  # 群发默认需人工确认

        if self.is_single_message():
            self.to_single()
            return None

        return None


# =============================================================================
# 6. P0 新增：数据库查询与导出监视器
# =============================================================================


class DataExportMonitor(BaseMonitor):
    """数据库查询与导出安全监视器。

    适用场景：EX-19 数据库查询与导出、EX-20 批量数据导入/更新。

    关键 RV 规则：
    - 查询敏感表（user/payment/credential）→ ask
    - 查询后立即导出（file_write + export）→ escalate
    - 批量导出（batch_export/large_export）→ block
    """

    _SENSITIVE_TABLES = {"user_table", "payment_data", "credential",
                         "customer_pii", "user", "payment", "credential"}

    def feed(self, step: dict[str, Any], window: WindowManager) -> str | None:
        props = set(step.get("props", []))
        ev = step.get("event", "")

        # 数据库查询
        if "database_query" in props or ev == "database_query":
            if self._SENSITIVE_TABLES & props:
                return "ask"
            if window.cumulative_count("database_query", window_size=20) >= 3:
                return "ask"  # 短时间内密集查询
            return None

        # 导出操作（file_write + export 标签）
        if "file_write" in props:
            if window.contains_any({"database_query"}, window_size=5):
                if "export_format" in props or "csv_export" in props or "large_export" in props:
                    return "escalate"
                return "ask"
            return None

        # 批量导出
        if "batch_export" in props or "large_export" in props:
            return "block"

        return None


# =============================================================================
# 7. P0 新增：文件批量操作监视器
# =============================================================================


class BatchFileMonitor(BaseMonitor):
    """文件批量操作安全监视器。

    适用场景：EX-27 文件批量上传/下载、EX-28 共享链接生成/修改、PO-07 云盘清理。

    关键 RV 规则：
    - "搜索→打包→外传"三步链 → block
    - 批量删除（累积 >= 10 ask, >= 50 block）
    - 共享链接改为公开/移除密码 → ask
    - 批量上传到外部目标 → escalate
    """

    def feed(self, step: dict[str, Any], window: WindowManager) -> str | None:
        props = set(step.get("props", []))
        ev = step.get("event", "")

        # 三步链：搜索文件 → 打包 → 外传
        if "network_egress" in props or "file_upload" in props:
            if window.sequence_matches([
                {"file_search", "file_read"},
                {"file_compress", "file_package"},
            ], window_size=10):
                return "block"

        # 批量删除
        if "file_delete" in props:
            cnt = window.cumulative_count("file_delete", window_size=20)
            if cnt >= 50:
                return "block"
            if cnt >= 10:
                return "ask"

        # 共享链接权限变更
        if "share_link_update" in props:
            if "public_access" in props:
                return "ask"
            if "password_removed" in props:
                return "ask"

        # 批量上传到外部目标
        if ("file_upload" in props or "batch_upload" in props) and "bulk_send" in props:
            if "external_target" in props:
                return "escalate"
            return "ask"

        # 云盘批量清理（高频删除 + 无备份）
        if "cloud_cleanup" in props or ev == "cloud_cleanup":
            if window.cumulative_count("file_delete", window_size=30) >= 100:
                return "escalate"

        return None
