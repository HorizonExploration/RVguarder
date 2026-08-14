"""核心数据模型（Pydantic v2）。

从 v0.2.1 的 @dataclass 迁移至 pydantic.BaseModel：
- to_dict() 保留为兼容别名 → model_dump()
- ControlledAction.__post_init__ 移除（pydantic 原生支持嵌套模型自动转换）
- EventStatus 新增 "allow" 兼容状态
- ActionType 新增 "unknown" 兜底类型

行为注意事项：
- 模型保持可变（非 frozen），维持现有代码中大量 in-place 字段赋值的兼容性
- validate_assignment=False（pydantic 默认），允许非验证的字段赋值
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


# ─── 类型别名 ────────────────────────────────────────────────────

Severity = Literal["critical", "high", "medium", "low", "info"]
RiskLevel = Literal["safe", "caution", "dangerous", "blocked"]
DecisionAction = Literal["allow", "ask", "block", "escalate", "revise"]
ActionType = Literal[
    "chat_message", "command_exec", "file_delete", "file_write",
    "config_modify", "network_egress", "channel_send", "skill_run",
    "unknown",  # 兜底：来自外部原始 payload 的未识别类型
]
EventStatus = Literal[
    "proposed", "pending_approval", "approved", "rejected",
    "blocked", "executing", "executed", "failed",
    "allow",  # 兼容：auto-allow 路径设置的运行时状态
]


# ─── 基础类 ──────────────────────────────────────────────────────

class GuardBaseModel(BaseModel):
    """项目的 BaseModel 基类，统一配置。

    - mutable（非 frozen）：现有代码大量使用 action.status = "xxx" 式 in-place 赋值
    - extra="ignore"：容错外部原始 payload 中的额外字段
    - 保留 to_dict() 兼容别名，阶段二可逐步替换为 model_dump()
    """

    model_config = ConfigDict(
        extra="ignore",
        validate_assignment=False,
    )

    def to_dict(self) -> dict[str, Any]:
        """兼容旧 @dataclass 接口，等同于 model_dump()。"""
        return self.model_dump()


# ─── 模型定义 ────────────────────────────────────────────────────


class AssetRecord(GuardBaseModel):
    category: str
    name: str
    value: str
    detail: str = ""
    source: str = ""


class BaselineFinding(GuardBaseModel):
    finding_id: str
    severity: Severity
    category: str
    title: str
    description: str
    evidence: dict[str, Any]
    recommendation: str
    compliant: bool = False


class BaselineCheck(GuardBaseModel):
    check_id: str
    category: str
    title: str
    status: Literal["ok", "warn", "risk"]
    severity: Severity
    description: str
    recommendation: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class ComplianceReport(GuardBaseModel):
    generated_at: str
    target_root: str | None
    config_path: str | None
    findings: list[BaselineFinding]
    checks: list[BaselineCheck] = Field(default_factory=list)
    assets: list[AssetRecord] = Field(default_factory=list)
    average_seconds: float = 0.0
    outputs: dict[str, str] = Field(default_factory=dict)

    # ── 计算属性 ────────────────────────────────────────────────

    def summary(self) -> dict[str, int]:
        """各严重度发现计数。"""
        payload: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            sev = finding.severity
            if sev in payload:
                payload[sev] += 1
        return payload

    def to_dict(self) -> dict[str, Any]:
        """带 computed summary 的自定义序列化。"""
        return {
            "generated_at": self.generated_at,
            "target_root": self.target_root,
            "config_path": self.config_path,
            "summary": self.summary(),
            "findings": [item.to_dict() for item in self.findings],
            "checks": [item.to_dict() for item in self.checks],
            "assets": [item.to_dict() for item in self.assets],
            "average_seconds": self.average_seconds,
            "outputs": self.outputs,
        }


class BehaviorEvent(GuardBaseModel):
    event_id: str
    timestamp: str
    action_type: ActionType
    process_name: str
    pid: int | None
    user: str | None
    command: str | None = None
    target_paths: list[str] = Field(default_factory=list)
    network_targets: list[str] = Field(default_factory=list)
    api_name: str | None = None
    skill_name: str | None = None
    channel_name: str | None = None
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    source: str = "hook"
    working_directory: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class DetectionRule(GuardBaseModel):
    rule_id: str
    title: str
    description: str
    action_types: list[ActionType]
    severity: Severity
    risk_level: RiskLevel
    decision: DecisionAction
    # 单一数据源：规则匹配所需的语义标签（由 SemanticEnhancer 产出）。
    # 匹配条件 = action_types 命中 且 match_labels 全部命中。
    match_labels: list[str] = Field(default_factory=list)


class DetectionDecision(GuardBaseModel):
    event_id: str
    timestamp: str
    action_type: ActionType
    risk_level: RiskLevel
    action: DecisionAction
    reason: str
    rule_ids: list[str] = Field(default_factory=list)
    trace: list[dict[str, Any]] = Field(default_factory=list)
    requires_second_confirmation: bool = False
    confirmation_word: str | None = None
    # 阶段 F：revise 干预携带的修正建议文本（session 风险升级时透出）
    revision_hint: str | None = None


class ControlledAction(GuardBaseModel):
    action_id: str
    source_message: str
    created_at: str
    status: EventStatus
    event: BehaviorEvent
    decision: DetectionDecision
    target_summary: str
    decision_trace: list[dict[str, Any]] = Field(default_factory=list)
    matched_whitelists: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    execution_result: dict[str, Any] = Field(default_factory=dict)

    # __post_init__ 移除 — pydantic 在构造时自动将嵌套 dict 转换
    # 为 BehaviorEvent / DetectionDecision 实例。

    def to_dict(self) -> dict[str, Any]:
        """自定义序列化：确保嵌套 model 也输出为 dict。"""
        return {
            "action_id": self.action_id,
            "source_message": self.source_message,
            "created_at": self.created_at,
            "status": self.status,
            "event": self.event.to_dict(),
            "decision": self.decision.to_dict(),
            "target_summary": self.target_summary,
            "decision_trace": self.decision_trace,
            "matched_whitelists": self.matched_whitelists,
            "matched_rules": self.matched_rules,
            "execution_result": self.execution_result,
        }


class AuditRecord(GuardBaseModel):
    record_id: str
    timestamp: str
    record_type: str
    payload: dict[str, Any]
    previous_hash: str
    record_hash: str


class CapabilityStatus(GuardBaseModel):
    name: str
    available: bool
    mode: str
    detail: str
