from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
RiskLevel = Literal["safe", "caution", "dangerous", "blocked"]
DecisionAction = Literal["allow", "ask", "block", "escalate"]
ActionType = Literal["chat_message", "command_exec", "file_delete", "file_write", "config_modify", "network_egress", "channel_send", "skill_run"]
EventStatus = Literal["proposed", "pending_approval", "approved", "rejected", "blocked", "executing", "executed", "failed"]


@dataclass
class AssetRecord:
    category: str
    name: str
    value: str
    detail: str = ""
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BaselineFinding:
    finding_id: str
    severity: Severity
    category: str
    title: str
    description: str
    evidence: dict[str, Any]
    recommendation: str
    compliant: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BaselineCheck:
    check_id: str
    category: str
    title: str
    status: Literal["ok", "warn", "risk"]
    severity: Severity
    description: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ComplianceReport:
    generated_at: str
    target_root: str | None
    config_path: str | None
    findings: list[BaselineFinding]
    checks: list[BaselineCheck] = field(default_factory=list)
    assets: list[AssetRecord] = field(default_factory=list)
    average_seconds: float = 0.0
    outputs: dict[str, str] = field(default_factory=dict)

    def summary(self) -> dict[str, int]:
        payload = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            payload[finding.severity] += 1
        return payload

    def to_dict(self) -> dict[str, Any]:
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


@dataclass
class BehaviorEvent:
    event_id: str
    timestamp: str
    action_type: ActionType
    process_name: str
    pid: int | None
    user: str | None
    command: str | None = None
    target_paths: list[str] = field(default_factory=list)
    network_targets: list[str] = field(default_factory=list)
    api_name: str | None = None
    skill_name: str | None = None
    channel_name: str | None = None
    raw_payload: dict[str, Any] = field(default_factory=dict)
    source: str = "hook"
    working_directory: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DetectionRule:
    rule_id: str
    title: str
    description: str
    action_types: list[ActionType]
    severity: Severity
    risk_level: RiskLevel
    decision: DecisionAction
    tags: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    path_prefixes: list[str] = field(default_factory=list)
    command_prefixes: list[str] = field(default_factory=list)
    network_patterns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DetectionDecision:
    event_id: str
    timestamp: str
    action_type: ActionType
    risk_level: RiskLevel
    action: DecisionAction
    reason: str
    rule_ids: list[str] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)
    requires_second_confirmation: bool = False
    confirmation_word: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ControlledAction:
    action_id: str
    source_message: str
    created_at: str
    status: EventStatus
    event: BehaviorEvent
    decision: DetectionDecision
    target_summary: str
    decision_trace: list[dict[str, Any]] = field(default_factory=list)
    matched_whitelists: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    execution_result: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.event, dict):
            self.event = BehaviorEvent(**self.event)
        if isinstance(self.decision, dict):
            self.decision = DetectionDecision(**self.decision)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["event"] = self.event.to_dict()
        payload["decision"] = self.decision.to_dict()
        return payload


@dataclass
class AuditRecord:
    record_id: str
    timestamp: str
    record_type: str
    payload: dict[str, Any]
    previous_hash: str
    record_hash: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CapabilityStatus:
    name: str
    available: bool
    mode: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
