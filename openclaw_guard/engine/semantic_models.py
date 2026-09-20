"""Validated, privacy-bounded semantic evidence exchanged with an LLM.

The model is deliberately smaller than the authorization trace.  It can name
known operation families and suggest controlled facts, but it cannot express
an authorization decision.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, StrictBool, StrictFloat, StrictInt, StrictStr, field_validator, model_validator

from openclaw_guard.engine.command_safety import analyze_command
from openclaw_guard.models import BehaviorEvent, GuardBaseModel


ALLOWED_OPERATION_FAMILIES = frozenset(
    {
        "message.send", "directory.read", "document.read", "document.write",
        "table.read", "data.export", "data.query", "file.bulk_transfer",
        "calendar.modify", "meeting.create", "workflow.approve", "event.subscribe",
        "network.egress", "browser.interact", "session.manage", "session.send",
        "session.control", "conversation.read", "conversation.send", "agent.spawn",
        "automation.modify", "gateway.modify", "user.interaction", "progress.write",
        "node.control", "computer.control", "ui.modify", "screen.read",
        "dashboard.read", "config.modify", "secret.read", "credential.read",
        "file.read", "file.delete", "process.execute", "file.write",
        "session.token.read", "identity.permission.grant", "identity.auth.modify",
        "audit.modify", "session.read", "memory.read", "goal.read", "goal.write",
        "plan.write", "agents.read", "conversation.message", "skill.execute",
    }
)

# Fact names are a closed protocol.  Their value types are validated as well,
# so arbitrary model text cannot become an evaluator predicate.
ALLOWED_SECURITY_FACTS: dict[str, type] = {
    "command.recursive_delete": bool,
    "command.download_pipe_execute": bool,
    "command.download_pipe_curl": bool,
    "command.download_pipe_wget": bool,
    "command.privileged": bool,
    "command.remote_shell": bool,
    "command.remote_copy": bool,
    "command.permission_change": bool,
    "command.owner_change": bool,
    "command.move": bool,
    "command.delete": bool,
    "command.delete_intent": bool,
    "command.read_only": bool,
    "resource.system_path": bool,
    "resource.sensitive_credentials": bool,
    "resource.log_path": bool,
    "resource.high_value": bool,
    "resource.openclaw_config": bool,
    "resource.script": bool,
    "resource.unresolved": bool,
    "resource.target_count": int,
    "network.http": bool,
    "network.public_ip": bool,
    "network.webhook": bool,
    "network.upload": bool,
    "network.secret_payload": bool,
    "network.proxy_change": bool,
    "channel.external": bool,
    "channel.admin": bool,
    "channel.present": bool,
    "channel.bulk": bool,
    "skill.shell": bool,
    "skill.network": bool,
    "skill.delete": bool,
    "skill.write": bool,
    "skill.persistence": bool,
    "skill.system_admin": bool,
    "config.provider_change": bool,
    "config.auth_disable": bool,
    "config.approval_bypass": bool,
    "config.sandbox_disable": bool,
    "config.audit_disable": bool,
    "data.sensitive": bool,
    "destination.external": bool,
}

_SECRET_VALUE_RE = re.compile(
    r"(?i)(?P<prefix>(?:api[_ -]?key|token|secret|password|passwd|authorization|cookie)"
    r"\s*[:=]\s*(?:bearer\s+)?)[^\s,;]+"
)
_BEARER_RE = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+")
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b", re.IGNORECASE)
_ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9])(?:/[A-Za-z0-9._~@%+,:=-]+){2,}")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [^-]*(?:PRIVATE KEY|OPENSSH PRIVATE KEY)-----.*?-----END [^-]+-----",
    re.DOTALL | re.IGNORECASE,
)


class OperationCandidate(GuardBaseModel):
    family: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str = Field(default="", max_length=160)

    @field_validator("family")
    @classmethod
    def validate_family(cls, value: str) -> str:
        if value not in ALLOWED_OPERATION_FAMILIES:
            raise ValueError("unknown operation family")
        return value


class FactEvidence(GuardBaseModel):
    value: StrictBool | StrictInt | StrictFloat | StrictStr
    source: Literal["deterministic", "llm", "local"]
    trust: Literal["verified", "suggested"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str = Field(default="", max_length=160)


class SemanticMatchIR(GuardBaseModel):
    version: Literal["v3"] = "v3"
    engine: str = "llm"
    operation_candidates: list[OperationCandidate] = Field(default_factory=list, max_length=3)
    facts: dict[str, FactEvidence] = Field(default_factory=dict)
    entities: dict[str, Any] = Field(default_factory=dict)
    constraints: dict[str, Any] = Field(default_factory=dict)
    uncertainties: list[str] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def validate_fact_protocol(self) -> "SemanticMatchIR":
        for name, evidence in self.facts.items():
            expected = ALLOWED_SECURITY_FACTS.get(name)
            if expected is None:
                raise ValueError(f"unknown security fact: {name}")
            value = evidence.value
            if expected is bool and type(value) is not bool:
                raise ValueError(f"fact {name} requires boolean value")
            if expected is int and (type(value) is not int or value < 0):
                raise ValueError(f"fact {name} requires non-negative integer value")
        allowed_entities = {"tool_name", "destination_kind", "resource_kind", "recipient_zone"}
        allowed_constraints = {"has_scope_constraint", "requires_human_review", "scope_hint"}
        if set(self.entities) - allowed_entities:
            raise ValueError("unknown semantic entity")
        if set(self.constraints) - allowed_constraints:
            raise ValueError("unknown semantic constraint")
        return self


def parse_semantic_match_response(content: str) -> SemanticMatchIR | None:
    """Parse one LLM response and force all model evidence to suggested trust."""

    try:
        payload = json.loads(content)
        if not isinstance(payload, dict):
            return None
        if "operation_candidates" not in payload or "facts" not in payload:
            return None
        raw_facts = payload.get("facts", {})
        if not isinstance(raw_facts, dict):
            return None
        for raw in raw_facts.values():
            if not isinstance(raw, dict):
                return None
            raw["source"] = "llm"
            raw["trust"] = "suggested"
        payload["version"] = "v3"
        payload["engine"] = str(payload.get("engine") or "llm")
        return SemanticMatchIR.model_validate(payload)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def build_sanitized_llm_input(
    event: BehaviorEvent,
    source_message: str,
    tool_name: str,
) -> dict[str, Any]:
    """Build the only payload permitted to enter an external semantic prompt."""

    command = analyze_command(event.command)
    command_traits = list(command.reason_codes)
    raw_command = str(event.command or "").lower()
    if re.search(r"\b(?:curl|wget)\b.*\|\s*(?:sh|bash)\b", raw_command):
        command_traits.append("download_pipe_execute")
    if command.classification == "privileged":
        command_traits.append("privileged")
    if command.safe_read_only:
        command_traits.append("read_only")

    path_traits = sorted({trait for path in event.target_paths for trait in _path_traits(path)})
    network_traits = sorted({trait for target in event.network_targets for trait in _network_traits(target)})
    return {
        "schema": "semantic-match-input-v1",
        "tool": {"name": _safe_identifier(tool_name), "known_profile": event.action_type != "unknown"},
        "action": {"type": event.action_type, "source": _safe_identifier(event.source)},
        "parameters": {
            "has_command": bool(event.command),
            "command_class": command.classification,
            "command_traits": sorted(set(command_traits)),
            "target_path_count": len(event.target_paths),
            "path_traits": path_traits,
            "network_target_count": len(event.network_targets),
            "network_traits": network_traits,
            "has_channel": bool(event.channel_name),
            "has_api": bool(event.api_name),
            "has_skill": bool(event.skill_name),
            "outside_workspace": bool(event.metadata.get("outside_workspace")),
        },
        "user_intent": _sanitize_text(source_message),
    }


def local_semantic_match(event: BehaviorEvent, *, engine: str = "builtin-fallback") -> SemanticMatchIR:
    family_by_action = {
        "command_exec": "process.execute",
        "file_read": "file.read",
        "file_delete": "file.delete",
        "file_write": "file.write",
        "config_modify": "config.modify",
        "network_egress": "network.egress",
        "channel_send": "message.send",
        "skill_run": "skill.execute",
        "chat_message": "conversation.message",
    }
    family = family_by_action.get(event.action_type)
    candidates = (
        [OperationCandidate(family=family, confidence=1.0, evidence="deterministic action mapping")]
        if family else []
    )
    facts: dict[str, FactEvidence] = {}
    command = analyze_command(event.command)
    raw_command = str(event.command or "").strip().lower()
    raw_text = " ".join(
        (
            raw_command,
            json.dumps(event.raw_payload, ensure_ascii=False, sort_keys=True).lower(),
            str(event.channel_name or "").lower(),
            str(event.skill_name or "").lower(),
        )
    )
    if event.command:
        _add_verified(facts, "command.read_only", command.safe_read_only, "command parser")
        _add_verified(
            facts,
            "command.recursive_delete",
            "recursive_delete" in command.reason_codes,
            "command parser",
        )
        _add_verified(
            facts,
            "command.download_pipe_execute",
            bool(re.search(r"\b(?:curl|wget)\b.*\|\s*(?:sh|bash)\b", event.command.lower())),
            "command parser",
        )
        _add_verified(facts, "command.download_pipe_curl", bool(re.search(r"\bcurl\b.*\|\s*(?:sh|bash)\b", raw_command)), "command parser")
        _add_verified(facts, "command.download_pipe_wget", bool(re.search(r"\bwget\b.*\|\s*(?:sh|bash)\b", raw_command)), "command parser")
        _add_verified(facts, "command.privileged", command.classification == "privileged", "command parser")
        _add_verified(facts, "command.remote_shell", _command_starts(raw_command, "ssh"), "command parser")
        _add_verified(facts, "command.remote_copy", _command_starts(raw_command, "scp"), "command parser")
        _add_verified(facts, "command.permission_change", _command_starts(raw_command, "chmod"), "command parser")
        _add_verified(facts, "command.owner_change", _command_starts(raw_command, "chown"), "command parser")
        _add_verified(facts, "command.move", _command_starts(raw_command, "mv"), "command parser")
        _add_verified(facts, "command.delete", _command_starts(raw_command, "rm"), "command parser")
        _add_verified(
            facts,
            "command.delete_intent",
            any(token in raw_text for token in (" delete ", " remove ", "删除", "移除")),
            "structured intent classifier",
        )
    _add_verified(facts, "resource.target_count", len(event.target_paths), "event shape")
    _add_verified(facts, "resource.unresolved", not bool(event.target_paths), "event shape")
    for name in ("system_path", "sensitive_credentials", "log_path", "high_value", "openclaw_config", "script"):
        _add_verified(
            facts,
            f"resource.{name}",
            any(name in _path_traits(path) for path in event.target_paths),
            "path classifier",
        )
    for name in ("http", "public_ip", "webhook"):
        _add_verified(
            facts,
            f"network.{name}",
            any(name in _network_traits(target) for target in event.network_targets),
            "destination classifier",
        )
    structured_checks = {
        "network.upload": any(token in raw_text for token in ("upload", "send file", "post data", "上传", "外发")),
        "network.secret_payload": any(token in raw_text for token in ("token", "secret", "password", "api_key", "api key")),
        "network.proxy_change": any(token in raw_text for token in ("proxy", "代理")),
        "channel.external": _has_external_recipient(raw_text),
        "channel.admin": any(token in raw_text for token in ("admin", "管理员")),
        "channel.present": event.action_type == "channel_send" or bool(event.channel_name),
        "channel.bulk": len(_EMAIL_RE.findall(raw_text)) > 1 or any(token in raw_text for token in ("broadcast", "群发", "bcc")),
        "skill.shell": any(token in raw_text for token in ("shell", "exec")),
        "skill.network": any(token in raw_text for token in ("webhook", "requests", "axios", "network")),
        "skill.delete": any(token in raw_text for token in ("delete", "remove file", "删除")),
        "skill.write": any(token in raw_text for token in ("write file", "overwrite", "写入")),
        "skill.persistence": any(token in raw_text for token in ("autorun", "daemon", "startup", "守护", "自启动")),
        "skill.system_admin": any(token in raw_text for token in ("sudo", "ssh", "system admin", "系统管理")),
        "config.provider_change": any(token in raw_text for token in ("baseurl", "endpoint", "provider", "模型配置", "网关配置")),
        "config.auth_disable": _disabled_near(raw_text, ("auth", "鉴权")),
        "config.approval_bypass": any(token in raw_text for token in ("bypass", "allow_all", "审批绕过")),
        "config.sandbox_disable": _disabled_near(raw_text, ("sandbox", "沙箱")),
        "config.audit_disable": _disabled_near(raw_text, ("audit", "logging", "审计", "日志")),
        "data.sensitive": any(
            bool(value)
            for value in (
                any(name in _path_traits(path) for path in event.target_paths for name in ("sensitive_credentials", "high_value")),
                any(token in raw_text for token in ("token", "secret", "password", "credential", "身份证", "客户资料")),
            )
        ),
        "destination.external": bool(event.network_targets) or _has_external_recipient(raw_text),
    }
    for name, value in structured_checks.items():
        _add_verified(facts, name, bool(value), "structured parameter classifier")
    return SemanticMatchIR(
        engine=engine,
        operation_candidates=candidates,
        facts=facts,
        entities={"tool_name": _safe_identifier(str(event.metadata.get("tool_name") or "")) or None},
        constraints={},
        uncertainties=["operation_unverified"] if not candidates else [],
    )


def _add_verified(facts: dict[str, FactEvidence], name: str, value: bool | int, evidence: str) -> None:
    facts[name] = FactEvidence(
        value=value,
        source="deterministic",
        trust="verified",
        confidence=1.0,
        evidence=evidence,
    )


def _command_starts(command: str, executable: str) -> bool:
    return bool(re.match(rf"^(?:(?:sudo|doas)\s+)?{re.escape(executable)}(?:\s|$)", command))


def _has_external_recipient(text: str) -> bool:
    for match in _EMAIL_RE.finditer(text):
        domain = match.group(1).lower()
        if domain not in {"openclaw.ai", "openclaw.local", "internal.local", "company.local"}:
            return True
    return False


def _disabled_near(text: str, subjects: tuple[str, ...]) -> bool:
    disabled = ("disable", "disabled", "false", "off", "关闭", "绕过")
    return any(subject in text for subject in subjects) and any(token in text for token in disabled)


def _sanitize_text(value: str) -> str:
    text = _PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", str(value or ""))
    text = _BEARER_RE.sub("Bearer [REDACTED_SECRET]", text)
    text = _SECRET_VALUE_RE.sub(lambda match: match.group("prefix") + "[REDACTED_SECRET]", text)
    text = _EMAIL_RE.sub(lambda match: f"***@{match.group(1).lower()}", text)
    text = _ABSOLUTE_PATH_RE.sub("[REDACTED_PATH]", text)
    return text[:400]


def _safe_identifier(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]", "_", str(value or ""))[:96]


def _path_traits(raw_path: str) -> set[str]:
    path = str(raw_path or "").replace("\\", "/").lower()
    traits: set[str] = set()
    if path.startswith(("/bin", "/etc", "/usr", "/system")):
        traits.add("system_path")
    if any(marker in path for marker in ("/.ssh", "/.aws", "/.gnupg", "id_rsa", "api_key", "/secrets/", "/credentials/")):
        traits.add("sensitive_credentials")
    if path.startswith(("/var/log", "/tmp/openclaw")):
        traits.add("log_path")
    if any(marker in path for marker in ("/cases/", "/evidence/", "evidence", "forensics")):
        traits.add("high_value")
    if path.endswith("openclaw.json"):
        traits.add("openclaw_config")
    if path.endswith((".sh", ".ps1", ".bat")):
        traits.add("script")
    return traits


def _network_traits(raw_target: str) -> set[str]:
    target = str(raw_target or "")
    lowered = target.lower()
    traits: set[str] = set()
    if lowered.startswith(("http://", "https://")):
        traits.add("http")
    if "webhook" in lowered:
        traits.add("webhook")
    hostname = urlsplit(target).hostname
    if hostname:
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            if not address.is_private and not address.is_loopback:
                traits.add("public_ip")
    return traits
