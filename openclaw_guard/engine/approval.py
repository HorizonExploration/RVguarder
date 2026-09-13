"""Approval presentation and scoped trust helpers.

The module keeps the OpenClaw prompt small while retaining a structured,
redacted representation for the Guard dashboard.
"""

from __future__ import annotations

import json
import re
import shlex
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from openclaw_guard.utils import sha256_text


_SECRET_KEY = re.compile(r"(token|secret|password|passwd|api[-_]?key|api[-_]?token|access[-_]?token|auth[-_]?token|client[-_]?secret|authorization|credential|private[-_]?key|\bkey\b)", re.I)
_SECRET_VALUE = re.compile(
    r"(?ix)(\bbearer\s+|\\?[\"']?(?:token|secret|password|passwd|api[-_]?key|api[-_]?token|access[-_]?token|auth[-_]?token|client[-_]?secret|authorization|credential|private[-_]?key|key)\\?[\"']?\s*[=:]\s*(?:bearer\s+)?|--(?:token|secret|password|passwd|api[-_]?key|api[-_]?token|access[-_]?token|auth[-_]?token|client[-_]?secret|authorization|credential|private[-_]?key|key)(?:\s+|=))(?:\\?[\"']?)([^\s'\",;]+)"
)
_URL_VALUE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"<>]+", re.I)
_URI_PREFIX = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://", re.I)
_SENSITIVE_PATH_SEGMENTS = frozenset({
    ".git", ".ssh", "credentials", "credential", "secrets", "secret",
    "id_rsa", "id_ed25519", "authorized_keys",
})
_SENSITIVE_PATH_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".kdb", ".jks")
_SENSITIVE_ENV_PREFIX = ".env"
_DEFAULT_TRUST_TTL_DAYS = 30


def _redact_value(value: Any, *, key: str = "") -> Any:
    if _SECRET_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact_value(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(item, key=key) for item in value]
    if isinstance(value, str):
        return _sanitize_text(value)
    return value


def _safe_url(value: str) -> str:
    """Keep only the origin when presenting a URL to a user or OpenClaw."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "[REDACTED_URL]"
    if not parsed.hostname:
        return "[REDACTED_URL]"
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        return "[REDACTED_URL]"
    return f"{parsed.scheme.lower()}://{host}{port}"


def _sanitize_text(value: str) -> str:
    text = str(value or "")
    text = _URL_VALUE.sub(lambda match: _safe_url(match.group(0).rstrip(".,);]")), text)
    return _SECRET_VALUE.sub(lambda match: match.group(1) + "[REDACTED]", text)


def _path_has_sensitive_segment(value: str) -> bool:
    normalized = str(value or "").replace("\\", "/")
    segments = [segment.lower() for segment in normalized.split("/") if segment not in {"", ".", ".."}]
    for segment in segments:
        for part in re.split(r"[:=]", segment):
            part = part.strip("'\"")
            if part in _SENSITIVE_PATH_SEGMENTS or part in {".envrc", ".npmrc", ".netrc"} or re.match(r"^\.env(?:$|[.*?\[])", part):
                return True
            if any(part.endswith(suffix) for suffix in _SENSITIVE_PATH_SUFFIXES):
                return True
            if "credential" in part or "secret" in part:
                return True
    return False


def _command_has_sensitive_target(command: str | None, working_directory: str | None) -> bool:
    try:
        tokens = shlex.split(str(command or ""), posix=True)
    except ValueError:
        return True
    cwd = Path(str(working_directory)).expanduser() if working_directory else None
    for index, token in enumerate(tokens):
        if not token or token in {";", "&&", "||", "|", ">", ">>", "<", "<<", "(", ")"}:
            continue
        if any(marker in token for marker in ("$", "*", "?", "[", "]")):
            return True
        if ":" in token and not _URI_PREFIX.match(token):
            return True
        if token.startswith("-") and "=" in token:
            return True
        if _path_has_sensitive_segment(token):
            return True
        # A relative symlink or file can resolve to a sensitive target even
        # when its displayed name is innocuous.  Do not persist trust for it.
        if index > 0 and cwd and not token.startswith("-") and "=" not in token:
            try:
                resolved = (cwd / token).resolve()
                cwd_resolved = cwd.resolve()
                if cwd_resolved != resolved and cwd_resolved not in resolved.parents:
                    return True
                if (cwd / token).exists() and _path_has_sensitive_segment(str(resolved)):
                    return True
            except (OSError, RuntimeError, ValueError):
                return True
    return False


def _contains_sensitive_target(event: Any) -> bool:
    if any(_path_has_sensitive_segment(str(item)) for item in getattr(event, "target_paths", []) or []):
        return True
    safety = event.metadata.get("command_safety") if isinstance(event.metadata, dict) else {}
    if isinstance(safety, dict) and any(_path_has_sensitive_segment(str(item)) for item in safety.get("path_hints", []) or []):
        return True
    command = getattr(event, "command", None)
    if _command_has_sensitive_target(command, getattr(event, "working_directory", None)) or _SECRET_VALUE.search(str(command or "")):
        return True
    params = event.raw_payload.get("params") if isinstance(getattr(event, "raw_payload", None), dict) else {}
    return _params_have_sensitive_target(params)


def _params_have_sensitive_target(value: Any, *, key: str = "") -> bool:
    if isinstance(value, dict):
        return any(_params_have_sensitive_target(item, key=str(name)) for name, item in value.items())
    if isinstance(value, list):
        return any(_params_have_sensitive_target(item, key=key) for item in value)
    if isinstance(value, str):
        if _SECRET_KEY.search(key):
            return True
        return _path_has_sensitive_segment(value) or _command_has_sensitive_target(value, None)
    return False


def _safe_target_label(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if _URI_PREFIX.match(text):
        return _safe_url(text)
    return "[REDACTED_PATH]" if _path_has_sensitive_segment(text) else text


def redact_command(command: str | None, *, max_chars: int = 512) -> str:
    """Return a bounded command preview without credential-like values."""
    text = _sanitize_text(str(command or "")).strip()
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 1].rstrip() + "…"


def canonical_approval_fingerprint(
    tool_name: str,
    params: dict[str, Any] | None,
    working_directory: str | None,
    agent_id: str | None,
    principal_id: str | None,
) -> str:
    payload = {
        "tool_name": str(tool_name or ""),
        # Hash the original parameters for exact matching.  The digest is
        # persisted, never the raw values; redaction is only for UI output.
        "params": params or {},
        "working_directory": str(working_directory or ""),
        "agent_id": str(agent_id or ""),
        "principal_id": str(principal_id or ""),
    }
    return sha256_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _allow_always_eligibility(event: Any, decision: Any) -> tuple[bool, str]:
    safety = event.metadata.get("command_safety") if isinstance(event.metadata, dict) else {}
    policy = getattr(decision, "policy_decision", None) or {}
    if isinstance(policy, dict) and policy and policy.get("effect") != "openclaw_approval":
        return False, "当前策略不属于 OpenClaw 审批"
    hard_violations = policy.get("hard_violations") if isinstance(policy, dict) else []
    if getattr(event, "action_type", "") not in {"command_exec", "unknown"} or not getattr(event, "command", None):
        return False, "仅支持命令执行"
    if getattr(decision, "action", "") != "ask":
        return False, "当前动作不是待审批"
    if not isinstance(safety, dict) or safety.get("classification") != "read_only":
        return False, "命令不是可持久信任的只读命令"
    if str(event.metadata.get("scope_class") or "") not in {"workspace", "managed_project"}:
        return False, "命令不在受管工作区内"
    if hard_violations:
        return False, "命中硬阻断规则"
    if isinstance(policy, dict) and any(policy.get(key) for key in ("excessive_permissions", "combo_violations", "scope_expansions", "grant_validation_gaps")):
        return False, "权限差分或组合风险未收敛"
    if getattr(decision, "risk_level", "") in {"dangerous", "blocked"}:
        return False, "风险等级不允许持久信任"
    rv_result = event.metadata.get("rv_result") if isinstance(event.metadata, dict) else {}
    if isinstance(rv_result, dict) and rv_result.get("verdict") not in {None, "", "ok"}:
        return False, "运行时验证尚未通过"
    principal_rv = event.metadata.get("principal_rv") if isinstance(event.metadata, dict) else {}
    if isinstance(principal_rv, dict) and principal_rv.get("effect") not in {None, "", "none"}:
        return False, "主体运行时验证尚未通过"
    agent_id = str(event.metadata.get("agent_id") or "").strip()
    trusted = event.metadata.get("trusted_identity") if isinstance(event.metadata.get("trusted_identity"), dict) else {}
    if not agent_id or trusted.get("trust") != "verified" or not str(trusted.get("principal_id") or "").strip():
        return False, "缺少已验证的 agent/principal 身份"
    if event.metadata.get("hook_auth_verified") is not True:
        return False, "缺少已验证的 OpenClaw Hook 上下文"
    if _contains_sensitive_target(event):
        return False, "命中敏感路径或凭据目标"
    tool_name = str(event.metadata.get("tool_name") or "")
    params = event.raw_payload.get("params") if isinstance(getattr(event, "raw_payload", None), dict) else {}
    if tool_name not in {"shell", "shell_exec", "exec", "process", "terminal", "code_execution"}:
        # Unknown bridged tools may opt into this narrow profile only when
        # their complete input is the command plus an explicit work directory.
        # Extra fields could alter execution semantics and are never trusted.
        if not isinstance(params, dict) or set(params) - {"command", "cwd", "workingDirectory", "working_directory"}:
            return False, "工具未声明为受信任的命令执行配置"
    return True, ""


def build_approval_presentation(event: Any, decision: Any) -> dict[str, Any]:
    metadata = event.metadata if isinstance(getattr(event, "metadata", None), dict) else {}
    semantic = metadata.get("semantic") if isinstance(metadata.get("semantic"), dict) else {}
    intent = semantic.get("intent") if isinstance(semantic.get("intent"), dict) else {}
    intent_summary = _sanitize_text(str(intent.get("goal") or "").strip())[:160]
    if not intent_summary:
        intent_summary = {
            "command_exec": "执行命令",
            "file_read": "读取文件",
            "file_write": "修改文件",
            "file_delete": "删除文件",
            "network_egress": "访问网络",
            "channel_send": "发送消息",
        }.get(str(getattr(event, "action_type", "")), "调用工具")
    concrete_targets = [
        *[_safe_target_label(str(item)) for item in getattr(event, "target_paths", [])[:2] if item],
        *[_safe_target_label(str(item)) for item in getattr(event, "network_targets", [])[:2] if item],
    ]
    target_summary = ", ".join(concrete_targets) or str(metadata.get("scope_class") or "未知范围")
    command_preview = redact_command(getattr(event, "command", None), max_chars=512)
    if not command_preview:
        params = event.raw_payload.get("params") if isinstance(getattr(event, "raw_payload", None), dict) else {}
        command_preview = redact_command(json.dumps(_redact_value(params or {}), ensure_ascii=False, sort_keys=True), max_chars=512)
    eligible, reason = _allow_always_eligibility(event, decision)
    agent_id = str(metadata.get("agent_id") or "")
    trusted = metadata.get("trusted_identity") if isinstance(metadata.get("trusted_identity"), dict) else {}
    principal_id = str(trusted.get("principal_id") or "")
    params = event.raw_payload.get("params") if isinstance(getattr(event, "raw_payload", None), dict) else {}
    fingerprint = canonical_approval_fingerprint(
        str(metadata.get("tool_name") or ""),
        params if isinstance(params, dict) else {},
        getattr(event, "working_directory", None),
        agent_id,
        principal_id,
    )
    return {
        "intent_summary": intent_summary,
        "target_summary": target_summary,
        "risk_summary": {
            "level": str(getattr(decision, "risk_level", "caution")),
            "reason": str(getattr(decision, "reason", "")),
        },
        "command_preview": command_preview,
        "details": {
            "tool_name": str(metadata.get("tool_name") or ""),
            "params": _redact_value(params if isinstance(params, dict) else {}),
            "working_directory": getattr(event, "working_directory", None),
            "agent_id": agent_id,
            "principal_id": principal_id,
            "rule_ids": list(getattr(decision, "rule_ids", []) or []),
            "decision_trace": list(getattr(decision, "trace", []) or []),
        },
        "allow_always": {
            "eligible": eligible,
            "reason": reason,
            "scope": "同一工具、完整参数、工作目录和 agent/principal",
            "ttl_days": _DEFAULT_TRUST_TTL_DAYS,
            "fingerprint": fingerprint,
        },
    }


class ApprovalTrustStore:
    """Small JSON-backed store for exact, expiring approval fingerprints."""

    def __init__(self, path: Path, *, ttl_days: int = _DEFAULT_TRUST_TTL_DAYS) -> None:
        self.path = path
        self.ttl_days = ttl_days
        self._lock = threading.RLock()

    def _read(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        return payload if isinstance(payload, dict) else {}

    def _write(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def add(self, fingerprint: str, *, action_id: str, scope: str) -> dict[str, Any]:
        with self._lock:
            now = datetime.now(timezone.utc)
            item = {
                "fingerprint": fingerprint,
                "action_id": action_id,
                "scope": scope,
                "created_at": now.isoformat(),
                "expires_at": (now + timedelta(days=self.ttl_days)).isoformat(),
                "last_used_at": now.isoformat(),
            }
            payload = self._read()
            items = [i for i in payload.get("items", []) if isinstance(i, dict) and i.get("fingerprint") != fingerprint]
            items.append(item)
            self._write({"version": 1, "items": items})
            return item

    def contains(self, fingerprint: str) -> bool:
        with self._lock:
            now = datetime.now(timezone.utc)
            payload = self._read()
            kept: list[dict[str, Any]] = []
            found = False
            for item in payload.get("items", []):
                if not isinstance(item, dict):
                    continue
                try:
                    expires = datetime.fromisoformat(str(item.get("expires_at", "")).replace("Z", "+00:00"))
                except ValueError:
                    continue
                if expires <= now:
                    continue
                if item.get("fingerprint") == fingerprint:
                    item["last_used_at"] = now.isoformat()
                    found = True
                kept.append(item)
            if kept != payload.get("items", []):
                self._write({"version": 1, "items": kept})
            return found

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            self.contains("")
            return list(self._read().get("items", []))

    def revoke(self, fingerprint: str) -> bool:
        with self._lock:
            payload = self._read()
            items = [i for i in payload.get("items", []) if isinstance(i, dict) and i.get("fingerprint") != fingerprint]
            changed = len(items) != len(payload.get("items", []))
            if changed:
                self._write({"version": 1, "items": items})
            return changed
