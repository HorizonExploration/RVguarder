from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from openclaw_guard.config import OpenClawTarget
from openclaw_guard.integrations.hook_runtime import DEFAULT_DECISION_TIMEOUT_MS

logger = logging.getLogger(__name__)


CHAT_SESSION_KEY = "main"
HOOK_STATUS_METHOD = "openclaw_guard.hook_status"


class OpenClawRelayError(RuntimeError):
    def __init__(self, code: str, detail: str, *, status_code: int = 503) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.status_code = status_code


@dataclass
class RelayCommand:
    argv: list[str]
    source: str
    working_dir: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RelayStatus:
    available: bool
    connected: bool
    can_send: bool
    connection_state: str
    source: str | None = None
    config_path: str | None = None
    gateway_url: str | None = None
    current_model: str | None = None
    current_agent: str | None = None
    available_models: list[str] = field(default_factory=list)
    session_key: str = CHAT_SESSION_KEY
    error_code: str | None = None
    error_detail: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ChatMessage:
    role: str
    text: str
    timestamp: str | None = None
    kind: str = "message"
    raw_role: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ChatSendResult:
    ok: bool
    session_key: str
    run_id: str | None
    status: str
    reply_text: str | None
    wait_status: str | None
    messages: list[ChatMessage]
    error_code: str | None = None
    error_detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "session_key": self.session_key,
            "run_id": self.run_id,
            "status": self.status,
            "reply_text": self.reply_text,
            "wait_status": self.wait_status,
            "messages": [message.to_dict() for message in self.messages],
            "error_code": self.error_code,
            "error_detail": self.error_detail,
        }


@dataclass
class ChatStartResult:
    ok: bool
    session_key: str
    run_id: str
    status: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def get_chat_status(target: OpenClawTarget) -> RelayStatus:
    command = _resolve_command(target)
    invocation = _resolve_invocation(target)
    if command is None:
        return RelayStatus(
            available=False,
            connected=False,
            can_send=False,
            connection_state="unavailable",
            error_code="cli_not_found",
            error_detail="OpenClaw CLI is not available.",
            details=_debug_context(target, command, invocation, last_error=None),
        )
    if invocation["config_path"] is None and invocation["gateway_url"] is None:
        return RelayStatus(
            available=True,
            connected=False,
            can_send=False,
            connection_state="missing",
            source=command.source,
            error_code="config_not_found",
            error_detail="OpenClaw config or gateway URL is missing.",
            current_model=target.current_model,
            current_agent=target.current_agent,
            available_models=list(target.available_models),
            details=_debug_context(target, command, invocation, last_error=None),
        )
    try:
        payload = _gateway_call(target, "health", {}, timeout_ms=5_000, step="health")
    except OpenClawRelayError as exc:
        if exc.code == "gateway_auth_failed":
            return RelayStatus(
                available=True,
                connected=False,
                can_send=False,
                connection_state="auth_required",
                source=command.source,
                config_path=invocation["config_path"],
                gateway_url=invocation["gateway_url"],
                current_model=target.current_model,
                current_agent=target.current_agent,
                available_models=list(target.available_models),
                error_code=exc.code,
                error_detail=exc.detail,
                details=_debug_context(target, command, invocation, last_error=exc),
            )
        can_send = bool(target.config_path)
        return RelayStatus(
            available=True,
            connected=False,
            can_send=can_send,
            connection_state="detected" if can_send else "disconnected",
            source=command.source,
            config_path=invocation["config_path"],
            gateway_url=invocation["gateway_url"],
            current_model=target.current_model,
            current_agent=target.current_agent,
            available_models=list(target.available_models),
            error_code=exc.code,
            error_detail=exc.detail,
            details=_debug_context(target, command, invocation, last_error=exc),
        )
    models = _safe_models_list(target)
    current_session = get_current_session_model(target)
    current_model = current_session.get("value") if current_session else target.current_model
    return RelayStatus(
        available=True,
        connected=True,
        can_send=True,
        connection_state="connected",
        source=command.source,
        config_path=invocation["config_path"],
        gateway_url=invocation["gateway_url"],
        current_model=current_model,
        current_agent=target.current_agent,
        available_models=models or list(target.available_models),
        details=_debug_context(target, command, invocation, last_error=None, extra=payload if isinstance(payload, dict) else {}),
    )


def get_chat_history(target: OpenClawTarget, *, session_key: str = CHAT_SESSION_KEY, limit: int = 80) -> list[ChatMessage]:
    try:
        payload = _gateway_call(
            target,
            "chat.history",
            {"sessionKey": session_key, "limit": limit},
            timeout_ms=10_000,
            step="history",
        )
    except OpenClawRelayError as exc:
        if exc.code == "gateway_call_failed":
            raise OpenClawRelayError("history_fetch_failed", exc.detail, status_code=503) from exc
        raise
    messages = payload.get("messages") if isinstance(payload, dict) else []
    if not isinstance(messages, list):
        return []
    return _normalize_history_messages(messages)


def send_chat_message(
    target: OpenClawTarget,
    *,
    message: str,
    session_key: str = CHAT_SESSION_KEY,
    timeout_ms: int = 30_000,
) -> ChatSendResult:
    normalized_text = message.strip()
    if not normalized_text:
        raise OpenClawRelayError("message_empty", "Message text is empty.", status_code=400)
    history_before = get_chat_history(target, session_key=session_key, limit=200)
    run_id = str(uuid4())
    try:
        send_payload = _gateway_call(
            target,
            "chat.send",
            {"sessionKey": session_key, "message": normalized_text, "idempotencyKey": run_id},
            timeout_ms=10_000,
            step="send",
        )
    except OpenClawRelayError as exc:
        if exc.code in {"gateway_call_failed", "gateway_invalid_response"}:
            raise OpenClawRelayError("send_failed", exc.detail, status_code=502) from exc
        raise

    returned_run_id = None
    send_status = "started"
    if isinstance(send_payload, dict):
        returned_run_id = _as_string(send_payload.get("runId")) or run_id
        send_status = _as_string(send_payload.get("status")) or send_status
    else:
        returned_run_id = run_id

    wait_status = None
    if returned_run_id:
        try:
            wait_payload = _gateway_call(
                target,
                "agent.wait",
                {"runId": returned_run_id, "timeoutMs": timeout_ms},
                timeout_ms=max(timeout_ms + 5_000, 15_000),
                step="wait",
            )
            if isinstance(wait_payload, dict):
                wait_status = _as_string(wait_payload.get("status"))
        except OpenClawRelayError as exc:
            if exc.code == "wait_timeout":
                wait_status = "timeout"
            else:
                raise

    try:
        history_after = get_chat_history(target, session_key=session_key, limit=200)
    except OpenClawRelayError as exc:
        if exc.code in {"gateway_call_failed", "gateway_invalid_response"}:
            raise OpenClawRelayError("history_fetch_failed", exc.detail, status_code=502) from exc
        raise
    reply_text = _extract_reply_text(history_before, history_after)
    if not reply_text and wait_status != "timeout":
        raise OpenClawRelayError("reply_not_found", "The OpenClaw reply was not found in chat history.", status_code=502)
    final_status = "completed" if reply_text else "pending"
    return ChatSendResult(
        ok=True,
        session_key=session_key,
        run_id=returned_run_id,
        status=final_status,
        reply_text=reply_text,
        wait_status=wait_status,
        messages=history_after,
    )


def start_chat_message(
    target: OpenClawTarget,
    *,
    message: str,
    session_key: str = CHAT_SESSION_KEY,
) -> ChatStartResult:
    normalized_text = message.strip()
    if not normalized_text:
        raise OpenClawRelayError("message_empty", "Message text is empty.", status_code=400)
    run_id = str(uuid4())
    try:
        send_payload = _gateway_call(
            target,
            "chat.send",
            {"sessionKey": session_key, "message": normalized_text, "idempotencyKey": run_id},
            timeout_ms=10_000,
            step="send",
        )
    except OpenClawRelayError as exc:
        if exc.code in {"gateway_call_failed", "gateway_invalid_response"}:
            raise OpenClawRelayError("send_failed", exc.detail, status_code=502) from exc
        raise
    returned_run_id = run_id
    status = "started"
    if isinstance(send_payload, dict):
        returned_run_id = _as_string(send_payload.get("runId")) or run_id
        status = _as_string(send_payload.get("status")) or status
    return ChatStartResult(ok=True, session_key=session_key, run_id=returned_run_id, status=status)


def wait_for_run(
    target: OpenClawTarget,
    *,
    run_id: str,
    timeout_ms: int = 1_000,
) -> dict[str, Any]:
    return _gateway_call(
        target,
        "agent.wait",
        {"runId": run_id, "timeoutMs": timeout_ms},
        timeout_ms=max(timeout_ms + 3_000, 5_000),
        step="wait",
    )


def list_available_models(target: OpenClawTarget) -> list[str]:
    runtime_models = _safe_models_list(target)
    if runtime_models:
        return runtime_models
    return list(target.available_models)


def switch_model(target: OpenClawTarget, model: str, *, session_key: str = CHAT_SESSION_KEY) -> dict[str, Any]:
    normalized = model.strip()
    if not normalized:
        raise OpenClawRelayError("message_empty", "Model value is empty.", status_code=400)
    session_store_key = resolve_session_key(target, session_key=session_key)
    payload = _gateway_call(
        target,
        "sessions.patch",
        {"key": session_store_key, "model": normalized},
        timeout_ms=10_000,
        step="sessions.patch",
    )
    current = get_current_session_model(target, session_key=session_key, fallback_key=session_store_key)
    if current:
        payload = dict(payload)
        payload["confirmedModel"] = current["value"]
        payload["confirmedSessionKey"] = current["key"]
        payload["confirmedModelProvider"] = current.get("provider")
        payload["confirmedModelId"] = current.get("model")
    return payload


def reset_chat_session(target: OpenClawTarget, *, session_key: str = CHAT_SESSION_KEY, reason: str = "new") -> dict[str, Any]:
    session_store_key = resolve_session_key(target, session_key=session_key)
    return _gateway_call(
        target,
        "sessions.reset",
        {"key": session_store_key, "reason": reason},
        timeout_ms=10_000,
        step="sessions.reset",
    )


def get_guard_hook_status(target: OpenClawTarget) -> dict[str, Any]:
    try:
        return _gateway_call(
            target,
            HOOK_STATUS_METHOD,
            {},
            timeout_ms=5_000,
            step=HOOK_STATUS_METHOD,
        )
    except OpenClawRelayError:
        # Fallback: check via plugins list
        plugin_info = inspect_guard_plugin(target)
        if plugin_info.get("found") and plugin_info.get("status") == "loaded":
            return {
                "ok": True,
                "pluginId": "openclaw-guard-hook",
                "guardUrl": None,
                "failClosed": True,
                "decisionTimeoutMs": DEFAULT_DECISION_TIMEOUT_MS,
            }
        raise


def inspect_guard_plugin(target: OpenClawTarget, *, plugin_id: str = "openclaw-guard-hook") -> dict[str, Any]:
    command = _resolve_command(target)
    invocation = _resolve_invocation(target)
    if command is None:
        return {"ok": False, "error_code": "cli_not_found", "detail": "OpenClaw CLI is not available."}
    if invocation["config_path"] is None:
        return {"ok": False, "error_code": "config_not_found", "detail": "OpenClaw config is missing."}
    argv = list(command.argv) + ["plugins", "list", "--json"]
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            cwd=command.working_dir or None,
            env=_build_environment(invocation["config_path"]),
            timeout=20,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {"ok": False, "error_code": "plugin_probe_timeout", "detail": "Timed out while probing OpenClaw plugins.", "exception": str(exc)}
    except OSError as exc:
        return {"ok": False, "error_code": "plugin_probe_failed", "detail": str(exc)}
    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    if completed.returncode != 0:
        return {
            "ok": False,
            "error_code": "plugin_probe_failed",
            "detail": stderr or stdout or "OpenClaw plugins list failed.",
        }
    payload = _parse_json_payload(stdout)
    if not isinstance(payload, dict):
        return {"ok": False, "error_code": "plugin_probe_invalid", "detail": "OpenClaw plugins list did not return valid JSON."}
    plugins = payload.get("plugins")
    if not isinstance(plugins, list):
        return {"ok": False, "error_code": "plugin_probe_invalid", "detail": "Plugins list response is missing the plugins array."}
    plugin = next((item for item in plugins if isinstance(item, dict) and item.get("id") == plugin_id), None)
    if not isinstance(plugin, dict):
        return {
            "ok": True,
            "found": False,
            "plugin_id": plugin_id,
            "workspace_dir": payload.get("workspaceDir"),
            "diagnostics": payload.get("diagnostics") if isinstance(payload.get("diagnostics"), list) else [],
        }
    return {
        "ok": True,
        "found": True,
        "plugin_id": plugin_id,
        "status": plugin.get("status"),
        "enabled": bool(plugin.get("enabled")),
        "hook_count": plugin.get("hookCount"),
        "hook_names": plugin.get("hookNames") if isinstance(plugin.get("hookNames"), list) else [],
        "gateway_methods": plugin.get("gatewayMethods") if isinstance(plugin.get("gatewayMethods"), list) else [],
        "source": plugin.get("source"),
        "workspace_dir": payload.get("workspaceDir"),
        "diagnostics": payload.get("diagnostics") if isinstance(payload.get("diagnostics"), list) else [],
    }


def resolve_plugin_approval(
    target: OpenClawTarget,
    *,
    plugin_id: str = "openclaw-guard-hook",
    run_id: str,
    tool_call_id: str = "",
    decision: str,
) -> dict[str, Any]:
    """Sync an approval decision from the Guard Dashboard back to OpenClaw.

    When a user approves/rejects a tool action in the Guard Dashboard
    (not in OpenClaw's native UI), this tells OpenClaw about the decision
    so the agent run can continue.

    This is best-effort: if the gateway call fails, a warning is logged and
    ``{"ok": False, "error": "approval_resolve_failed"}`` is returned.
    """
    # Approach 1: approvals.resolve
    try:
        return _gateway_call(
            target,
            "approvals.resolve",
            {"pluginId": plugin_id, "runId": run_id, "decision": decision},
            timeout_ms=5000,
            step="approvals.resolve",
        )
    except OpenClawRelayError as exc:
        if exc.code not in ("gateway_call_failed", "gateway_invalid_response"):
            # Non-recoverable errors (auth, unreachable, etc.) — don't try fallback
            logger.warning(
                "Failed to resolve plugin approval via approvals.resolve: %s (code=%s)",
                exc.detail,
                exc.code,
            )
            return {"ok": False, "error": "approval_resolve_failed"}

    # Approach 2 (fallback): plugin.resolveApproval
    try:
        return _gateway_call(
            target,
            "plugin.resolveApproval",
            {"pluginId": plugin_id, "decision": decision, "toolCallId": tool_call_id},
            timeout_ms=5000,
            step="plugin.resolveApproval",
        )
    except OpenClawRelayError as exc:
        logger.warning(
            "Failed to resolve plugin approval via fallback plugin.resolveApproval: %s (code=%s)",
            exc.detail,
            exc.code,
        )
        return {"ok": False, "error": "approval_resolve_failed"}


def resolve_session_key(target: OpenClawTarget, *, session_key: str = CHAT_SESSION_KEY) -> str:
    session_entry = get_current_session_model(target, session_key=session_key)
    if session_entry:
        return session_entry["key"]
    try:
        payload = _gateway_call(
            target,
            "sessions.list",
            {"includeGlobal": False, "includeUnknown": False, "activeMinutes": 30, "limit": 20},
            timeout_ms=8_000,
            step="sessions.list",
        )
    except OpenClawRelayError:
        agent = target.current_agent or "main"
        if agent == "default":
            agent = "main"
        return f"agent:{agent}:{session_key}"
    sessions = payload.get("sessions") if isinstance(payload, dict) else None
    if isinstance(sessions, list):
        for item in sessions:
            if not isinstance(item, dict):
                continue
            key = item.get("key")
            if isinstance(key, str) and key == session_key:
                return key
        preferred_suffixes = [f":{session_key}", ":main"]
        for suffix in preferred_suffixes:
            for item in sessions:
                if not isinstance(item, dict):
                    continue
                key = item.get("key")
                if isinstance(key, str) and key.endswith(suffix):
                    return key
    agent = target.current_agent or "main"
    if agent == "default":
        agent = "main"
    return f"agent:{agent}:{session_key}"


def get_current_session_model(
    target: OpenClawTarget,
    *,
    session_key: str = CHAT_SESSION_KEY,
    fallback_key: str | None = None,
) -> dict[str, str] | None:
    try:
        payload = _gateway_call(
            target,
            "sessions.list",
            {"includeGlobal": False, "includeUnknown": False, "activeMinutes": 30, "limit": 20},
            timeout_ms=8_000,
            step="sessions.list",
        )
    except OpenClawRelayError:
        return None
    sessions = payload.get("sessions") if isinstance(payload, dict) else None
    if not isinstance(sessions, list):
        return None
    preferred_keys: list[str] = []
    if session_key:
        preferred_keys.append(session_key)
    if fallback_key and fallback_key not in preferred_keys:
        preferred_keys.append(fallback_key)
    preferred_suffixes = [f":{session_key}", ":main"]
    candidates: list[dict[str, Any]] = []
    for item in sessions:
        if not isinstance(item, dict):
            continue
        key = item.get("key")
        if isinstance(key, str):
            if key in preferred_keys:
                candidates.insert(0, item)
                continue
            if any(key.endswith(suffix) for suffix in preferred_suffixes):
                candidates.append(item)
    if not candidates:
        return None
    row = candidates[0]
    key = row.get("key")
    provider = row.get("modelProvider") or (row.get("resolved") or {}).get("modelProvider")
    model = row.get("model") or (row.get("resolved") or {}).get("model")
    if not isinstance(key, str):
        return None
    if isinstance(provider, str) and isinstance(model, str) and provider and model:
        return {"key": key, "provider": provider, "model": model, "value": f"{provider}/{model}"}
    return {"key": key, "value": ""}


def _resolve_command(target: OpenClawTarget) -> RelayCommand | None:
    installed = shutil.which("openclaw")
    if installed:
        return RelayCommand(argv=[installed], source="openclaw-cli")
    if target.source_root:
        dist_index = Path(target.source_root) / "dist" / "index.js"
        if dist_index.exists():
            return RelayCommand(argv=["node", str(dist_index)], source="source-dist", working_dir=str(target.source_root))
    return None


def _resolve_invocation(target: OpenClawTarget) -> dict[str, str | None]:
    config_path = str(target.config_path) if target.config_path else None
    gateway_url = None
    if config_path is None and target.gateway_urls:
        gateway_url = target.gateway_urls[0]
    elif config_path is None and target.reachable_ports:
        gateway_url = f"ws://127.0.0.1:{target.reachable_ports[0]}"
    return {"config_path": config_path, "gateway_url": gateway_url}


def _build_environment(config_path: str | None) -> dict[str, str]:
    env = dict(os.environ)
    if config_path:
        config_file = Path(config_path)
        env["OPENCLAW_CONFIG_PATH"] = str(config_file)
        env["OPENCLAW_STATE_DIR"] = str(config_file.parent)
        creds = _read_gateway_credentials(config_file)
        if creds.get("token"):
            env["OPENCLAW_GATEWAY_TOKEN"] = creds["token"]
        if creds.get("password"):
            env["OPENCLAW_GATEWAY_PASSWORD"] = creds["password"]
    return env


def _read_gateway_credentials(config_file: Path) -> dict[str, str]:
    try:
        config = json.loads(config_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    gateway = config.get("gateway") if isinstance(config, dict) else None
    auth = gateway.get("auth") if isinstance(gateway, dict) else None
    if not isinstance(auth, dict):
        return {}
    output: dict[str, str] = {}
    token = auth.get("token")
    password = auth.get("password")
    if isinstance(token, str) and token.strip():
        output["token"] = token.strip()
    if isinstance(password, str) and password.strip():
        output["password"] = password.strip()
    return output


def _gateway_call(target: OpenClawTarget, method: str, params: dict[str, Any], *, timeout_ms: int, step: str) -> dict[str, Any]:
    command = _resolve_command(target)
    invocation = _resolve_invocation(target)
    if command is None:
        raise OpenClawRelayError("cli_not_found", "OpenClaw CLI is not available.")
    if invocation["config_path"] is None and invocation["gateway_url"] is None:
        raise OpenClawRelayError("config_not_found", "OpenClaw config or gateway URL is missing.", status_code=404)
    argv = list(command.argv) + ["gateway", "call", method]
    if invocation["gateway_url"]:
        argv.extend(["--url", invocation["gateway_url"]])
    argv.extend(["--params", json.dumps(params, ensure_ascii=False, separators=(",", ":")), "--timeout", str(max(timeout_ms, 1000)), "--json"])
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            cwd=command.working_dir or None,
            env=_build_environment(invocation["config_path"]),
            timeout=max(timeout_ms / 1000, 1.0) + 10.0,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        if step == "wait":
            raise OpenClawRelayError("wait_timeout", "Timed out while waiting for the OpenClaw reply.", status_code=504) from exc
        raise OpenClawRelayError("gateway_unreachable", "Timed out while contacting the OpenClaw gateway.", status_code=504) from exc
    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    if completed.returncode != 0:
        detail = stderr or stdout
        error = _classify_gateway_error(detail, step=step)
        raise OpenClawRelayError(error["code"], error["detail"], status_code=error["status_code"])
    if not stdout:
        return {}
    payload = _parse_json_payload(stdout)
    if payload is None:
        raise OpenClawRelayError("gateway_invalid_response", "Invalid gateway JSON response.")
    if not isinstance(payload, dict):
        raise OpenClawRelayError("gateway_invalid_response", "Unexpected gateway response type.")
    return payload


def _classify_gateway_error(detail: str, *, step: str) -> dict[str, Any]:
    lowered = detail.lower()
    if any(token in lowered for token in ("unauthorized", "forbidden", "auth failed", "invalid password", "invalid token", "authentication")):
        return {"code": "gateway_auth_failed", "detail": detail or "Gateway authentication failed.", "status_code": 401}
    if "timed out" in lowered and step == "wait":
        return {"code": "wait_timeout", "detail": detail or "Timed out while waiting for the OpenClaw reply.", "status_code": 504}
    if any(token in lowered for token in ("gateway closed", "econnrefused", "abnormal closure", "failed to connect", "connection refused", "connect eacces")):
        return {
            "code": "runtime_not_running" if step == "health" else "gateway_unreachable",
            "detail": detail or "OpenClaw gateway is not reachable.",
            "status_code": 503,
        }
    return {"code": "gateway_call_failed", "detail": detail or "OpenClaw gateway call failed.", "status_code": 502}


def _safe_models_list(target: OpenClawTarget) -> list[str]:
    try:
        payload = _gateway_call(target, "models.list", {}, timeout_ms=10_000, step="models.list")
    except OpenClawRelayError:
        return []
    output: list[str] = []
    for container_key in ("items", "models", "rows"):
        items = payload.get(container_key)
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, str):
                output.append(item)
                continue
            if not isinstance(item, dict):
                continue
            for key in ("key", "ref", "id", "name", "model"):
                value = item.get(key)
                if isinstance(value, str) and value:
                    output.append(value)
                    break
            else:
                provider = item.get("provider")
                model = item.get("model")
                if isinstance(provider, str) and isinstance(model, str):
                    output.append(f"{provider}/{model}")
    unique: list[str] = []
    seen: set[str] = set()
    for item in output:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def _parse_json_payload(stdout: str) -> Any:
    text = stdout.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                continue
    start_candidates = [index for index in (text.find("\n{"), text.find("\n[")) if index != -1]
    if start_candidates:
        start = min(start_candidates) + 1
        try:
            return json.loads(text[start:])
        except json.JSONDecodeError:
            return None
    return None


def _debug_context(target: OpenClawTarget, command: RelayCommand | None, invocation: dict[str, str | None], *, last_error: OpenClawRelayError | None, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    details = {
        "entry_source": command.source if command else None,
        "entry_command": command.argv if command else None,
        "working_dir": command.working_dir if command else None,
        "profile": target.profile,
        "config_path": invocation.get("config_path"),
        "source_root": str(target.source_root) if target.source_root else None,
        "gateway_url": invocation.get("gateway_url"),
        "gateway_urls": target.gateway_urls,
        "gateway_port": target.gateway_port,
        "gateway_bind": target.gateway_bind,
        "auth_mode": target.auth_mode,
        "reachability_state": target.reachability_state,
        "current_model": target.current_model,
        "current_agent": target.current_agent,
        "last_error_code": last_error.code if last_error else None,
        "last_error_detail": last_error.detail if last_error else None,
    }
    if extra:
        details["health"] = extra
    return details


def _normalize_history_messages(messages: list[Any]) -> list[ChatMessage]:
    normalized: list[ChatMessage] = []
    for item in messages:
        if not isinstance(item, dict):
            continue
        raw_role = _as_string(item.get("role")) or _as_string(item.get("kind")) or "system"
        text = _extract_text(item.get("content")) or _extract_text(item.get("message"))
        if not text:
            continue
        role = raw_role
        if role not in {"user", "assistant", "system"}:
            if "tool" in role.lower():
                role = "system"
            else:
                role = "assistant" if "assistant" in role.lower() else "system"
        normalized.append(ChatMessage(role=role, text=text, timestamp=_as_string(item.get("timestamp")), kind=_as_string(item.get("type")) or "message", raw_role=raw_role))
    return normalized


def _extract_text(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        if "text" in value and isinstance(value["text"], str):
            return value["text"].strip()
        if "message" in value:
            return _extract_text(value["message"])
        if "content" in value:
            return _extract_text(value["content"])
        return ""
    if isinstance(value, list):
        parts: list[str] = []
        for block in value:
            if isinstance(block, str):
                text = block.strip()
                if text:
                    parts.append(text)
                continue
            if not isinstance(block, dict):
                continue
            block_type = _as_string(block.get("type")) or ""
            if block_type in {"text", "input_text", "output_text"}:
                text = _as_string(block.get("text"))
                if text:
                    parts.append(text.strip())
            elif block_type in {"toolCall", "tool_call"}:
                tool_name = _as_string(block.get("toolName")) or _as_string(block.get("name")) or "tool"
                parts.append(f"[tool:{tool_name}]")
            elif block_type in {"toolResult", "tool_result"}:
                tool_name = _as_string(block.get("toolName")) or _as_string(block.get("name")) or "tool"
                parts.append(f"[tool-result:{tool_name}]")
            elif "text" in block:
                text = _as_string(block.get("text"))
                if text:
                    parts.append(text.strip())
        return "\n".join(part for part in parts if part).strip()
    return ""


def _extract_reply_text(before: list[ChatMessage], after: list[ChatMessage]) -> str | None:
    if not after:
        return None
    new_messages = after[len(before):] if len(after) >= len(before) else after
    for message in reversed(new_messages):
        if message.role == "assistant" and message.text:
            return message.text
    for message in reversed(after):
        if message.role == "assistant" and message.text:
            return message.text
    return None


def _as_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None
