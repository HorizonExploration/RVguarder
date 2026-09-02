from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from openclaw_guard.models import BehaviorEvent
from openclaw_guard.utils import sha256_text, utc_now_iso


PATH_KEYS = {
    "path",
    "paths",
    "file",
    "filePath",
    "filepath",
    "targetPath",
    "targetPaths",
    "sourcePath",
    "destinationPath",
    "destPath",
    "from",
    "to",
    "cwd",
    "workingDirectory",
}
URL_KEYS = {"url", "uri", "endpoint", "baseUrl", "webhook"}
COMMAND_KEYS = {"command", "commandText", "commandPreview", "cmd", "shellCommand", "script"}
DELETE_KEYWORDS = ("delete", "remove", "unlink", "rm", "trash", "wipe", "clean")
WRITE_KEYWORDS = ("write", "save", "create", "update", "edit", "overwrite", "patch")
CHANNEL_KEYWORDS = ("channel", "message", "send", "post", "reply")
SKILL_KEYWORDS = ("skill",)
CONFIG_KEYWORDS = ("config", "openclaw.json", "settings")
COMMAND_TOOL_KEYWORDS = ("shell", "exec", "command", "bash", "terminal", "run")
READ_TOOL_NAMES = {"read", "file_read", "read_file", "file.read", "grep", "cat", "head", "tail", "list", "ls"}
OPENCLAW_NATIVE_TOOL_PROFILES = {
    "before_prompt_build": {
        "action_type": "unknown",
        "tool_group": "prompting",
        "tool_origin": "openclaw_native",
        "permission_family": "prompt.precheck",
        "risk_class": "low",
        "summary": "提示词构建前预检查",
    },
    "sessions_history": {
        "action_type": "file_read",
        "tool_group": "session",
        "tool_origin": "openclaw_native",
        "permission_family": "session.read",
        "risk_class": "low",
        "summary": "读取会话历史",
    },
    "sessions_list": {
        "action_type": "file_read",
        "tool_group": "session",
        "tool_origin": "openclaw_native",
        "permission_family": "session.read",
        "risk_class": "low",
        "summary": "列出会话",
    },
    "memory_search": {
        "action_type": "file_read",
        "tool_group": "memory",
        "tool_origin": "openclaw_native",
        "permission_family": "memory.read",
        "risk_class": "low",
        "summary": "搜索记忆",
    },
    "memory_get": {
        "action_type": "file_read",
        "tool_group": "memory",
        "tool_origin": "openclaw_native",
        "permission_family": "memory.read",
        "risk_class": "low",
        "summary": "读取记忆",
    },
    "session_status": {
        "action_type": "file_read",
        "tool_group": "session",
        "tool_origin": "openclaw_native",
        "permission_family": "session.read",
        "risk_class": "low",
        "summary": "读取会话状态",
    },
    "agents_list": {
        "action_type": "file_read",
        "tool_group": "agents",
        "tool_origin": "openclaw_native",
        "permission_family": "agents.read",
        "risk_class": "low",
        "summary": "列出代理",
    },
    "get_goal": {
        "action_type": "file_read",
        "tool_group": "planning",
        "tool_origin": "openclaw_native",
        "permission_family": "goal.read",
        "risk_class": "low",
        "summary": "读取目标",
    },
    "update_plan": {
        "action_type": "file_write",
        "tool_group": "planning",
        "tool_origin": "openclaw_native",
        "permission_family": "plan.write",
        "risk_class": "medium",
        "summary": "更新计划",
    },
    "create_goal": {
        "action_type": "file_write",
        "tool_group": "planning",
        "tool_origin": "openclaw_native",
        "permission_family": "goal.write",
        "risk_class": "medium",
        "summary": "创建目标",
    },
    "update_goal": {
        "action_type": "file_write",
        "tool_group": "planning",
        "tool_origin": "openclaw_native",
        "permission_family": "goal.write",
        "risk_class": "medium",
        "summary": "更新目标",
    },
}


def build_hook_event(payload: dict[str, Any]) -> BehaviorEvent:
    tool_name = str(payload.get("toolName") or payload.get("tool_name") or "tool")
    params = payload.get("params")
    params = params if isinstance(params, dict) else {}
    tool_profile = _native_tool_profile(tool_name, params=params, payload=payload)
    target_paths = _collect_paths(params)
    network_targets = _collect_urls(params)
    command = _extract_command(params)
    action_type = str(tool_profile.get("action_type")) if tool_profile else _infer_action_type(
        tool_name,
        params,
        target_paths,
        network_targets,
        command,
    )
    agent_id = str(payload.get("agentId") or "").strip()
    trusted_identity = {}
    if agent_id:
        trusted_identity = {
            "principal_id": agent_id,
            "principal_type": "agent",
            "agent_id": agent_id,
            "capability_lineage": [f"openclaw-agent:{agent_id}"],
            "trust": "verified",
        }
    metadata = {
        "hook_bridge": True,
        "tool_name": tool_name,
        "run_id": payload.get("runId"),
        "tool_call_id": payload.get("toolCallId"),
        "session_key": payload.get("sessionKey"),
        "session_id": payload.get("sessionId"),
        "agent_id": agent_id or None,
        "trusted_identity": trusted_identity,
        "hook_key": hook_key_from_payload(payload),
        "tool_group": tool_profile.get("tool_group") if tool_profile else _infer_tool_group(action_type),
        "tool_origin": tool_profile.get("tool_origin") if tool_profile else "hook_bridged",
        "permission_family": tool_profile.get("permission_family") if tool_profile else _infer_permission_family(action_type),
        "risk_class": tool_profile.get("risk_class") if tool_profile else _infer_risk_class(action_type, command),
        # AgentDojo is an authenticated, local synthetic benchmark boundary.
        # Keep the marker explicit so the semantic layer can select its
        # deterministic path without changing unmarked OpenClaw requests.
        "evaluation_mode": (
            "agentdojo"
            if payload.get("evaluationMode") == "agentdojo" and payload.get("agentdojoToolName")
            else None
        ),
    }
    return BehaviorEvent(
        event_id=metadata["hook_key"],
        timestamp=utc_now_iso(),
        action_type=action_type,
        process_name="openclaw",
        pid=None,
        user="openclaw",
        command=command,
        target_paths=target_paths,
        network_targets=network_targets,
        raw_payload=payload,
        source="openclaw-before-tool-call",
        working_directory=_extract_working_directory(params),
        metadata=metadata,
    )


def build_hook_source_message(event: BehaviorEvent) -> str:
    tool_name = str(event.metadata.get("tool_name") or event.action_type)
    if tool_name == "before_prompt_build":
        return "OpenClaw 提示词构建前预检查"
    native_summary = _native_tool_summary(tool_name)
    if native_summary:
        return f"OpenClaw 请求{native_summary}"
    if event.action_type == "file_delete":
        if event.target_paths:
            return f"OpenClaw 请求删除文件：{', '.join(event.target_paths[:3])}"
        return f"OpenClaw 请求删除文件（工具：{tool_name}）"
    if event.action_type == "file_write":
        if event.target_paths:
            return f"OpenClaw 请求写入文件：{', '.join(event.target_paths[:3])}"
        return f"OpenClaw 请求写入文件（工具：{tool_name}）"
    if event.action_type == "config_modify":
        if event.target_paths:
            return f"OpenClaw 请求修改配置：{', '.join(event.target_paths[:2])}"
        return "OpenClaw 请求修改配置"
    if event.action_type == "network_egress":
        if event.network_targets:
            return f"OpenClaw 请求访问网络：{', '.join(event.network_targets[:2])}"
        return f"OpenClaw 请求外联（工具：{tool_name}）"
    if event.action_type == "command_exec":
        if event.command:
            return f"OpenClaw 请求执行命令：{event.command}"
        return f"OpenClaw 请求执行命令（工具：{tool_name}）"
    if event.action_type == "channel_send":
        return f"OpenClaw 请求发送渠道消息（工具：{tool_name}）"
    if event.action_type == "skill_run":
        return f"OpenClaw 请求运行技能（工具：{tool_name}）"
    return f"OpenClaw 请求调用工具：{tool_name}"


def hook_key_from_payload(payload: dict[str, Any]) -> str:
    run_id = str(payload.get("runId") or "").strip()
    tool_call_id = str(payload.get("toolCallId") or "").strip()
    if run_id and tool_call_id:
        return f"{run_id}:{tool_call_id}"
    fingerprint_source = json.dumps(
        {
            "toolName": payload.get("toolName"),
            "params": payload.get("params"),
            "sessionKey": payload.get("sessionKey"),
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return sha256_text(fingerprint_source)[:24]


def _infer_action_type(
    tool_name: str,
    params: dict[str, Any],
    target_paths: list[str],
    network_targets: list[str],
    command: str | None,
) -> str:
    lowered_tool = tool_name.lower()
    if lowered_tool == "before_prompt_build":
        return "unknown"
    if lowered_tool in READ_TOOL_NAMES:
        return "file_read"
    haystack = " ".join(
        [
            lowered_tool,
            command or "",
            " ".join(target_paths),
            " ".join(network_targets),
            json.dumps(params, ensure_ascii=False),
        ]
    ).lower()

    if _matches_any(haystack, DELETE_KEYWORDS) or (command and _matches_any(command.lower(), ("rm ", "rm -", "unlink", "del "))):
        return "file_delete"
    if any(path.endswith("openclaw.json") for path in target_paths) or _matches_any(haystack, CONFIG_KEYWORDS):
        return "config_modify"
    if network_targets or _matches_any(lowered_tool, CHANNEL_KEYWORDS) and _matches_any(haystack, ("http://", "https://", "webhook")):
        return "network_egress"
    if command or _matches_any(lowered_tool, COMMAND_TOOL_KEYWORDS):
        return "command_exec"
    if _matches_any(lowered_tool, CHANNEL_KEYWORDS):
        return "channel_send"
    if _matches_any(lowered_tool, SKILL_KEYWORDS):
        return "skill_run"
    if target_paths or _matches_any(haystack, WRITE_KEYWORDS):
        return "file_write"
    return "command_exec"


def _native_tool_profile(
    tool_name: str,
    *,
    params: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, str]:
    profile = dict(OPENCLAW_NATIVE_TOOL_PROFILES.get(tool_name.lower(), {}))
    if profile and params is not None and not _native_params_are_safe(params, payload or {}):
        return {}
    return profile


def _native_tool_summary(tool_name: str) -> str:
    profile = OPENCLAW_NATIVE_TOOL_PROFILES.get(tool_name.lower(), {})
    return str(profile.get("summary") or "")


def _native_params_are_safe(params: dict[str, Any], payload: dict[str, Any]) -> bool:
    """Keep native read trust conditional on local, same-principal parameters."""
    current_sessions = {
        str(payload.get(key) or "").strip()
        for key in ("sessionKey", "session_key", "sessionId", "session_id")
        if str(payload.get(key) or "").strip()
    }
    current_agents = {
        str(payload.get(key) or "").strip()
        for key in ("agentId", "agent_id", "principalId", "principal_id")
        if str(payload.get(key) or "").strip()
    }
    session_keys = {"sessionkey", "session_key", "targetsession", "target_session"}
    principal_keys = {
        "agentid",
        "agent_id",
        "principalid",
        "principal_id",
        "targetagent",
        "target_agent",
        "userid",
        "user_id",
    }

    def visit(value: Any, key: str = "") -> bool:
        lowered_key = key.lower()
        if isinstance(value, dict):
            return all(visit(child, str(child_key)) for child_key, child in value.items())
        if isinstance(value, list):
            return all(visit(child, key) for child in value)
        if not isinstance(value, str):
            return True
        text = value.strip()
        if not text:
            return True
        if lowered_key in session_keys:
            if not current_sessions or text not in current_sessions:
                return False
        if lowered_key in principal_keys:
            if not current_agents or text not in current_agents:
                return False
        if re.search(r"https?://|file://", text, re.IGNORECASE):
            return False
        if re.search(r"(^|\s)(?:/|~[/\\]|[A-Za-z]:[\\/])", text):
            return False
        if re.search(r"(?:^|[/\\])\.\.(?:[/\\]|$)", text):
            return False
        return True

    return visit(params)


def _infer_tool_group(action_type: str) -> str:
    if action_type == "command_exec":
        return "command"
    if action_type in {"file_read", "file_write", "file_delete"}:
        return "file"
    if action_type == "config_modify":
        return "config"
    if action_type == "network_egress":
        return "network"
    if action_type == "channel_send":
        return "channel"
    if action_type == "skill_run":
        return "skill"
    return "unknown"


def _infer_permission_family(action_type: str) -> str:
    if action_type == "command_exec":
        return "process.execute"
    if action_type == "file_read":
        return "file.read"
    if action_type == "file_write":
        return "file.write"
    if action_type == "file_delete":
        return "file.delete"
    if action_type == "config_modify":
        return "config.modify"
    if action_type == "network_egress":
        return "network.egress"
    if action_type == "channel_send":
        return "message.send"
    if action_type == "skill_run":
        return "skill.run"
    return "unknown"


def _infer_risk_class(action_type: str, command: str | None) -> str:
    lowered_command = (command or "").lower()
    if action_type == "file_delete" or _matches_any(lowered_command, ("rm ", "rm -", "unlink", "del ")):
        return "critical"
    if action_type in {"config_modify", "network_egress", "channel_send", "skill_run"}:
        return "high"
    if action_type in {"command_exec", "file_write"}:
        return "medium"
    if action_type == "file_read":
        return "low"
    return "medium"


def _collect_paths(payload: Any) -> list[str]:
    results: list[str] = []

    def visit(value: Any, key: str | None = None) -> None:
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                visit(child_value, child_key)
            return
        if isinstance(value, list):
            for child in value:
                visit(child, key)
            return
        if not isinstance(value, str):
            return
        candidate = value.strip().strip("\"'")
        if not candidate:
            return
        if key in PATH_KEYS or _looks_like_path(candidate):
            if candidate.startswith(("http://", "https://")):
                return
            if candidate not in results:
                results.append(candidate)

    visit(payload)
    return results[:8]


def _collect_urls(payload: Any) -> list[str]:
    results: list[str] = []

    def visit(value: Any, key: str | None = None) -> None:
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                visit(child_value, child_key)
            return
        if isinstance(value, list):
            for child in value:
                visit(child, key)
            return
        if not isinstance(value, str):
            return
        candidate = value.strip()
        if not candidate:
            return
        if key in URL_KEYS or candidate.startswith(("http://", "https://")):
            if candidate not in results:
                results.append(candidate)

    visit(payload)
    return results[:6]


def _extract_command(params: dict[str, Any]) -> str | None:
    for key in COMMAND_KEYS:
        value = params.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for key, value in params.items():
        if isinstance(value, str) and key.lower().endswith("command") and value.strip():
            return value.strip()
    return None


def _extract_working_directory(params: dict[str, Any]) -> str | None:
    for key in ("cwd", "workingDirectory", "working_directory"):
        value = params.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _looks_like_path(value: str) -> bool:
    if value.startswith("~") or value.startswith("/"):
        return True
    if re.match(r"^[A-Za-z]:\\\\", value):
        return True
    if "/" in value and not value.startswith(("http://", "https://")):
        return True
    suffix = Path(value).suffix.lower()
    return suffix in {".txt", ".json", ".md", ".sh", ".py", ".yaml", ".yml", ".log"}


def _matches_any(haystack: str, patterns: tuple[str, ...]) -> bool:
    return any(pattern in haystack for pattern in patterns)
