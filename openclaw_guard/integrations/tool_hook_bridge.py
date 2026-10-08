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
    "cwd",
    "workingDirectory",
}
URL_KEYS = {"url", "uri", "endpoint", "baseUrl", "webhook"}
COMMAND_KEYS = {"command", "commandText", "commandPreview", "cmd", "shellCommand", "script"}
OPENCLAW_NATIVE_TOOL_PROFILES = {
    "read": {
        "action_type": "file_read", "tool_group": "filesystem", "tool_origin": "openclaw_native",
        "permission_family": "file.read", "risk_class": "low", "safe_params_required": True, "summary": "读取文件",
    },
    "file_read": {
        "action_type": "file_read", "tool_group": "filesystem", "tool_origin": "openclaw_native",
        "permission_family": "file.read", "risk_class": "low", "safe_params_required": True, "summary": "读取文件",
    },
    "write": {
        "action_type": "file_write", "tool_group": "filesystem", "tool_origin": "openclaw_native",
        "permission_family": "file.write", "risk_class": "high", "summary": "写入文件",
    },
    "edit": {
        "action_type": "file_write", "tool_group": "filesystem", "tool_origin": "openclaw_native",
        "permission_family": "file.write", "risk_class": "high", "summary": "编辑文件",
    },
    "apply_patch": {
        "action_type": "file_write", "tool_group": "filesystem", "tool_origin": "openclaw_native",
        "permission_family": "file.write", "risk_class": "high", "summary": "修改文件",
    },
    "file_delete": {
        "action_type": "file_delete", "tool_group": "filesystem", "tool_origin": "openclaw_native",
        "permission_family": "file.delete", "risk_class": "high", "summary": "删除文件",
    },
    "shell": {
        "action_type": "command_exec", "tool_group": "execution", "tool_origin": "openclaw_native",
        "permission_family": "process.execute", "risk_class": "high", "summary": "执行命令",
    },
    "shell_exec": {
        "action_type": "command_exec", "tool_group": "execution", "tool_origin": "openclaw_native",
        "permission_family": "process.execute", "risk_class": "high", "summary": "执行命令",
    },
    "exec": {
        "action_type": "command_exec", "tool_group": "execution", "tool_origin": "openclaw_native",
        "permission_family": "process.execute", "risk_class": "high", "summary": "执行命令",
    },
    "process": {
        "action_type": "command_exec", "tool_group": "execution", "tool_origin": "openclaw_native",
        "permission_family": "process.execute", "risk_class": "high", "summary": "管理进程",
    },
    "terminal": {
        "action_type": "command_exec", "tool_group": "execution", "tool_origin": "openclaw_native",
        "permission_family": "process.execute", "risk_class": "high", "summary": "操作终端",
    },
    "code_execution": {
        "action_type": "command_exec", "tool_group": "execution", "tool_origin": "openclaw_native",
        "permission_family": "process.execute", "risk_class": "high", "summary": "执行代码",
    },
    "network.request": {
        "action_type": "network_egress", "tool_group": "network", "tool_origin": "openclaw_native",
        "permission_family": "network.egress", "risk_class": "high", "summary": "访问网络",
    },
    "web_search": {
        "action_type": "network_egress", "tool_group": "web", "tool_origin": "openclaw_native",
        "permission_family": "network.egress", "risk_class": "medium", "summary": "搜索网页",
    },
    "x_search": {
        "action_type": "network_egress", "tool_group": "web", "tool_origin": "openclaw_native",
        "permission_family": "network.egress", "risk_class": "medium", "summary": "搜索 X",
    },
    "web_fetch": {
        "action_type": "network_egress", "tool_group": "web", "tool_origin": "openclaw_native",
        "permission_family": "network.egress", "risk_class": "high", "summary": "抓取网页",
    },
    "browser": {
        "action_type": "network_egress", "tool_group": "browser", "tool_origin": "openclaw_native",
        "permission_family": "browser.interact", "risk_class": "high", "summary": "操作浏览器",
    },
    "feishu.im.send": {
        "action_type": "channel_send", "tool_group": "messaging", "tool_origin": "openclaw_native",
        "permission_family": "channel.send", "risk_class": "high", "summary": "发送消息",
    },
    "message": {
        "action_type": "channel_send", "tool_group": "messaging", "tool_origin": "openclaw_native",
        "permission_family": "message.send", "risk_class": "high", "summary": "发送消息",
    },
    # Compatibility adapter used by the local chat/office fixtures.  It is
    # explicit rather than inferred, but is not advertised as a native tool.
    "mail-send": {
        "action_type": "network_egress", "tool_group": "messaging", "tool_origin": "hook_bridged",
        "permission_family": "network.egress", "risk_class": "high", "summary": "发送邮件",
    },
    "sessions_history": {
        "action_type": "file_read",
        "tool_group": "session",
        "tool_origin": "openclaw_native",
        "permission_family": "session.read",
        "risk_class": "low",
        "safe_params_required": True,
        "summary": "读取会话历史",
    },
    "sessions": {
        "action_type": "config_modify", "tool_group": "session", "tool_origin": "openclaw_native",
        "permission_family": "session.manage", "risk_class": "high", "summary": "管理会话",
    },
    "sessions_list": {
        "action_type": "file_read",
        "tool_group": "session",
        "tool_origin": "openclaw_native",
        "permission_family": "session.read",
        "risk_class": "low",
        "safe_params_required": True,
        "summary": "列出会话",
    },
    "sessions_search": {
        "action_type": "file_read", "tool_group": "session", "tool_origin": "openclaw_native",
        "permission_family": "session.read", "risk_class": "low", "safe_params_required": True, "summary": "搜索会话",
    },
    "sessions_send": {
        "action_type": "channel_send", "tool_group": "session", "tool_origin": "hook_bridged",
        "permission_family": "session.send", "risk_class": "high", "summary": "发送到会话",
    },
    "sessions_spawn": {
        "action_type": "skill_run", "tool_group": "session", "tool_origin": "hook_bridged",
        "permission_family": "agent.spawn", "risk_class": "high", "summary": "创建子代理",
    },
    "sessions_yield": {
        "action_type": "config_modify", "tool_group": "session", "tool_origin": "openclaw_native",
        "permission_family": "session.control", "risk_class": "medium", "summary": "暂停会话",
    },
    "conversations_list": {
        "action_type": "file_read", "tool_group": "session", "tool_origin": "openclaw_native",
        "permission_family": "conversation.read", "risk_class": "low", "safe_params_required": True, "summary": "列出外部会话",
    },
    "conversations_send": {
        "action_type": "channel_send", "tool_group": "session", "tool_origin": "openclaw_native",
        "permission_family": "conversation.send", "risk_class": "high", "summary": "发送外部会话消息",
    },
    "conversations_turn": {
        "action_type": "channel_send", "tool_group": "session", "tool_origin": "openclaw_native",
        "permission_family": "conversation.send", "risk_class": "high", "summary": "发起外部会话交互",
    },
    "memory_search": {
        "action_type": "file_read",
        "tool_group": "memory",
        "tool_origin": "openclaw_native",
        "permission_family": "memory.read",
        "risk_class": "low",
        "safe_params_required": True,
        "summary": "搜索记忆",
    },
    "memory_get": {
        "action_type": "file_read",
        "tool_group": "memory",
        "tool_origin": "openclaw_native",
        "permission_family": "memory.read",
        "risk_class": "low",
        "safe_params_required": True,
        "summary": "读取记忆",
    },
    "session_status": {
        "action_type": "file_read",
        "tool_group": "session",
        "tool_origin": "openclaw_native",
        "permission_family": "session.read",
        "risk_class": "low",
        "safe_params_required": True,
        "summary": "读取会话状态",
    },
    "agents_list": {
        "action_type": "file_read",
        "tool_group": "agents",
        "tool_origin": "openclaw_native",
        "permission_family": "agents.read",
        "risk_class": "low",
        "safe_params_required": True,
        "summary": "列出代理",
    },
    "get_goal": {
        "action_type": "file_read",
        "tool_group": "planning",
        "tool_origin": "openclaw_native",
        "permission_family": "goal.read",
        "risk_class": "low",
        "safe_params_required": True,
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
    "progress_card": {
        "action_type": "file_write", "tool_group": "agents", "tool_origin": "openclaw_native",
        "permission_family": "progress.write", "risk_class": "low", "summary": "更新进度卡片",
    },
    "cron": {
        "action_type": "config_modify", "tool_group": "automation", "tool_origin": "openclaw_native",
        "permission_family": "automation.modify", "risk_class": "high", "summary": "管理定时任务",
    },
    # OpenClaw 明确把 automations 定为 cron 的永久别名（RFC 0026，同一调度器工具，
    # 见 dist 中的 automations-tool-name 模块）。两者必须同档，否则同一工具在
    # allow/deny、风险分级与 RV 判定上会出现不一致。
    "automations": {
        "action_type": "config_modify", "tool_group": "automation", "tool_origin": "openclaw_native",
        "permission_family": "automation.modify", "risk_class": "high", "summary": "管理定时任务",
    },
    "gateway": {
        "action_type": "config_modify", "tool_group": "automation", "tool_origin": "openclaw_native",
        "permission_family": "gateway.modify", "risk_class": "critical", "summary": "管理网关",
    },
    "ask_user": {
        "action_type": "chat_message", "tool_group": "human_input", "tool_origin": "openclaw_native",
        "permission_family": "user.interaction", "risk_class": "low", "summary": "请求用户输入",
    },
    "secrets": {
        "action_type": "file_read", "tool_group": "credentials", "tool_origin": "openclaw_native",
        "permission_family": "credential.read", "risk_class": "high", "summary": "读取凭据",
    },
    "nodes": {
        "action_type": "config_modify", "tool_group": "nodes", "tool_origin": "openclaw_native",
        "permission_family": "node.control", "risk_class": "high", "summary": "管理节点",
    },
    "computer": {
        "action_type": "config_modify", "tool_group": "nodes", "tool_origin": "openclaw_native",
        "permission_family": "computer.control", "risk_class": "critical", "summary": "控制计算机",
    },
    "canvas": {
        "action_type": "file_write", "tool_group": "ui", "tool_origin": "openclaw_native",
        "permission_family": "ui.modify", "risk_class": "medium", "summary": "修改画布",
    },
    "screen": {
        "action_type": "file_read", "tool_group": "ui", "tool_origin": "openclaw_native",
        "permission_family": "screen.read", "risk_class": "medium", "safe_params_required": True, "summary": "读取屏幕",
    },
    "dashboard": {
        "action_type": "file_read", "tool_group": "ui", "tool_origin": "openclaw_native",
        "permission_family": "dashboard.read", "risk_class": "low", "safe_params_required": True, "summary": "读取控制面板",
    },
    # 办公外发适配器（本地 office fixture / 插件）。它们与 office_network_post 同属
    # 外发 sink：office_message_send 的参数携带收件人，office_document_share 携带共享
    # 文档与访问级别（external 表示对外共享），二者都载有可离开工作区的数据。
    # 须显式登记，否则 action_type 退化为 unknown，PMKB 与 RV 都会失去对这些外发动作的
    # 可见性（既无法命中外发/渠道规则，也无法参与跨步链式判定）。
    "office_network_post": {
        "action_type": "network_egress", "tool_group": "office", "tool_origin": "hook_bridged",
        "permission_family": "network.egress", "risk_class": "high", "summary": "外发办公数据",
    },
    "office_message_send": {
        "action_type": "channel_send", "tool_group": "office", "tool_origin": "hook_bridged",
        "permission_family": "message.send", "risk_class": "high", "summary": "发送办公消息",
    },
    "office_document_share": {
        "action_type": "network_egress", "tool_group": "office", "tool_origin": "hook_bridged",
        "permission_family": "network.egress", "risk_class": "high", "summary": "外发办公文档",
    },
}


def build_hook_event(
    payload: dict[str, Any],
    *,
    managed_project_root: str | Path | None = None,
) -> BehaviorEvent:
    tool_name = str(payload.get("toolName") or payload.get("tool_name") or "tool")
    params = payload.get("params")
    params = params if isinstance(params, dict) else {}
    tool_profile = _native_tool_profile(tool_name, params=params, payload=payload)
    profile_safe = bool(
        tool_profile
        and (
            tool_profile.get("safe_params_required") is not True
            or _native_params_are_safe(params, payload, managed_project_root)
        )
    )
    derived_paths = payload.get("derivedPaths")
    derived_paths = [str(item) for item in derived_paths if item] if isinstance(derived_paths, list) else []
    target_paths = list(dict.fromkeys([*_collect_paths(params), *derived_paths]))
    network_targets = _collect_urls(params)
    command = _extract_command(params)
    action_type = (
        str(tool_profile.get("action_type")) if profile_safe
        else "unknown" if tool_profile
        else _infer_action_type(tool_name, params, target_paths, network_targets, command)
    )
    agent_id = str(payload.get("agentId") or "").strip()
    trusted_identity = {}
    if agent_id:
        hook_binding = str(payload.get("_hook_auth_binding") or "").strip()
        principal_id = f"hook:{hook_binding}" if hook_binding else agent_id
        trusted_identity = {
            "principal_id": principal_id,
            "principal_type": "agent",
            "agent_id": agent_id,
            "capability_lineage": [f"openclaw-agent:{agent_id}"],
            "trust": "verified",
            "binding": "hook_token" if hook_binding else "direct_test_context",
        }
    metadata = {
        "hook_bridge": True,
        "tool_name": tool_name,
        "tool_kind": str(payload.get("toolKind") or "") or None,
        "tool_input_kind": str(payload.get("toolInputKind") or "") or None,
        "derived_paths": derived_paths,
        "tool_action": _native_tool_action(tool_name, params),
        "run_id": payload.get("runId"),
        "tool_call_id": payload.get("toolCallId"),
        "session_key": payload.get("sessionKey"),
        "session_id": payload.get("sessionId"),
        "agent_id": agent_id or None,
        "trusted_identity": trusted_identity,
        # FastAPI's Hook dependency sets this server-side after validating the
        # bridge token.  A caller-supplied field is never treated as proof.
        "hook_auth_verified": payload.get("_hook_auth_verified") is True,
        "hook_auth_binding": str(payload.get("_hook_auth_binding") or "") or None,
        "hook_key": hook_key_from_payload(payload),
        "tool_group": tool_profile.get("tool_group") if tool_profile else _infer_tool_group(action_type),
        "tool_origin": tool_profile.get("tool_origin") if profile_safe else "hook_bridged",
        "permission_family": (
            tool_profile.get("permission_family") if profile_safe
            else "unknown" if tool_profile
            else _infer_permission_family(action_type)
        ),
        "risk_class": (
            tool_profile.get("risk_class") if profile_safe
            else "unknown" if tool_profile
            else _infer_risk_class(action_type, command)
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
    """Unknown tools stay unknown; parameters are evidence, not a tool schema."""
    del tool_name, params, target_paths, network_targets, command
    return "unknown"


def _native_tool_profile(
    tool_name: str,
    *,
    params: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    profile = dict(OPENCLAW_NATIVE_TOOL_PROFILES.get(tool_name.lower(), {}))
    return profile


def _native_tool_summary(tool_name: str) -> str:
    profile = OPENCLAW_NATIVE_TOOL_PROFILES.get(tool_name.lower(), {})
    return str(profile.get("summary") or "")


def _native_tool_action(tool_name: str, params: dict[str, Any]) -> str:
    """Normalize sub-actions for compound OpenClaw tools without free-text inference."""
    if tool_name.lower() == "message":
        value = params.get("action") or params.get("operation")
        return str(value).strip().lower() if isinstance(value, str) and value.strip() else "send"
    if tool_name.lower() == "browser":
        value = params.get("action") or params.get("operation")
        return str(value).strip().lower() if isinstance(value, str) and value.strip() else "navigate"
    if tool_name.lower() in {"sessions", "cron", "automations", "gateway", "nodes", "computer"}:
        value = params.get("action") or params.get("operation") or params.get("method")
        return str(value).strip().lower() if isinstance(value, str) and value.strip() else "invoke"
    return "invoke"


def _native_params_are_safe(
    params: dict[str, Any],
    payload: dict[str, Any],
    managed_project_root: str | Path | None = None,
) -> bool:
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
    session_keys = {
        "sessionkey", "session_key", "sessionid", "session_id",
        "targetsession", "target_session", "targetsessionid", "target_session_id",
    }
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
            if managed_project_root:
                try:
                    candidate = Path(text).expanduser().resolve()
                    root = Path(managed_project_root).expanduser().resolve()
                    if candidate == root or root in candidate.parents:
                        return True
                except (OSError, RuntimeError, ValueError):
                    pass
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
    return "unknown"


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
    return results


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
