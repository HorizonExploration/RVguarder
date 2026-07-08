from __future__ import annotations

import re
from typing import Any
from uuid import uuid4

from openclaw_guard.utils import utc_now_iso

_RE_PATH = re.compile(r"(~/[^\s]+|/[^\s]+)")
_RE_URL = re.compile(r"(https?://[^\s]+)", re.IGNORECASE)
_RE_RM_RF = re.compile(r"\brm\s+-rf\b")
_RE_DANGEROUS_CMD = re.compile(r"\b(sudo|ssh|scp|chmod|chown|mv|rm)\b")
_MAX_URL_LENGTH = 2048
_MAX_PATH_LENGTH = 4096


def new_message(role: str, content: str, *, kind: str = "message", metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "message_id": uuid4().hex[:16],
        "role": role,
        "content": content,
        "kind": kind,
        "created_at": utc_now_iso(),
        "metadata": metadata or {},
    }


def infer_event_from_text(text: str) -> dict[str, Any]:
    lowered = text.lower()
    path_match = _RE_PATH.search(text)
    url_match = _RE_URL.search(text)
    inferred_path = _safe_path_match(path_match.group(1)) if path_match else None
    inferred_url = _safe_url_match(url_match.group(1)) if url_match else None
    delete_intent = _contains_delete_intent(text, lowered)
    write_intent = _contains_write_intent(text, lowered)
    config_intent = _contains_config_intent(text, lowered)
    home_intent = _contains_home_intent(text, lowered)
    payload: dict[str, Any] = {
        "process_name": "openclaw",
        "user": "operator",
        "raw_user_intent": text,
        "working_directory": None,
        "metadata": {"chat_relay": True},
    }
    if home_intent:
        payload["metadata"]["outside_workspace"] = True
    if _RE_RM_RF.search(lowered):
        payload.update({"action_type": "command_exec", "command": text})
        return payload
    if _RE_DANGEROUS_CMD.search(lowered):
        payload.update({"action_type": "command_exec", "command": text})
        return payload
    if delete_intent:
        payload.update({"action_type": "file_delete", "target_paths": [inferred_path] if inferred_path else []})
        return payload
    if write_intent:
        payload.update({"action_type": "file_write", "target_paths": [inferred_path] if inferred_path else []})
        return payload
    if config_intent:
        payload.update({"action_type": "config_modify", "target_paths": [inferred_path] if inferred_path else []})
        return payload
    if inferred_url or any(token in lowered for token in ("webhook", "外联", "上传", "send to", "http://", "https://")):
        payload.update({"action_type": "network_egress", "network_targets": [inferred_url] if inferred_url else []})
        return payload
    if any(token in lowered for token in ("渠道", "频道", "channel", "发消息到")):
        payload.update({"action_type": "channel_send", "channel_name": "external-channel"})
        return payload
    if any(token in lowered for token in ("skill", "技能", "插件")):
        payload.update({"action_type": "skill_run", "skill_name": "requested-skill"})
        return payload
    payload.update({"action_type": "chat_message"})
    return payload


def _safe_url_match(url: str) -> str | None:
    if len(url) > _MAX_URL_LENGTH:
        return url[:_MAX_URL_LENGTH]
    return url


def _safe_path_match(path: str) -> str | None:
    if len(path) > _MAX_PATH_LENGTH:
        return None
    return _normalize_path_match(path)


def assistant_reply_for_action(action: dict[str, Any]) -> str:
    decision = (action.get("decision") or {}).get("action")
    target = action.get("target_summary") or "当前请求"
    reason = (action.get("decision") or {}).get("reason") or "需要进一步确认。"
    if decision == "block":
        return f"我已经拦截了这个请求：{target}。原因是：{reason}"
    if decision in {"ask", "escalate"}:
        return f"我已经把这个请求加入待审批队列：{target}。原因是：{reason}。在你批准之前，它不会继续执行。"
    return f"这条消息看起来没有明显高风险，已继续发送到 OpenClaw。"


def _normalize_path_match(value: str) -> str:
    return value.rstrip(".,;:!?)]}\"'，。；：！？）】》")


def _contains_delete_intent(text: str, lowered: str) -> bool:
    tokens = (
        "删除",
        "删掉",
        "删了",
        "删去",
        "移除",
        "清除",
        "清空",
        "remove",
        "delete",
        "unlink",
    )
    return any(token in text or token in lowered for token in tokens)


def _contains_write_intent(text: str, lowered: str) -> bool:
    tokens = (
        "写入",
        "保存",
        "覆盖",
        "改写",
        "创建文件",
        "create file",
        "write file",
        "overwrite",
    )
    return any(token in text or token in lowered for token in tokens)


def _contains_config_intent(text: str, lowered: str) -> bool:
    tokens = (
        "配置",
        "openclaw.json",
        "baseurl",
        "endpoint",
        "provider",
        "模型配置",
        "网关配置",
    )
    return any(token in text or token in lowered for token in tokens)


def _contains_home_intent(text: str, lowered: str) -> bool:
    tokens = (
        "用户目录",
        "home目录",
        "主目录",
        "home directory",
        "user directory",
    )
    return any(token in text or token in lowered for token in tokens)
