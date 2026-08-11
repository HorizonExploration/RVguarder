"""
trace_abstractor.py —— 阶段 C 步骤抽象器。

将 rv_trace 步骤（ToolCallIR 或 dict）抽象为紧凑的三元组符号，
用于基线 DFA 学习时的特征降维。

设计原则：
- 从高维 props/entities 空间压缩到低维符号，减少 DFA 状态爆炸
- 粗粒度分类：事件类型 + 实体类别位图 + 标签大类
- 纯函数，无副作用
"""

from __future__ import annotations

from typing import Any

# 标签→大类映射
_LABEL_CLASS_MAP: dict[str, str] = {
    # 办公类
    "mail_send": "office", "mail_read": "office",
    "report_send": "office", "report_generate": "office",
    "chat_message": "office", "channel_send": "office",
    "external_recipient": "office", "internal_recipient": "office",
    "has_recipient": "office", "bulk_send": "office",
    "ai_generated_content": "office", "internal_source": "office",
    "contains_secret": "office", "contains_attachment": "office",
    "attachment_open": "office", "attachment_download": "office",
    "cross_org": "office", "contacts_db": "office",
    # 文件操作
    "file_read": "file", "file_write": "file", "file_delete": "file",
    "file_search": "file", "file_compress": "file", "file_package": "file",
    "file_merge": "file", "file_upload": "file",
    "path_system_root": "file", "path_sensitive_creds": "file",
    "path_high_value": "file", "path_log": "file", "path_script": "file",
    # 网络
    "network_egress": "network", "network_http": "network",
    "network_webhook": "network", "network_upload": "network",
    "network_proxy": "network", "network_public_ip": "network",
    "network_secret_payload": "network",
    # 配置
    "config_modify": "config", "config_provider_change": "config",
    "config_auth_disable": "config", "config_bypass": "config",
    "config_sandbox_disable": "config", "config_audit_disable": "config",
    # 命令
    "command_exec": "command", "command_rm_rf": "command",
    "command_sudo": "command", "command_ssh": "command",
    "command_chmod": "command", "command_chown": "command",
    "command_mv": "command", "command_rm": "command",
    # 技能
    "skill_run": "skill", "skill_shell": "skill",
    "skill_network": "skill", "skill_delete": "skill",
    "skill_write": "skill", "skill_persistence": "skill",
}


def abstract_step(step: dict[str, Any]) -> str:
    """将单条 rv_trace 步骤抽象为紧凑符号字符串。

    符号格式: "<event_type>|<entity_sig>|<label_class>"

    其中:
    - event_type: 步骤的 event 字段（如 mail_send, file_delete）
    - entity_sig: 实体类别位图（R=recipients, P=paths, U=urls, T=tool, 无则 `_`）
    - label_class: 标签大类（取 props 中第一个可映射的 label class）

    例: "mail_send|R|office" 表示含有收件人的邮件发送操作。
    """
    event_type = str(step.get("event", "unknown") or "unknown")

    # 实体位图
    entity_parts: list[str] = []
    entities = step.get("entities") or []
    if isinstance(entities, list):
        entity_kinds = _extract_entity_kinds(entities)
        for prefix, kind in [("R", "recipients"), ("P", "paths"), ("U", "urls"), ("T", "tool_name")]:
            if kind in entity_kinds:
                entity_parts.append(prefix)
    entity_sig = "".join(entity_parts) if entity_parts else "_"

    # 标签大类
    props = step.get("props") or []
    label_class = _classify_props(props)

    return f"{event_type}|{entity_sig}|{label_class}"


def abstract_trace(trace: list[dict[str, Any]]) -> list[str]:
    """将 rv_trace 步骤列表抽象为符号序列。"""
    return [abstract_step(step) for step in trace]


def _extract_entity_kinds(entities: list[Any]) -> set[str]:
    """从实体列表提取 kind 集合。"""
    kinds: set[str] = set()
    for e in entities:
        if isinstance(e, dict):
            k = e.get("kind")
            if k:
                kinds.add(str(k))
        elif hasattr(e, "kind"):
            kinds.add(str(e.kind))
    return kinds


def _classify_props(props: list[Any]) -> str:
    """props → 标签大类（取最先命中的大类）。"""
    for p in props:
        c = _LABEL_CLASS_MAP.get(str(p))
        if c:
            return c
    return "other"
