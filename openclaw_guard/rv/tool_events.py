"""将真实工具调用投影为有限操作效果；旧语义轨迹仅用于兼容回放。"""
from __future__ import annotations

from typing import Any

from openclaw_guard.rv.ir import ToolCallIR
from openclaw_guard.engine.command_safety import analyze_command

# 所有 PMKB 原生操作必须在此登记；新增或未知操作不会借语义标签冒充已知效果。
OPERATION_EFFECTS = {
    **{name: ("read",) for name in (
        "directory.read", "document.read", "table.read", "conversation.read",
        "screen.read", "dashboard.read", "secret.read", "credential.read",
        "file.read", "session.token.read", "session.read", "memory.read", "goal.read", "agents.read",
    )},
    **{name: ("write",) for name in (
        "document.write", "file.write", "progress.write", "goal.write", "plan.write",
    )},
    **{name: ("egress",) for name in (
        "message.send", "network.egress", "session.send", "conversation.send",
    )},
    **{name: ("configure",) for name in (
        "config.modify", "gateway.modify", "identity.auth.modify", "audit.modify",
        "calendar.modify", "meeting.create", "event.subscribe", "session.manage",
        "session.control", "ui.modify",
    )},
    "document.write": ("write", "transform"), "file.write": ("write", "transform"),
    "file.delete": ("delete",), "process.execute": ("execute",),
    "skill.execute": ("execute",), "data.query": ("read", "query"),
    "data.export": ("read", "transform", "egress"),
    "file.bulk_transfer": ("egress",), "automation.modify": ("configure", "schedule"),
    "identity.permission.grant": ("grant",), "agent.spawn": ("spawn",),
    "browser.interact": ("interact",), "node.control": ("interact",),
    "computer.control": ("interact",), "user.interaction": ("interact",),
    "workflow.approve": ("grant",), "conversation.message": ("interact",),
}

# 多功能工具必须按已登记的原生子动作建模；未知子动作保持未知。
TOOL_ACTION_EFFECTS = {
    "message": {
        "send": ("egress",), "broadcast": ("egress",), "read": ("read",),
        "search": ("read",), "edit": ("write",), "delete": ("delete",), "react": ("write",),
    },
    "cron": {
        "list": ("read",), "get": ("read",), "status": ("read",), "runs": ("read",),
        "next_check": ("read",),
        "add": ("configure", "schedule"), "update": ("configure", "schedule"),
        "remove": ("configure",), "run": ("execute", "schedule"),
    },
    "gateway": {
        "config.get": ("read",), "config.schema": ("read",),
        "config.patch": ("configure",), "config.apply": ("configure",),
        "restart": ("configure", "execute"), "update.run": ("configure", "execute"),
    },
}

# OpenClaw 2026.9.5 uses automations; cron remains its documented legacy alias.
TOOL_ACTION_EFFECTS["automations"] = TOOL_ACTION_EFFECTS["cron"]

# 仅用于迁移旧 DSL 的动作词，不用于推断真实工具的效果。
LEGACY_EFFECTS = {
    "mail_send": "egress", "report_send": "egress", "channel_send": "egress",
    "network_egress": "egress", "file_upload": "egress", "batch_upload": "egress",
    "file_read": "read", "mail_read": "read", "file_search": "read", "database_query": "query",
    "file_write": "write", "file_delete": "delete", "config_modify": "configure",
    "command_exec": "execute", "command_ssh": "egress",
    "file_compress": "transform", "file_package": "transform", "file_merge": "transform",
    "report_generate": "transform", "share_link_update": "configure",
    "cloud_cleanup": "delete",
}


def effect_label(label: str) -> str:
    """将旧动作条件转换为统一效果条件，事实标签原样保留。"""
    return f"effect:{LEGACY_EFFECTS[label]}" if label in LEGACY_EFFECTS else label


def build_tool_call_step(event: Any, authorization_trace: Any) -> dict[str, Any]:
    """一次真实调用产生一个事件；语义步骤不能添加工具效果或额外调用。"""
    trace = authorization_trace.model_dump() if hasattr(authorization_trace, "model_dump") else authorization_trace or {}
    operation = trace.get("operation") or {}
    family = str(operation.get("family") or "unknown_tool")
    effects = list(OPERATION_EFFECTS.get(family, ("unknown",)))
    metadata = event.metadata
    tool_name = str(metadata.get("tool_name") or event.api_name or event.action_type)
    if family != "unknown_tool":
        if tool_name in TOOL_ACTION_EFFECTS:
            effects = list(TOOL_ACTION_EFFECTS[tool_name].get(str(metadata.get("tool_action")), ("unknown",)))
        elif tool_name in {"web_fetch", "web_search", "x_search"}:
            effects = ["read"]
        elif family == "process.execute":
            safety = analyze_command(event.command)
            if safety.safe_read_only:
                effects.append("read")
            elif safety.classification == "network":
                effects.append("egress")
            elif safety.classification == "destructive":
                effects.append("delete")
            else:
                effects.append("unknown")
            if set(safety.commands).intersection({"rm", "rmdir"}):
                effects.append("delete")
    effects = list(dict.fromkeys(effects))
    structural = set()
    if family != "unknown_tool":
        if tool_name in {"web_fetch", "web_search", "x_search"}:
            # GET的URL、查询词也会离开本机；读结果与发送请求是同一次调用。
            effects = list(dict.fromkeys([*effects, "egress"]))
            structural.update({"contract:remote_request", "contract:untrusted_input"})
        if family == "process.execute":
            safety = analyze_command(event.command)
            effects = list(dict.fromkeys([*effects, *safety.potential_effects]))
            structural.update(f"contract:potential_{effect}" for effect in safety.potential_effects)
            if "unknown" in safety.potential_effects:
                structural.add("contract:opaque_execution")
        if family in {"secret.read", "credential.read", "session.token.read"}:
            structural.add("contract:sensitive_read")
        if tool_name == "gateway" and str(metadata.get("tool_action")) in {"config.patch", "config.apply", "update.run"}:
            structural.add("contract:control_plane_change")
        if "grant" in effects:
            structural.add("contract:permission_grant")
        if "schedule" in effects:
            structural.add("contract:delayed_authority")
    semantic = metadata.get("semantic") or {}
    semantic_steps = metadata.get("semantic_rv_trace", metadata.get("rv_trace", []))
    labels = {str(value) for value in semantic.get("labels", [])}
    for step in semantic_steps:
        if isinstance(step, dict):
            labels.update(str(value) for value in step.get("props", []))
    # 删除所有动作声明以及调用者伪造的效果命名空间。
    labels = {label for label in labels if label not in LEGACY_EFFECTS and not label.startswith(("effect:", "contract:"))}
    labels.update(structural)
    labels.update(f"effect:{effect}" for effect in effects)
    resource = trace.get("resource") or {}
    data = trace.get("data") or {}
    context = trace.get("context") or {}
    zone = context.get("recipient_zone")
    if zone in {"internal", "external"}:
        labels.difference_update({"internal_recipient", "external_recipient"})
        labels.add(f"{zone}_recipient")
    recipients = resource.get("ids", []) if resource.get("type") == "recipient" else []
    entities = []
    for kind, values in (("paths", event.target_paths), ("urls", event.network_targets), ("recipients", recipients)):
        if values:
            entities.append({"kind": kind, "values": list(values)})
    run_id, call_id = metadata.get("run_id"), metadata.get("tool_call_id")
    identity = f"{run_id}:{call_id}" if run_id and call_id else str(event.event_id)
    # ToolCallIR绑定真正传给工具的参数。PMKB的action_type/argv等派生字段
    # 留在授权Trace，不得污染执行器签名所覆盖的参数哈希。
    native_arguments = event.raw_payload.get("params") if isinstance(event.raw_payload, dict) else None
    call_arguments = dict(native_arguments) if isinstance(native_arguments, dict) else dict(operation.get("arguments") or {})
    return ToolCallIR(
        step_id=identity, event="tool_call", event_model="tool-call-v1",
        tool_name=tool_name,
        operation_family=family, effects=effects,
        arguments=call_arguments, props=sorted(labels), entities=entities,
        sensitivity=data.get("classification"), quantity=int(data.get("quantity") or 0),
        context={"scope": resource.get("scope"), "recipient_zone": zone,
                 "session_id": metadata.get("session_id"), "agent_id": metadata.get("agent_id"),
                 "principal": trace.get("principal"), "coverage": trace.get("coverage"),
                 "authorization_trace_id": trace.get("trace_id")},
        provenance={"source": "hook_projection" if metadata.get("hook_bridge") else "behavior_projection", "effect_source": "pmkb_operation_catalog_and_native_contract",
                    "semantic_facts_trust": "suggested", "contract_facts_trust": "deterministic_native_projection",
                    "command_effects_semantics": "potential_capabilities_not_execution_receipts",
                    "run_id": run_id, "tool_call_id": call_id},
    ).model_dump(mode="json")


def adapt_legacy_step(step: dict[str, Any]) -> dict[str, Any]:
    """兼容离线旧轨迹；不能作为真实 Hook 调用的可信证据。"""
    if step.get("event_model") == "tool-call-v1":
        return dict(step)
    props = list(step.get("props", []))
    labels = [*props, str(step.get("event") or "")]
    effects = sorted({LEGACY_EFFECTS[label] for label in labels if label in LEGACY_EFFECTS})
    return {**step, "event_model": "tool-call-v1", "operation_family": "legacy_replay",
            "execution_state": "legacy_replay",
            "effects": effects or ["unknown"],
            "props": list(dict.fromkeys([*props, *(effect_label(label) for label in labels)])),
            "provenance": {"source": "legacy_replay", "trust": "unverified"}}


def migrate_requirement(raw: dict[str, Any]) -> dict[str, Any]:
    """递归迁移动作、计数和时序条件到同一工具效果词汇表。"""
    result = dict(raw)
    for field in ("all_of", "any_of", "none_of"):
        if field in result:
            result[field] = list(dict.fromkeys(effect_label(label) for label in result[field]))
    event = result.pop("event", None)
    if event and event != "tool_call":
        result["all_of"] = list(dict.fromkeys([*result.get("all_of", []), effect_label(event)]))
    result["tool"] = {**(result.get("tool") or {}), "event_model": "tool-call-v1"}
    if result.get("count_gte"):
        result["count_gte"] = {**result["count_gte"], "label": effect_label(result["count_gte"]["label"])}
    if result.get("window_any_of"):
        result["window_any_of"] = {**result["window_any_of"], "labels": list(dict.fromkeys(
            effect_label(label) for label in result["window_any_of"]["labels"]))}
    if result.get("sequence"):
        result["sequence"] = {**result["sequence"], "steps": [migrate_requirement(step) for step in result["sequence"]["steps"]]}
    return result


def migrate_rules_document(raw: dict[str, Any]) -> dict[str, Any]:
    """迁移行为规约，保留规则 ID、状态和裁决，便于审计对照。"""
    return {**raw, "version": max(2, raw.get("version", 1)), "event_model": "tool-call-v1",
            "monitors": [{**monitor, "rules": [
                {**rule, "when": migrate_requirement(rule.get("when", {}))}
                for rule in monitor.get("rules", [])]} for monitor in raw.get("monitors", [])]}
