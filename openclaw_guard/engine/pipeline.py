"""热路径安全决策流水线 —— 从 manager.py 提取的协调函数。

本模块包含：
- ingest_event_pipeline: 聊天路径流水线（collect → detect → RV → controller → save）
- handle_before_tool_call_pipeline: Hook 路径流水线（OpenClaw 审批门）
- handle_after_tool_call_pipeline: 执行后流水线（状态更新 + 审计）
- 共享私有工具函数: _annotate_event_context, _apply_rv_if_available 等

所有函数接收 GuardServices 容器作为首个参数，
从中读取 detector / controller / rv_engine / audit_store 等组件。
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, TYPE_CHECKING

from openclaw_guard.integrations.tool_hook_bridge import (
    build_hook_event,
    build_hook_source_message,
    hook_key_from_payload,
)
from openclaw_guard.utils import utc_now_iso

if TYPE_CHECKING:
    from openclaw_guard.services import GuardServices


# ---------------------------------------------------------------------------
# 共享工具函数
# ---------------------------------------------------------------------------


def _ensure_pipeline_timings(event: Any) -> dict[str, Any]:
    """确保 event.metadata 中存在 pipeline_timings_ms 字典。"""
    metadata = getattr(event, "metadata", None)
    if not isinstance(metadata, dict):
        return {}
    timings = metadata.get("pipeline_timings_ms")
    if not isinstance(timings, dict):
        timings = {}
        metadata["pipeline_timings_ms"] = timings
    return timings


def _resolve_rv_session_key(event: Any) -> str:
    """解析 RV 会话键用于 per-session 窗口隔离。

    优先级：
    1. Hook bridge 事件：使用 metadata 中的 session_id/hook_key
    2. Chat 事件：使用 raw_payload 中的 sessionId
    3. 默认："_default"（向后兼容）
    """
    metadata = getattr(event, "metadata", {}) or {}
    raw = getattr(event, "raw_payload", {}) or {}

    # Hook 事件优先使用 session_id
    session_id = str(metadata.get("session_id") or raw.get("sessionId") or "")
    if session_id:
        return f"session_{session_id}"

    # 回退到 session_key
    session_key = str(metadata.get("session_key") or raw.get("sessionKey") or "")
    if session_key:
        return f"session_{session_key}"

    return "_default"


def _annotate_event_context(
    services: GuardServices,
    event: Any,
    *,
    source_message: str = "",
    origin: str = "unknown",
) -> None:
    """为事件标注工作区边界 + 语义分析 + RV trace。

    原地修改 event.metadata。
    """
    workspace = services.context.target.workspace_path
    if workspace and event.target_paths:
        workspace_root = Path(workspace).expanduser()
        outside = False
        for item in event.target_paths:
            try:
                Path(item).expanduser().resolve().relative_to(workspace_root.resolve())
            except Exception:
                outside = True
                break
        event.metadata["outside_workspace"] = outside
    if len(event.target_paths) > 1:
        event.metadata["multi-target"] = True
    semantic_started = time.perf_counter()
    semantic_payload = services.semantic_enhancer.evaluate(
        event,
        {
            "source_message": source_message,
            "origin": origin,
            "workspace_path": str(workspace) if workspace else None,
        },
    )
    timings = _ensure_pipeline_timings(event)
    timings["semantic_ms"] = round((time.perf_counter() - semantic_started) * 1000.0, 3)
    event.metadata["semantic"] = semantic_payload["semantic"]
    event.metadata["rv_trace"] = semantic_payload["rv_trace"]


def _apply_rv_if_available(
    services: GuardServices,
    event: Any,
    decision: Any,
) -> Any:
    """在现有 detection decision 上叠加 RV 判定。

    RV 判定仅在 rv_trace 存在时执行。如果 RV 的风险等级高于
    原有 detection 判定，则覆盖 action/reason/rule_ids。

    支持 per-session 窗口隔离：不同 OpenClaw 会话拥有独立的 RV 窗口。
    """
    rv_trace = event.metadata.get("rv_trace", [])
    if not rv_trace:
        timings = _ensure_pipeline_timings(event)
        timings.setdefault("rv_ms", 0.0)
        return decision

    # Per-session 窗口隔离
    session_key = _resolve_rv_session_key(event)

    rv_started = time.perf_counter()
    rv_result = services.rv_engine.evaluate(rv_trace, session_key=session_key)
    timings = _ensure_pipeline_timings(event)
    timings["rv_ms"] = round((time.perf_counter() - rv_started) * 1000.0, 3)
    event.metadata["rv_result"] = rv_result
    event.metadata["rv_session_key"] = session_key

    rv_severity = {"block": 4, "escalate": 3, "ask": 2, "ok": 1}
    det_severity = {"block": 4, "escalate": 3, "ask": 2, "allow": 1}

    rv_level = rv_severity.get(rv_result["verdict"], 0)
    det_action = getattr(decision, "action", "allow")
    det_level = det_severity.get(det_action, 1)

    if rv_level > det_level:
        decision.action = rv_result["verdict"]
        decision.reason = (
            f"[RV] {rv_result.get('reason', '')} "
            f"(原有: {det_action})"
        )
        if rv_result.get("triggered_by"):
            decision.rule_ids = list(decision.rule_ids) + [
                f"RV-{rv_result['triggered_by']}"
            ]
    return decision


def _apply_constraint_engine(
    services: GuardServices,
    event: Any,
    decision: Any,
) -> Any:
    """在 detection 判定后叠加约束推理引擎判定（升权不降权，阶段 B）。

    约束引擎消费 rv_trace 中的结构化字段（entities/constraints/confidence），
    与 detection 的标签布尔匹配并行。仅在命中更高风险等级时覆盖决策，
    可通过 `OPENCLAW_RV_CONSTRAINT_MODE=off` 关闭。
    """
    engine = getattr(services, "constraint_engine", None)
    if engine is None or not services.constraint_engine_enabled():
        return decision
    rv_trace = event.metadata.get("rv_trace", [])
    if not rv_trace:
        return decision

    c_started = time.perf_counter()
    results = engine.evaluate_steps(rv_trace)
    timings = _ensure_pipeline_timings(event)
    timings["constraint_ms"] = round((time.perf_counter() - c_started) * 1000.0, 3)
    if not results:
        return decision

    rule, score = results[0]
    severity = {"block": 4, "escalate": 3, "ask": 2, "ok": 1}
    det_action = getattr(decision, "action", "allow")
    if severity.get(rule.decision, 0) > severity.get(det_action, 1):
        decision.action = rule.decision
        decision.reason = f"[Constraint] {rule.title} (score={score:.2f}) 原有: {det_action}"
        decision.rule_ids = list(decision.rule_ids) + [rule.rule_id]
    return decision


def _apply_session_escalation(
    services: GuardServices,
    event: Any,
    decision: Any,
) -> Any:
    """应用会话级风险升级（阶段 F）。

    按 session_key 维护 SessionSafetyState：记录每次判定累计风险，
    连续 escalate 或累计风险升级裁决（escalate→block），并附修正建议。
    可通过 `OPENCLAW_RV_SESSION_STATE=off` 关闭。
    """
    if not services.session_state_enabled():
        return decision
    session_key = _resolve_rv_session_key(event)
    state = services.session_state_for(session_key)
    upgrade = state.record(getattr(decision, "action", "ok"), decision.reason)
    event.metadata["session_state"] = state.status()
    if upgrade:
        hint = state.revision_hint()
        decision.action = upgrade
        decision.reason = (
            f"[Session] 会话风险升级为 {upgrade}（累计风险 {state.total_score}）"
            f"{('; ' + hint) if hint else ''}"
        )
        decision.rule_ids = list(decision.rule_ids) + [f"SESSION-{session_key}"]
    return decision


# ---------------------------------------------------------------------------
# 公共流水线入口
# ---------------------------------------------------------------------------


def ingest_event_pipeline(
    services: GuardServices,
    payload: dict[str, Any],
    source_message: str = "",
    *,
    auto_execute: bool = True,
) -> dict[str, Any]:
    """聊天路径安全判定流水线。

    collect → annotate → detect → RV overlay → controller → save → audit.
    """
    started = time.perf_counter()
    event = services.collectors.ingest(payload)
    _annotate_event_context(services, event, source_message=source_message, origin="chat")
    detect_started = time.perf_counter()
    decision = services.detector.evaluate(event)
    timings = _ensure_pipeline_timings(event)
    timings["detection_ms"] = round((time.perf_counter() - detect_started) * 1000.0, 3)
    decision = _apply_constraint_engine(services, event, decision)
    decision = _apply_rv_if_available(services, event, decision)
    timings = _ensure_pipeline_timings(event)
    timings.setdefault("rv_ms", 0.0)
    decision = _apply_session_escalation(services, event, decision)
    controller_started = time.perf_counter()
    controlled = services.controller.decide(event, decision, source_message or payload.get("raw_user_intent", ""))
    timings = _ensure_pipeline_timings(event)
    timings["controller_ms"] = round((time.perf_counter() - controller_started) * 1000.0, 3)
    timings["total_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
    services._save_action(controlled)
    services.audit_store.append("detection_decision", controlled.to_dict())
    services._log("detection_decision", action_id=controlled.action_id, status=controlled.status, decision=controlled.decision.action)
    if auto_execute and controlled.status == "proposed":
        return services._execute(controlled.action_id)
    return controlled.to_dict()


def handle_before_tool_call_pipeline(
    services: GuardServices,
    payload: dict[str, Any],
    *,
    wait_timeout_ms: int | None = None,
) -> dict[str, Any]:
    """Hook 路径安全判定流水线 —— OpenClaw 审批门。

    build_hook_event → annotate → detect → RV overlay → controller → save → 返回 Hook 响应。
    """
    started = time.perf_counter()

    # 自动收尾该会话中可能残留的"执行中"状态（防止 Hook 事件丢失导致卡死）
    session_id = str(payload.get("sessionId") or "")
    if session_id:
        services._auto_complete_previous_actions(session_id)

    event = build_hook_event(payload)
    hook_source_message = build_hook_source_message(event)
    _annotate_event_context(services, event, source_message=hook_source_message, origin="hook")
    detect_started = time.perf_counter()
    decision = services.detector.evaluate(event)
    timings = _ensure_pipeline_timings(event)
    timings["detection_ms"] = round((time.perf_counter() - detect_started) * 1000.0, 3)
    decision = _apply_constraint_engine(services, event, decision)
    decision = _apply_rv_if_available(services, event, decision)
    timings = _ensure_pipeline_timings(event)
    timings.setdefault("rv_ms", 0.0)
    decision = _apply_session_escalation(services, event, decision)
    controller_started = time.perf_counter()
    controlled = services.controller.decide(event, decision, hook_source_message)
    timings = _ensure_pipeline_timings(event)
    timings["controller_ms"] = round((time.perf_counter() - controller_started) * 1000.0, 3)
    timings["total_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
    hook_key = str(event.metadata.get("hook_key") or hook_key_from_payload(payload))
    controlled.event.metadata["hook_key"] = hook_key
    controlled.event.metadata["hook_bridge"] = True
    controlled.execution_result = {
        "mode": "openclaw-before-tool-call",
        "tool_name": event.metadata.get("tool_name"),
    }
    services._save_action(controlled)
    services.audit_store.append("hook_before_tool_call", controlled.to_dict())
    services._log(
        "hook_before_tool_call",
        action_id=controlled.action_id,
        hook_key=hook_key,
        tool_name=event.metadata.get("tool_name"),
        decision=controlled.decision.action,
    )

    # 意图预警阶段禁止触发阻塞审批（OpenClaw 此时不等待返回）
    if event.metadata.get("tool_name") == "before_prompt_build":
        return {
            "action": "allow",
            "action_record": controlled.to_dict(),
        }

    if controlled.status == "blocked":
        return {
            "action": "block",
            "blockReason": controlled.decision.reason,
            "action_record": controlled.to_dict(),
        }

    if controlled.status == "proposed":
        controlled.status = "executing"
        controlled.execution_result["approved_at"] = utc_now_iso()
        items = services._replace_action(controlled)
        services._save_all(items)
        return {
            "action": "allow",
            "params": payload.get("params") if isinstance(payload.get("params"), dict) else {},
            "action_record": controlled.to_dict(),
        }

    if controlled.status == "pending_approval":
        return {
            "action": "require_approval",
            "message": controlled.decision.reason,
            "severity": "critical" if controlled.decision.action == "escalate" else "warning",
            "action_record": controlled.to_dict(),
        }

    return {
        "action": "allow",
        "params": payload.get("params") if isinstance(payload.get("params"), dict) else {},
        "action_record": controlled.to_dict(),
    }


def handle_after_tool_call_pipeline(
    services: GuardServices,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """执行后状态更新流水线。

    查找 → 更新 execution_result → 标记 failed/executed → save → audit.
    """
    hook_key = hook_key_from_payload(payload)
    action = services._find_action_by_hook_key(hook_key)
    if action is None:
        return {"ok": False, "error": "action_not_found", "hook_key": hook_key}
    error = str(payload.get("error") or "").strip()
    result_summary = str(payload.get("resultSummary") or "").strip()
    action.execution_result.update(
        {
            "tool_name": payload.get("toolName"),
            "duration_ms": payload.get("durationMs"),
            "result_summary": result_summary or None,
            "completed_at": utc_now_iso(),
        }
    )
    if error:
        action.status = "failed"
        action.execution_result.update(
            {
                "error_code": "tool_execution_failed",
                "message": error,
                "user_message": "OpenClaw 工具执行失败，请查看动作详情。",
            }
        )
    elif action.status not in {"blocked", "rejected"}:
        action.status = "executed"
        action.execution_result.update({"status": "completed"})

    # 如果动作已经被拦截或拒绝，但仍然收到了 after_tool_call
    if action.status in {"blocked", "rejected"} and not error:
        action.execution_result["unexpected_execution"] = True
        services._log("unexpected_execution_after_block", action_id=action.action_id, status=action.status)

    services._save_all(services._replace_action(action))
    services.audit_store.append("hook_after_tool_call", action.to_dict())
    services._log(
        "hook_after_tool_call",
        action_id=action.action_id,
        hook_key=hook_key,
        status=action.status,
        tool_name=payload.get("toolName"),
    )
    return {"ok": True, "action": action.to_dict()}
