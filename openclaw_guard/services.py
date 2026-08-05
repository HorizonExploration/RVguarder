"""GuardServices 容器 —— OpenClaw-RVGuarder 的服务编排层。

替代原 manager.py 的上帝对象模式：
- 热路径组件（detector / semantic / controller / whitelist / audit_store）在构造时急切初始化
- 冷路径组件（rv_engine / baseline_service / audit_service / runtime_hook）通过 LazyProxy 惰性加载
- 热路径流水线（ingest / before_tool_call / after_tool_call）委托给 engine.pipeline 模块
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from dataclasses import asdict
from pathlib import Path
from typing import Any, TYPE_CHECKING

from openclaw_guard.core.action_service import ActionService
from openclaw_guard.core.baseline_service import BaselineService
from openclaw_guard.core.audit_service import AuditService
from openclaw_guard.baseline import BaselineScanner
from openclaw_guard.engine.behavior import BehaviorCollectorManager
from openclaw_guard.config import AppContext, GuardSettings, apply_env_overrides, default_paths
from openclaw_guard.engine.control import GuardController
from openclaw_guard.conversation import assistant_reply_for_action, infer_event_from_text, new_message
from openclaw_guard.engine.detection import DetectionEngine
from openclaw_guard.integrations.discovery import discover_openclaw
from openclaw_guard.storage.audit_store import AuditStore
from openclaw_guard.integrations.hook_runtime import ensure_runtime_hook_plugin
from openclaw_guard.engine.semantic_enhancer import SemanticEnhancer
from openclaw_guard.engine.runtime_verification import RuntimeVerificationEngine
from openclaw_guard.models import ControlledAction
from openclaw_guard.integrations.openclaw_adapter import (
    ChatMessage,
    OpenClawRelayError,
    get_chat_history,
    get_guard_hook_status,
    get_chat_status,
    inspect_guard_plugin,
    list_available_models,
    reset_chat_session,
    resolve_plugin_approval,
    send_chat_message,
    start_chat_message,
    switch_model,
    wait_for_run,
)
from openclaw_guard.integrations.tool_hook_bridge import build_hook_event, build_hook_source_message, hook_key_from_payload
from openclaw_guard.utils import LazyProxy, append_jsonl, read_json, utc_now_iso, write_json
from openclaw_guard.engine.whitelist import WhitelistEngine, default_police_whitelist

if TYPE_CHECKING:
    from openclaw_guard.engine.pipeline import (  # noqa: F401 - 仅类型检查使用
        _annotate_event_context,
        _apply_rv_if_available,
        _ensure_pipeline_timings,
        _resolve_rv_session_key,
        handle_after_tool_call_pipeline,
        handle_before_tool_call_pipeline,
        ingest_event_pipeline,
    )


# ------------------------------------------------------------------
# 适配器耦合方法的模块级实现
#
# 将方法体提取为模块级函数，接受适配器可调用对象作为关键字参数。
# GuardServices 使用 services.py 中导入的适配器函数调用它们；
# OpenclawGuardManager 子类使用 manager.py 中导入的适配器函数调用它们。
# 这样 patch("openclaw_guard.manager.<name>", ...) 才能生效。
# ------------------------------------------------------------------


def _chat_status_impl(services, *, get_chat_status_fn, list_available_models_fn):
    """chat_status 的实现 —— 参数化的适配器函数。"""
    status = get_chat_status_fn(services.context.target)
    if status.connected and not status.available_models:
        status.available_models = list_available_models_fn(services.context.target)
    elif not status.available_models:
        status.available_models = list(services.context.target.available_models)
    return status


def _chat_history_impl(services, *, get_chat_history_fn):
    """chat_history 的实现。"""
    try:
        messages = get_chat_history_fn(services.context.target)
    except OpenClawRelayError:
        return []
    normalized = services._dedupe_messages([services._message_from_chat(item) for item in messages])
    return normalized


def _new_chat_impl(services, *, reset_chat_session_fn):
    """new_chat 的实现。"""
    try:
        result = reset_chat_session_fn(services.context.target)
    except OpenClawRelayError as exc:
        services._log("chat_reset_failed", error_code=exc.code, detail=exc.detail)
        raise
    intro = [
        new_message(
            "assistant",
            "已为你开启新对话。你可以直接继续提问，危险动作仍会在执行前先让你确认。",
            kind="system",
        )
    ]
    services._log("chat_reset", result=result)
    services.audit_store.append("chat_reset", {"result": result})
    return {"ok": True, "messages": intro, "result": result}


def _hook_status_impl(services, *, inspect_guard_plugin_fn, get_guard_hook_status_fn):
    """hook_status 的实现。"""
    payload = dict(services.runtime_hook)
    plugin_probe = inspect_guard_plugin_fn(services.context.target)
    payload["plugin_probe"] = plugin_probe
    payload["runtime_entry_hint"] = services._runtime_entry_hint()
    recent_hook_event = services._recent_hook_activity()
    if not payload.get("installed"):
        return payload
    if payload.get("plugin_valid") is False:
        payload.setdefault("active", False)
        payload["state"] = "plugin_invalid"
        payload.setdefault("error_code", "plugin_load_failed")
        payload.setdefault("error_detail", payload.get("plugin_validation_error") or "The Guard hook plugin could not be parsed by OpenClaw.")
        return payload

    plugin_loaded_in_gateway = bool(
        plugin_probe.get("ok") and plugin_probe.get("found") and plugin_probe.get("status") == "loaded"
    )
    if plugin_loaded_in_gateway:
        payload.update(
            {
                "active": True,
                "state": "active",
                "plugin_loaded": True,
                "plugin_hook_count": plugin_probe.get("hook_count"),
                "plugin_gateway_methods": plugin_probe.get("gateway_methods"),
                "error_code": None,
                "error_detail": "Guard Hook 已成功加载到 OpenClaw gateway 中，正实时拦截工具调用。",
            }
        )
        if recent_hook_event:
            payload["runtime_hint"] = "recent_hook_activity"
        return payload

    if payload.get("restart_required"):
        payload.setdefault("active", False)
        payload["state"] = "loaded_waiting_restart"
        payload.setdefault("error_code", "gateway_restart_required")
        payload.setdefault("error_detail",
            "Guard Hook 插件已写入 OpenClaw 配置，但尚未加载到 Gateway 中。\n"
            "请在 OpenClaw 原版目录下执行以下命令重启 Gateway：\n"
            "  npm run openclaw gateway"
        )
        if recent_hook_event:
            payload["runtime_hint"] = "recent_hook_activity（来自历史日志，非当前实时连接）"
        return payload

    try:
        remote = get_guard_hook_status_fn(services.context.target)
        payload.update(
            {
                "active": bool(remote.get("ok")),
                "runtime": remote,
            }
        )
        payload["state"] = "active" if payload["active"] else "runtime_unreachable"
        return payload
    except OpenClawRelayError as exc:
        payload.update(
            {
                "active": False,
                "error_code": "gateway_unreachable",
                "error_detail": "无法连接 OpenClaw gateway。请先启动 OpenClaw，再运行本服务。",
            }
        )
        payload["state"] = "runtime_unreachable"
        if recent_hook_event:
            payload["runtime_hint"] = "recent_hook_activity（历史日志）"
        return payload


def _start_chat_action_impl(services, action_id, *, get_chat_history_fn, start_chat_message_fn):
    """start_chat_action 的实现。"""
    items = services._load_actions()
    action = services._find_action(action_id, items=items)
    if action is None:
        raise KeyError("action_not_found")
    if action.status not in {"approved", "proposed"}:
        raise ValueError("action_not_ready")
    action.status = "executing"
    history_before_count = 0
    try:
        history_before_count = len(get_chat_history_fn(services.context.target, limit=200))
    except OpenClawRelayError:
        history_before_count = 0
    try:
        relay = start_chat_message_fn(services.context.target, message=action.source_message)
    except OpenClawRelayError as exc:
        action.status = "failed"
        action.execution_result = {"error_code": exc.code, "message": exc.detail, "failed_at": utc_now_iso()}
        items = services._replace_action(action, items=items)
        services._save_all(items)
        services.audit_store.append("chat_send_failed", {"action_id": action.action_id, "error_code": exc.code, "detail": exc.detail})
        services._log("chat_send_failed", action_id=action.action_id, error_code=exc.code, detail=exc.detail)
        raise
    action.execution_result = {
        "mode": "openclaw-gateway-relay",
        "run_id": relay.run_id,
        "status": relay.status,
        "session_key": relay.session_key,
        "history_before_count": history_before_count,
        "started_at": utc_now_iso(),
    }
    items = services._replace_action(action, items=items)
    services._save_all(items)
    services.audit_store.append("chat_send_started", {"action_id": action.action_id, "run_id": relay.run_id, "status": relay.status})
    services._log("chat_send_started", action_id=action.action_id, run_id=relay.run_id, status=relay.status)
    return {
        "action": action.to_dict(),
        "messages": [],
        "reply_text": None,
        "status": relay.status,
        "wait_status": "pending",
        "done": False,
    }


def _poll_chat_action_impl(services, action_id, *, timeout_ms=1000, wait_for_run_fn, get_chat_history_fn):
    """poll_chat_action 的实现。"""
    items = services._load_actions()
    action = services._find_action(action_id, items=items)
    if action is None:
        raise KeyError("action_not_found")
    if action.status == "executed":
        return {
            "action": action.to_dict(),
            "messages": [],
            "reply_text": action.execution_result.get("reply_text"),
            "status": action.execution_result.get("status", "completed"),
            "wait_status": action.execution_result.get("wait_status"),
            "done": True,
        }
    if action.status == "failed":
        return {
            "action": action.to_dict(),
            "messages": [],
            "reply_text": None,
            "status": "failed",
            "wait_status": action.execution_result.get("wait_status"),
            "done": True,
        }
    if action.status != "executing":
        raise ValueError("action_not_ready")

    run_id = str(action.execution_result.get("run_id") or "")
    session_key = str(action.execution_result.get("session_key") or "main")
    history_before_count = int(action.execution_result.get("history_before_count") or 0)
    wait_status = "pending"
    try:
        wait_payload = wait_for_run_fn(services.context.target, run_id=run_id, timeout_ms=timeout_ms)
        if isinstance(wait_payload, dict):
            wait_status = str(wait_payload.get("status") or "completed")
            wait_error = str(wait_payload.get("error") or "").strip()
            if wait_status == "error" or wait_error:
                error_code, user_message = services._classify_runtime_failure(wait_error or "OpenClaw 运行失败。")
                action.status = "failed"
                action.execution_result.update(
                    {
                        "error_code": error_code,
                        "message": wait_error or user_message,
                        "user_message": user_message,
                        "wait_status": wait_status or "error",
                        "failed_at": utc_now_iso(),
                    }
                )
                items = services._replace_action(action, items=items)
                services._save_all(items)
                services.audit_store.append("chat_wait_failed", {"action_id": action.action_id, "error_code": error_code, "detail": wait_error})
                services._log("chat_wait_failed", action_id=action.action_id, error_code=error_code, detail=wait_error)
                return {
                    "action": action.to_dict(),
                    "messages": [],
                    "reply_text": None,
                    "status": "failed",
                    "wait_status": wait_status or "error",
                    "done": True,
                }
    except OpenClawRelayError as exc:
        if exc.code == "wait_timeout":
            wait_status = "timeout"
        else:
            action.status = "failed"
            action.execution_result.update({"error_code": exc.code, "message": exc.detail, "wait_status": "failed", "failed_at": utc_now_iso()})
            items = services._replace_action(action, items=items)
            services._save_all(items)
            services.audit_store.append("chat_wait_failed", {"action_id": action.action_id, "error_code": exc.code, "detail": exc.detail})
            services._log("chat_wait_failed", action_id=action.action_id, error_code=exc.code, detail=exc.detail)
            raise

    try:
        history_after = get_chat_history_fn(services.context.target, session_key=session_key, limit=200)
    except OpenClawRelayError as exc:
        if exc.code in {"gateway_call_failed", "gateway_invalid_response"}:
            exc = OpenClawRelayError("history_fetch_failed", exc.detail, status_code=502)
        action.execution_result["wait_status"] = wait_status
        services._save_all(services._replace_action(action, items=items))
        if exc.code == "history_fetch_failed":
            services._log("history_fetch_failed", action_id=action.action_id, error_code=exc.code, detail=exc.detail)
        raise

    messages = [services._message_from_chat(item) for item in history_after]
    suffix = history_after[history_before_count:] if history_before_count < len(history_after) else []
    reply_text = next((item.text for item in reversed(suffix) if item.role == "assistant" and item.text.strip()), None)

    if reply_text:
        reply_event = services.collectors.ingest(infer_event_from_text(reply_text))
        services._annotate_event_context(reply_event, source_message=reply_text, origin="reply")
        reply_scan = services.detector.evaluate(reply_event)
        action.execution_result.update(
            {
                "status": "completed",
                "wait_status": wait_status,
                "reply_text": reply_text,
                "reply_scan": reply_scan.to_dict(),
                "completed_at": utc_now_iso(),
            }
        )
        action.status = "executed"
        items = services._replace_action(action, items=items)
        services._save_all(items)
        services.audit_store.append("chat_send", {"action_id": action.action_id, "run_id": run_id, "status": "completed"})
        services._log("chat_send_completed", action_id=action.action_id, run_id=run_id, wait_status=wait_status)
        return {
            "action": action.to_dict(),
            "messages": [],
            "reply_text": reply_text,
            "status": "completed",
            "wait_status": wait_status,
            "done": True,
        }

    action.execution_result["wait_status"] = wait_status
    items = services._replace_action(action, items=items)
    services._save_all(items)
    services._log("chat_poll_pending", action_id=action.action_id, run_id=run_id, wait_status=wait_status)
    return {
        "action": action.to_dict(),
        "messages": [],
        "reply_text": None,
        "status": "pending",
        "wait_status": wait_status,
        "done": False,
    }


class GuardServices:
    """安全服务容器 —— 替代原 OpenclawGuardManager 上帝对象。

    持有所有子组件的引用，急热懒冷。
    公开方法与旧 manager 接口完全兼容。
    """

    def __init__(self, context: AppContext) -> None:
        context.paths.ensure()
        settings = context.settings
        settings.sqlite_path = settings.sqlite_path or context.paths.audit_dir / "audit.db"
        settings.json_backup_path = settings.json_backup_path or context.paths.audit_dir / "audit.jsonl"
        self.context = context

        # ── 热路径：急切初始化 ──
        self.collectors = BehaviorCollectorManager()
        self.detector = DetectionEngine()
        self.semantic_enhancer = SemanticEnhancer(config_path=context.paths.runtime_dir / "guard-config.json")
        self.whitelist = WhitelistEngine(default_police_whitelist())
        self.controller = GuardController(self.whitelist)

        # AuditStore —— SQLite 连接（~50ms）
        db_url = settings.get_database_url()
        if db_url:
            self.audit_store = AuditStore(
                sqlite_path=settings.sqlite_path,
                json_backup_path=settings.json_backup_path,
                connection_string=db_url,
                store_mode=settings.db_store_mode,
            )
        else:
            self.audit_store = AuditStore(
                sqlite_path=settings.sqlite_path,
                json_backup_path=settings.json_backup_path,
                store_mode=settings.db_store_mode,
            )

        self.actions_path = context.paths.runtime_dir / "controlled-actions.json"
        self.latest_baseline_path = context.paths.runtime_dir / "latest-baseline.json"
        self.conversation_path = context.paths.runtime_dir / "conversation.json"
        self.preferences_path = context.paths.runtime_dir / "preferences.json"
        self.log_path = context.paths.runtime_dir / "guard.log"

        # ── 冷路径：LazyProxy 惰性加载 ──
        self.rv_engine = LazyProxy(
            lambda: RuntimeVerificationEngine(
                window_size=10,
                rule_mode=str(self.preferences().get("rv_rule_mode") or "") or None,
            )
        )  # type: ignore[assignment]
        self.baseline_service = LazyProxy(lambda: BaselineService(context, self.latest_baseline_path))  # type: ignore[assignment]
        self.audit_service = LazyProxy(lambda: AuditService(self.audit_store))  # type: ignore[assignment]
        self.runtime_hook = LazyProxy(lambda: ensure_runtime_hook_plugin(self.context))  # type: ignore[assignment]
        self.runtime_hook._get()  # 立即执行插件写盘 —— 测试契约要求 build 后可检查文件

        self._log("session_started", mode="plugin", profile=self.context.target.profile)

        # ActionService —— 依赖上述全部组件
        self.action_service = ActionService(
            context, self.detector, self.whitelist, self.controller, self.semantic_enhancer,
            self.actions_path, lambda t, p: self.audit_store.append(t, p),
        )

    # ------------------------------------------------------------------
    # 流水线委托（热路径 —— 委托给 engine.pipeline）
    # ------------------------------------------------------------------

    def ingest_event(self, payload: dict[str, Any], source_message: str = "", *, auto_execute: bool = True) -> dict[str, Any]:
        from openclaw_guard.engine.pipeline import ingest_event_pipeline

        return ingest_event_pipeline(self, payload, source_message, auto_execute=auto_execute)

    def handle_before_tool_call(self, payload: dict[str, Any], *, wait_timeout_ms: int | None = None) -> dict[str, Any]:
        from openclaw_guard.engine.pipeline import handle_before_tool_call_pipeline

        return handle_before_tool_call_pipeline(self, payload, wait_timeout_ms=wait_timeout_ms)

    def handle_after_tool_call(self, payload: dict[str, Any]) -> dict[str, Any]:
        from openclaw_guard.engine.pipeline import handle_after_tool_call_pipeline

        return handle_after_tool_call_pipeline(self, payload)

    def _annotate_event_context(self, event: Any, *, source_message: str = "", origin: str = "unknown") -> None:
        from openclaw_guard.engine.pipeline import _annotate_event_context

        return _annotate_event_context(self, event, source_message=source_message, origin=origin)

    # ------------------------------------------------------------------
    # 状态 / 摘要查询
    # ------------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        actions = self._load_actions()
        counts = {
            "total": len(actions),
            "pending": sum(1 for item in actions if item.status == "pending_approval"),
            "approved": sum(1 for item in actions if item.status == "approved"),
            "executing": sum(1 for item in actions if item.status == "executing"),
            "executed": sum(1 for item in actions if item.status == "executed" or item.status == "allow"),
            "failed": sum(1 for item in actions if item.status == "failed"),
            "rejected": sum(1 for item in actions if item.status == "rejected"),
        }
        latest_baseline = self.ensure_baseline()
        chat_status = self.chat_status()
        return {
            "generated_at": utc_now_iso(),
            "product": self.context.describe()["product"],
            "target": self.context.target.to_dict(),
            "paths": self.context.paths.to_dict(),
            "settings": self.context.settings.to_dict(),
            "capabilities": [item.to_dict() for item in self.collectors.capabilities()],
            "baseline": latest_baseline,
            "actions": {"counts": counts, "items": [item.to_dict() for item in list(reversed(actions))[:50]]},
            "console": {},
            "chat": chat_status.to_dict(),
            "hook": self.hook_status(),
            "execution_guard": self.execution_guard_status(),
            "skills": self.skills_summary(),
            "channels": self.channels_summary(),
            "preferences": self.preferences(),
            "audit": {
                "chain": self.audit_store.verify_chain(),
                "recent": self.audit_store.query(limit=20),
            },
            "policy": {
                "template": self.context.settings.policy_template,
                "builtin_rule_count": len(self.detector.rules),
                "whitelist": asdict(default_police_whitelist()),
            },
            "rv": {
                "mode": self.preferences().get("rv_mode", True),
                "engine": self.rv_engine.result_summary(),
            },
        }

    def ensure_baseline(self) -> dict[str, Any]:
        return self.baseline_service.ensure()

    def run_baseline(self) -> dict[str, Any]:
        self.refresh_runtime_target()
        try:
            status = self.chat_status()
            if status.connected:
                self.context.target.reachability_state = "reachable"
                if self.context.target.gateway_port and self.context.target.gateway_port not in self.context.target.reachable_ports:
                    self.context.target.reachable_ports.append(self.context.target.gateway_port)
        except Exception as exc:
            self._log("baseline_precheck_failed", error=str(exc))
        return self.baseline_service.run()

    def conversation_summary(
        self,
        *,
        messages: list[dict[str, Any]] | None = None,
        actions: list[ControlledAction] | None = None,
    ) -> dict[str, Any]:
        items = messages if messages is not None else []
        action_items = list(reversed(actions if actions is not None else self._load_actions()))
        pending = [item.to_dict() for item in action_items if item.status == "pending_approval"]
        chat_status = self.chat_status()
        return {
            "messages": items[-40:],
            "pending_requests": pending[:8],
            "request_count": len(pending),
            "workspace": str(self.context.target.workspace_path) if self.context.target.workspace_path else None,
            "profile": self.context.target.profile,
            "connection_state": chat_status.connection_state,
            "current_model": chat_status.current_model,
            "current_agent": chat_status.current_agent,
            "available_models": chat_status.available_models,
        }

    def chat_status(self) -> Any:
        return _chat_status_impl(self, get_chat_status_fn=get_chat_status, list_available_models_fn=list_available_models)

    def chat_history(self) -> list[dict[str, Any]]:
        return _chat_history_impl(self, get_chat_history_fn=get_chat_history)

    def new_chat(self) -> dict[str, Any]:
        return _new_chat_impl(self, reset_chat_session_fn=reset_chat_session)

    def chat_debug(self) -> dict[str, Any]:
        status = self.chat_status().to_dict()
        return {
            "profile": self.context.target.profile,
            "config_path": str(self.context.target.config_path) if self.context.target.config_path else None,
            "source_root": str(self.context.target.source_root) if self.context.target.source_root else None,
            "gateway_port": self.context.target.gateway_port,
            "gateway_bind": self.context.target.gateway_bind,
            "gateway_urls": list(self.context.target.gateway_urls),
            "auth_mode": self.context.target.auth_mode,
            "reachability_state": self.context.target.reachability_state,
            "relay": status,
            "hook": self.hook_status(),
            "log_path": str(self.log_path),
        }

    def hook_status(self) -> dict[str, Any]:
        return _hook_status_impl(self, inspect_guard_plugin_fn=inspect_guard_plugin, get_guard_hook_status_fn=get_guard_hook_status)

    def execution_guard_status(self) -> dict[str, Any]:
        hook = self.hook_status()
        ready = bool(hook.get("active"))
        reason = None
        if not ready:
            reason = hook.get("error_detail") or hook.get("error_code") or hook.get("reason") or "hook_inactive"
        return {
            "ready": ready,
            "mode": "runtime-hook",
            "reason": reason,
            "hook": hook,
        }

    # ------------------------------------------------------------------
    # 运行时配置 / 技能 / 频道
    # ------------------------------------------------------------------

    def _runtime_entry_hint(self) -> str | None:
        if self.context.target.source_root:
            return f"cd {self.context.target.source_root} && npm run openclaw gateway"
        return None

    def refresh_runtime_target(self) -> dict[str, Any]:
        refreshed = discover_openclaw(
            openclaw_root=self.context.target.source_root,
            config_path=self.context.target.config_path,
            profile=self.context.target.profile,
            cwd=self.context.paths.project_dir,
        )
        self.context.target = refreshed
        self.runtime_hook = LazyProxy(lambda: ensure_runtime_hook_plugin(self.context))  # type: ignore[assignment]
        return self.chat_debug()

    def load_runtime_config(self) -> dict[str, Any]:
        config_path = self.context.target.config_path
        if config_path is None:
            return {}
        data = read_json(config_path)
        return data or {}

    def save_runtime_config(self, payload: dict[str, Any]) -> None:
        config_path = self.context.target.config_path
        if config_path is None:
            raise FileNotFoundError("config_not_found")
        write_json(config_path, payload)

    def skills_summary(self) -> dict[str, Any]:
        config = self.load_runtime_config()
        skills = config.get("skills") if isinstance(config, dict) else None
        items: list[dict[str, Any]] = []
        if isinstance(skills, dict):
            for name, value in skills.items():
                if not isinstance(value, dict):
                    value = {"value": value}
                items.append(
                    {
                        "name": name,
                        "enabled": bool(value.get("enabled", True)),
                        "description": value.get("description") or "",
                        "permissions": value.get("permissions") or value.get("capabilities") or [],
                    }
                )
        return {"items": items}

    def channels_summary(self) -> dict[str, Any]:
        config = self.load_runtime_config()
        channels = config.get("channels") if isinstance(config, dict) else None
        items: list[dict[str, Any]] = []
        if isinstance(channels, dict):
            for name, value in channels.items():
                if not isinstance(value, dict):
                    value = {"value": value}
                items.append(
                    {
                        "name": name,
                        "enabled": bool(value.get("enabled", True)),
                        "status": value.get("status") or ("enabled" if value.get("enabled", True) else "disabled"),
                        "target": value.get("defaultTarget") or value.get("target") or "",
                    }
                )
        return {"items": items}

    def preferences(self) -> dict[str, Any]:
        return read_json(self.preferences_path) or {"guard_mode": "strict", "reply_scan": True}

    def save_preferences(self, payload: dict[str, Any]) -> dict[str, Any]:
        prefs = self.preferences()
        prefs.update({k: v for k, v in payload.items() if k in {"guard_mode", "reply_scan"}})
        write_json(self.preferences_path, prefs)
        return prefs

    def rv_toggle(self, payload: dict[str, Any]) -> dict[str, Any]:
        enabled = bool(payload.get("enabled", True))
        rule_mode = payload.get("rule_mode")
        prefs = self.preferences()
        prefs["rv_mode"] = enabled
        if isinstance(rule_mode, str) and rule_mode.strip():
            prefs["rv_rule_mode"] = rule_mode.strip()
        write_json(self.preferences_path, prefs)
        if isinstance(rule_mode, str) and rule_mode.strip():
            try:
                self.rv_engine.set_rule_mode(rule_mode.strip())
            except Exception:
                pass
        return {"ok": True, "rv_mode": enabled, "rule_mode": prefs.get("rv_rule_mode")}

    def rv_status(self) -> dict[str, Any]:
        return {
            "ok": True,
            "mode": self.preferences().get("rv_mode", True),
            "engine": self.rv_engine.result_summary(),
            "session_count": self.rv_engine.session_count(),
        }

    def rv_monitor_status(self, session_key: str = "_default") -> dict[str, Any]:
        return self.rv_engine.result_summary(session_key=session_key)

    def cleanup_rv_session(self, session_key: str) -> dict[str, Any]:
        self.rv_engine.release_session(session_key)
        return {"ok": True, "session_key": session_key}

    def upsert_skill(self, name: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not name.strip():
            raise ValueError("message_empty")
        config = self.load_runtime_config()
        skills = config.get("skills")
        if not isinstance(skills, dict):
            skills = {}
        skills[name] = {
            "enabled": bool(payload.get("enabled", True)),
            "description": str(payload.get("description") or ""),
            "permissions": list(payload.get("permissions") or []),
        }
        config["skills"] = skills
        self.save_runtime_config(config)
        self.audit_store.append("skill_upsert", {"name": name, "enabled": skills[name]["enabled"]})
        return {"ok": True, "skills": self.skills_summary()}

    def delete_skill(self, name: str) -> dict[str, Any]:
        config = self.load_runtime_config()
        skills = config.get("skills")
        if isinstance(skills, dict):
            skills.pop(name, None)
            config["skills"] = skills
            self.save_runtime_config(config)
        self.audit_store.append("skill_delete", {"name": name})
        return {"ok": True, "skills": self.skills_summary()}

    def upsert_channel(self, name: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not name.strip():
            raise ValueError("message_empty")
        config = self.load_runtime_config()
        channels = config.get("channels")
        if not isinstance(channels, dict):
            channels = {}
        channels[name] = {
            "enabled": bool(payload.get("enabled", True)),
            "defaultTarget": str(payload.get("target") or ""),
            "status": str(payload.get("status") or ("enabled" if payload.get("enabled", True) else "disabled")),
        }
        config["channels"] = channels
        self.save_runtime_config(config)
        self.audit_store.append("channel_upsert", {"name": name, "enabled": channels[name]["enabled"]})
        return {"ok": True, "channels": self.channels_summary()}

    def delete_channel(self, name: str) -> dict[str, Any]:
        config = self.load_runtime_config()
        channels = config.get("channels")
        if isinstance(channels, dict):
            channels.pop(name, None)
            config["channels"] = channels
            self.save_runtime_config(config)
        self.audit_store.append("channel_delete", {"name": name})
        return {"ok": True, "channels": self.channels_summary()}

    # ------------------------------------------------------------------
    # 动作生命周期
    # ------------------------------------------------------------------

    def create_chat_action(self, text: str) -> dict[str, Any]:
        event = infer_event_from_text(text)
        action = self.ingest_event(event, text, auto_execute=False)
        decision = (action.get("decision") or {}).get("action")
        if decision in {"ask", "escalate", "block"}:
            msg = new_message(
                "system",
                assistant_reply_for_action(action),
                kind="status",
                metadata={"action_id": action.get("action_id"), "decision": decision},
            )
            action["messages"] = [msg]
        return action

    def execute_chat_action(self, action_id: str) -> dict[str, Any]:
        started = self.start_chat_action(action_id)
        action = started["action"]
        if action["status"] != "executing":
            return started
        max_attempts = 12
        for _ in range(max_attempts):
            polled = self.poll_chat_action(action_id, timeout_ms=1_500)
            if polled.get("done"):
                return polled
        return self.poll_chat_action(action_id, timeout_ms=1_500)

    def start_chat_action(self, action_id: str) -> dict[str, Any]:
        return _start_chat_action_impl(self, action_id, get_chat_history_fn=get_chat_history, start_chat_message_fn=start_chat_message)

    def poll_chat_action(self, action_id: str, *, timeout_ms: int = 1_000) -> dict[str, Any]:
        return _poll_chat_action_impl(self, action_id, timeout_ms=timeout_ms, wait_for_run_fn=wait_for_run, get_chat_history_fn=get_chat_history)

    def switch_chat_model(self, model: str) -> dict[str, Any]:
        result = switch_model(self.context.target, model)
        confirmed_model = str(result.get("confirmedModel") or model)
        self.context.target.current_model = confirmed_model
        if confirmed_model not in self.context.target.available_models:
            self.context.target.available_models = [*self.context.target.available_models, confirmed_model]
        self.audit_store.append("chat_model_switch", {"requested_model": model, "confirmed_model": confirmed_model, "result": result})
        self._log("chat_model_switch", requested_model=model, confirmed_model=confirmed_model)
        return {"ok": True, "model": confirmed_model, "requested_model": model, "result": result}

    def approve_action(self, action_id: str, confirmation_text: str | None = None) -> dict[str, Any]:
        action = self._find_action(action_id)
        if action is None:
            raise KeyError("action_not_found")
        if action.status != "pending_approval":
            raise ValueError("action_not_pending")
        if action.decision.requires_second_confirmation and (
            (confirmation_text or "").upper() != (action.decision.confirmation_word or "EXECUTE").upper()
        ):
            raise ValueError("confirmation_word_required")
        result = self.action_service.approve(action_id, confirmation_text)
        if action.event.metadata.get("hook_bridge"):
            run_id = (action.event.metadata.get("run_id") or
                      action.event.raw_payload.get("runId") or
                      (action.execution_result or {}).get("run_id") or "")
            if run_id:
                import threading
                threading.Thread(
                    target=lambda: resolve_plugin_approval(
                        self.context.target,
                        plugin_id="openclaw-guard-hook",
                        run_id=run_id,
                        tool_call_id=action.event.metadata.get("tool_call_id") or "",
                        decision="allow-once",
                    ),
                    daemon=True,
                ).start()
        if action.event.metadata.get("chat_relay"):
            if action.decision.action in {"ask", "escalate"}:
                guard = self.execution_guard_status()
                if not guard["ready"]:
                    action.status = "blocked"
                    action.execution_result = {
                        "blocked_at": utc_now_iso(),
                        "error_code": "runtime_hook_inactive",
                        "message": "Runtime hook is not active.",
                        "user_message": "当前还没有接入 OpenClaw 的真实执行拦截链，所以为了安全，这个高风险请求不会继续发送。请先让 Guard Hook 处于已连接状态，再继续执行。",
                        "guard": guard,
                    }
                    items = self._replace_action(action)
                    self._save_all(items)
                    self.audit_store.append("action_blocked_guard_inactive", action.to_dict())
                    self._log("action_blocked_guard_inactive", action_id=action.action_id)
                    return {"action": action.to_dict(), "reply_text": action.execution_result["user_message"]}
            return self.start_chat_action(action_id)
        return result

    def reject_action(self, action_id: str) -> dict[str, Any]:
        action = self._find_action(action_id)
        if action is None:
            raise KeyError("action_not_found")
        result = self.action_service.reject(action_id)
        self._log("action_rejected", action_id=action_id)
        if action.event.metadata.get("hook_bridge"):
            run_id = (action.event.metadata.get("run_id") or
                      action.event.raw_payload.get("runId") or
                      (action.execution_result or {}).get("run_id") or "")
            if run_id:
                import threading
                threading.Thread(
                    target=lambda: resolve_plugin_approval(
                        self.context.target,
                        plugin_id="openclaw-guard-hook",
                        run_id=run_id,
                        tool_call_id=action.event.metadata.get("tool_call_id") or "",
                        decision="deny",
                    ),
                    daemon=True,
                ).start()
        return result

    def list_actions(self) -> list[dict[str, Any]]:
        return self.action_service.list_actions()

    def clear_actions(self) -> dict[str, Any]:
        self.action_service.clear_all()
        return {"ok": True}

    def export_audit(self) -> dict[str, str]:
        return self.audit_service.export()

    def recent_logs(self, limit: int = 80) -> list[dict[str, Any]]:
        if not self.log_path.exists():
            return []
        items: list[dict[str, Any]] = []
        try:
            with self.log_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        parsed = json.loads(line)
                    except Exception:
                        continue
                    if isinstance(parsed, dict):
                        items.append(parsed)
        except OSError:
            return []
        return items[-limit:]

    # ------------------------------------------------------------------
    # 私有工具函数
    # ------------------------------------------------------------------

    def _recent_hook_activity(self) -> dict[str, Any] | None:
        threshold = datetime.now(timezone.utc) - timedelta(hours=6)
        for item in reversed(self.recent_logs(limit=200)):
            if item.get("event") in {"hook_before_tool_call", "hook_after_tool_call"}:
                timestamp = str(item.get("timestamp") or "")
                try:
                    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except ValueError:
                    parsed = None
                if parsed is None or parsed >= threshold:
                    return item
        return None

    def _execute(self, action_id: str, *, items: list[ControlledAction] | None = None) -> dict[str, Any]:
        items = items if items is not None else self._load_actions()
        action = self._find_action(action_id, items=items)
        if action is None:
            raise KeyError("action_not_found")
        if action.status not in {"approved", "proposed"}:
            raise ValueError("action_not_ready")

        if action.status == "proposed":
            action.status = "allow"
            action.execution_result = {
                "completed_at": utc_now_iso(),
                "mode": "simulation",
                "message": "已安全放行（模拟执行）",
            }
            items = self._replace_action(action, items=items)
            self._save_all(items)
            self.audit_store.append("action_allowed", action.to_dict())
            return {
                "action": action.to_dict(),
                "reply_text": "已安全放行。",
                "messages": [],
            }

        action.status = "executing"
        items = self._replace_action(action, items=items)
        self._save_all(items)
        user_message = "当前版本还没有接入这个动作的真实执行器，所以这次不会真的执行。请求已被暂停，请在接入 Hook 执行链后再继续。"
        action.execution_result = {
            "failed_at": utc_now_iso(),
            "mode": "non-intrusive-hook",
            "error_code": "executor_unavailable",
            "message": "Non-chat executor is not connected yet.",
            "user_message": user_message,
        }
        action.status = "failed"
        items = self._replace_action(action, items=items)
        self._save_all(items)
        self.audit_store.append("action_execution_failed", action.to_dict())
        self._log("action_execution_failed", action_id=action.action_id, mode="non-intrusive-hook", error_code="executor_unavailable")
        return {
            "action": action.to_dict(),
            "reply_text": user_message,
            "messages": [],
        }

    def _load_actions(self) -> list[ControlledAction]:
        return self.action_service._load()

    def _save_action(self, action: ControlledAction) -> None:
        items = self._load_actions()
        items.append(action)
        self._save_all(items)

    def _save_all(self, items: list[ControlledAction]) -> None:
        self.action_service._save_all(items)

    def _log(self, event: str, **payload: Any) -> None:
        append_jsonl(
            self.log_path,
            {
                "timestamp": utc_now_iso(),
                "event": event,
                "profile": self.context.target.profile,
                "config_path": str(self.context.target.config_path) if self.context.target.config_path else None,
                **payload,
            },
        )

    def _classify_runtime_failure(self, detail: str) -> tuple[str, str]:
        lowered = detail.lower()
        if "429" in lowered or "rate limit" in lowered or "余额不足" in detail or "充值" in detail:
            return ("provider_rate_limited", "当前模型服务已限流或额度不足，请稍后重试，或切换到其他可用模型。")
        if "authentication" in lowered or "invalid api key" in lowered or "unauthorized" in lowered:
            return ("provider_auth_failed", "当前模型服务鉴权失败，请检查模型提供方配置。")
        return ("runtime_execution_failed", "本次回复执行失败，请查看设置页中的日志详情后重试。")

    def _auto_complete_previous_actions(self, session_id: str) -> None:
        actions = self.action_service._load()
        changed = False
        for action in actions:
            if action.status == "executing" and action.event and action.event.metadata.get("session_id") == session_id:
                action.status = "executed"
                action.execution_result.update({
                    "status": "completed",
                    "completed_at": utc_now_iso(),
                    "auto_completed": True
                })
                changed = True
        if changed:
            self._save_all(actions)

    def _find_action(self, action_id: str, *, items: list[ControlledAction] | None = None) -> ControlledAction | None:
        return self.action_service._find(action_id, items=items)

    def _find_action_by_hook_key(self, hook_key: str) -> ControlledAction | None:
        return self.action_service._find_by_hook_key(hook_key)

    def _replace_action(self, action: ControlledAction, *, items: list[ControlledAction] | None = None) -> list[ControlledAction]:
        return self.action_service._replace(action, items=items)

    @staticmethod
    def _message_from_chat(item: ChatMessage) -> dict[str, Any]:
        return {
            "role": item.role,
            "content": item.text,
            "timestamp": item.timestamp,
            "kind": item.kind,
            "metadata": item.metadata,
        }

    @staticmethod
    def _dedupe_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen = set()
        unique = []
        for msg in messages:
            key = (msg.get("role"), msg.get("content"), msg.get("timestamp"))
            if key not in seen:
                seen.add(key)
                unique.append(msg)
        return unique

    # ------------------------------------------------------------------
    # 维护子命令
    # ------------------------------------------------------------------

    def install_hook(self) -> dict[str, Any]:
        target = self.context.target
        plugin = dict(self.runtime_hook)
        plugin_dir_str = plugin.get("plugin_dir")
        if not plugin_dir_str:
            return {"status": "error", "reason": "plugin_not_generated"}
        plugin_dir = Path(plugin_dir_str)
        config_path = target.config_path
        if not config_path:
            return {"status": "error", "reason": "openclaw_config_not_found", "plugin_path": str(plugin_dir)}

        try:
            from openclaw_guard.integrations.hook_runtime import register_runtime_hook_in_config

            registered = register_runtime_hook_in_config(config_path, plugin_dir)
        except Exception as exc:  # pragma: no cover - defensive
            return {"status": "error", "reason": "write_failed", "detail": str(exc)}

        return {
            "status": "ok" if registered else "noop",
            "config_path": str(config_path),
            "plugin_path": str(plugin_dir),
        }

    def uninstall_hook(self) -> dict[str, Any]:
        target = self.context.target
        config_path = target.config_path
        if not config_path:
            return {"status": "error", "reason": "openclaw_config_not_found"}

        try:
            from openclaw_guard.integrations.hook_runtime import unregister_runtime_hook_in_config

            removed = unregister_runtime_hook_in_config(config_path)
        except Exception as exc:  # pragma: no cover - defensive
            return {"status": "error", "reason": "write_failed", "detail": str(exc)}

        return {"status": "ok" if removed else "noop", "config_path": str(config_path)}

    def doctor(self) -> dict[str, Any]:
        target = self.context.target
        paths = self.context.paths

        def _exists(p: Path | None) -> bool:
            return bool(p) and Path(p).exists()  # type: ignore[arg-type]

        return {
            "paths": {
                "project_dir": str(paths.project_dir),
                "runtime_dir": str(paths.runtime_dir),
                "audit_dir": str(paths.audit_dir),
                "report_dir": str(paths.report_dir),
                "export_dir": str(paths.export_dir),
                "runtime_dir_exists": _exists(paths.runtime_dir),
                "audit_dir_exists": _exists(paths.audit_dir),
            },
            "target": {
                "config_path": str(target.config_path) if target.config_path else None,
                "config_exists": _exists(target.config_path),
                "root": str(target.root) if target.root else None,
                "root_exists": _exists(target.root),
                "gateway_port": target.gateway_port,
                "reachability_state": target.reachability_state,
            },
            "runtime_hook": {
                "plugin_path": str(self.runtime_hook.get("plugin_dir")) if self.runtime_hook else None,
                "plugin_path_exists": _exists(self.runtime_hook.get("plugin_dir")) if self.runtime_hook else False,
                "installed": bool(self.runtime_hook.get("installed")) if self.runtime_hook else False,
                "restart_required": bool(self.runtime_hook.get("restart_required")) if self.runtime_hook else False,
            },
            "summary": self.summary(),
        }


# ------------------------------------------------------------------
# 工厂函数
# ------------------------------------------------------------------


def build_services(
    project_dir: Path,
    *,
    openclaw_root: Path | None = None,
    config_path: Path | None = None,
    profile: str | None = None,
    host: str = "127.0.0.1",
    port: int = 8780,
    ui_mode: str = "pro",
) -> GuardServices:
    """构建 GuardServices 容器（替代原 build_manager 工厂）。"""
    from openclaw_guard.storage.db_store import reset_db_store

    reset_db_store()
    paths = default_paths(project_dir)
    target = discover_openclaw(openclaw_root=openclaw_root, config_path=config_path, profile=profile, cwd=project_dir)
    settings = apply_env_overrides(GuardSettings(host=host, port=port, ui_mode=ui_mode))
    context = AppContext(paths=paths, target=target, settings=settings)
    return GuardServices(context)
