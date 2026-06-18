from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from dataclasses import asdict
from pathlib import Path
from typing import Any

from openclaw_guard.baseline import BaselineScanner
from openclaw_guard.behavior import BehaviorCollectorManager
from openclaw_guard.config import AppContext, GuardSettings, default_paths
from openclaw_guard.control import GuardController
from openclaw_guard.conversation import assistant_reply_for_action, infer_event_from_text, new_message
from openclaw_guard.detection import DetectionEngine
from openclaw_guard.discovery import discover_openclaw
from openclaw_guard.audit_store import AuditStore
from openclaw_guard.hook_runtime import ensure_runtime_hook_plugin
from openclaw_guard.models import ControlledAction
from openclaw_guard.openclaw_adapter import (
    ChatMessage,
    OpenClawRelayError,
    get_chat_history,
    get_guard_hook_status,
    get_chat_status,
    inspect_guard_plugin,
    list_available_models,
    reset_chat_session,
    send_chat_message,
    start_chat_message,
    switch_model,
    wait_for_run,
)
from openclaw_guard.tool_hook_bridge import build_hook_event, build_hook_source_message, hook_key_from_payload
from openclaw_guard.utils import append_jsonl, read_json, utc_now_iso, write_json
from openclaw_guard.whitelist import WhitelistEngine, default_police_whitelist


class OpenclawGuardManager:
    def __init__(self, context: AppContext) -> None:
        context.paths.ensure()
        settings = context.settings
        settings.sqlite_path = settings.sqlite_path or context.paths.audit_dir / "audit.db"
        settings.json_backup_path = settings.json_backup_path or context.paths.audit_dir / "audit.jsonl"
        self.context = context
        self.collectors = BehaviorCollectorManager()
        self.detector = DetectionEngine()
        self.whitelist = WhitelistEngine(default_police_whitelist())
        self.controller = GuardController(self.whitelist)
        self.audit_store = AuditStore(settings.sqlite_path, settings.json_backup_path)
        self.actions_path = context.paths.runtime_dir / "controlled-actions.json"
        self.latest_baseline_path = context.paths.runtime_dir / "latest-baseline.json"
        self.conversation_path = context.paths.runtime_dir / "conversation.json"
        self.preferences_path = context.paths.runtime_dir / "preferences.json"
        self.log_path = context.paths.runtime_dir / "guard.log"
        self._hook_waiters: dict[str, threading.Event] = {}
        self._hook_waiters_lock = threading.Lock()
        self.runtime_hook = ensure_runtime_hook_plugin(context)
        self._log("session_started", ui_mode=self.context.settings.ui_mode)

    def summary(self) -> dict[str, Any]:
        actions = self._load_actions()
        counts = {
            "pending": sum(1 for item in actions if item.status == "pending_approval"),
            "blocked": sum(1 for item in actions if item.status == "blocked"),
            "executed": sum(1 for item in actions if item.status == "executed"),
            "failed": sum(1 for item in actions if item.status == "failed"),
        }
        latest_baseline = self.ensure_baseline()
        messages = self._load_messages()
        conversation = self.conversation_summary(messages=messages, actions=actions)
        chat_status = self.chat_status()
        return {
            "generated_at": utc_now_iso(),
            "product": self.context.describe()["product"],
            "target": self.context.target.to_dict(),
            "paths": self.context.paths.to_dict(),
            "settings": self.context.settings.to_dict(),
            "capabilities": [item.to_dict() for item in self.collectors.capabilities()],
            "baseline": latest_baseline,
            "actions": {"counts": counts, "items": [item.to_dict() for item in actions[:20]]},
            "console": conversation,
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
        }

    def ensure_baseline(self) -> dict[str, Any]:
        cached = read_json(self.latest_baseline_path)
        if cached and cached.get("checks"):
            return cached
        return self.run_baseline()

    def run_baseline(self) -> dict[str, Any]:
        report = BaselineScanner(self.context).run()
        payload = report.to_dict()
        write_json(self.latest_baseline_path, payload)
        self.audit_store.append("baseline_scan", payload)
        return payload

    def conversation_summary(
        self,
        *,
        messages: list[dict[str, Any]] | None = None,
        actions: list[ControlledAction] | None = None,
    ) -> dict[str, Any]:
        items = messages if messages is not None else self._load_messages()
        action_items = actions if actions is not None else self._load_actions()
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
        status = get_chat_status(self.context.target)
        if status.connected and not status.available_models:
            status.available_models = list_available_models(self.context.target)
        elif not status.available_models:
            status.available_models = list(self.context.target.available_models)
        return status

    def chat_history(self) -> list[dict[str, Any]]:
        try:
            messages = get_chat_history(self.context.target)
        except OpenClawRelayError:
            return self._load_messages()
        normalized = self._dedupe_messages([self._message_from_chat(item) for item in messages])
        if normalized:
            self._save_messages(normalized)
            return normalized
        return self._load_messages()

    def new_chat(self) -> dict[str, Any]:
        try:
            result = reset_chat_session(self.context.target)
        except OpenClawRelayError as exc:
            self._log("chat_reset_failed", error_code=exc.code, detail=exc.detail)
            raise
        intro = [
            new_message(
                "assistant",
                "已为你开启新对话。你可以直接继续提问，危险动作仍会在执行前先让你确认。",
                kind="system",
            )
        ]
        self._save_messages(intro)
        self._log("chat_reset", result=result)
        self.audit_store.append("chat_reset", {"result": result})
        return {"ok": True, "messages": intro, "result": result}

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
        payload = dict(self.runtime_hook)
        plugin_probe = inspect_guard_plugin(self.context.target)
        payload["plugin_probe"] = plugin_probe
        payload["runtime_entry_hint"] = self._runtime_entry_hint()
        recent_hook_event = self._recent_hook_activity()
        if not payload.get("installed"):
            return payload
        if payload.get("plugin_valid") is False:
            payload.setdefault("active", False)
            payload["state"] = "plugin_invalid"
            payload.setdefault("error_code", "plugin_load_failed")
            payload.setdefault("error_detail", payload.get("plugin_validation_error") or "The Guard hook plugin could not be parsed by OpenClaw.")
            return payload
        if recent_hook_event:
            payload.update(
                {
                    "active": True,
                    "state": "active",
                    "runtime_hint": "recent_hook_activity",
                    "runtime_event": recent_hook_event,
                    "error_code": None,
                    "error_detail": "最近已经收到 OpenClaw 真实工具调用，Guard Hook 当前已在执行链中工作。",
                }
            )
            if plugin_probe.get("ok") and plugin_probe.get("found") and plugin_probe.get("status") == "loaded":
                payload["plugin_loaded"] = True
                payload["plugin_hook_count"] = plugin_probe.get("hook_count")
                payload["plugin_gateway_methods"] = plugin_probe.get("gateway_methods")
            return payload
        if payload.get("restart_required"):
            payload.setdefault("active", False)
            payload["state"] = "loaded_waiting_restart"
            payload.setdefault("error_code", "gateway_restart_required")
            payload.setdefault("error_detail", "OpenClaw gateway must restart before the Guard hook becomes active.")
            return payload
        try:
            remote = get_guard_hook_status(self.context.target)
        except OpenClawRelayError as exc:
            payload.update(
                {
                    "active": False,
                    "error_code": exc.code,
                    "error_detail": exc.detail,
                }
            )
            if plugin_probe.get("ok") and plugin_probe.get("found") and plugin_probe.get("status") == "loaded":
                payload["plugin_loaded"] = True
                payload["plugin_hook_count"] = plugin_probe.get("hook_count")
                payload["plugin_gateway_methods"] = plugin_probe.get("gateway_methods")
                if exc.code in {"gateway_unreachable", "runtime_not_running"}:
                    payload["state"] = "loaded_waiting_restart"
                    payload["error_code"] = "gateway_restart_required"
                    payload["error_detail"] = (
                        "Guard Hook 插件已经写入并可被 OpenClaw 加载，但当前正在运行的 gateway 进程还没有接入它。"
                        "请在 OpenClaw 原版目录下重新执行 npm run openclaw gateway。"
                    )
                    return payload
            payload.setdefault("state", "runtime_unreachable")
            return payload
        payload.update(
            {
                "active": bool(remote.get("ok")),
                "runtime": remote,
            }
        )
        payload["state"] = "active" if payload["active"] else "runtime_unreachable"
        return payload

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
        self.runtime_hook = ensure_runtime_hook_plugin(self.context)
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
                        "raw": value,
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
                        "raw": value,
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

    def create_chat_action(self, text: str) -> dict[str, Any]:
        event = infer_event_from_text(text)
        action = self.ingest_event(event, text, auto_execute=False)
        decision = (action.get("decision") or {}).get("action")
        if decision in {"ask", "escalate", "block"}:
            messages = self._load_messages()
            messages.append(
                new_message(
                    "system",
                    assistant_reply_for_action(action),
                    kind="status",
                    metadata={"action_id": action.get("action_id"), "decision": decision},
                )
            )
            self._save_messages(messages)
            action["messages"] = messages[-60:]
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
        items = self._load_actions()
        action = self._find_action(action_id, items=items)
        if action is None:
            raise KeyError("action_not_found")
        if action.status not in {"approved", "proposed"}:
            raise ValueError("action_not_ready")
        action.status = "executing"
        messages_before = self._load_messages()
        history_before_count = 0
        try:
            history_before_count = len(get_chat_history(self.context.target, limit=200))
        except OpenClawRelayError:
            history_before_count = 0
        user_message = new_message("user", action.source_message, kind="request", metadata={"action_id": action.action_id, "relay": True})
        messages_after = list(messages_before)
        if not messages_after or messages_after[-1].get("content") != action.source_message or messages_after[-1].get("role") != "user":
            messages_after.append(user_message)
        self._save_messages(messages_after)
        try:
            relay = start_chat_message(self.context.target, message=action.source_message)
        except OpenClawRelayError as exc:
            action.status = "failed"
            action.execution_result = {"error_code": exc.code, "message": exc.detail, "failed_at": utc_now_iso()}
            items = self._replace_action(action, items=items)
            self._save_all(items)
            self._append_system_message(f"消息发送失败：{exc.detail}")
            self.audit_store.append("chat_send_failed", {"action_id": action.action_id, "error_code": exc.code, "detail": exc.detail})
            self._log("chat_send_failed", action_id=action.action_id, error_code=exc.code, detail=exc.detail)
            raise
        action.execution_result = {
            "mode": "openclaw-gateway-relay",
            "run_id": relay.run_id,
            "status": relay.status,
            "session_key": relay.session_key,
            "history_before_count": history_before_count,
            "started_at": utc_now_iso(),
        }
        items = self._replace_action(action, items=items)
        self._save_all(items)
        self.audit_store.append("chat_send_started", {"action_id": action.action_id, "run_id": relay.run_id, "status": relay.status})
        self._log("chat_send_started", action_id=action.action_id, run_id=relay.run_id, status=relay.status)
        return {
            "action": action.to_dict(),
            "messages": messages_after[-60:],
            "reply_text": None,
            "status": relay.status,
            "wait_status": "pending",
            "done": False,
        }

    def poll_chat_action(self, action_id: str, *, timeout_ms: int = 1_000) -> dict[str, Any]:
        items = self._load_actions()
        action = self._find_action(action_id, items=items)
        if action is None:
            raise KeyError("action_not_found")
        if action.status == "executed":
            messages = self._load_messages()
            return {
                "action": action.to_dict(),
                "messages": messages[-60:],
                "reply_text": action.execution_result.get("reply_text"),
                "status": action.execution_result.get("status", "completed"),
                "wait_status": action.execution_result.get("wait_status"),
                "done": True,
            }
        if action.status == "failed":
            messages = self._load_messages()
            return {
                "action": action.to_dict(),
                "messages": messages[-60:],
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
            wait_payload = wait_for_run(self.context.target, run_id=run_id, timeout_ms=timeout_ms)
            if isinstance(wait_payload, dict):
                wait_status = str(wait_payload.get("status") or "completed")
                wait_error = str(wait_payload.get("error") or "").strip()
                if wait_status == "error" or wait_error:
                    error_code, user_message = self._classify_runtime_failure(wait_error or "OpenClaw 运行失败。")
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
                    items = self._replace_action(action, items=items)
                    self._save_all(items)
                    messages = self._load_messages() + [
                        new_message("system", user_message, kind="status", metadata={"action_id": action.action_id, "error_code": error_code})
                    ]
                    self._save_messages(messages)
                    self.audit_store.append("chat_wait_failed", {"action_id": action.action_id, "error_code": error_code, "detail": wait_error})
                    self._log("chat_wait_failed", action_id=action.action_id, error_code=error_code, detail=wait_error)
                    return {
                        "action": action.to_dict(),
                        "messages": messages[-60:],
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
                items = self._replace_action(action, items=items)
                self._save_all(items)
                self.audit_store.append("chat_wait_failed", {"action_id": action.action_id, "error_code": exc.code, "detail": exc.detail})
                self._log("chat_wait_failed", action_id=action.action_id, error_code=exc.code, detail=exc.detail)
                raise

        try:
            history_after = get_chat_history(self.context.target, session_key=session_key, limit=200)
        except OpenClawRelayError as exc:
            if exc.code in {"gateway_call_failed", "gateway_invalid_response"}:
                exc = OpenClawRelayError("history_fetch_failed", exc.detail, status_code=502)
            action.execution_result["wait_status"] = wait_status
            self._save_all(self._replace_action(action, items=items))
            if exc.code == "history_fetch_failed":
                self._log("history_fetch_failed", action_id=action.action_id, error_code=exc.code, detail=exc.detail)
            raise

        messages = [self._message_from_chat(item) for item in history_after]
        if messages:
            self._save_messages(self._dedupe_messages(messages))
        suffix = history_after[history_before_count:] if history_before_count < len(history_after) else []
        reply_text = next((item.text for item in reversed(suffix) if item.role == "assistant" and item.text.strip()), None)

        if reply_text:
            reply_scan = self.detector.evaluate(self.collectors.ingest(infer_event_from_text(reply_text)))
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
            items = self._replace_action(action, items=items)
            self._save_all(items)
            if reply_scan.action in {"ask", "escalate", "block"}:
                messages = messages + [
                    new_message(
                        "system",
                        f"安全提醒：OpenClaw 的回复里包含{reply_scan.reason}，如果你打算继续执行，请先检查动作页里的风险说明。",
                        kind="reply-safety",
                        metadata={"action_id": action.action_id, "reply_scan": reply_scan.to_dict()},
                    )
                ]
                self._save_messages(self._dedupe_messages(messages))
            self.audit_store.append("chat_send", {"action_id": action.action_id, "run_id": run_id, "status": "completed"})
            self._log("chat_send_completed", action_id=action.action_id, run_id=run_id, wait_status=wait_status)
            return {
                "action": action.to_dict(),
                "messages": messages[-60:],
                "reply_text": reply_text,
                "status": "completed",
                "wait_status": wait_status,
                "done": True,
            }

        action.execution_result["wait_status"] = wait_status
        items = self._replace_action(action, items=items)
        self._save_all(items)
        self._log("chat_poll_pending", action_id=action.action_id, run_id=run_id, wait_status=wait_status)
        return {
            "action": action.to_dict(),
            "messages": self._load_messages()[-60:],
            "reply_text": None,
            "status": "pending",
            "wait_status": wait_status,
            "done": False,
        }

    def switch_chat_model(self, model: str) -> dict[str, Any]:
        result = switch_model(self.context.target, model)
        confirmed_model = str(result.get("confirmedModel") or model)
        self.context.target.current_model = confirmed_model
        if confirmed_model not in self.context.target.available_models:
            self.context.target.available_models = [*self.context.target.available_models, confirmed_model]
        self.audit_store.append("chat_model_switch", {"requested_model": model, "confirmed_model": confirmed_model, "result": result})
        self._log("chat_model_switch", requested_model=model, confirmed_model=confirmed_model)
        return {"ok": True, "model": confirmed_model, "requested_model": model, "result": result}

    def ingest_event(self, payload: dict[str, Any], source_message: str = "", *, auto_execute: bool = True) -> dict[str, Any]:
        event = self.collectors.ingest(payload)
        workspace = self.context.target.workspace_path
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
        decision = self.detector.evaluate(event)
        controlled = self.controller.decide(event, decision, source_message or payload.get("raw_user_intent", ""))
        self._save_action(controlled)
        self.audit_store.append("detection_decision", controlled.to_dict())
        self._log("detection_decision", action_id=controlled.action_id, status=controlled.status, decision=controlled.decision.action)
        if auto_execute and controlled.status == "proposed":
            return self._execute(controlled.action_id)
        return controlled.to_dict()

    def handle_before_tool_call(self, payload: dict[str, Any], *, wait_timeout_ms: int | None = None) -> dict[str, Any]:
        event = build_hook_event(payload)
        workspace = self.context.target.workspace_path
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
        decision = self.detector.evaluate(event)
        controlled = self.controller.decide(event, decision, build_hook_source_message(event))
        hook_key = str(event.metadata.get("hook_key") or hook_key_from_payload(payload))
        controlled.event.metadata["hook_key"] = hook_key
        controlled.event.metadata["hook_bridge"] = True
        controlled.execution_result = {
            "mode": "openclaw-before-tool-call",
            "tool_name": event.metadata.get("tool_name"),
        }
        waiter: threading.Event | None = None
        if controlled.status == "pending_approval":
            waiter = threading.Event()
            self._register_hook_waiter(hook_key, waiter)
        self._save_action(controlled)
        self.audit_store.append("hook_before_tool_call", controlled.to_dict())
        self._log(
            "hook_before_tool_call",
            action_id=controlled.action_id,
            hook_key=hook_key,
            tool_name=event.metadata.get("tool_name"),
            decision=controlled.decision.action,
        )

        if controlled.status == "blocked":
            self._append_system_message(f"已拦截高风险工具调用：{controlled.target_summary}")
            return {
                "action": "block",
                "blockReason": controlled.decision.reason,
                "action_record": controlled.to_dict(),
            }

        if controlled.status == "proposed":
            controlled.status = "executing"
            controlled.execution_result["approved_at"] = utc_now_iso()
            items = self._replace_action(controlled)
            self._save_all(items)
            return {
                "action": "allow",
                "params": payload.get("params") if isinstance(payload.get("params"), dict) else {},
                "action_record": controlled.to_dict(),
            }

        self._append_system_message(f"OpenClaw 请求执行动作，已暂停等待确认：{controlled.target_summary}")
        effective_timeout_ms = wait_timeout_ms or 180_000
        approved = bool(waiter) and waiter.wait(timeout=max(effective_timeout_ms / 1000.0, 1.0))
        self._clear_hook_waiter(hook_key)
        refreshed = self._find_action_by_hook_key(hook_key)
        if refreshed is None:
            return {
                "action": "block",
                "blockReason": "Openclaw Guard 未找到待审批动作记录。",
            }
        if not approved:
            if refreshed.status == "pending_approval":
                refreshed.status = "blocked"
                refreshed.execution_result = {
                    "error_code": "approval_timeout",
                    "message": "Timed out while waiting for operator approval.",
                    "failed_at": utc_now_iso(),
                }
                self._save_all(self._replace_action(refreshed))
            return {
                "action": "block",
                "blockReason": "等待龙虾卫士审批超时，已阻止本次工具执行。",
                "action_record": refreshed.to_dict(),
            }
        if refreshed.status == "approved":
            refreshed.status = "executing"
            refreshed.execution_result.update(
                {
                    "approved_at": utc_now_iso(),
                    "mode": "openclaw-before-tool-call",
                }
            )
            self._save_all(self._replace_action(refreshed))
            return {
                "action": "allow",
                "params": payload.get("params") if isinstance(payload.get("params"), dict) else {},
                "action_record": refreshed.to_dict(),
            }
        if refreshed.status == "rejected":
            return {
                "action": "block",
                "blockReason": "该工具调用已被用户拒绝。",
                "action_record": refreshed.to_dict(),
            }
        if refreshed.status == "blocked":
            return {
                "action": "block",
                "blockReason": refreshed.decision.reason,
                "action_record": refreshed.to_dict(),
            }
        return {
            "action": "block",
            "blockReason": "Openclaw Guard 未批准本次工具执行。",
            "action_record": refreshed.to_dict(),
        }

    def handle_after_tool_call(self, payload: dict[str, Any]) -> dict[str, Any]:
        hook_key = hook_key_from_payload(payload)
        action = self._find_action_by_hook_key(hook_key)
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
            self._append_system_message(f"工具执行失败：{action.target_summary}")
        else:
            action.status = "executed"
            action.execution_result.update({"status": "completed"})
        self._save_all(self._replace_action(action))
        self.audit_store.append("hook_after_tool_call", action.to_dict())
        self._log(
            "hook_after_tool_call",
            action_id=action.action_id,
            hook_key=hook_key,
            status=action.status,
            tool_name=payload.get("toolName"),
        )
        return {"ok": True, "action": action.to_dict()}

    def approve_action(self, action_id: str, confirmation_text: str | None = None) -> dict[str, Any]:
        items = self._load_actions()
        action = self._find_action(action_id, items=items)
        if action is None:
            raise KeyError("action_not_found")
        if action.status != "pending_approval":
            raise ValueError("action_not_pending")
        if action.decision.requires_second_confirmation:
            expected = action.decision.confirmation_word or "EXECUTE"
            if (confirmation_text or "").upper() != expected:
                raise ValueError("confirmation_word_required")
        action.status = "approved"
        items = self._replace_action(action, items=items)
        self._save_all(items)
        if action.event.metadata.get("hook_bridge"):
            self._signal_hook_waiter(str(action.event.metadata.get("hook_key") or ""))
            self._append_system_message(f"已批准执行：{action.target_summary}")
            self.audit_store.append("action_approved", action.to_dict())
            self._log("action_approved", action_id=action.action_id, mode="hook_bridge")
            return {"action": action.to_dict(), "messages": self._load_messages()[-60:], "reply_text": "已批准，正在继续执行。"}
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
                    items = self._replace_action(action, items=items)
                    self._save_all(items)
                    self._append_system_message(action.execution_result["user_message"])
                    self.audit_store.append("action_blocked_guard_inactive", action.to_dict())
                    self._log("action_blocked_guard_inactive", action_id=action.action_id)
                    return {"action": action.to_dict(), "messages": self._load_messages()[-60:], "reply_text": action.execution_result["user_message"]}
            return self.start_chat_action(action_id)
        return self._execute(action_id, items=items)

    def reject_action(self, action_id: str) -> dict[str, Any]:
        items = self._load_actions()
        action = self._find_action(action_id, items=items)
        if action is None:
            raise KeyError("action_not_found")
        if action.status != "pending_approval":
            raise ValueError("action_not_pending")
        action.status = "rejected"
        items = self._replace_action(action, items=items)
        self._save_all(items)
        if action.event.metadata.get("hook_bridge"):
            self._signal_hook_waiter(str(action.event.metadata.get("hook_key") or ""))
        self._append_system_message(f"已拒绝请求：{action.target_summary}")
        self.audit_store.append("action_rejected", action.to_dict())
        self._log("action_rejected", action_id=action.action_id)
        return action.to_dict()

    def list_actions(self) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self._load_actions()]

    def export_audit(self) -> dict[str, str]:
        result = self.audit_store.export(self.context.paths.export_dir)
        self.audit_store.append("audit_export", result)
        return result

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
        self._append_system_message(f"{user_message} 目标：{action.target_summary}")
        self.audit_store.append("action_execution_failed", action.to_dict())
        self._log("action_execution_failed", action_id=action.action_id, mode="non-intrusive-hook", error_code="executor_unavailable")
        return {
            "action": action.to_dict(),
            "reply_text": user_message,
            "messages": self._load_messages()[-60:],
        }

    def list_messages(self) -> list[dict[str, Any]]:
        return self._load_messages()

    def _load_actions(self) -> list[ControlledAction]:
        if not self.actions_path.exists():
            return []
        data = read_json(self.actions_path)
        if not data:
            return []
        items = data.get("items", [])
        output: list[ControlledAction] = []
        for item in items:
            try:
                output.append(_action_from_mapping(item))
            except Exception:
                continue
        return output

    def _load_messages(self) -> list[dict[str, Any]]:
        data = read_json(self.conversation_path)
        if not data:
            return [
                new_message(
                    "assistant",
                    "这里是龙虾卫士。你可以直接在这里和 OpenClaw 对话，危险动作会在执行前停下来等你确认。",
                    kind="system",
                )
            ]
        items = data.get("items", [])
        return [item for item in items if isinstance(item, dict)]

    def _save_action(self, action: ControlledAction) -> None:
        items = self._load_actions()
        items.append(action)
        self._save_all(items)

    def _save_all(self, items: list[ControlledAction]) -> None:
        write_json(self.actions_path, {"items": [item.to_dict() for item in items]})

    def _save_messages(self, items: list[dict[str, Any]]) -> None:
        write_json(self.conversation_path, {"items": self._dedupe_messages(items)})

    def _append_system_message(self, content: str) -> None:
        items = self._load_messages()
        items.append(new_message("system", content, kind="status"))
        self._save_messages(items)

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

    def _dedupe_messages(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str, str]] = set()
        for index, item in enumerate(items):
            key = (
                str(item.get("role") or ""),
                str(item.get("kind") or ""),
                str(item.get("content") or ""),
                str((item.get("metadata") or {}).get("raw_role") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            normalized = dict(item)
            normalized["message_id"] = normalized.get("message_id") or f"msg-{index}"
            output.append(normalized)
        return output

    def _classify_runtime_failure(self, detail: str) -> tuple[str, str]:
        lowered = detail.lower()
        if "429" in lowered or "rate limit" in lowered or "余额不足" in detail or "充值" in detail:
            return ("provider_rate_limited", "当前模型服务已限流或额度不足，请稍后重试，或切换到其他可用模型。")
        if "authentication" in lowered or "invalid api key" in lowered or "unauthorized" in lowered:
            return ("provider_auth_failed", "当前模型服务鉴权失败，请检查模型提供方配置。")
        return ("runtime_execution_failed", "本次回复执行失败，请查看设置页中的日志详情后重试。")

    def _message_from_chat(self, message: ChatMessage) -> dict[str, Any]:
        kind = "message"
        if message.role == "assistant":
            kind = "assistant-reply"
        elif message.role == "system":
            kind = "status"
        return {
            "message_id": f"relay-{hash((message.role, message.text, message.timestamp)) & 0xffffffff:x}",
            "role": message.role,
            "content": message.text,
            "kind": kind,
            "created_at": message.timestamp or utc_now_iso(),
            "metadata": {"raw_role": message.raw_role, "relay": True},
        }

    def _find_action(self, action_id: str, *, items: list[ControlledAction] | None = None) -> ControlledAction | None:
        action_items = items if items is not None else self._load_actions()
        for item in action_items:
            if item.action_id == action_id:
                return item
        return None

    def _find_action_by_hook_key(self, hook_key: str) -> ControlledAction | None:
        for item in self._load_actions():
            if str(item.event.metadata.get("hook_key") or "") == hook_key:
                return item
        return None

    def _replace_action(self, action: ControlledAction, *, items: list[ControlledAction] | None = None) -> list[ControlledAction]:
        action_items = items if items is not None else self._load_actions()
        replaced: list[ControlledAction] = []
        for item in action_items:
            replaced.append(action if item.action_id == action.action_id else item)
        return replaced

    def _register_hook_waiter(self, hook_key: str, waiter: threading.Event) -> None:
        with self._hook_waiters_lock:
            self._hook_waiters[hook_key] = waiter

    def _signal_hook_waiter(self, hook_key: str) -> None:
        if not hook_key:
            return
        with self._hook_waiters_lock:
            waiter = self._hook_waiters.get(hook_key)
        if waiter is not None:
            waiter.set()

    def _clear_hook_waiter(self, hook_key: str) -> None:
        with self._hook_waiters_lock:
            self._hook_waiters.pop(hook_key, None)


def build_manager(
    project_dir: Path,
    *,
    openclaw_root: Path | None = None,
    config_path: Path | None = None,
    profile: str | None = None,
    ui_mode: str = "pro",
    host: str = "127.0.0.1",
    port: int = 8780,
) -> OpenclawGuardManager:
    paths = default_paths(project_dir)
    target = discover_openclaw(openclaw_root=openclaw_root, config_path=config_path, profile=profile, cwd=project_dir)
    context = AppContext(paths=paths, target=target, settings=GuardSettings(ui_mode=ui_mode, host=host, port=port))
    return OpenclawGuardManager(context)


def _action_from_mapping(payload: dict[str, Any]) -> ControlledAction:
    from openclaw_guard.models import BehaviorEvent, ControlledAction, DetectionDecision

    event = BehaviorEvent(**payload["event"])
    decision = DetectionDecision(**payload["decision"])
    return ControlledAction(
        action_id=payload["action_id"],
        source_message=payload["source_message"],
        created_at=payload["created_at"],
        status=payload["status"],
        event=event,
        decision=decision,
        target_summary=payload.get("target_summary", ""),
        decision_trace=list(payload.get("decision_trace", [])),
        matched_whitelists=list(payload.get("matched_whitelists", [])),
        matched_rules=list(payload.get("matched_rules", [])),
        execution_result=dict(payload.get("execution_result", {})),
    )
