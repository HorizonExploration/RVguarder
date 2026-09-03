"""前后端 HTTP API 边界。

本模块按主题分组路由处理函数，`web.py` 负责把它们装配到 BaseHTTPRequestHandler。
不在这里放任何业务逻辑，所有动作都委托给 manager / service。
"""
from __future__ import annotations

import json
from http import HTTPStatus
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from openclaw_guard.services import GuardServices
from openclaw_guard.utils import json_dumps
from openclaw_guard.utils import sha256_text, utc_now_iso


JsonResponse = tuple[dict[str, Any], int]


def health(manager: GuardServices) -> JsonResponse:
    bundle = manager.policy_engine.bundle
    fingerprint = sha256_text(json.dumps(
        {"version": bundle.version, "rules": [rule.id for rule in bundle.rules]},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ))[:16]
    return (
        {
            "ok": True,
            "product": "openclaw-guard",
            "profile": manager.context.target.profile,
            "has_target": bool(manager.context.target.config_path),
            "policy_version": bundle.version,
            "policy_rule_count": len(bundle.rules),
            "policy_fingerprint": fingerprint,
        },
        HTTPStatus.OK,
    )


def summary(manager: GuardServices, *, compact: bool = False) -> JsonResponse:
    return manager.summary(compact=compact), HTTPStatus.OK


def baseline_latest(manager: GuardServices) -> JsonResponse:
    return manager.ensure_baseline(), HTTPStatus.OK


def baseline_run(manager: GuardServices, payload: dict[str, Any] | None = None) -> JsonResponse:
    return manager.run_baseline(), HTTPStatus.OK


def list_actions(manager: GuardServices, *, status: str | None = None, source: str | None = None, limit: int = 1000) -> JsonResponse:
    items = manager.action_service.list_actions(status=status, limit=limit)
    if source:
        items = [item for item in items if item.get("source") == source or item.get("event", {}).get("metadata", {}).get("hook_bridge") == (source == "hook_bridge")]
    return {"items": items}, HTTPStatus.OK


def get_action(manager: GuardServices, action_id: str) -> JsonResponse:
    action = manager.action_service.get_action(action_id)
    if action is None:
        return _error("action_not_found", HTTPStatus.NOT_FOUND)
    return {"action": action}, HTTPStatus.OK


def clear_actions(manager: GuardServices, payload: dict[str, Any] | None = None) -> JsonResponse:
    return manager.clear_actions(), HTTPStatus.OK


def approve_action(manager: GuardServices, payload: dict[str, Any]) -> JsonResponse:
    return _call_action(manager.approve_action, payload, "action_id", confirmation_text="confirmation_text")


def reject_action(manager: GuardServices, payload: dict[str, Any]) -> JsonResponse:
    action_id = str(payload.get("action_id") or "")
    if not action_id:
        return _error("message_empty", HTTPStatus.BAD_REQUEST)
    try:
        return manager.reject_action(action_id), HTTPStatus.OK
    except KeyError:
        return _error("action_not_found", HTTPStatus.NOT_FOUND)
    except ValueError as exc:
        return _error(str(exc), HTTPStatus.BAD_REQUEST)


def ingest_event(manager: GuardServices, payload: dict[str, Any]) -> JsonResponse:
    raw_intent = str(payload.get("raw_user_intent") or "")
    return manager.ingest_event(payload, raw_intent), HTTPStatus.OK


def audit_export(manager: GuardServices, payload: dict[str, Any] | None = None) -> JsonResponse:
    return manager.export_audit(), HTTPStatus.OK


def hook_before_tool_call(manager: GuardServices, payload: dict[str, Any]) -> JsonResponse:
    return manager.handle_before_tool_call(payload), HTTPStatus.OK


def hook_after_tool_call(manager: GuardServices, payload: dict[str, Any]) -> JsonResponse:
    return manager.handle_after_tool_call(payload), HTTPStatus.OK


def resolve_hook_approval(manager: GuardServices, payload: dict[str, Any]) -> JsonResponse:
    action_id = str(payload.get("actionId") or payload.get("action_id") or "")
    decision = str(payload.get("decision") or "")
    if not action_id or not decision:
        manager.record_approval_sync("invalid")
        return _error("Missing actionId or decision", HTTPStatus.BAD_REQUEST)
    try:
        action = manager.action_service.get_action(action_id)
        if action is None:
            manager.record_approval_sync("orphans")
            manager.events.publish("hook.orphan_resolution", {"action_id": action_id, "decision": decision})
            return _error("action_not_found", HTTPStatus.NOT_FOUND)
        if action.get("source") != "hook_bridge" and not action.get("event", {}).get("metadata", {}).get("hook_bridge"):
            manager.record_approval_sync("invalid")
            return _error("hook_action_required", HTTPStatus.CONFLICT)
        normalized_decision = decision.replace("_", "-").strip().lower()
        if normalized_decision not in {"allow-once", "deny", "timeout", "cancelled"}:
            manager.record_approval_sync("invalid", _approval_latency_ms(action))
            return _error("unsupported_resolution", HTTPStatus.BAD_REQUEST)
        allowed = normalized_decision == "allow-once"
        desired_state = "allowed" if allowed else "denied"
        existing = action.get("resolution") or {}
        terminal_statuses = {"approved", "rejected", "blocked", "executed", "failed", "allow"}
        if existing:
            if (
                action.get("status") in terminal_statuses
                and existing.get("decision_state") == desired_state
            ):
                latency_ms = _approval_latency_ms(action)
                manager.record_approval_sync("idempotent", latency_ms)
                return {
                    "ok": True,
                    "accepted": True,
                    "idempotent": True,
                    "action_id": action_id,
                    "decision_state": action.get("decision_state", desired_state),
                    "sync_state": action.get("sync_state", "callback_received"),
                    "event_seq": action.get("last_event_seq"),
                    "received_at": existing.get("received_at"),
                    "latency_ms": latency_ms,
                }, HTTPStatus.OK
            if action.get("status") not in terminal_statuses:
                manager.record_approval_sync("conflicts", _approval_latency_ms(action))
                manager.audit_store.append("hook_resolution_conflict", {
                    "action_id": action_id,
                    "existing": existing,
                    "incoming_decision": decision,
                    "reason": "resolution_for_non_terminal_action",
                })
                manager.events.publish("action.conflict", {"action_id": action_id, "decision": decision})
                return _error("resolution_conflict", HTTPStatus.CONFLICT)
            action_model = manager._find_action(action_id)
            action_model.sync_state = "conflict"
            manager._save_all(manager._replace_action(action_model))
            manager.record_approval_sync("conflicts", _approval_latency_ms(action))
            manager.audit_store.append("hook_resolution_conflict", {
                "action_id": action_id,
                "existing": existing,
                "incoming_decision": decision,
            })
            manager.events.publish("action.conflict", {"action_id": action_id, "decision": decision})
            return _error("resolution_conflict", HTTPStatus.CONFLICT)

        if action.get("status") != "pending_approval":
            manager.record_approval_sync("conflicts", _approval_latency_ms(action))
            manager.audit_store.append("hook_resolution_conflict", {
                "action_id": action_id,
                "incoming_decision": decision,
                "reason": "action_not_pending",
                "status": action.get("status"),
            })
            manager.events.publish("action.conflict", {"action_id": action_id, "decision": decision})
            return _error("resolution_conflict", HTTPStatus.CONFLICT)

        if action.get("status") == "pending_approval":
            if allowed:
                manager.action_service.approve(action_id, None)
            else:
                manager.action_service.reject(action_id)
        action_model = manager._find_action(action_id)
        received_at = utc_now_iso()
        action_model.decision_state = desired_state
        action_model.execution_state = "not_started"
        action_model.sync_state = "callback_received"
        action_model.resolution = {
            "decision": normalized_decision,
            "source": "openclaw",
            "received_at": received_at,
            "decision_state": desired_state,
            "latency_ms": _approval_latency_ms(action),
        }
        # Persist the terminal decision before notifying SSE subscribers.  A
        # frontend fetch triggered by action.resolved must never observe the
        # pre-callback state from the JSON backing store.
        manager._save_all(manager._replace_action(action_model))
        event = manager.events.publish("action.resolved", {
            "action_id": action_id,
            "decision": decision,
            "source": "openclaw",
        })
        action_model.last_event_seq = event["seq"]
        manager._save_all(manager._replace_action(action_model))
        latency_ms = action_model.resolution["latency_ms"]
        manager.record_approval_sync("accepted", latency_ms)
        return {
            "ok": True,
            "accepted": True,
            "action_id": action_id,
            "decision_state": desired_state,
            "sync_state": "callback_received",
            "event_seq": event["seq"],
            "received_at": received_at,
            "latency_ms": latency_ms,
        }, HTTPStatus.OK
    except (KeyError, ValueError) as e:
        manager.record_approval_sync("invalid")
        return _error(str(e), HTTPStatus.BAD_REQUEST)
    except Exception as e:
        manager.record_approval_sync("errors")
        return _error(str(e), HTTPStatus.INTERNAL_SERVER_ERROR)


def _approval_latency_ms(action: dict[str, Any]) -> float | None:
    """Calculate callback delay from action creation without retaining payloads."""
    created_at = action.get("created_at")
    if not created_at:
        return None
    try:
        created = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return round(max(0.0, (datetime.now(timezone.utc) - created).total_seconds() * 1000), 3)
    except (TypeError, ValueError):
        return None


def refresh_runtime(manager: GuardServices) -> JsonResponse:
    return manager.refresh_runtime_target(), HTTPStatus.OK


def rv_status(manager: GuardServices) -> JsonResponse:
    return manager.rv_status(), HTTPStatus.OK


def rv_toggle(manager: GuardServices, payload: dict[str, Any]) -> JsonResponse:
    return manager.rv_toggle(payload), HTTPStatus.OK


def debug_logs(manager: GuardServices) -> JsonResponse:
    return {"path": str(manager.log_path), "items": manager.recent_logs()}, HTTPStatus.OK


def skill_upsert(manager: GuardServices, payload: dict[str, Any]) -> JsonResponse:
    name = str(payload.get("name") or "")
    if not name:
        return _error("message_empty", HTTPStatus.BAD_REQUEST)
    try:
        return manager.upsert_skill(name, payload), HTTPStatus.OK
    except FileNotFoundError:
        return _error("config_not_found", HTTPStatus.NOT_FOUND)
    except ValueError as exc:
        return _error(str(exc), HTTPStatus.BAD_REQUEST)


def skill_delete(manager: GuardServices, payload: dict[str, Any]) -> JsonResponse:
    name = str(payload.get("name") or "")
    if not name:
        return _error("message_empty", HTTPStatus.BAD_REQUEST)
    try:
        return manager.delete_skill(name), HTTPStatus.OK
    except FileNotFoundError:
        return _error("config_not_found", HTTPStatus.NOT_FOUND)
    except ValueError as exc:
        return _error(str(exc), HTTPStatus.BAD_REQUEST)


def channel_upsert(manager: GuardServices, payload: dict[str, Any]) -> JsonResponse:
    name = str(payload.get("name") or "")
    if not name:
        return _error("message_empty", HTTPStatus.BAD_REQUEST)
    try:
        return manager.upsert_channel(name, payload), HTTPStatus.OK
    except FileNotFoundError:
        return _error("config_not_found", HTTPStatus.NOT_FOUND)
    except ValueError as exc:
        return _error(str(exc), HTTPStatus.BAD_REQUEST)


def channel_delete(manager: GuardServices, payload: dict[str, Any]) -> JsonResponse:
    name = str(payload.get("name") or "")
    if not name:
        return _error("message_empty", HTTPStatus.BAD_REQUEST)
    try:
        return manager.delete_channel(name), HTTPStatus.OK
    except FileNotFoundError:
        return _error("config_not_found", HTTPStatus.NOT_FOUND)
    except ValueError as exc:
        return _error(str(exc), HTTPStatus.BAD_REQUEST)


# ---------- helpers ----------

def _call_action(
    fn: Callable[..., Any],
    payload: dict[str, Any],
    *fields: str,
    confirmation_text: str | None = None,
) -> JsonResponse:
    args: list[Any] = [str(payload.get(field) or "") for field in fields]
    if confirmation_text is not None:
        args.append(str(payload.get(confirmation_text) or ""))
    try:
        return fn(*args), HTTPStatus.OK
    except KeyError:
        return _error("action_not_found", HTTPStatus.NOT_FOUND)
    except ValueError as exc:
        return _error(str(exc), HTTPStatus.BAD_REQUEST)
    except PermissionError as exc:
        return _error(str(exc), HTTPStatus.CONFLICT)
    except Exception as exc:  # pragma: no cover - defensive
        code = getattr(exc, "code", "send_failed")
        status = HTTPStatus(getattr(exc, "status_code", 503))
        return _error(str(code), status, getattr(exc, "detail", str(exc)))


def _error(code: str, status: HTTPStatus, detail: str | None = None) -> JsonResponse:
    payload: dict[str, Any] = {
        "error": code,
        "error_code": code,
    }
    if detail:
        payload["detail"] = detail
    return payload, status


def dump_response(payload: Any) -> bytes:
    """统一 JSON 编码入口，方便 web.py 复用。"""
    return json_dumps(payload).encode("utf-8")


def read_json_body(raw: bytes) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        payload = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def hook_authorized(manager: GuardServices, token_header: str) -> bool:
    """校验来自 OpenClaw Hook 插件的鉴权 token。"""
    token = (token_header or "").strip()
    auth_path_str = manager.runtime_hook.get("auth_token_path") if manager.runtime_hook else None
    if not auth_path_str:
        return True
    auth_path = Path(str(auth_path_str))
    if not auth_path.exists():
        return False
    try:
        state = json.loads(auth_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    expected = state.get("auth_token", "")
    return bool(token) and token == expected
