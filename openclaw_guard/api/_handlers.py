"""前后端 HTTP API 边界。

本模块按主题分组路由处理函数，`web.py` 负责把它们装配到 BaseHTTPRequestHandler。
不在这里放任何业务逻辑，所有动作都委托给 manager / service。
"""
from __future__ import annotations

import json
from http import HTTPStatus
from pathlib import Path
from typing import Any, Callable

from openclaw_guard.services import GuardServices
from openclaw_guard.utils import json_dumps


JsonResponse = tuple[dict[str, Any], int]


def health(manager: GuardServices) -> JsonResponse:
    return (
        {
            "ok": True,
            "product": "openclaw-guard",
            "profile": manager.context.target.profile,
            "has_target": bool(manager.context.target.config_path),
        },
        HTTPStatus.OK,
    )


def summary(manager: GuardServices) -> JsonResponse:
    return manager.summary(), HTTPStatus.OK


def baseline_latest(manager: GuardServices) -> JsonResponse:
    return manager.ensure_baseline(), HTTPStatus.OK


def baseline_run(manager: GuardServices, payload: dict[str, Any] | None = None) -> JsonResponse:
    return manager.run_baseline(), HTTPStatus.OK


def list_actions(manager: GuardServices) -> JsonResponse:
    return {"items": manager.list_actions()}, HTTPStatus.OK


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
        return _error("Missing actionId or decision", HTTPStatus.BAD_REQUEST)
    try:
        # get_action returns dict
        action = manager.action_service.get_action(action_id)
        if action is None:
            return _error("action_not_found", HTTPStatus.NOT_FOUND)
        # action is a dict, check status field
        if action.get("status") == "pending_approval":
            # Allow decisions (including dash format from official spec and underscore from legacy)
            if decision in ("allow-once", "allow-always", "allow_once", "allow_always"):
                manager.action_service.approve(action_id, None)
            else:
                # deny, timeout, cancelled are all reject
                manager.action_service.reject(action_id)
        return {"ok": True}, HTTPStatus.OK
    except (KeyError, ValueError) as e:
        return _error(str(e), HTTPStatus.BAD_REQUEST)
    except Exception as e:
        return _error(str(e), HTTPStatus.INTERNAL_SERVER_ERROR)


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
