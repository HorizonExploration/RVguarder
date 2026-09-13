"""FastAPI 依赖注入：manager 获取、body 解析、Hook 鉴权。"""

from __future__ import annotations

from typing import Any

from fastapi import Body, Depends, Header, Request

from openclaw_guard.api import hook_authorized
from openclaw_guard.services import GuardServices
from openclaw_guard.web.errors import GuardError
from openclaw_guard.utils import sha256_text


def get_manager(request: Request) -> GuardServices:
    """从 app.state.manager 获取全局 manager 单例。"""
    return request.app.state.manager  # type: ignore[attr-defined]


def body_payload(payload: dict[str, Any] | None = Body(default=None)) -> dict[str, Any]:
    """宽松 body 解析 —— 复刻 api.read_json_body() 行为：缺失/空 → {}。"""
    return payload or {}


def require_hook_token(
    request: Request,
    manager: GuardServices = Depends(get_manager),
    token: str | None = Header(default=None, alias="x-openclaw-guard-token"),
) -> None:
    """Hook 鉴权依赖：调用 api.hook_authorized，失败抛 401 GuardError。

    应用于整个 /api/hook router 级别，所有 Hook 端点自动鉴权。
    """
    if not hook_authorized(manager, token or ""):
        raise GuardError("hook_unauthorized", 401)
    hook_state = manager.runtime_hook.get("auth_token_path") if manager.runtime_hook else None
    request.state.openclaw_hook_authenticated = bool(hook_state)
    request.state.openclaw_hook_binding = sha256_text(token)[:32] if hook_state else None
