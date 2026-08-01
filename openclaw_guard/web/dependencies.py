"""FastAPI 依赖注入：manager 获取、body 解析、Hook 鉴权。"""

from __future__ import annotations

from typing import Any

from fastapi import Body, Depends, Header, Request

from openclaw_guard.api import hook_authorized
from openclaw_guard.manager import OpenclawGuardManager
from openclaw_guard.web.errors import GuardError


def get_manager(request: Request) -> OpenclawGuardManager:
    """从 app.state.manager 获取全局 manager 单例。"""
    return request.app.state.manager  # type: ignore[attr-defined]


def body_payload(payload: dict[str, Any] | None = Body(default=None)) -> dict[str, Any]:
    """宽松 body 解析 —— 复刻 api.read_json_body() 行为：缺失/空 → {}。"""
    return payload or {}


def require_hook_token(
    manager: OpenclawGuardManager = Depends(get_manager),
    token: str | None = Header(default=None, alias="x-openclaw-guard-token"),
) -> None:
    """Hook 鉴权依赖：调用 api.hook_authorized，失败抛 401 GuardError。

    应用于整个 /api/hook router 级别，所有 Hook 端点自动鉴权。
    """
    if not hook_authorized(manager, token or ""):
        raise GuardError("hook_unauthorized", 401)
