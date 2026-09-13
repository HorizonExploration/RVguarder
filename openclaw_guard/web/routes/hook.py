"""Hook 桥接 API — OpenClaw Plugin SDK 合约端点。

所有 /api/hook/* 端点通过 router 级别依赖自动鉴权（x-openclaw-guard-token）。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from openclaw_guard import api
from openclaw_guard.web.dependencies import body_payload, get_manager, require_hook_token

router = APIRouter(
    prefix="/api/hook",
    tags=["hook"],
    dependencies=[Depends(require_hook_token)],
)


@router.post("/before-tool-call")
def before_tool_call(request: Request, payload: dict = Depends(body_payload), manager=Depends(get_manager)):
    payload = {
        **payload,
        "_hook_auth_verified": bool(getattr(request.state, "openclaw_hook_authenticated", False)),
        "_hook_auth_binding": getattr(request.state, "openclaw_hook_binding", None),
    }
    payload, status = api.hook_before_tool_call(manager, payload)
    return JSONResponse(content=payload, status_code=int(status))


@router.post("/after-tool-call")
def after_tool_call(payload: dict = Depends(body_payload), manager=Depends(get_manager)):
    payload, status = api.hook_after_tool_call(manager, payload)
    return JSONResponse(content=payload, status_code=int(status))


@router.post("/resolve-approval")
def resolve_approval(payload: dict = Depends(body_payload), manager=Depends(get_manager)):
    payload, status = api.resolve_hook_approval(manager, payload)
    return JSONResponse(content=payload, status_code=int(status))
