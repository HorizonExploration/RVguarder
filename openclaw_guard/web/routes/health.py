"""健康检查 / 摘要 / 调试 / 运行时刷新。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from openclaw_guard import api
from openclaw_guard.web.dependencies import get_manager

router = APIRouter(tags=["health"])


@router.get("/api/health")
def health(manager=Depends(get_manager)):
    payload, status = api.health(manager)
    return JSONResponse(content=payload, status_code=int(status))


@router.get("/api/summary")
def summary(view: str | None = Query(default=None), manager=Depends(get_manager)):
    payload, status = api.summary(manager, compact=view == "compact")
    return JSONResponse(content=payload, status_code=int(status))


@router.get("/api/debug/logs")
def debug_logs(manager=Depends(get_manager)):
    payload, status = api.debug_logs(manager)
    return JSONResponse(content=payload, status_code=int(status))


@router.get("/api/runtime/refresh")
def refresh_runtime(manager=Depends(get_manager)):
    payload, status = api.refresh_runtime(manager)
    return JSONResponse(content=payload, status_code=int(status))
