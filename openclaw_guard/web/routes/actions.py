"""动作审批 / Skills / Channels API — 端点最多、错误处理最复杂的路由组。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from openclaw_guard import api
from openclaw_guard.web.dependencies import body_payload, get_manager

router = APIRouter(tags=["actions"])


@router.get("/api/actions")
def list_actions(
    status_filter: str | None = Query(default=None, alias="status"),
    source: str | None = None,
    limit: int = Query(default=1000, ge=1, le=1000),
    manager=Depends(get_manager),
):
    payload, status = api.list_actions(manager, status=status_filter, source=source, limit=limit)
    return JSONResponse(content=payload, status_code=int(status))


@router.get("/api/actions/{action_id}")
def get_action(action_id: str, manager=Depends(get_manager)):
    payload, status = api.get_action(manager, action_id)
    return JSONResponse(content=payload, status_code=int(status))


@router.post("/api/actions/ingest")
def ingest_event(payload: dict = Depends(body_payload), manager=Depends(get_manager)):
    payload, status = api.ingest_event(manager, payload)
    return JSONResponse(content=payload, status_code=int(status))


@router.post("/api/actions/approve")
def approve_action(payload: dict = Depends(body_payload), manager=Depends(get_manager)):
    payload, status = api.approve_action(manager, payload)
    return JSONResponse(content=payload, status_code=int(status))


@router.post("/api/actions/reject")
def reject_action(payload: dict = Depends(body_payload), manager=Depends(get_manager)):
    payload, status = api.reject_action(manager, payload)
    return JSONResponse(content=payload, status_code=int(status))


@router.post("/api/actions/clear")
def clear_actions(payload: dict = Depends(body_payload), manager=Depends(get_manager)):
    payload, status = api.clear_actions(manager, payload)
    return JSONResponse(content=payload, status_code=int(status))


# ─── Skills ──────────────────────────────────────────────────────


@router.post("/api/skills/upsert")
def skill_upsert(payload: dict = Depends(body_payload), manager=Depends(get_manager)):
    payload, status = api.skill_upsert(manager, payload)
    return JSONResponse(content=payload, status_code=int(status))


@router.post("/api/skills/delete")
def skill_delete(payload: dict = Depends(body_payload), manager=Depends(get_manager)):
    payload, status = api.skill_delete(manager, payload)
    return JSONResponse(content=payload, status_code=int(status))


# ─── Channels ────────────────────────────────────────────────────


@router.post("/api/channels/upsert")
def channel_upsert(payload: dict = Depends(body_payload), manager=Depends(get_manager)):
    payload, status = api.channel_upsert(manager, payload)
    return JSONResponse(content=payload, status_code=int(status))


@router.post("/api/channels/delete")
def channel_delete(payload: dict = Depends(body_payload), manager=Depends(get_manager)):
    payload, status = api.channel_delete(manager, payload)
    return JSONResponse(content=payload, status_code=int(status))
