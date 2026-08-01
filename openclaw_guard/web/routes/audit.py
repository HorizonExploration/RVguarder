"""审计导出 API。"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from openclaw_guard import api
from openclaw_guard.web.dependencies import body_payload, get_manager

router = APIRouter(tags=["audit"])


@router.get("/api/audit/export")
def audit_export_get(manager=Depends(get_manager)):
    payload, status = api.audit_export(manager)
    return JSONResponse(content=payload, status_code=int(status))


@router.post("/api/audit/export")
def audit_export_post(payload: dict = Depends(body_payload), manager=Depends(get_manager)):
    payload, status = api.audit_export(manager, payload)
    return JSONResponse(content=payload, status_code=int(status))
