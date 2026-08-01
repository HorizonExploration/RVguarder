"""基线扫描 API。"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from openclaw_guard import api
from openclaw_guard.web.dependencies import body_payload, get_manager

router = APIRouter(tags=["baseline"])


@router.get("/api/baseline/latest")
def baseline_latest(manager=Depends(get_manager)):
    payload, status = api.baseline_latest(manager)
    return JSONResponse(content=payload, status_code=int(status))


@router.post("/api/baseline/run")
def baseline_run(payload: dict = Depends(body_payload), manager=Depends(get_manager)):
    payload, status = api.baseline_run(manager, payload)
    return JSONResponse(content=payload, status_code=int(status))
