"""Guard 前端的 SSE 事件流。"""

from __future__ import annotations

import json
from typing import Generator

from fastapi import APIRouter, Depends, Header, Query
from fastapi.responses import StreamingResponse

from openclaw_guard.web.dependencies import get_manager

router = APIRouter(tags=["events"])


def _format_event(event: dict) -> str:
    return f"id: {event['seq']}\nevent: {event['type']}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"


@router.get("/api/events")
def events(
    after_seq: int = Query(default=0, ge=0),
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    manager=Depends(get_manager),
):
    if after_seq == 0 and last_event_id:
        try:
            after_seq = max(0, int(last_event_id))
        except ValueError:
            after_seq = 0
    def stream() -> Generator[str, None, None]:
        cursor = after_seq
        for event in manager.events.wait_since(cursor, timeout=15.0):
            cursor = int(event["seq"])
            yield _format_event(event)
        yield ": heartbeat\n\n"

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )
