"""轻量级进程内事件总线。

事件只承担前端实时刷新职责；持久化真相仍由动作记录和审计链提供。
"""

from __future__ import annotations

from collections import deque
from threading import Condition, Lock
from typing import Any

from openclaw_guard.utils import utc_now_iso


class EventBus:
    def __init__(self, max_events: int = 256) -> None:
        self._events: deque[dict[str, Any]] = deque(maxlen=max_events)
        self._next_seq = 1
        self._condition = Condition(Lock())

    def publish(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._condition:
            event = {
                "type": event_type,
                "seq": self._next_seq,
                "at": utc_now_iso(),
                **payload,
            }
            self._next_seq += 1
            self._events.append(event)
            self._condition.notify_all()
            return dict(event)

    def since(self, after_seq: int = 0) -> list[dict[str, Any]]:
        with self._condition:
            return [dict(item) for item in self._events if int(item["seq"]) > after_seq]

    def wait_since(self, after_seq: int = 0, timeout: float = 15.0) -> list[dict[str, Any]]:
        with self._condition:
            events = [dict(item) for item in self._events if int(item["seq"]) > after_seq]
            if events:
                return events
            self._condition.wait(timeout)
            return [dict(item) for item in self._events if int(item["seq"]) > after_seq]

    @property
    def latest_seq(self) -> int:
        with self._condition:
            return self._next_seq - 1
