"""有界后台准备授权事实；热路径监视器只查宿主内存，不等待IO。"""
from __future__ import annotations

from collections import OrderedDict
import copy
from dataclasses import dataclass, field
from queue import Empty, Full, Queue
import threading
import time
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

from openclaw_guard.engine.experiment_components import commit_if_current, snapshot
from openclaw_guard.spec.call_authorizer import HostCallAuthorizer, PreparedCallAuthorization
from openclaw_guard.spec.content_receipts import _freeze_bounded_json


@dataclass
class _Preparation:
    """私有请求票据，超时/替换后不可向新调用提交。"""
    token: str
    generation: int
    event: Any
    step: dict
    completed: threading.Event = field(default_factory=threading.Event)


class BoundedAuthorizationPreparation:
    """16项队列、64项短期内存、有界等待；默认仅显式私有配置启用。"""

    def __init__(self, authorizer: HostCallAuthorizer, *, component: str = "authorization") -> None:
        """创建单个daemon核验线程，关闭不等待慢IO。"""
        if component not in {"authorization", "cross_session_rv"}:
            raise ValueError("unsupported preparation component")
        self.component = component
        self.authorizer = authorizer
        self._queue: Queue = Queue(maxsize=16)
        self._lock = threading.Lock()
        self._closed = False
        self._latest: OrderedDict[str, str] = OrderedDict()
        self._ready: dict[str, PreparedCallAuthorization] = {}
        self._worker = threading.Thread(target=self._run, daemon=True, name="rv-call-authorization")
        self._worker.start()

    def prepare(self, event: Any, step: dict, *, wait_ms: int = 20) -> dict:
        """同步入口最多等待20ms后台结果；未完成维持原RV/PMKB裁决。"""
        components, generation = snapshot()
        if not getattr(components, self.component):
            return {"status": "disabled"}
        if not 0 <= wait_ms <= 20:
            raise ValueError("authorization preparation wait must be between 0 and 20ms")
        step_id = step.get("step_id")
        if not isinstance(step_id, str) or not step_id or len(step_id) > 1024:
            return {"status": "invalid_step_identity"}
        # 同一call的新核验即使缺失证明，也不能复用旧事实或让旧worker提交。
        with self._lock:
            self._latest.pop(step_id, None)
            previous = self._ready.pop(step_id, None)
        if previous is not None and hasattr(previous, "close"):
            previous.close()
        metadata = {key: event.metadata.get(key) for key in (
            "hook_auth_verified", "hook_auth_binding", "agent_id", "session_id", "run_id", "tool_call_id")}
        try:
            envelope = _freeze_bounded_json(event.raw_payload.get("executionProposal"), 16384)
            params = _freeze_bounded_json(event.raw_payload.get("params"), 65536)
            captured = {key: step.get(key) for key in ("step_id", "event_model", "execution_state", "tool_name", "operation_family")}
            captured["effects"] = list(step.get("effects") or [])
            if not isinstance(envelope, dict) or not isinstance(params, dict) or not captured["step_id"]:
                return {"status": "no_execution_proposal"}
        except (ValueError, TypeError, RecursionError):
            return {"status": "invalid_execution_proposal"}
        ticket = _Preparation(uuid4().hex, generation, SimpleNamespace(metadata=metadata,
                              raw_payload={"params": params, "executionProposal": envelope}), captured)
        retired = []
        with self._lock:
            if self._closed:
                return {"status": "disabled"}
            self._latest[step_id] = ticket.token
            self._latest.move_to_end(step_id)
            self._ready.pop(step_id, None)
            while len(self._latest) > 64:
                old, _ = self._latest.popitem(last=False)
                value = self._ready.pop(old, None)
                if value is not None:
                    retired.append(value)
        for value in retired:
            if hasattr(value, "close"):
                value.close()
        try:
            self._queue.put_nowait(ticket)
        except Full:
            self._invalidate(step_id, ticket.token)
            return {"status": "authorization_queue_full"}
        if not ticket.completed.wait(wait_ms / 1000):
            self._invalidate(step_id, ticket.token)
            return {"status": "authorization_preparation_timeout"}
        prepared = self._get(step_id, expected_token=ticket.token)
        return {"status": "authorization_prepared" if prepared else "authorization_not_verified"}

    def authorization_for_step(self, step: dict, _rule_id: str) -> Any:
        """只返回当前代际不可变事实；不从步骤自报字段或字典重建事实。"""
        prepared = self._get(step.get("step_id"))
        return prepared.fact if prepared else None

    def permit_for_exceptions(self, step_id: str, exceptions: list[dict]) -> dict | None:
        """仅实际命中的逐规则例外可携带执行permit，不能为任意allow签许可。"""
        prepared = self._get(step_id)
        if prepared is None or not any(all(item.get(key) == getattr(prepared.fact, key)
                for key in ("step_id", "grant_id", "snapshot_id", "task_id")) for item in exceptions):
            return None
        return copy.deepcopy(prepared.permit)

    def _get(self, step_id: str, *, expected_token: str | None = None) -> PreparedCallAuthorization | None:
        _, generation = snapshot()
        def read():
            with self._lock:
                if expected_token is not None and self._latest.get(step_id) != expected_token:
                    return None
                prepared = self._ready.get(step_id) if not self._closed else None
                if prepared is None or prepared.fact.component_generation != generation or prepared.fact.expires_at_ms <= int(time.time() * 1000):
                    return None
                return prepared
        accepted, result = commit_if_current(generation, self.component, read)
        return result if accepted else None

    def _invalidate(self, step_id: str, token: str) -> None:
        removed = None
        with self._lock:
            if self._latest.get(step_id) == token:
                self._latest.pop(step_id, None)
                removed = self._ready.pop(step_id, None)
        if removed is not None and hasattr(removed, "close"):
            removed.close()

    def release_for_step(self, step_id: str) -> None:
        """调用决策结束时撤去短期历史事实并释放数据库读租约。"""
        with self._lock:
            value = self._ready.pop(step_id, None)
            self._latest.pop(step_id, None)
        if value is not None and hasattr(value, "close"):
            value.close()

    def _run(self) -> None:
        while True:
            with self._lock:
                if self._closed:
                    return
            try:
                ticket = self._queue.get(timeout=0.1)
            except Empty:
                continue
            try:
                components, generation = snapshot()
                prepared = None
                if getattr(components, self.component) and ticket.generation == generation:
                    prepared = self.authorizer.prepare(ticket.event.raw_payload["executionProposal"], event=ticket.event, step=ticket.step)
                if prepared is not None:
                    def save():
                        with self._lock:
                            key = ticket.step["step_id"]
                            if not self._closed and self._latest.get(key) == ticket.token:
                                self._ready[key] = prepared
                                return True
                            return False
                    accepted, saved = commit_if_current(ticket.generation, self.component, save)
                    if (not accepted or not saved) and hasattr(prepared, "close"):
                        prepared.close()
            except Exception:
                pass  # 核验失败保留原RV裁决，不升级为Guard后端故障透传。
            finally:
                ticket.completed.set()
                self._queue.task_done()

    def close(self) -> None:
        """立即撤去事实及待提交票据，慢worker不得随后重新发布。"""
        with self._lock:
            self._closed = True
            self._latest.clear()
            values = list(self._ready.values())
            self._ready.clear()
        for value in values:
            if hasattr(value, "close"):
                value.close()
