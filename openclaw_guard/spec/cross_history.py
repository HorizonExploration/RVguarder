"""有界核验真实跨会话读取历史；供有限工具DSL的独立block守卫。"""
from __future__ import annotations

from dataclasses import dataclass
from queue import Empty, Full, Queue
import threading
import time
from types import SimpleNamespace

from openclaw_guard.engine.experiment_components import snapshot, commit_if_current, persistent_component_commit
from openclaw_guard.spec.content_receipts import _freeze_bounded_json
from openclaw_guard.spec.history_facts import VerifiedCrossSessionHistory
from openclaw_guard.spec.host_authorization import TaskBinding


@dataclass(frozen=True)
class PreparedCrossHistory:
    """只用于当前真实调用的不可变事实，不附带执行许可。"""
    fact: VerifiedCrossSessionHistory

    def close(self) -> None:
        """决策结束或票据失效后释放只读租约。"""
        self.fact.lease.release()


class HostCrossHistoryAuthorizer:
    """后台读取宿主任务关联与确切字节收据，绝不从文件名推断内容分类。"""
    def __init__(self, verifier, history) -> None:
        """核验器和历史表须由宿主私有配置注入。"""
        self.verifier, self.history = verifier, history

    def prepare(self, envelope: dict, *, event, step: dict) -> PreparedCrossHistory | None:
        """证明只能来自当前签名快照、同宿主任务以及已执行完整read。"""
        components, generation = snapshot()
        if not components.cross_session_rv:
            return None
        proposal = self.verifier.verify(envelope, event=event, step=step)
        binding = TaskBinding(proposal.task_id, proposal.principal_id, proposal.agent_id, proposal.session_id, proposal.run_id)
        witnesses = self.history.sensitive_history(binding, proposal.source)
        if not witnesses:
            witnesses = self.history.sensitive_history(binding, proposal.source, require_same_bytes=False)
        now = int(time.time() * 1000)
        expires = min([proposal.expires_at_ms, now + 1000] + [w["expires_at_ms"] for w in witnesses])
        if not witnesses or expires <= now:
            return None
        from openclaw_guard.spec.task_history import HostHistoryLease
        lease = HostHistoryLease(self.history, list({w["link_id"] for w in witnesses}), expires_at_ms=expires)
        fact = VerifiedCrossSessionHistory(relationship=witnesses[0]["relationship"], component_generation=generation,
            lease=lease,
            step_id=step["step_id"], principal_id=proposal.principal_id, agent_id=proposal.agent_id,
            session_id=proposal.session_id, run_id=proposal.run_id, tool_name=proposal.tool_name,
            operation_family=proposal.operation_family, arguments_sha256=proposal.arguments_sha256,
            task_id=proposal.task_id, history_step_ids=tuple(w["step_id"] for w in witnesses),
            receipt_ids=tuple(w["receipt_id"] for w in witnesses), link_ids=tuple(w["link_id"] for w in witnesses),
            source_sha256=proposal.source.sha256, expires_at_ms=expires)
        accepted, result = commit_if_current(generation, "cross_session_rv", lambda: PreparedCrossHistory(fact))
        if not accepted:
            lease.release()
        return result if accepted else None


class BoundedHistoryRecorder:
    """16项认证完成队列；关闭组件时不查询、核验或提交新历史。"""
    def __init__(self, authority, history) -> None:
        """启动后台核验；所有存储均在宿主私有目录。"""
        self.authority, self.history = authority, history
        self._queue = Queue(maxsize=16)
        self._closed = threading.Event()
        self._commit_lock = threading.Lock()
        self._worker = threading.Thread(target=self._run, daemon=True, name="rv-cross-history")
        self._worker.start()

    def submit(self, envelope: dict, *, event, step: dict) -> dict:
        """只接受认证的实际成功read；模型计划和失败调用不能进队列。"""
        components, generation = snapshot()
        if self._closed.is_set() or not components.cross_session_rv:
            return {"status": "disabled"}
        if step.get("execution_state") != "succeeded" or step.get("operation_family") != "file.read":
            return {"status": "not_successful_read"}
        try:
            captured = SimpleNamespace(metadata=_freeze_bounded_json({key: event.metadata.get(key) for key in (
                "hook_auth_verified", "hook_auth_binding", "agent_id", "session_id", "run_id", "tool_call_id")}, 8192),
                raw_payload={"params": _freeze_bounded_json(event.raw_payload.get("params"), 65536)})
            self._queue.put_nowait((_freeze_bounded_json(envelope, 20000), captured,
                                   _freeze_bounded_json(step, 20000), generation))
        except (Full, ValueError, TypeError, RecursionError):
            return {"status": "history_unavailable"}
        return {"status": "pending_verification"}

    def _run(self) -> None:
        """后台只提交当前代际；各实验臂必须使用独立实例和存储。"""
        while not self._closed.is_set():
            try:
                envelope, event, step, generation = self._queue.get(timeout=0.1)
            except Empty:
                continue
            try:
                components, active = snapshot()
                if components.cross_session_rv and active == generation and not self._closed.is_set():
                    receipt = self.authority.verify(envelope, event=event, step=step)
                    with self._commit_lock:
                        if not self._closed.is_set():
                            with persistent_component_commit(generation, "cross_session_rv") as accepted:
                                if accepted:
                                    self.history.record_verified(envelope, receipt)
            except Exception:
                pass  # 缺证据不影响已有RV/PMKB，不能构造allow或block。
            finally:
                self._queue.task_done()

    def close(self) -> None:
        """停止接收并串行结束持久提交；只在宿主关闭流程调用，不在Hook里调用。"""
        self._closed.set()
        with self._commit_lock:
            pass

    def wait_idle(self, *, timeout: float = 1) -> bool:
        """宿主验收冷重启前等待有界队列，禁止在before Hook中调用。"""
        if not 0 <= timeout <= 1:
            raise ValueError("history drain budget at most one second")
        with self._queue.all_tasks_done:
            return self._queue.all_tasks_done.wait_for(lambda: self._queue.unfinished_tasks == 0, timeout)
