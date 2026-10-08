"""受控执行器的内容收据：绑定有限调用与实际字节，不从工具文字推导血缘。

签发API只供持有宿主私有密钥的执行器调用，不作为Agent工具或HTTP入口。
可信度依赖执行器确实传入消费/产生的字节及Docker对密钥的隔离。
收据只证明所记录的内容关系，不签发授权、不把变换结果降级为公开。
"""
from __future__ import annotations

from collections import OrderedDict
import hashlib
import hmac
import json
import math
import os
import stat
import threading
from queue import Empty, Full, Queue
from types import SimpleNamespace
import time
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from openclaw_guard.rv.tool_events import OPERATION_EFFECTS
from openclaw_guard.spec.host_authorization import HostAuthorizationError, HostAuthorizationStore, TaskBinding


class ContentReceiptError(ValueError):
    """内容收据来源、范围或字节关系不可信。"""


class ContentVersion(BaseModel):
    """描述实际字节的规范资源、哈希和读取范围，不提供分类证明。"""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    namespace: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    resource_id: str = Field(min_length=1, max_length=2048)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0, le=32 * 1024 * 1024)
    full_resource: bool
    offset: int = Field(ge=0)

    @model_validator(mode="after")
    def check_resource(self) -> ContentVersion:
        """要求资源ID属于命名空间，完整内容从偏移零开始。"""
        path = self.resource_id.removeprefix(self.namespace + ":")
        if not self.resource_id.startswith(self.namespace + ":") or not path or path.startswith("/") or "\\" in path or any(part in {"", ".", ".."} for part in path.split("/")):
            raise ValueError("invalid canonical resource id")
        if self.full_resource and self.offset:
            raise ValueError("full content cannot have nonzero offset")
        return self


class ContentReceipt(BaseModel):
    """单个真实调用的受控执行器成功收据。"""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    format_version: Literal[1] = 1
    arguments_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    receipt_id: str = Field(min_length=1, max_length=64)
    issuer: str = Field(min_length=1, max_length=128)
    task_id: str = Field(min_length=1, max_length=256)
    principal_id: str = Field(min_length=1, max_length=256)
    agent_id: str = Field(min_length=1, max_length=256)
    session_id: str = Field(max_length=256)
    run_id: str = Field(min_length=1, max_length=256)
    tool_call_id: str = Field(min_length=1, max_length=256)
    tool_name: str = Field(min_length=1, max_length=128)
    operation_family: str = Field(min_length=1, max_length=128)
    kind: Literal["read", "copy", "transform", "egress"]
    inputs: list[ContentVersion] = Field(max_length=8)
    outputs: list[ContentVersion] = Field(max_length=8)
    issued_at_ms: int = Field(ge=0)
    expires_at_ms: int = Field(ge=0)
    success: Literal[True]

    @model_validator(mode="after")
    def check_relationship(self) -> ContentReceipt:
        """限定有限效果和字节关系，部分读取不建立完整复制边。"""
        effects = OPERATION_EFFECTS.get(self.operation_family, ())
        if self.expires_at_ms <= self.issued_at_ms or self.expires_at_ms - self.issued_at_ms > 300000:
            raise ValueError("receipt lifetime must be at most five minutes")
        if self.kind == "read" and ("read" not in effects or len(self.inputs) != 1 or self.outputs):
            raise ValueError("read receipt requires one input and no output")
        if self.kind == "egress" and ("egress" not in effects or len(self.inputs) != 1 or self.outputs):
            raise ValueError("egress receipt requires one input and no output")
        if self.kind in {"copy", "transform"}:
            if "write" not in effects or not self.inputs or len(self.outputs) != 1:
                raise ValueError("transformation requires inputs and one output")
            if not all(v.full_resource for v in (*self.inputs, *self.outputs)):
                raise ValueError("partial resource cannot establish transformation lineage")
            if self.kind == "copy" and (len(self.inputs) != 1 or self.inputs[0].sha256 != self.outputs[0].sha256 or self.inputs[0].size_bytes != self.outputs[0].size_bytes):
                raise ValueError("copy bytes differ")
        return self


def content_version(namespace: str, relative_path: str, data: bytes, *, full_resource: bool = True, offset: int = 0) -> ContentVersion:
    """供受控执行器对实际处理字节计算版本，不接受参数中的哈希声明。"""
    return ContentVersion(namespace=namespace, resource_id=f"{namespace}:{relative_path}",
                          sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data),
                          full_resource=full_resource, offset=offset)


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def _freeze_bounded_json(value: Any, limit: int) -> Any:
    """先限节点、深度与字符总量，再序列化有界JSON副本。"""
    remaining, nodes = limit, 2048

    def inspect(item: Any, depth: int) -> None:
        nonlocal remaining, nodes
        nodes -= 1
        remaining -= 1
        if nodes < 0 or remaining < 0 or depth > 16:
            raise ContentReceiptError("JSON evidence complexity exceeds budget")
        if isinstance(item, str):
            remaining -= len(item)
        elif item is None or isinstance(item, bool):
            remaining -= 5
        elif isinstance(item, int):
            if item.bit_length() > 256:
                raise ContentReceiptError("JSON integer exceeds budget")
            remaining -= 80
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ContentReceiptError("nonfinite JSON number")
            remaining -= 32
        elif isinstance(item, (list, dict)):
            if len(item) > nodes:
                raise ContentReceiptError("JSON container exceeds budget")
            if isinstance(item, dict):
                for key, child in item.items():
                    if not isinstance(key, str):
                        raise ContentReceiptError("JSON keys must be strings")
                    inspect(key, depth + 1)
                    inspect(child, depth + 1)
            else:
                for child in item:
                    inspect(child, depth + 1)
        else:
            raise ContentReceiptError("unsupported JSON value")
        if remaining < 0:
            raise ContentReceiptError("JSON evidence size exceeds budget")

    inspect(value, 0)
    encoded = _canonical(value)
    if len(encoded) > limit:
        raise ContentReceiptError("JSON encoded evidence exceeds budget")
    return json.loads(encoded)


class HostContentReceiptAuthority:
    """使用宿主私有密钥签发/核验内容证据，不提供授权或工具事件。"""

    def __init__(self, store: HostAuthorizationStore, *, issuer: str, tool_operations: dict[str, str]) -> None:
        """显式登记受控执行器的具体tool→有限operation映射，启动时缓存密钥。"""
        if not issuer or not tool_operations or any(family not in OPERATION_EFFECTS for family in tool_operations.values()):
            raise ContentReceiptError("invalid trusted issuer tool contract")
        self._store = store
        self.issuer = issuer
        self.tool_operations = dict(tool_operations)
        self.task_resolver = lambda **context: self._store.resolve_task_binding(**context)
        # 复用已验证的宿主独占目录；密钥仅在启动读取，不在Hook等待磁盘。
        with store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            path = store.state_dir / "content-signing.key"
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                pass
            else:
                try:
                    os.write(fd, os.urandom(32))
                finally:
                    os.close(fd)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1:
                    raise HostAuthorizationError("content signing key must be host-private")
                self._key = os.read(fd, 33)
                if len(self._key) != 32:
                    raise ContentReceiptError("invalid content signing key")
            finally:
                os.close(fd)

    def issue(
        self, *, binding: TaskBinding, tool_call_id: str, tool_name: str, kind: str,
        inputs: list[ContentVersion], outputs: list[ContentVersion], arguments: dict,
    ) -> dict[str, Any]:
        """受控执行器仅在真实成功后调用；绑定实际消费/产生的内容版本。"""
        binding.validate()
        trusted = self.task_resolver(principal_id=binding.principal_id, agent_id=binding.agent_id,
                                                  session_id=binding.session_id, run_id=binding.run_id)
        if trusted is None or trusted.task_id != binding.task_id:
            raise ContentReceiptError("task binding is not uniquely host-registered")
        family = self.tool_operations.get(tool_name)
        if family is None:
            raise ContentReceiptError("unregistered tool producer")
        now = int(time.time() * 1000)
        receipt = ContentReceipt(arguments_sha256=hashlib.sha256(_canonical(arguments)).hexdigest(), receipt_id=str(uuid4()), issuer=self.issuer, **binding.__dict__,
                                 tool_call_id=tool_call_id, tool_name=tool_name, operation_family=family,
                                 kind=kind, inputs=inputs, outputs=outputs,
                                 issued_at_ms=now, expires_at_ms=now + 300000, success=True)
        payload = receipt.model_dump(mode="json")
        return {"payload": payload, "signature": hmac.new(self._key, _canonical(payload), hashlib.sha256).hexdigest()}

    def verify(self, envelope: dict, *, event: Any, step: dict) -> ContentReceipt:
        """后台核验签名、调用与宿主唯一任务；不得在Hook热路径调用。"""
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
            raise ContentReceiptError("invalid signed receipt envelope")
        payload, signature = envelope["payload"], envelope["signature"]
        if not isinstance(payload, dict) or not isinstance(signature, str):
            raise ContentReceiptError("invalid receipt types")
        encoded = _canonical(payload)
        if len(encoded) > 16384 or len(signature) != 64 or not hmac.compare_digest(signature, hmac.new(self._key, encoded, hashlib.sha256).hexdigest()):
            raise ContentReceiptError("invalid receipt signature or size")
        if payload.get("kind") == "read_access":
            from openclaw_guard.spec.read_access_receipts import NativeReadAccessReceipt
            receipt = NativeReadAccessReceipt.model_validate(payload)
        else:
            receipt = ContentReceipt.model_validate(payload)
        meta = event.metadata
        expected = {"principal_id": f"hook:{meta.get('hook_auth_binding')}", "agent_id": meta.get("agent_id"),
                    "session_id": meta.get("session_id") or "", "run_id": meta.get("run_id"),
                    "tool_call_id": meta.get("tool_call_id"), "tool_name": step.get("tool_name"),
                    "operation_family": step.get("operation_family")}
        if meta.get("hook_auth_verified") is not True or not meta.get("hook_auth_binding") or step.get("event_model") != "tool-call-v1":
            raise ContentReceiptError("untrusted completion context")
        if receipt.issuer != self.issuer or self.tool_operations.get(receipt.tool_name) != receipt.operation_family or any(getattr(receipt, key) != value for key, value in expected.items()):
            raise ContentReceiptError("receipt call context mismatch")
        arguments = event.raw_payload.get("params")
        if not isinstance(arguments, dict) or hashlib.sha256(_canonical(arguments)).hexdigest() != receipt.arguments_sha256:
            raise ContentReceiptError("receipt arguments mismatch")
        trusted = self.task_resolver(principal_id=receipt.principal_id, agent_id=receipt.agent_id,
                                                  session_id=receipt.session_id, run_id=receipt.run_id)
        if trusted is None or trusted.task_id != receipt.task_id:
            raise ContentReceiptError("receipt task does not match unique active host task")
        expected_effect = {"read": "read", "read_access": "read", "copy": "write", "transform": "write", "egress": "egress"}[receipt.kind]
        if expected_effect not in step.get("effects", []) or "unknown" in step.get("effects", []):
            raise ContentReceiptError("receipt effect does not match finite tool call")
        now = int(time.time() * 1000)
        if not receipt.issued_at_ms <= now < receipt.expires_at_ms:
            raise ContentReceiptError("receipt expired or not yet valid")
        return receipt


class ExecutedContentLedger:
    """有界记录已核验成功调用的内容关系，拒绝同调用重复或矛盾证据。"""

    def __init__(self, authority: HostContentReceiptAuthority, *, capacity: int = 256, background: bool = False) -> None:
        """建立仅宿主可访问的内存证据表，持久恢复尚未接入。"""
        if capacity <= 0:
            raise ContentReceiptError("invalid ledger capacity")
        self.authority = authority
        self.capacity = capacity
        self._lock = threading.Lock()
        self._calls: OrderedDict[tuple, dict] = OrderedDict()
        self._call_generations: dict[tuple, int] = {}
        self._queue: Queue = Queue(maxsize=16)
        self._closed = threading.Event()
        self._results: OrderedDict[str, dict] = OrderedDict()
        self._result_generations: dict[str, int] = {}
        self._worker = None
        if background:
            self._worker = threading.Thread(target=self._verify_pending, daemon=True, name="rv-content-receipts")
            self._worker.start()

    def submit(self, envelope: dict, *, event: Any, step: dict) -> dict:
        """非阻塞提交执行后内容核验，磁盘查询只在后台发生。"""
        from openclaw_guard.engine.experiment_components import snapshot
        components, generation = snapshot()
        if not components.authorization:
            return {"status": "disabled", "content_lineage_verified": False}
        if self._closed.is_set() or self._worker is None:
            return {"status": "verification_unavailable", "content_lineage_verified": False}
        # 后台任务不能保留调用者可变对象；超大参数仅失去可选证据。
        try:
            captured_envelope = _freeze_bounded_json(envelope, 20000)
            captured_params = _freeze_bounded_json(event.raw_payload.get("params") or {}, 65536)
        except (TypeError, ValueError, RecursionError):
            return {"status": "unverified", "content_lineage_verified": False}
        captured = SimpleNamespace(metadata={key: event.metadata.get(key) for key in (
            "hook_auth_verified", "hook_auth_binding", "agent_id", "session_id", "run_id", "tool_call_id",
        )}, raw_payload={"params": captured_params})
        captured_step = {key: step.get(key) for key in ("execution_state", "event_model", "tool_name", "operation_family")}
        captured_step["effects"] = list(step.get("effects") or [])
        try:
            self._queue.put_nowait((str(event.event_id), captured_envelope, captured, captured_step, generation))
        except Full:
            return {"status": "verification_queue_full", "content_lineage_verified": False}
        return {"status": "pending_verification", "content_lineage_verified": False}

    def result_for_call(self, event_id: str) -> dict | None:
        """只读查询后台核验诊断，不让结果成为先前调用的放行理由。"""
        from openclaw_guard.engine.experiment_components import snapshot, commit_if_current
        _, generation = snapshot()
        def read_result():
            with self._lock:
                value = self._results.get(event_id)
                if value is not None and self._result_generations.get(event_id) != generation:
                    return {"status": "disabled", "content_lineage_verified": False}
                return json.loads(json.dumps(value)) if value is not None else None
        accepted, result = commit_if_current(generation, "authorization", read_result)
        return result if accepted else {"status": "disabled", "content_lineage_verified": False}

    def close(self) -> None:
        """停止接收任务，不等待慢宿主存储。"""
        with self._lock:
            self._closed.set()

    def _verify_pending(self) -> None:
        from openclaw_guard.engine.experiment_components import snapshot
        while not self._closed.is_set():
            try:
                event_id, envelope, event, step, generation = self._queue.get(timeout=0.1)
            except Empty:
                continue
            try:
                components, active_generation = snapshot()
                result = self.commit(envelope, event=event, step=step, component_generation=generation) if components.authorization and active_generation == generation else {"status": "disabled"}
            except Exception:
                result = {"status": "unverified", "content_lineage_verified": False}
            with self._lock:
                self._results[event_id] = result
                self._result_generations[event_id] = generation
                self._results.move_to_end(event_id)
                while len(self._results) > 64:
                    removed, _ = self._results.popitem(last=False)
                    self._result_generations.pop(removed, None)
            self._queue.task_done()

    def commit(self, envelope: dict, *, event: Any, step: dict, component_generation: int | None = None) -> dict:
        """只在认证成功回调后提交一个真实调用的签名内容关系。"""
        from openclaw_guard.engine.experiment_components import snapshot, commit_if_current
        components, active_generation = snapshot()
        if component_generation is None:
            component_generation = active_generation
        if not components.authorization or component_generation != active_generation:
            return {"status": "disabled", "content_lineage_verified": False}
        receipt = self.authority.verify(envelope, event=event, step=step)
        if receipt.kind == "read_access":
            return {"status": "access_only_not_content_lineage", "content_lineage_verified": False}
        if step.get("execution_state") != "succeeded":
            raise ContentReceiptError("call did not succeed")
        key = (receipt.principal_id, receipt.agent_id, receipt.session_id, receipt.run_id, receipt.tool_call_id)
        record = receipt.model_dump(mode="json")
        def store_record() -> dict:
            with self._lock:
                if self._closed.is_set():
                    return {"status": "disabled", "content_lineage_verified": False}
                # 新臂从空证据状态开始；旧臂不能占用容量或使同call重放变成duplicate。
                stale = [old_key for old_key in self._calls
                         if self._call_generations.get(old_key) != component_generation]
                for old_key in stale:
                    del self._calls[old_key]
                    self._call_generations.pop(old_key, None)
                if key in self._calls:
                    if self._calls[key] != record:
                        raise ContentReceiptError("conflicting receipt for same call")
                    return {"status": "duplicate", "receipt_id": receipt.receipt_id}
                if len(self._calls) >= self.capacity:
                    raise ContentReceiptError("content ledger full")
                self._calls[key] = record
                self._call_generations[key] = component_generation
            return {"status": "verified", "receipt_id": receipt.receipt_id, "kind": receipt.kind,
                "content_lineage_verified": receipt.kind in {"copy", "transform"},
                "inputs": record["inputs"], "outputs": record["outputs"],
                "classification_evidence": "not_provided", "task_id": receipt.task_id}
        accepted, result = commit_if_current(component_generation, "authorization", store_record)
        return result if accepted else {"status": "disabled", "content_lineage_verified": False}

    def snapshot(self) -> list[dict]:
        """返回证据副本用于审计，不让调用者改写既有关系。"""
        from openclaw_guard.engine.experiment_components import snapshot, commit_if_current
        _, generation = snapshot()
        def read_records():
            with self._lock:
                return json.loads(json.dumps([value for key, value in self._calls.items()
                    if self._call_generations.get(key) == generation]))
        accepted, records = commit_if_current(generation, "authorization", read_records)
        return records if accepted else []
