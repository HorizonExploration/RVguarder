"""宿主限定的任务/会话关联与成功内容历史；不推测派生血缘或新工具调用。"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import hmac
import json
import time
import threading
from uuid import uuid4

from openclaw_guard.spec.content_receipts import ContentReceipt, ContentReceiptError, _canonical
from openclaw_guard.spec.host_authorization import HostAuthorizationError, HostAuthorizationStore, TaskBinding


class HostHistoryLease:
    """短只读事务与宿主撤销串行；监视器仅检查内存活性。"""
    def __init__(self, history, link_ids: list[str], *, expires_at_ms: int) -> None:
        """后台创建，最多一秒自动释放；不允许跨调用长期缓存。"""
        self._lock = threading.Lock()
        self._active = False
        self._context = history.store._connect(timeout=0, check_same_thread=False)
        self._db = self._context.__enter__()
        try:
            self._db.execute("BEGIN")
            rows = self._db.execute("SELECT id FROM task_links WHERE revoked=0 AND expires>? LIMIT ?", (time.time(), history.capacity + 1)).fetchall()
            if len(rows) > history.capacity:
                raise HostAuthorizationError("history lease link bound exceeded")
            if not set(link_ids).issubset({row[0] for row in rows}) or not link_ids:
                raise HostAuthorizationError("history link revoked before decision lease")
            self.expires_at_ms = min(expires_at_ms, int(time.time() * 1000) + 1000)
            self._active = True
            self._released = threading.Event()
            self._worker = threading.Thread(target=self._finish_transaction, daemon=True,
                                            name="rv-history-lease")
            self._worker.start()
        except Exception:
            self._context.__exit__(None, None, None)
            raise

    def is_active(self) -> bool:
        """纯内存活性，不在DSL热路径访问SQLite。"""
        with self._lock:
            return self._active and int(time.time() * 1000) < self.expires_at_ms

    def commit_if_active(self, callback):
        """短内存裁决与停用串行；此处是使用历史事实的线性化点。"""
        with self._lock:
            if not self._active or int(time.time() * 1000) >= self.expires_at_ms:
                return False, None
            return True, callback()

    def release(self) -> None:
        """热路径仅停用内存；后台结束事务后宿主撤销才能成功返回。"""
        with self._lock:
            self._active = False
            self._released.set()

    def _finish_transaction(self) -> None:
        """至多一秒后停用；所有SQLite清理都在此后台线程进行。"""
        self._released.wait(max(0, self.expires_at_ms / 1000 - time.time()))
        with self._lock:
            self._active = False
        self._context.__exit__(None, None, None)


class HostTaskHistory:
    """私有持久证据：只有受控宿主关联的任务与确切敏感字节可复用历史。"""

    def __init__(self, store: HostAuthorizationStore, authority, *, capacity: int = 1024) -> None:
        """启动时创建有界宿主表，Agent工作区和HTTP参数不能写这些表。"""
        if not 1 <= capacity <= 4096:
            raise HostAuthorizationError("invalid task history capacity")
        self.store, self.authority, self.capacity = store, authority, capacity
        with store._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS task_links (id TEXT PRIMARY KEY, payload TEXT NOT NULL, expires REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)")
            db.execute("CREATE INDEX IF NOT EXISTS task_links_active ON task_links (revoked, expires)")
            db.execute("CREATE TABLE IF NOT EXISTS content_history (call_key TEXT PRIMARY KEY, envelope TEXT NOT NULL, expires REAL NOT NULL, link_ids TEXT NOT NULL)")

    def register(self, bindings: list[TaskBinding], *, sensitive_versions: list[dict], ttl_seconds: float = 300) -> dict:
        """宿主显式关联独立session和分类版本；不签发任何工具权限。"""
        if not 0 < ttl_seconds <= 300 or len(bindings) < 2 or len(bindings) > 16:
            raise HostAuthorizationError("bounded multi-session task association required")
        for binding in bindings:
            binding.validate()
            if not binding.session_id:
                raise HostAuthorizationError("cross-session history requires explicit session")
        identities = {(b.task_id, b.principal_id, b.agent_id) for b in bindings}
        if len(identities) != 1 or len({(b.session_id, b.run_id) for b in bindings}) != len(bindings):
            raise HostAuthorizationError("task links cannot cross tasks/principals/agents or repeat contexts")
        if not sensitive_versions or len(sensitive_versions) > 32:
            raise HostAuthorizationError("declare bounded classified content versions")
        from openclaw_guard.spec.content_receipts import ContentVersion
        versions = [ContentVersion.model_validate(v).model_dump(mode="json") for v in sensitive_versions]
        if any(not v["full_resource"] for v in versions):
            raise HostAuthorizationError("classification requires exact full resource version")
        now = time.time()
        record = {"id": str(uuid4()), "bindings": [asdict(b) for b in bindings],
                  "sensitive_versions": versions, "classification_source": "controlled_host_registration",
                  "issued_at": now, "expires_at": now + ttl_seconds}
        encoded = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode()) > 16384:
            raise HostAuthorizationError("task link too large")
        with self.store._connect(timeout=0) as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT COUNT(*) FROM task_links WHERE revoked=0 AND expires>?", (now,)).fetchone()[0] >= self.capacity:
                raise HostAuthorizationError("task links full")
            db.execute("INSERT INTO task_links VALUES (?,?,?,0)", (record["id"], encoded, record["expires_at"]))
        return record

    def revoke(self, link_id: str) -> bool:
        """立即持久撤销任务关联，历史不得绕过已撤销的关联。"""
        with self.store._connect(timeout=2) as db:
            return db.execute("UPDATE task_links SET revoked=1 WHERE id=?", (link_id,)).rowcount == 1

    def _active(self, db=None) -> list[dict]:
        if db is None:
            with self.store._connect(timeout=0) as connection:
                return self._active(connection)
        rows = db.execute("SELECT payload FROM task_links WHERE revoked=0 AND expires>? LIMIT ?", (time.time(), self.capacity + 1)).fetchall()
        if len(rows) > self.capacity:
            raise HostAuthorizationError("task link bound exceeded")
        records = []
        for (raw,) in rows:
            if len(raw.encode()) > 16384:
                raise HostAuthorizationError("task link record too large")
            records.append(json.loads(raw))
        return records

    @staticmethod
    def _matches(binding: dict, context: TaskBinding) -> bool:
        return all(binding.get(k) == getattr(context, k) for k in ("task_id", "principal_id", "agent_id", "session_id")) and (
            not binding.get("run_id") or binding["run_id"] == context.run_id)

    def resolve_task_binding(self, *, principal_id: str, agent_id: str, session_id: str = "", run_id: str = "") -> TaskBinding | None:
        """仅认证Hook上下文可查询，歧义任务不给出关联证明。"""
        candidates = {}
        for grant in self.store.query_for_decision():
            item = grant["binding"]
            if item["principal_id"] == principal_id and item["agent_id"] == agent_id and (
                    not item["session_id"] or item["session_id"] == session_id) and (not item["run_id"] or item["run_id"] == run_id):
                candidates[item["task_id"]] = TaskBinding(item["task_id"], principal_id, agent_id, session_id, run_id)
        for link in self._active():
            for item in link["bindings"]:
                if item["principal_id"] == principal_id and item["agent_id"] == agent_id and item["session_id"] == session_id and (
                        not item["run_id"] or item["run_id"] == run_id):
                    candidates[item["task_id"]] = TaskBinding(item["task_id"], principal_id, agent_id, session_id, run_id)
        return next(iter(candidates.values())) if len(candidates) == 1 else None

    def record_verified(self, envelope: dict, receipt: ContentReceipt) -> dict:
        """认证执行后核验者提交真实完整read；相同call幂等，冲突拒绝。"""
        source = receipt.accessed_resource if receipt.kind == "read_access" else (receipt.inputs[0] if receipt.inputs else None)
        if receipt.kind not in {"read", "read_access"} or source is None or not source.full_resource:
            return {"status": "unsupported_history_kind"}
        payload = receipt.model_dump(mode="json")
        if envelope.get("payload") != payload or not hmac.compare_digest(str(envelope.get("signature", "")),
                hmac.new(self.authority._key, _canonical(payload), hashlib.sha256).hexdigest()):
            raise ContentReceiptError("history envelope does not match verified receipt")
        binding = TaskBinding(receipt.task_id, receipt.principal_id, receipt.agent_id, receipt.session_id, receipt.run_id)
        key = json.dumps([receipt.principal_id, receipt.agent_id, receipt.session_id, receipt.run_id, receipt.tool_call_id])
        encoded = json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with self.store._connect(timeout=0) as db:
            db.execute("BEGIN IMMEDIATE")
            active_links = db.execute("SELECT id,payload FROM task_links WHERE revoked=0 AND expires>? LIMIT ?",
                                      (time.time(), self.capacity + 1)).fetchall()
            if len(active_links) > self.capacity or any(len(raw.encode()) > 16384 for _, raw in active_links):
                raise HostAuthorizationError("task link bound exceeded")
            link_ids = [link_id for link_id, raw in active_links
                        if any(self._matches(b, binding) for b in json.loads(raw)["bindings"])
                        and source.model_dump(mode="json") in json.loads(raw)["sensitive_versions"]]
            if not link_ids:
                return {"status": "unlinked_or_unclassified_read"}
            old = db.execute("SELECT envelope FROM content_history WHERE call_key=?", (key,)).fetchone()
            if old:
                if old[0] != encoded:
                    raise ContentReceiptError("conflicting native history for same call")
                return {"status": "duplicate", "receipt_id": receipt.receipt_id}
            db.execute("DELETE FROM content_history WHERE expires<=?", (time.time(),))
            if db.execute("SELECT COUNT(*) FROM content_history").fetchone()[0] >= self.capacity:
                raise ContentReceiptError("history capacity exceeded")
            db.execute("INSERT INTO content_history VALUES (?,?,?,?)", (key, encoded, receipt.expires_at_ms / 1000, json.dumps(sorted(link_ids))))
        return {"status": "verified", "receipt_id": receipt.receipt_id}

    def sensitive_history(self, binding: TaskBinding, target, *, require_same_bytes: bool = True) -> list[dict]:
        """仅同宿主任务和确切字节版本匹配，转换结果不因参数或文件名继承敏感。"""
        binding.validate()
        with self.store._connect(timeout=0) as db:
            # 活动关联与历史须来自同一读取事务；撤销不能夹在两次快照之间。
            db.execute("BEGIN")
            links = [link for link in self._active(db) if any(self._matches(b, binding) for b in link["bindings"])]
            if {link["bindings"][0]["task_id"] for link in links} != {binding.task_id}:
                return []
            rows = db.execute("SELECT envelope,link_ids FROM content_history WHERE expires>? LIMIT ?", (time.time(), self.capacity + 1)).fetchall()
        if len(rows) > self.capacity:
            raise ContentReceiptError("history capacity exceeded")
        found = []
        for raw, link_ids_raw in rows:
            if len(raw.encode()) > 20000:
                raise ContentReceiptError("history receipt too large")
            envelope = json.loads(raw)
            recorded_link_ids = json.loads(link_ids_raw)
            if not isinstance(recorded_link_ids, list) or len(recorded_link_ids) > self.capacity:
                raise ContentReceiptError("invalid historical link bindings")
            payload = envelope["payload"]
            if not hmac.compare_digest(envelope["signature"], hmac.new(self.authority._key, _canonical(payload), hashlib.sha256).hexdigest()):
                raise ContentReceiptError("restored history signature mismatch")
            if payload.get("kind") == "read_access":
                from openclaw_guard.spec.read_access_receipts import NativeReadAccessReceipt
                receipt = NativeReadAccessReceipt.model_validate(payload)
            else:
                receipt = ContentReceipt.model_validate(payload)
            if not receipt.issued_at_ms <= int(time.time() * 1000) < receipt.expires_at_ms or receipt.session_id == binding.session_id:
                continue
            source = receipt.accessed_resource if receipt.kind == "read_access" else receipt.inputs[0]
            same_bytes = receipt.kind == "read" and (source.namespace, source.sha256, source.size_bytes) == (target.namespace, target.sha256, target.size_bytes)
            if receipt.kind not in {"read", "read_access"} or not source.full_resource or not target.full_resource or (require_same_bytes and not same_bytes):
                continue
            source_binding = TaskBinding(receipt.task_id, receipt.principal_id, receipt.agent_id, receipt.session_id, receipt.run_id)
            for link in links:
                if link["id"] in recorded_link_ids and any(self._matches(b, source_binding) for b in link["bindings"]) and source.model_dump(mode="json") in link["sensitive_versions"]:
                    found.append({"step_id": f"{receipt.run_id}:{receipt.tool_call_id}", "receipt_id": receipt.receipt_id,
                                  "link_id": link["id"], "source_session_id": receipt.session_id,
                                  "resource_version": source.model_dump(mode="json"),
                                  "relationship": "exact_consumed_byte_identity" if same_bytes else "same_task_sensitive_read_capability",
                                  "classification_source": link["classification_source"],
                                  "source_observation": "observed_before_after" if receipt.kind == "read_access" else "actual_returned_full_bytes"})
                    found[-1]["expires_at_ms"] = min(receipt.expires_at_ms, int(link["expires_at"] * 1000))
                    break
        return found
