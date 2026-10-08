"""受控宿主授权存储：仅本机命令写入，工具载荷与附件不签发授权。

存储目录必须位于已声明的全部 Agent 工作区之外，并由宿主独占。
权限检查不能替代 Docker 挂载/宿主 exec 隔离，真实部署须另外验证。
本模块不修改 PMKB/RV 裁决，授权接入必须保留单步硬约束。
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import time
from typing import Iterator
from uuid import uuid4

from openclaw_guard.rv.tool_events import OPERATION_EFFECTS
from openclaw_guard.spec.resource_evidence import HostResourceObserver


class HostAuthorizationError(ValueError):
    """宿主授权配置、范围或存储不满足可信边界。"""


@dataclass(frozen=True)
class TaskBinding:
    """绑定单个任务、可信主体、Agent及具体session或宿主run。"""

    task_id: str
    principal_id: str
    agent_id: str
    session_id: str = ""
    run_id: str = ""

    def validate(self) -> None:
        """禁止缺失身份和通配范围，至少绑定session或宿主run之一。"""
        for value in asdict(self).values():
            if not isinstance(value, str) or value != value.strip() or "\x00" in value or value == "*":
                raise HostAuthorizationError("binding must contain exact identifiers")
        if not self.task_id or not self.principal_id or not self.agent_id or not (self.session_id or self.run_id):
            raise HostAuthorizationError("task, principal, agent and session/run are required")


class HostAuthorizationStore:
    """保存按有限工具操作签发的精确授权；不接受声明式导入授权。"""

    def __init__(self, state_dir: Path, *, agent_workspaces: list[Path]) -> None:
        """验证宿主独占目录和全部已声明Agent工作区隔离。"""
        if not agent_workspaces:
            raise HostAuthorizationError("declare all agent workspaces")
        path = Path(state_dir).absolute()
        for ancestor in (path, *path.parents):
            if ancestor.is_symlink():
                raise HostAuthorizationError("authorization path must not contain symlinks")
        resolved = path.resolve()
        for workspace in agent_workspaces:
            if resolved.is_relative_to(Path(workspace).resolve()):
                raise HostAuthorizationError("authorization storage must be outside agent workspaces")
        path.mkdir(mode=0o700, exist_ok=True)
        info = path.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise HostAuthorizationError("authorization directory must be host-owned and private")
        self.state_dir = path
        self._directory_identity = (info.st_dev, info.st_ino)
        self.database = path / "authorization.sqlite3"
        self._agent_workspaces = [Path(p).resolve() for p in agent_workspaces]
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, payload TEXT NOT NULL, expires REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)")

    @contextmanager
    def _connect(self, *, timeout: float = 5, check_same_thread: bool = True) -> Iterator[sqlite3.Connection]:
        info = self.state_dir.lstat()
        if (info.st_dev, info.st_ino) != self._directory_identity or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise HostAuthorizationError("authorization directory identity or permissions changed")
        handle = os.open(self.database, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            metadata = os.fstat(handle)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077 or metadata.st_nlink != 1:
                raise HostAuthorizationError("authorization database must be a private regular file")
        finally:
            os.close(handle)
        connection = sqlite3.connect(self.database, timeout=timeout, check_same_thread=check_same_thread)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def issue(
        self, observer: HostResourceObserver, namespace: str, relative_path: str, *,
        binding: TaskBinding, operation: str, recipient: str, ttl_seconds: float = 3600,
    ) -> dict:
        """宿主重新读取资源版本并签发范围精确的有限操作授权。

        不接收外部ResourceDescriptor、工具参数或授权文字作为内容证明。
        多功能工具子动作仍需由实际ToolCallIR核验，不能以此授权整个工具。
        """
        binding.validate()
        self._validate_operation(operation, recipient)
        if not math.isfinite(ttl_seconds) or not 0 < ttl_seconds <= 86400:
            raise HostAuthorizationError("ttl must be positive and at most 86400 seconds")
        resource = observer.observe(namespace, relative_path)
        issued = time.time()
        record = {
            "id": str(uuid4()), "issuer": "controlled_host_command", "binding": asdict(binding),
            "resource": resource.to_dict(), "operation": operation, "recipient": recipient,
            "issued_at": issued, "expires_at": issued + ttl_seconds, "revoked": False,
        }
        with self._connect() as db:
            db.execute("INSERT INTO grants(id,payload,expires) VALUES(?,?,?)", (record["id"], json.dumps(record, sort_keys=True), record["expires_at"]))
        return record

    def query(self, grant_id: str | None = None) -> list[dict]:
        """查询实际宿主记录并返回当前过期/撤销状态，不恢复或扩大授权。"""
        with self._connect() as db:
            rows = db.execute("SELECT payload,revoked,expires FROM grants WHERE id=? ORDER BY id", (grant_id,)).fetchall() if grant_id else db.execute("SELECT payload,revoked,expires FROM grants ORDER BY id").fetchall()
        now = time.time()
        return [{**json.loads(payload), "revoked": bool(revoked), "expired": expires <= now} for payload, revoked, expires in rows]

    def revoke(self, grant_id: str) -> bool:
        """宿主持久撤销授权；重复撤销幂等，未知ID返回False。"""
        with self._connect() as db:
            cursor = db.execute("UPDATE grants SET revoked=1 WHERE id=?", (grant_id,))
        return bool(cursor.rowcount)

    def query_for_decision(self, *, max_records: int = 1024) -> list[dict]:
        """后台有界读取当前授权快照；SQLite忙立即失败，不在监视器内调用。"""
        if not 1 <= max_records <= 1024:
            raise HostAuthorizationError("decision record budget must be between 1 and 1024")
        now = time.time()
        with self._connect(timeout=0) as db:
            rows = db.execute("SELECT payload FROM grants WHERE revoked=0 AND expires>? ORDER BY id LIMIT ?",
                              (now, max_records + 1)).fetchall()
        if len(rows) > max_records or any(len(payload.encode()) > 16384 for (payload,) in rows):
            raise HostAuthorizationError("decision authorization snapshot exceeds budget")
        return [{**json.loads(payload), "revoked": False, "expired": False} for (payload,) in rows]

    def match(
        self, observer: HostResourceObserver, namespace: str, relative_path: str, *,
        binding: TaskBinding, operation: str, recipient: str,
    ) -> dict | None:
        """重新观察真实资源并精确查询，不接受外部资源描述或grant ID。

        binding须由服务端认证身份及宿主任务映射构造；Hook目前仅关联
        参数引用，不允许将raw_user_intent中的task/session当作可信绑定。
        """
        binding.validate()
        self._validate_operation(operation, recipient)
        resource = observer.observe(namespace, relative_path)
        for grant in self.query():
            expected = grant["binding"]
            actual = asdict(binding)
            if any(expected[key] != actual[key] for key in ("task_id", "principal_id", "agent_id")):
                continue
            if any(expected[key] and expected[key] != actual[key] for key in ("session_id", "run_id")):
                continue
            if grant["revoked"] or grant["expired"] or grant["operation"] != operation or grant["recipient"] != recipient:
                continue
            if any(grant["resource"][key] != getattr(resource, key) for key in ("namespace", "resource_id", "content_version")):
                continue
            return grant
        return None

    def resolve_task_binding(
        self, *, principal_id: str, agent_id: str, session_id: str = "", run_id: str = "",
    ) -> TaskBinding | None:
        """从宿主有效记录解析任务，禁止由工具参数声明task_id。

        参数只能来自认证Hook上下文。一个上下文关联多个任务时返回
        None，后续高风险调用应请求审批；不能任选第一条授权。
        """
        if not principal_id or not agent_id or not (session_id or run_id):
            return None
        candidates: dict[str, TaskBinding] = {}
        for grant in self.query():
            if grant["revoked"] or grant["expired"]:
                continue
            binding = TaskBinding(**grant["binding"])
            if binding.principal_id != principal_id or binding.agent_id != agent_id:
                continue
            if binding.session_id and binding.session_id != session_id:
                continue
            if binding.run_id and binding.run_id != run_id:
                continue
            candidates[binding.task_id] = TaskBinding(binding.task_id, principal_id, agent_id, session_id, run_id)
        return next(iter(candidates.values())) if len(candidates) == 1 else None

    @staticmethod
    def _validate_operation(operation: str, recipient: str) -> None:
        if operation not in OPERATION_EFFECTS:
            raise HostAuthorizationError("operation must belong to finite tool operation catalog")
        if not isinstance(recipient, str) or not recipient or recipient != recipient.strip() or recipient == "*" or "\x00" in recipient:
            raise HostAuthorizationError("recipient must be exact and nonempty")
