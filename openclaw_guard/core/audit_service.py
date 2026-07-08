"""
审计服务。

封装审计记录的追加、查询、导出和完整性校验。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from openclaw_guard.storage.audit_store import AuditStore


class AuditService:
    """负责审计存储的追加、查询和导出。"""

    def __init__(self, store: AuditStore) -> None:
        self.store = store

    def append(self, record_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.store.append(record_type, payload).to_dict()

    def query(self, record_type: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        return self.store.query(record_type=record_type, limit=limit)

    def export(self) -> dict[str, str]:
        return self.store.export(Path("output/audit"))

    def verify(self) -> dict[str, Any]:
        return self.store.verify_chain()
