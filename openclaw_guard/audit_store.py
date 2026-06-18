from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import uuid4

from openclaw_guard.models import AuditRecord
from openclaw_guard.utils import append_jsonl, json_dumps, sha256_text, utc_now_iso, write_csv, write_json


class AuditStore:
    def __init__(self, sqlite_path: Path, json_backup_path: Path) -> None:
        self.sqlite_path = sqlite_path
        self.json_backup_path = json_backup_path
        self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        self.json_backup_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    record_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_log(record_type)")
            conn.commit()

    def append(self, record_type: str, payload: dict[str, Any]) -> AuditRecord:
        previous_hash = self._last_hash()
        record = AuditRecord(
            record_id=uuid4().hex[:16],
            timestamp=utc_now_iso(),
            record_type=record_type,
            payload=payload,
            previous_hash=previous_hash,
            record_hash=sha256_text(previous_hash + json.dumps(payload, ensure_ascii=False, sort_keys=True)),
        )
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO audit_log(record_id, timestamp, record_type, payload_json, previous_hash, record_hash) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    record.record_id,
                    record.timestamp,
                    record.record_type,
                    json.dumps(payload, ensure_ascii=False, sort_keys=True),
                    record.previous_hash,
                    record.record_hash,
                ),
            )
            conn.commit()
        append_jsonl(self.json_backup_path, record.to_dict())
        return record

    def query(self, record_type: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        return self._fetch_rows(record_type=record_type, limit=limit, descending=True)

    def export(self, output_dir: Path) -> dict[str, str]:
        output_dir.mkdir(parents=True, exist_ok=True)
        items = self.query(limit=2000)
        json_path = output_dir / "audit-export.json"
        csv_path = output_dir / "audit-export.csv"
        write_json(json_path, {"items": items, "exported_at": utc_now_iso()})
        flat_rows = [
            {
                "record_id": item["record_id"],
                "timestamp": item["timestamp"],
                "record_type": item["record_type"],
                "previous_hash": item["previous_hash"],
                "record_hash": item["record_hash"],
                "payload": json.dumps(item["payload"], ensure_ascii=False),
            }
            for item in items
        ]
        write_csv(csv_path, flat_rows)
        return {"json": str(json_path), "csv": str(csv_path)}

    def verify_chain(self) -> dict[str, Any]:
        rows = self._fetch_rows(limit=100000, descending=False)
        previous = "GENESIS"
        broken: list[str] = []
        for row in rows:
            current = sha256_text(previous + json.dumps(row["payload"], ensure_ascii=False, sort_keys=True))
            if row["previous_hash"] != previous or row["record_hash"] != current:
                broken.append(row["record_id"])
            previous = row["record_hash"]
        return {"ok": not broken, "broken_records": broken}

    def _last_hash(self) -> str:
        with self._connection() as conn:
            row = conn.execute("SELECT record_hash FROM audit_log ORDER BY rowid DESC LIMIT 1").fetchone()
        return row[0] if row else "GENESIS"

    def _fetch_rows(
        self,
        *,
        record_type: str | None = None,
        limit: int | None = 200,
        descending: bool = True,
    ) -> list[dict[str, Any]]:
        sql = "SELECT record_id, timestamp, record_type, payload_json, previous_hash, record_hash FROM audit_log"
        params: list[Any] = []
        if record_type:
            sql += " WHERE record_type = ?"
            params.append(record_type)
        sql += f" ORDER BY rowid {'DESC' if descending else 'ASC'}"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        with self._connection() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [
            {
                "record_id": row[0],
                "timestamp": row[1],
                "record_type": row[2],
                "payload": json.loads(row[3]),
                "previous_hash": row[4],
                "record_hash": row[5],
            }
            for row in rows
        ]

    @contextmanager
    def _connection(self):
        conn = sqlite3.connect(self.sqlite_path)
        try:
            yield conn
        finally:
            conn.close()
