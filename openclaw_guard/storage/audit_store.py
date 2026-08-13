"""
Audit Store Module - Now using DBStore abstraction layer

The AuditStore now supports:
- PostgreSQL (with Redis caching) for production
- SQLite as fallback for development/simple deployments

Configuration:
    # PostgreSQL (production)
    DATABASE_URL=postgresql://user:pass@localhost:5432/openclaw_guard

    # SQLite (development)
    DATABASE_URL=sqlite:///output/audit/audit.db
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from openclaw_guard.storage.db_store import DBConfig, get_db_store, reset_db_store
from openclaw_guard.models import AuditRecord
from openclaw_guard.utils import append_jsonl, utc_now_iso, write_csv, write_json


class AuditStore:
    """
    Audit Store with pluggable database backend.

    Supports PostgreSQL (production) with Redis caching, or SQLite (development).
    """

    def __init__(
        self,
        sqlite_path: Path | None = None,
        json_backup_path: Path | None = None,
        *,
        connection_string: str | None = None,
        db_config: DBConfig | None = None,
        store_mode: str | None = None,
    ) -> None:
        self.sqlite_path = sqlite_path or Path("output/audit/audit.db")
        self.json_backup_path = json_backup_path or self.sqlite_path.parent / "audit.jsonl"
        self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        self.json_backup_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database store
        if connection_string:
            self._db = get_db_store(connection_string, mode=store_mode)
        elif db_config:
            self._db = get_db_store(config=db_config, mode=store_mode)
        else:
            # Default to SQLite
            self._db = get_db_store(f"sqlite:///{self.sqlite_path}", mode=store_mode)

    def append(self, record_type: str, payload: dict[str, Any]) -> AuditRecord:
        """
        Append a new audit record.

        The record is stored in the database and optionally backed up to JSONL.
        Thread-safe with database-level locking.
        """
        record_dict = self._db.append_audit_record(record_type, payload)

        # Convert to AuditRecord
        record = AuditRecord(
            record_id=record_dict["record_id"],
            timestamp=record_dict["timestamp"],
            record_type=record_dict["record_type"],
            payload=record_dict["payload"],
            previous_hash=record_dict["previous_hash"],
            record_hash=record_dict["record_hash"],
        )

        # Backup to JSONL (best effort)
        try:
            append_jsonl(self.json_backup_path, record.to_dict())
        except Exception:
            pass

        return record

    def query(
        self,
        record_type: str | None = None,
        limit: int = 200,
        offset: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Query audit records with optional filtering.

        Args:
            record_type: Filter by record type (e.g., "chat_send", "hook_before_tool_call")
            limit: Maximum number of records to return (default 200)
            offset: Number of records to skip for pagination

        Returns:
            List of audit record dictionaries, ordered by timestamp descending
        """
        return self._db.query_audit_records(
            record_type=record_type,
            limit=limit,
            offset=offset,
        )

    def export(self, output_dir: Path) -> dict[str, str]:
        """
        Export audit records to JSON and CSV files.

        Args:
            output_dir: Directory to write export files

        Returns:
            Dictionary with paths to exported files
        """
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
        """
        Verify the integrity of the audit hash chain.

        Returns:
            Dictionary with 'ok' (bool) and 'broken_records' (list of record_ids)
        """
        return self._db.verify_audit_chain()

    def health_check(self) -> dict[str, Any]:
        """
        Check database health status.

        Returns:
            Dictionary with health status of underlying databases
        """
        return self._db.health_check()

    def close(self) -> None:
        """Close all database connections."""
        self._db.close()


# =============================================================================
# Legacy Compatibility Functions (for existing code that uses _connection)
# =============================================================================

    @contextmanager
    def _connection(self):
        """
        Legacy SQLite connection context manager.

        Deprecated: Only provided for backward compatibility with existing code.
        Internally uses the DBStore abstraction.
        """
        import sqlite3

        conn = sqlite3.connect(str(self.sqlite_path), timeout=30.0)
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """
        Legacy database initialization.

        Deprecated: Database is now initialized by DBStore.
        """
        pass

    def _last_hash(self) -> str:
        """
        Get the hash of the last audit record.

        Deprecated: Use DBStore directly for better performance.
        """
        records = self._db.query_audit_records(limit=1)
        if records:
            return records[0]["record_hash"]
        return "GENESIS"

    def _fetch_rows(
        self,
        *,
        record_type: str | None = None,
        limit: int | None = 200,
        offset: int | None = None,
        descending: bool = True,
    ) -> list[dict[str, Any]]:
        """
        Fetch audit records with legacy-compatible parameters.

        Deprecated: Use query() method directly.
        """
        return self._db.query_audit_records(
            record_type=record_type,
            limit=limit or 200,
            offset=offset,
        )


# =============================================================================
# Module-level functions for testing and utilities
# =============================================================================

def create_audit_store(
    connection_string: str | None = None,
    *,
    sqlite_path: Path | None = None,
    json_backup_path: Path | None = None,
) -> AuditStore:
    """
    Factory function to create an AuditStore instance.

    Args:
        connection_string: Database connection string
            - "postgresql://user:pass@host:port/dbname" for PostgreSQL
            - "sqlite:///path/to/db" for SQLite
        sqlite_path: Path for SQLite database (alternative to connection_string)
        json_backup_path: Path for JSONL backup file

    Returns:
        Configured AuditStore instance
    """
    return AuditStore(
        sqlite_path=sqlite_path,
        json_backup_path=json_backup_path,
        connection_string=connection_string,
    )


def reset_audit_store() -> None:
    """
    Reset the global audit store instance.

    Useful for testing or when reconfiguring the database connection.
    """
    reset_db_store()
