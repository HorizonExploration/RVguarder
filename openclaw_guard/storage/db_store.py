"""
Database Abstraction Layer for OpenClaw Guard
Supports PostgreSQL with SQLite fallback

Usage:
    from openclaw_guard.storage.db_store import get_db_store
    db = get_db_store(connection_string="postgresql://user:pass@localhost/dbname")
    db.append_audit_record("chat_send", {"message": "hello"})
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

# Optional PostgreSQL support
try:
    import psycopg2
    import psycopg2.pool
    from psycopg2.extras import RealDictCursor, Json

    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False
    psycopg2 = None
    psycopg2_pool = None
    RealDictCursor = None
    Json = None

# Optional Redis support
try:
    import redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

try:
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import Engine
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.inspection import inspect as sqlalchemy_inspect

    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False
    create_engine = None
    text = None
    Engine = None
    SQLAlchemyError = Exception
    sqlalchemy_inspect = None


# =============================================================================
# Database Configuration
# =============================================================================

@dataclass
class DBConfig:
    """Database configuration"""
    db_type: str = "sqlite"  # "postgresql" or "sqlite"
    host: str = "localhost"
    port: int = 5432
    database: str = "openclaw_guard"
    username: str = ""
    password: str = ""
    # SQLite specific
    sqlite_path: Path | None = None
    # Connection pool settings
    min_connections: int = 2
    max_connections: int = 10
    # Redis cache settings
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str | None = None
    cache_ttl: int = 300  # seconds

    def get_postgresql_dsn(self) -> str:
        return f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"

    def get_postgresql_dsn_without_password(self) -> str:
        return f"postgresql://{self.username}@{self.host}:{self.port}/{self.database}"


# =============================================================================
# Database Store Interface
# =============================================================================

class DBStoreInterface(ABC):
    """Abstract interface for database operations"""

    @abstractmethod
    def append_audit_record(self, record_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Append a new audit record with hash chain"""
        pass

    @abstractmethod
    def query_audit_records(
        self,
        record_type: str | None = None,
        limit: int = 200,
        offset: int | None = None,
        since: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Query audit records with optional filtering"""
        pass

    @abstractmethod
    def verify_audit_chain(self) -> dict[str, Any]:
        """Verify the integrity of the audit hash chain"""
        pass

    @abstractmethod
    def save_action(self, action_data: dict[str, Any]) -> bool:
        """Save or update a controlled action"""
        pass

    @abstractmethod
    def get_action(self, action_id: str) -> dict[str, Any] | None:
        """Get a controlled action by ID"""
        pass

    @abstractmethod
    def list_actions(
        self,
        status: str | None = None,
        limit: int = 1000,
        offset: int | None = None,
    ) -> list[dict[str, Any]]:
        """List controlled actions with optional filtering"""
        pass

    @abstractmethod
    def append_runtime_log(self, event: str, profile: str, **kwargs) -> bool:
        """Append a runtime log entry"""
        pass

    @abstractmethod
    def get_recent_logs(self, limit: int = 80) -> list[dict[str, Any]]:
        """Get recent runtime logs"""
        pass

    @abstractmethod
    def upsert_skill(self, name: str, data: dict[str, Any]) -> bool:
        """Insert or update a skill"""
        pass

    @abstractmethod
    def delete_skill(self, name: str) -> bool:
        """Delete a skill"""
        pass

    @abstractmethod
    def list_skills(self) -> list[dict[str, Any]]:
        """List all skills"""
        pass

    @abstractmethod
    def upsert_channel(self, name: str, data: dict[str, Any]) -> bool:
        """Insert or update a channel"""
        pass

    @abstractmethod
    def delete_channel(self, name: str) -> bool:
        """Delete a channel"""
        pass

    @abstractmethod
    def list_channels(self) -> list[dict[str, Any]]:
        """List all channels"""
        pass

    @abstractmethod
    def health_check(self) -> dict[str, Any]:
        """Check database health"""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close all connections"""
        pass


# =============================================================================
# PostgreSQL Implementation
# =============================================================================

class PostgreSQLStore(DBStoreInterface):
    """PostgreSQL implementation of DBStoreInterface"""

    def __init__(self, config: DBConfig) -> None:
        if not PSYCOPG2_AVAILABLE:
            raise ImportError("psycopg2 is required for PostgreSQL support. Install with: pip install psycopg2-binary")

        self.config = config
        self._pool: psycopg2.pool.ThreadedConnectionPool | None = None
        self._redis_client: redis.Redis | None = None
        self._lock = threading.RLock()
        self._init_pool()
        self._init_redis()

    def _init_pool(self) -> None:
        try:
            self._pool = psycopg2.pool.ThreadedConnectionPool(
                self.config.min_connections,
                self.config.max_connections,
                host=self.config.host,
                port=self.config.port,
                database=self.config.database,
                user=self.config.username,
                password=self.config.password,
            )
        except psycopg2.OperationalError as exc:
            raise ConnectionError(f"Failed to create PostgreSQL connection pool: {exc}")

    def _init_redis(self) -> None:
        if not REDIS_AVAILABLE:
            return
        try:
            self._redis_client = redis.Redis(
                host=self.config.redis_host,
                port=self.config.redis_port,
                db=self.config.redis_db,
                password=self.config.redis_password,
                decode_responses=True,
                socket_timeout=5,
            )
            self._redis_client.ping()
        except redis.RedisError:
            self._redis_client = None

    @contextmanager
    def _get_connection(self) -> Iterator[Any]:
        conn = self._pool.getconn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)

    @contextmanager
    def _get_cursor(self) -> Iterator[Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            try:
                yield cursor
            finally:
                cursor.close()

    def _compute_hash(self, previous_hash: str, payload_json: str) -> str:
        return hashlib.sha256(f"{previous_hash}{payload_json}".encode()).hexdigest()

    def _compute_payload_hash(self, payload_json: str) -> str:
        return hashlib.sha256(payload_json.encode()).hexdigest()

    def _get_last_hash(self) -> str:
        with self._get_cursor() as cursor:
            cursor.execute(
                "SELECT record_hash FROM audit_log ORDER BY timestamp DESC, log_id DESC LIMIT 1 FOR UPDATE"
            )
            row = cursor.fetchone()
            return row["record_hash"] if row else "GENESIS"

    def append_audit_record(self, record_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
            record_id = uuid4().hex[:16]
            payload_json = json.dumps(payload, ensure_ascii=False, sort_keys=True)
            payload_hash = self._compute_payload_hash(payload_json)

            with self._get_connection() as conn:
                cursor = conn.cursor(cursor_factory=RealDictCursor)
                cursor.execute(
                    "SELECT record_hash FROM audit_log ORDER BY timestamp DESC LIMIT 1 FOR UPDATE"
                )
                row = cursor.fetchone()
                previous_hash = row["record_hash"] if row else "GENESIS"

            record_hash = self._compute_hash(previous_hash, payload_json)

            record = {
                "record_id": record_id,
                "timestamp": timestamp,
                "record_type": record_type,
                "payload": payload,
                "previous_hash": previous_hash,
                "record_hash": record_hash,
            }

            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO audit_log (record_id, timestamp, record_type, payload, payload_hash, previous_hash, record_hash)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (record_id, timestamp, record_type, Json(payload), payload_hash, previous_hash, record_hash),
                )

            # Invalidate cache
            self._invalidate_cache("audit:*")

            return record

    def query_audit_records(
        self,
        record_type: str | None = None,
        limit: int = 200,
        offset: int | None = None,
        since: datetime | None = None,
    ) -> list[dict[str, Any]]:
        cache_key = f"audit:query:{record_type}:{limit}:{offset}:{since}"
        cached = self._get_cache(cache_key)
        if cached is not None:
            return cached

        with self._get_cursor() as cursor:
            sql = "SELECT * FROM audit_log WHERE 1=1"
            params: list[Any] = []

            if record_type:
                sql += " AND record_type = %s"
                params.append(record_type)
            if since:
                sql += " AND timestamp >= %s"
                params.append(since)

            sql += " ORDER BY timestamp DESC"
            sql += f" LIMIT {limit}"
            if offset:
                sql += f" OFFSET {offset}"

            cursor.execute(sql, params)
            rows = cursor.fetchall()

        result = []
        for row in rows:
            record = dict(row)
            if isinstance(record["payload"], str):
                record["payload"] = json.loads(record["payload"])
            result.append(record)

        self._set_cache(cache_key, result)
        return result

    def verify_audit_chain(self) -> dict[str, Any]:
        with self._get_cursor() as cursor:
            cursor.execute(
                "SELECT record_id, payload, payload_hash, previous_hash, record_hash FROM audit_log ORDER BY timestamp ASC LIMIT 100000"
            )
            rows = cursor.fetchall()

        previous = "GENESIS"
        broken: list[str] = []

        for row in rows:
            payload_json = json.dumps(row["payload"], ensure_ascii=False, sort_keys=True)
            expected_payload_hash = hashlib.sha256(payload_json.encode()).hexdigest()
            expected_record_hash = hashlib.sha256(f"{previous}{payload_json}".encode()).hexdigest()

            if row["previous_hash"] != previous:
                broken.append(row["record_id"])
            if row["payload_hash"] != expected_payload_hash:
                broken.append(row["record_id"])
            if row["record_hash"] != expected_record_hash:
                broken.append(row["record_id"])

            previous = row["record_hash"]

        return {"ok": not broken, "broken_records": broken}

    def save_action(self, action_data: dict[str, Any]) -> bool:
        action_id = action_data.get("action_id")
        if not action_id:
            return False

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO controlled_actions (
                    action_id, source_message, status, event_data, decision_data,
                    target_summary, decision_trace, matched_whitelists, matched_rules, execution_result
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (action_id) DO UPDATE SET
                    source_message = EXCLUDED.source_message,
                    status = EXCLUDED.status,
                    event_data = EXCLUDED.event_data,
                    decision_data = EXCLUDED.decision_data,
                    target_summary = EXCLUDED.target_summary,
                    decision_trace = EXCLUDED.decision_trace,
                    matched_whitelists = EXCLUDED.matched_whitelists,
                    matched_rules = EXCLUDED.matched_rules,
                    execution_result = EXCLUDED.execution_result
                """,
                (
                    action_id,
                    action_data.get("source_message", ""),
                    action_data.get("status", "proposed"),
                    Json(action_data.get("event", {})),
                    Json(action_data.get("decision", {})),
                    action_data.get("target_summary", ""),
                    Json(action_data.get("decision_trace", [])),
                    Json(action_data.get("matched_whitelists", [])),
                    Json(action_data.get("matched_rules", [])),
                    Json(action_data.get("execution_result", {})),
                ),
            )

        self._invalidate_cache("actions:*")
        return True

    def get_action(self, action_id: str) -> dict[str, Any] | None:
        cache_key = f"actions:id:{action_id}"
        cached = self._get_cache(cache_key)
        if cached is not None:
            return cached

        with self._get_cursor() as cursor:
            cursor.execute(
                "SELECT * FROM controlled_actions WHERE action_id = %s",
                (action_id,)
            )
            row = cursor.fetchone()

        if not row:
            return None

        result = self._action_row_to_dict(row)
        self._set_cache(cache_key, result, ttl=60)
        return result

    def list_actions(
        self,
        status: str | None = None,
        limit: int = 1000,
        offset: int | None = None,
    ) -> list[dict[str, Any]]:
        cache_key = f"actions:list:{status}:{limit}:{offset}"
        cached = self._get_cache(cache_key)
        if cached is not None:
            return cached

        with self._get_cursor() as cursor:
            sql = "SELECT * FROM controlled_actions WHERE 1=1"
            params: list[Any] = []

            if status:
                sql += " AND status = %s"
                params.append(status)

            sql += " ORDER BY created_at DESC"
            sql += f" LIMIT {limit}"
            if offset:
                sql += f" OFFSET {offset}"

            cursor.execute(sql, params)
            rows = cursor.fetchall()

        result = [self._action_row_to_dict(row) for row in rows]
        self._set_cache(cache_key, result, ttl=30)
        return result

    def _action_row_to_dict(self, row: dict[str, Any]) -> dict[str, Any]:
        result = dict(row)
        for key in ["event_data", "decision_data", "decision_trace", "matched_whitelists", "matched_rules", "execution_result"]:
            if key in result and isinstance(result[key], str):
                result[key] = json.loads(result[key])
        return result

    def append_runtime_log(self, event: str, profile: str, **kwargs) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO runtime_logs (event, profile, payload)
                VALUES (%s, %s, %s)
                """,
                (event, profile, Json(kwargs)),
            )
        self._invalidate_cache("logs:*")
        return True

    def get_recent_logs(self, limit: int = 80) -> list[dict[str, Any]]:
        cache_key = f"logs:recent:{limit}"
        cached = self._get_cache(cache_key)
        if cached is not None:
            return cached

        with self._get_cursor() as cursor:
            cursor.execute(
                "SELECT * FROM runtime_logs ORDER BY timestamp DESC LIMIT %s",
                (limit,)
            )
            rows = cursor.fetchall()

        result = []
        for row in rows:
            log = dict(row)
            if isinstance(log.get("payload"), str):
                log["payload"] = json.loads(log["payload"])
            result.append(log)

        self._set_cache(cache_key, result, ttl=10)
        return result

    def upsert_skill(self, name: str, data: dict[str, Any]) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO skills (name, enabled, description, permissions, raw_config)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (name) DO UPDATE SET
                    enabled = EXCLUDED.enabled,
                    description = EXCLUDED.description,
                    permissions = EXCLUDED.permissions,
                    raw_config = EXCLUDED.raw_config
                """,
                (
                    name,
                    bool(data.get("enabled", True)),
                    str(data.get("description", ""))[:500],
                    Json(data.get("permissions", [])),
                    Json(data.get("raw", data)),
                ),
            )
        self._invalidate_cache("skills:*")
        return True

    def delete_skill(self, name: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM skills WHERE name = %s", (name,))
        self._invalidate_cache("skills:*")
        return True

    def list_skills(self) -> list[dict[str, Any]]:
        cache_key = "skills:list"
        cached = self._get_cache(cache_key)
        if cached is not None:
            return cached

        with self._get_cursor() as cursor:
            cursor.execute("SELECT * FROM skills ORDER BY name")
            rows = cursor.fetchall()

        result = []
        for row in rows:
            skill = dict(row)
            if isinstance(skill.get("permissions"), str):
                skill["permissions"] = json.loads(skill["permissions"])
            if isinstance(skill.get("raw_config"), str):
                skill["raw_config"] = json.loads(skill["raw_config"])
            result.append(skill)

        self._set_cache(cache_key, result, ttl=60)
        return result

    def upsert_channel(self, name: str, data: dict[str, Any]) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO channels (name, enabled, status, default_target, raw_config)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (name) DO UPDATE SET
                    enabled = EXCLUDED.enabled,
                    status = EXCLUDED.status,
                    default_target = EXCLUDED.default_target,
                    raw_config = EXCLUDED.raw_config
                """,
                (
                    name,
                    bool(data.get("enabled", True)),
                    str(data.get("status", "enabled")),
                    str(data.get("target", "")),
                    Json(data.get("raw", data)),
                ),
            )
        self._invalidate_cache("channels:*")
        return True

    def delete_channel(self, name: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM channels WHERE name = %s", (name,))
        self._invalidate_cache("channels:*")
        return True

    def list_channels(self) -> list[dict[str, Any]]:
        cache_key = "channels:list"
        cached = self._get_cache(cache_key)
        if cached is not None:
            return cached

        with self._get_cursor() as cursor:
            cursor.execute("SELECT * FROM channels ORDER BY name")
            rows = cursor.fetchall()

        result = []
        for row in rows:
            channel = dict(row)
            if isinstance(channel.get("raw_config"), str):
                channel["raw_config"] = json.loads(channel["raw_config"])
            result.append(channel)

        self._set_cache(cache_key, result, ttl=60)
        return result

    def health_check(self) -> dict[str, Any]:
        status: dict[str, Any] = {"ok": True, "postgres": False, "redis": False}

        # Check PostgreSQL
        try:
            with self._get_cursor() as cursor:
                cursor.execute("SELECT 1")
            status["postgres"] = True
        except Exception as exc:
            status["postgres"] = str(exc)
            status["ok"] = False

        # Check Redis
        if self._redis_client:
            try:
                self._redis_client.ping()
                status["redis"] = True
            except Exception as exc:
                status["redis"] = str(exc)

        return status

    def close(self) -> None:
        if self._pool:
            self._pool.closeall()
        if self._redis_client:
            self._redis_client.close()

    # ---- Cache helpers ----

    def _get_cache(self, key: str) -> Any | None:
        if not self._redis_client:
            return None
        try:
            data = self._redis_client.get(f"openclaw_guard:{key}")
            if data:
                return json.loads(data)
        except redis.RedisError:
            pass
        return None

    def _set_cache(self, key: str, value: Any, ttl: int | None = None) -> None:
        if not self._redis_client:
            return
        try:
            ttl = ttl or self.config.cache_ttl
            self._redis_client.setex(
                f"openclaw_guard:{key}",
                ttl,
                json.dumps(value),
            )
        except redis.RedisError:
            pass

    def _invalidate_cache(self, pattern: str) -> None:
        if not self._redis_client:
            return
        try:
            keys = self._redis_client.keys(f"openclaw_guard:{pattern}")
            if keys:
                self._redis_client.delete(*keys)
        except redis.RedisError:
            pass


class SQLAlchemyStore(DBStoreInterface):
    """SQLAlchemy implementation of DBStoreInterface."""

    def __init__(self, db_url: str) -> None:
        if not SQLALCHEMY_AVAILABLE:
            raise ImportError(
                "sqlalchemy is required for SQLAlchemyStore. Install with: pip install sqlalchemy"
            )
        self.db_url = db_url
        self._engine: Engine | None = None
        self._lock = threading.RLock()
        self._dialect_name: str | None = None
        self._audit_has_payload_json: bool | None = None
        self._audit_has_payload: bool | None = None
        self._audit_has_payload_hash: bool | None = None
        self._audit_has_log_id: bool | None = None

    def _ensure_engine(self) -> Engine:
        engine = self._engine
        if engine is not None:
            return engine
        with self._lock:
            engine = self._engine
            if engine is not None:
                return engine
            connect_args: dict[str, Any] | None = None
            if self.db_url.startswith("sqlite:"):
                connect_args = {"check_same_thread": False}
            engine = create_engine(self.db_url, pool_pre_ping=True, connect_args=connect_args or {})
            self._engine = engine
            self._dialect_name = engine.dialect.name
            return engine

    def _ensure_schema(self) -> None:
        engine = self._ensure_engine()
        with engine.begin() as conn:
            conn.exec_driver_sql(
                "CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            conn.exec_driver_sql(
                "INSERT INTO schema_meta (key, value) VALUES ('schema_version', '1') "
                "ON CONFLICT (key) DO NOTHING"
            )

            insp = sqlalchemy_inspect(engine)
            audit_exists = insp.has_table("audit_log")
            if not audit_exists:
                conn.exec_driver_sql(
                    "CREATE TABLE IF NOT EXISTS audit_log ("
                    "record_id TEXT PRIMARY KEY, "
                    "timestamp TEXT NOT NULL, "
                    "record_type TEXT NOT NULL, "
                    "payload_json TEXT NOT NULL, "
                    "previous_hash TEXT NOT NULL, "
                    "record_hash TEXT NOT NULL"
                    ")"
                )
                conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
                conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_log(record_type)")

            columns = {c["name"] for c in insp.get_columns("audit_log")}
            self._audit_has_payload_json = "payload_json" in columns
            self._audit_has_payload = "payload" in columns
            self._audit_has_payload_hash = "payload_hash" in columns
            self._audit_has_log_id = "log_id" in columns

            conn.exec_driver_sql(
                "CREATE TABLE IF NOT EXISTS controlled_actions ("
                "action_id TEXT PRIMARY KEY, "
                "payload_json TEXT NOT NULL, "
                "updated_at TEXT NOT NULL"
                ")"
            )
            conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS idx_actions_updated_at ON controlled_actions(updated_at)")

            conn.exec_driver_sql(
                "CREATE TABLE IF NOT EXISTS runtime_logs ("
                "log_id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "timestamp TEXT NOT NULL, "
                "event TEXT NOT NULL, "
                "profile TEXT NOT NULL, "
                "payload_json TEXT NOT NULL"
                ")"
            )
            conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON runtime_logs(timestamp)")

            conn.exec_driver_sql(
                "CREATE TABLE IF NOT EXISTS skills ("
                "name TEXT PRIMARY KEY, "
                "payload_json TEXT NOT NULL, "
                "updated_at TEXT NOT NULL"
                ")"
            )
            conn.exec_driver_sql(
                "CREATE TABLE IF NOT EXISTS channels ("
                "name TEXT PRIMARY KEY, "
                "payload_json TEXT NOT NULL, "
                "updated_at TEXT NOT NULL"
                ")"
            )

    def _audit_order_clause(self) -> str:
        if self._audit_has_log_id:
            return "timestamp DESC, log_id DESC"
        return "timestamp DESC"

    def _audit_lock_clause(self) -> str:
        if self._dialect_name == "postgresql":
            return " FOR UPDATE"
        return ""

    def _compute_hash(self, previous_hash: str, payload_json: str) -> str:
        return hashlib.sha256(f"{previous_hash}{payload_json}".encode()).hexdigest()

    def _compute_payload_hash(self, payload_json: str) -> str:
        return hashlib.sha256(payload_json.encode()).hexdigest()

    def append_audit_record(self, record_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._ensure_schema()
        payload_json = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        record_id = uuid4().hex[:16]
        timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

        with self._lock:
            engine = self._ensure_engine()
            with engine.begin() as conn:
                previous_sql = (
                    f"SELECT record_hash FROM audit_log ORDER BY {self._audit_order_clause()} LIMIT 1"
                    f"{self._audit_lock_clause()}"
                )
                row = conn.execute(text(previous_sql)).fetchone()
                previous_hash = row[0] if row else "GENESIS"

                record_hash = self._compute_hash(previous_hash, payload_json)
                payload_hash = self._compute_payload_hash(payload_json)

                columns: list[str] = ["record_id", "timestamp", "record_type", "previous_hash", "record_hash"]
                values: dict[str, Any] = {
                    "record_id": record_id,
                    "timestamp": timestamp,
                    "record_type": record_type,
                    "previous_hash": previous_hash,
                    "record_hash": record_hash,
                }
                if self._audit_has_payload_json:
                    columns.append("payload_json")
                    values["payload_json"] = payload_json
                elif self._audit_has_payload:
                    columns.append("payload")
                    values["payload"] = payload
                else:
                    columns.append("payload_json")
                    values["payload_json"] = payload_json
                if self._audit_has_payload_hash:
                    columns.append("payload_hash")
                    values["payload_hash"] = payload_hash

                placeholders = ", ".join([f":{c}" for c in columns])
                sql = f"INSERT INTO audit_log ({', '.join(columns)}) VALUES ({placeholders})"
                conn.execute(text(sql), values)

        return {
            "record_id": record_id,
            "timestamp": timestamp,
            "record_type": record_type,
            "payload": payload,
            "previous_hash": previous_hash,
            "record_hash": record_hash,
        }

    def query_audit_records(
        self,
        record_type: str | None = None,
        limit: int = 200,
        offset: int | None = None,
        since: datetime | None = None,
    ) -> list[dict[str, Any]]:
        self._ensure_schema()
        engine = self._ensure_engine()
        where = ["1=1"]
        params: dict[str, Any] = {"limit": limit}
        if record_type:
            where.append("record_type = :record_type")
            params["record_type"] = record_type
        if since:
            where.append("timestamp >= :since")
            params["since"] = since.isoformat()
        if offset:
            params["offset"] = offset

        payload_column = "payload_json" if self._audit_has_payload_json else ("payload" if self._audit_has_payload else "payload_json")
        sql = (
            "SELECT record_id, timestamp, record_type, "
            f"{payload_column} AS payload_value, previous_hash, record_hash "
            f"FROM audit_log WHERE {' AND '.join(where)} "
            f"ORDER BY {self._audit_order_clause()} "
            "LIMIT :limit"
        )
        if offset:
            sql += " OFFSET :offset"

        with engine.begin() as conn:
            rows = conn.execute(text(sql), params).fetchall()

        result: list[dict[str, Any]] = []
        for row in rows:
            payload_value = row[3]
            if payload_value is None:
                payload_obj: Any = {}
            elif isinstance(payload_value, str):
                try:
                    payload_obj = json.loads(payload_value)
                except json.JSONDecodeError:
                    payload_obj = {"_raw": payload_value}
            else:
                payload_obj = payload_value
            result.append(
                {
                    "record_id": row[0],
                    "timestamp": row[1],
                    "record_type": row[2],
                    "payload": payload_obj,
                    "previous_hash": row[4],
                    "record_hash": row[5],
                }
            )
        return result

    def verify_audit_chain(self) -> dict[str, Any]:
        self._ensure_schema()
        engine = self._ensure_engine()
        payload_column = "payload_json" if self._audit_has_payload_json else ("payload" if self._audit_has_payload else "payload_json")
        sql = (
            "SELECT record_id, "
            f"{payload_column} AS payload_value, previous_hash, record_hash "
            "FROM audit_log ORDER BY timestamp ASC LIMIT 100000"
        )
        with engine.begin() as conn:
            rows = conn.execute(text(sql)).fetchall()

        previous = "GENESIS"
        broken: list[str] = []
        for row in rows:
            payload_value = row[1]
            if isinstance(payload_value, str):
                payload_json = payload_value
            else:
                payload_json = json.dumps(payload_value, ensure_ascii=False, sort_keys=True)
            expected_hash = self._compute_hash(previous, payload_json)
            if row[2] != previous or row[3] != expected_hash:
                broken.append(row[0])
            previous = row[3]

        return {"ok": not broken, "broken_records": broken}

    def save_action(self, action_data: dict[str, Any]) -> bool:
        self._ensure_schema()
        action_id = action_data.get("action_id")
        if not action_id:
            return False
        payload_json = json.dumps(action_data, ensure_ascii=False)
        updated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        engine = self._ensure_engine()
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO controlled_actions (action_id, payload_json, updated_at) "
                    "VALUES (:action_id, :payload_json, :updated_at) "
                    "ON CONFLICT (action_id) DO UPDATE SET "
                    "payload_json = EXCLUDED.payload_json, "
                    "updated_at = EXCLUDED.updated_at"
                ),
                {"action_id": action_id, "payload_json": payload_json, "updated_at": updated_at},
            )
        return True

    def get_action(self, action_id: str) -> dict[str, Any] | None:
        self._ensure_schema()
        engine = self._ensure_engine()
        with engine.begin() as conn:
            row = conn.execute(
                text("SELECT payload_json FROM controlled_actions WHERE action_id = :action_id"),
                {"action_id": action_id},
            ).fetchone()
        if not row:
            return None
        try:
            return json.loads(row[0])
        except json.JSONDecodeError:
            return None

    def list_actions(
        self,
        status: str | None = None,
        limit: int = 1000,
        offset: int | None = None,
    ) -> list[dict[str, Any]]:
        self._ensure_schema()
        engine = self._ensure_engine()
        params: dict[str, Any] = {"limit": limit}
        if offset:
            params["offset"] = offset
        sql = "SELECT payload_json FROM controlled_actions ORDER BY updated_at DESC LIMIT :limit"
        if offset:
            sql += " OFFSET :offset"
        with engine.begin() as conn:
            rows = conn.execute(text(sql), params).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            try:
                item = json.loads(row[0])
            except json.JSONDecodeError:
                continue
            if status and item.get("status") != status:
                continue
            items.append(item)
        return items

    def append_runtime_log(self, event: str, profile: str, **kwargs) -> bool:
        self._ensure_schema()
        payload_json = json.dumps(kwargs, ensure_ascii=False)
        timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        engine = self._ensure_engine()
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO runtime_logs (timestamp, event, profile, payload_json) "
                    "VALUES (:timestamp, :event, :profile, :payload_json)"
                ),
                {"timestamp": timestamp, "event": event, "profile": profile, "payload_json": payload_json},
            )
        return True

    def get_recent_logs(self, limit: int = 80) -> list[dict[str, Any]]:
        self._ensure_schema()
        engine = self._ensure_engine()
        with engine.begin() as conn:
            rows = conn.execute(
                text("SELECT timestamp, event, profile, payload_json FROM runtime_logs ORDER BY timestamp DESC LIMIT :limit"),
                {"limit": limit},
            ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row[3])
            except json.JSONDecodeError:
                payload = {}
            items.append({"timestamp": row[0], "event": row[1], "profile": row[2], "payload": payload})
        return items

    def upsert_skill(self, name: str, data: dict[str, Any]) -> bool:
        self._ensure_schema()
        payload_json = json.dumps(data, ensure_ascii=False)
        updated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        engine = self._ensure_engine()
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO skills (name, payload_json, updated_at) "
                    "VALUES (:name, :payload_json, :updated_at) "
                    "ON CONFLICT (name) DO UPDATE SET "
                    "payload_json = EXCLUDED.payload_json, "
                    "updated_at = EXCLUDED.updated_at"
                ),
                {"name": name, "payload_json": payload_json, "updated_at": updated_at},
            )
        return True

    def delete_skill(self, name: str) -> bool:
        self._ensure_schema()
        engine = self._ensure_engine()
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM skills WHERE name = :name"), {"name": name})
        return True

    def list_skills(self) -> list[dict[str, Any]]:
        self._ensure_schema()
        engine = self._ensure_engine()
        with engine.begin() as conn:
            rows = conn.execute(text("SELECT name, payload_json FROM skills ORDER BY name")).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row[1])
            except json.JSONDecodeError:
                payload = {}
            items.append({"name": row[0], **payload})
        return items

    def upsert_channel(self, name: str, data: dict[str, Any]) -> bool:
        self._ensure_schema()
        payload_json = json.dumps(data, ensure_ascii=False)
        updated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        engine = self._ensure_engine()
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO channels (name, payload_json, updated_at) "
                    "VALUES (:name, :payload_json, :updated_at) "
                    "ON CONFLICT (name) DO UPDATE SET "
                    "payload_json = EXCLUDED.payload_json, "
                    "updated_at = EXCLUDED.updated_at"
                ),
                {"name": name, "payload_json": payload_json, "updated_at": updated_at},
            )
        return True

    def delete_channel(self, name: str) -> bool:
        self._ensure_schema()
        engine = self._ensure_engine()
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM channels WHERE name = :name"), {"name": name})
        return True

    def list_channels(self) -> list[dict[str, Any]]:
        self._ensure_schema()
        engine = self._ensure_engine()
        with engine.begin() as conn:
            rows = conn.execute(text("SELECT name, payload_json FROM channels ORDER BY name")).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row[1])
            except json.JSONDecodeError:
                payload = {}
            items.append({"name": row[0], **payload})
        return items

    def health_check(self) -> dict[str, Any]:
        try:
            self._ensure_schema()
            engine = self._ensure_engine()
            with engine.begin() as conn:
                conn.execute(text("SELECT 1"))
            return {"ok": True, "sqlalchemy": True}
        except Exception as exc:
            return {"ok": False, "sqlalchemy": str(exc)}

    def close(self) -> None:
        engine = self._engine
        if engine is not None:
            engine.dispose()
        self._engine = None


# =============================================================================
# SQLite Fallback Implementation
# =============================================================================

class SQLiteStore(DBStoreInterface):
    """SQLite fallback implementation (original behavior)"""

    def __init__(self, sqlite_path: Path) -> None:
        self.sqlite_path = sqlite_path
        self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            conn = sqlite3.connect(self.sqlite_path, timeout=30.0)
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
            conn.close()

    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.sqlite_path, timeout=30.0)
        try:
            yield conn
        finally:
            conn.close()

    def _compute_hash(self, previous_hash: str, payload_json: str) -> str:
        return hashlib.sha256(f"{previous_hash}{payload_json}".encode()).hexdigest()

    def append_audit_record(self, record_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT record_hash FROM audit_log ORDER BY ROWID DESC LIMIT 1")
                row = cursor.fetchone()
                previous_hash = row[0] if row else "GENESIS"

            payload_json = json.dumps(payload, ensure_ascii=False, sort_keys=True)
            record_id = uuid4().hex[:16]
            timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
            record_hash = self._compute_hash(previous_hash, payload_json)

            record = {
                "record_id": record_id,
                "timestamp": timestamp,
                "record_type": record_type,
                "payload": payload,
                "previous_hash": previous_hash,
                "record_hash": record_hash,
            }

            with self._get_connection() as conn:
                conn.execute(
                    "INSERT INTO audit_log (record_id, timestamp, record_type, payload_json, previous_hash, record_hash) VALUES (?, ?, ?, ?, ?, ?)",
                    (record_id, timestamp, record_type, payload_json, previous_hash, record_hash),
                )
                conn.commit()

            return record

    def query_audit_records(
        self,
        record_type: str | None = None,
        limit: int = 200,
        offset: int | None = None,
        since: datetime | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                sql = "SELECT record_id, timestamp, record_type, payload_json, previous_hash, record_hash FROM audit_log WHERE 1=1"
                params: list[Any] = []

                if record_type:
                    sql += " AND record_type = ?"
                    params.append(record_type)
                if since:
                    sql += " AND timestamp >= ?"
                    params.append(since.isoformat())

                sql += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                if offset:
                    sql += " OFFSET ?"
                    params.append(offset)

                cursor = conn.execute(sql, params)
                rows = cursor.fetchall()

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

    def verify_audit_chain(self) -> dict[str, Any]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT record_id, payload_json, previous_hash, record_hash FROM audit_log ORDER BY timestamp ASC LIMIT 100000"
                )
                rows = cursor.fetchall()

        previous = "GENESIS"
        broken: list[str] = []

        for row in rows:
            expected_hash = self._compute_hash(previous, row[1])
            if row[2] != previous or row[3] != expected_hash:
                broken.append(row[0])
            previous = row[3]

        return {"ok": not broken, "broken_records": broken}

    def save_action(self, action_data: dict[str, Any]) -> bool:
        # SQLite doesn't support ON CONFLICT with JSON, simplified implementation
        action_id = action_data.get("action_id")
        if not action_id:
            return False

        # Store in a separate JSON file for simplicity
        actions_path = self.sqlite_path.parent / "controlled-actions.json"
        data = {}
        if actions_path.exists():
            try:
                data = json.loads(actions_path.read_text())
            except (json.JSONDecodeError, OSError):
                data = {}

        items = data.get("items", [])
        # Replace or append
        replaced = False
        for i, item in enumerate(items):
            if item.get("action_id") == action_id:
                items[i] = action_data
                replaced = True
                break
        if not replaced:
            items.append(action_data)

        data["items"] = items[-1000:]  # Keep last 1000
        actions_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return True

    def get_action(self, action_id: str) -> dict[str, Any] | None:
        actions_path = self.sqlite_path.parent / "controlled-actions.json"
        if not actions_path.exists():
            return None
        try:
            data = json.loads(actions_path.read_text())
            for item in data.get("items", []):
                if item.get("action_id") == action_id:
                    return item
        except (json.JSONDecodeError, OSError):
            pass
        return None

    def list_actions(
        self,
        status: str | None = None,
        limit: int = 1000,
        offset: int | None = None,
    ) -> list[dict[str, Any]]:
        actions_path = self.sqlite_path.parent / "controlled-actions.json"
        if not actions_path.exists():
            return []
        try:
            data = json.loads(actions_path.read_text())
            items = data.get("items", [])
            if status:
                items = [i for i in items if i.get("status") == status]
            if offset:
                items = items[offset:]
            return items[:limit]
        except (json.JSONDecodeError, OSError):
            return []

    def append_runtime_log(self, event: str, profile: str, **kwargs) -> bool:
        from openclaw_guard.utils import append_jsonl

        log_path = self.sqlite_path.parent.parent / "runtime" / "guard.log"
        append_jsonl(
            log_path,
            {"event": event, "profile": profile, **kwargs},
        )
        return True

    def get_recent_logs(self, limit: int = 80) -> list[dict[str, Any]]:
        log_path = self.sqlite_path.parent.parent / "runtime" / "guard.log"
        if not log_path.exists():
            return []
        try:
            lines = log_path.read_text(encoding="utf-8").strip().splitlines()
            items = []
            for line in lines[-limit:]:
                line = line.strip()
                if line:
                    try:
                        items.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return items
        except OSError:
            return []

    def upsert_skill(self, name: str, data: dict[str, Any]) -> bool:
        return self._upsert_config("skills", name, data)

    def delete_skill(self, name: str) -> bool:
        return self._delete_config("skills", name)

    def list_skills(self) -> list[dict[str, Any]]:
        return self._list_config("skills")

    def upsert_channel(self, name: str, data: dict[str, Any]) -> bool:
        return self._upsert_config("channels", name, data)

    def delete_channel(self, name: str) -> bool:
        return self._delete_config("channels", name)

    def list_channels(self) -> list[dict[str, Any]]:
        return self._list_config("channels")

    def _upsert_config(self, config_type: str, name: str, data: dict[str, Any]) -> bool:
        config_path = self.sqlite_path.parent.parent / "runtime" / f"{config_type}.json"
        config_data = {}
        if config_path.exists():
            try:
                config_data = json.loads(config_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass

        if not isinstance(config_data, dict):
            config_data = {}

        if config_type not in config_data:
            config_data[config_type] = {}

        config_data[config_type][name] = data
        config_path.write_text(json.dumps(config_data, ensure_ascii=False), encoding="utf-8")
        return True

    def _delete_config(self, config_type: str, name: str) -> bool:
        config_path = self.sqlite_path.parent.parent / "runtime" / f"{config_type}.json"
        if not config_path.exists():
            return True
        try:
            config_data = json.loads(config_path.read_text(encoding="utf-8"))
            if isinstance(config_data.get(config_type), dict):
                config_data[config_type].pop(name, None)
            config_path.write_text(json.dumps(config_data, ensure_ascii=False), encoding="utf-8")
        except (json.JSONDecodeError, OSError):
            pass
        return True

    def _list_config(self, config_type: str) -> list[dict[str, Any]]:
        config_path = self.sqlite_path.parent.parent / "runtime" / f"{config_type}.json"
        if not config_path.exists():
            return []
        try:
            config_data = json.loads(config_path.read_text(encoding="utf-8"))
            items = config_data.get(config_type, {})
            if isinstance(items, dict):
                return [
                    {"name": k, "enabled": v.get("enabled", True), **v}
                    for k, v in items.items()
                ]
        except (json.JSONDecodeError, OSError):
            pass
        return []

    def health_check(self) -> dict[str, Any]:
        try:
            with self._get_connection() as conn:
                conn.execute("SELECT 1")
            return {"ok": True, "sqlite": True, "redis": False}
        except Exception as exc:
            return {"ok": False, "sqlite": str(exc), "redis": False}

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None


# =============================================================================
# Factory Function
# =============================================================================

_db_store_cache: dict[str, DBStoreInterface] = {}
_db_store_lock = threading.Lock()


def _normalize_store_mode(mode: str | None) -> str:
    normalized = (mode or "").strip().lower()
    return normalized or "native"


def _store_cache_key(connection_string: str | None, config: DBConfig | None, store_mode: str | None) -> str:
    normalized_mode = _normalize_store_mode(store_mode)
    if connection_string:
        return f"{normalized_mode}:{connection_string}"
    if not config:
        return f"{normalized_mode}:sqlite:///output/audit/audit.db"
    if config.db_type == "postgresql":
        return (
            f"{normalized_mode}:postgresql://{config.username}:{config.password}@"
            f"{config.host}:{config.port}/{config.database}"
        )
    return f"{normalized_mode}:sqlite:///{config.sqlite_path or Path('output/audit/audit.db')}"


def get_db_store(
    connection_string: str | None = None,
    config: DBConfig | None = None,
    *,
    mode: str | None = None,
) -> DBStoreInterface:
    """
    Get or create the database store instance.

    Args:
        connection_string: PostgreSQL connection string (postgresql://user:pass@host:port/dbname)
                         or "sqlite:///path/to/db" for SQLite
        config: DBConfig object (alternative to connection_string)

    Returns:
        DBStoreInterface implementation

    Example:
        # PostgreSQL
        db = get_db_store("postgresql://user:pass@localhost:5432/openclaw_guard")

        # SQLite
        db = get_db_store("sqlite:///path/to/output/audit/audit.db")

        # SQLAlchemy
        db = get_db_store("sqlite:///path/to/output/audit/audit.db", mode="sqlalchemy")

        # With config
        config = DBConfig(db_type="postgresql", host="localhost", database="openclaw_guard",
                         username="user", password="pass")
        db = get_db_store(config=config)
    """
    cache_key = _store_cache_key(connection_string, config, mode)
    cached = _db_store_cache.get(cache_key)
    if cached is not None:
        return cached

    with _db_store_lock:
        cached = _db_store_cache.get(cache_key)
        if cached is not None:
            return cached

        if config is None:
            config = _parse_connection_string(connection_string or "sqlite:///output/audit/audit.db")

        normalized_mode = _normalize_store_mode(mode)
        if normalized_mode == "sqlalchemy":
            if not SQLALCHEMY_AVAILABLE:
                raise ImportError(
                    "sqlalchemy is required for SQLAlchemyStore. Install with: pip install sqlalchemy"
                )
            if connection_string:
                db_url = connection_string
            elif config.db_type == "postgresql":
                db_url = config.get_postgresql_dsn()
            else:
                db_url = f"sqlite:///{config.sqlite_path or Path('output/audit/audit.db')}"
            store = SQLAlchemyStore(db_url)
        elif config.db_type == "postgresql":
            store = PostgreSQLStore(config)
        else:
            store = SQLiteStore(config.sqlite_path or Path("output/audit/audit.db"))

        cache_key = _store_cache_key(connection_string, config, mode)
        _db_store_cache[cache_key] = store
        return store


def _parse_connection_string(connection_string: str) -> DBConfig:
    """Parse connection string into DBConfig"""
    if connection_string.startswith("postgresql"):
        # Parse postgresql://user:pass@host:port/dbname
        import urllib.parse

        parsed = urllib.parse.urlparse(connection_string)
        return DBConfig(
            db_type="postgresql",
            username=parsed.username or "",
            password=parsed.password or "",
            host=parsed.hostname or "localhost",
            port=parsed.port or 5432,
            database=parsed.path.lstrip("/") or "openclaw_guard",
        )
    elif connection_string.startswith("sqlite"):
        # Parse sqlite:///path/to/db
        path = connection_string.replace("sqlite:///", "")
        return DBConfig(
            db_type="sqlite",
            sqlite_path=Path(path),
        )
    else:
        # Default to SQLite
        return DBConfig(
            db_type="sqlite",
            sqlite_path=Path("output/audit/audit.db"),
        )


def reset_db_store() -> None:
    """Reset the global database store (for testing or reconfiguration)"""
    with _db_store_lock:
        for store in _db_store_cache.values():
            store.close()
        _db_store_cache.clear()
