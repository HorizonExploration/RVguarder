from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from openclaw_guard.storage.db_store import SQLALCHEMY_AVAILABLE, get_db_store, reset_db_store


class SQLAlchemyStoreDependencyTests(unittest.TestCase):
    def tearDown(self) -> None:
        reset_db_store()

    def test_missing_sqlalchemy_dep_raises_readable_error(self) -> None:
        with patch("openclaw_guard.storage.db_store.SQLALCHEMY_AVAILABLE", False):
            with self.assertRaises(ImportError) as ctx:
                get_db_store("sqlite:///output/audit/audit.db", mode="sqlalchemy")
        self.assertIn("sqlalchemy", str(ctx.exception).lower())

    def test_missing_sqlalchemy_dep_does_not_break_native_default(self) -> None:
        with patch("openclaw_guard.storage.db_store.SQLALCHEMY_AVAILABLE", False):
            store = get_db_store("sqlite:///output/audit/audit.db")
        self.assertEqual(store.__class__.__name__, "SQLiteStore")


@unittest.skipUnless(SQLALCHEMY_AVAILABLE, "sqlalchemy not installed")
class SQLAlchemyStoreSQLiteTests(unittest.TestCase):
    def tearDown(self) -> None:
        reset_db_store()

    def test_sqlalchemy_store_sqlite_append_query_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "audit.db"
            store = get_db_store(f"sqlite:///{db_path}", mode="sqlalchemy")
            store.append_audit_record("t1", {"a": 1})
            store.append_audit_record("t2", {"b": 2})
            items = store.query_audit_records(limit=10)
            self.assertEqual(len(items), 2)
            self.assertEqual({item["record_type"] for item in items}, {"t1", "t2"})
            self.assertTrue(store.verify_audit_chain()["ok"])

    def test_sqlalchemy_store_reads_legacy_sqlite_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "audit.db"
            native = get_db_store(f"sqlite:///{db_path}")
            native.append_audit_record("legacy", {"k": "v"})

            sqlalchemy_store = get_db_store(f"sqlite:///{db_path}", mode="sqlalchemy")
            items = sqlalchemy_store.query_audit_records(limit=10)
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["record_type"], "legacy")
            self.assertEqual(json.dumps(items[0]["payload"], ensure_ascii=False, sort_keys=True), json.dumps({"k": "v"}, ensure_ascii=False, sort_keys=True))

    def test_sqlalchemy_store_query_filters_since_limit_offset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "audit.db"
            store = get_db_store(f"sqlite:///{db_path}", mode="sqlalchemy")

            t0 = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
            with patch(
                "openclaw_guard.storage.db_store.datetime",
                now=patch.DEFAULT,
            ) as dt:
                dt.now.side_effect = [t0, t0 + timedelta(seconds=1), t0 + timedelta(seconds=2)]
                store.append_audit_record("t", {"i": 0})
                store.append_audit_record("t", {"i": 1})
                store.append_audit_record("t", {"i": 2})

            items_all = store.query_audit_records(record_type="t", limit=10)
            self.assertEqual([item["payload"]["i"] for item in items_all], [2, 1, 0])

            items_since = store.query_audit_records(record_type="t", limit=10, since=t0 + timedelta(seconds=1))
            self.assertEqual([item["payload"]["i"] for item in items_since], [2, 1])

            items_offset = store.query_audit_records(record_type="t", limit=1, offset=1)
            self.assertEqual([item["payload"]["i"] for item in items_offset], [1])

    def test_sqlalchemy_store_verify_chain_detects_tamper(self) -> None:
        import sqlite3

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "audit.db"
            store = get_db_store(f"sqlite:///{db_path}", mode="sqlalchemy")

            with patch(
                "openclaw_guard.storage.db_store.datetime",
                now=patch.DEFAULT,
            ) as dt:
                t0 = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
                dt.now.side_effect = [t0, t0 + timedelta(seconds=1)]
                r1 = store.append_audit_record("t", {"i": 0})
                store.append_audit_record("t", {"i": 1})

            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    "UPDATE audit_log SET payload_json = ? WHERE record_id = ?",
                    (json.dumps({"i": 999}, ensure_ascii=False, sort_keys=True), r1["record_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            result = store.verify_audit_chain()
            self.assertFalse(result["ok"])
            self.assertIn(r1["record_id"], result["broken_records"])

    def test_sqlalchemy_store_actions_crud_and_list_filtering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "audit.db"
            store = get_db_store(f"sqlite:///{db_path}", mode="sqlalchemy")

            self.assertFalse(store.save_action({"status": "pending_approval"}))

            t0 = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
            with patch(
                "openclaw_guard.storage.db_store.datetime",
                now=patch.DEFAULT,
            ) as dt:
                dt.now.side_effect = [t0, t0 + timedelta(seconds=1)]
                self.assertTrue(store.save_action({"action_id": "a1", "status": "pending_approval"}))
                self.assertTrue(store.save_action({"action_id": "a2", "status": "approved"}))

            self.assertEqual(store.get_action("a1")["action_id"], "a1")

            items = store.list_actions(limit=10)
            self.assertEqual([item["action_id"] for item in items], ["a2", "a1"])

            pending = store.list_actions(status="pending_approval", limit=10)
            self.assertEqual([item["action_id"] for item in pending], ["a1"])

    def test_sqlalchemy_store_runtime_logs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "audit.db"
            store = get_db_store(f"sqlite:///{db_path}", mode="sqlalchemy")

            t0 = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
            with patch(
                "openclaw_guard.storage.db_store.datetime",
                now=patch.DEFAULT,
            ) as dt:
                dt.now.side_effect = [t0, t0 + timedelta(seconds=1)]
                self.assertTrue(store.append_runtime_log("e1", "p1", x=1))
                self.assertTrue(store.append_runtime_log("e2", "p2", y=2))

            items = store.get_recent_logs(limit=10)
            self.assertEqual(items[0]["event"], "e2")
            self.assertEqual(items[1]["event"], "e1")
            self.assertEqual(items[0]["payload"]["y"], 2)

    def test_sqlalchemy_store_skills_channels_crud(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "audit.db"
            store = get_db_store(f"sqlite:///{db_path}", mode="sqlalchemy")

            self.assertTrue(store.upsert_skill("s1", {"enabled": True, "description": "d"}))
            self.assertTrue(store.upsert_channel("c1", {"enabled": True, "target": "t"}))

            skills = store.list_skills()
            self.assertEqual([item["name"] for item in skills], ["s1"])
            self.assertTrue(skills[0]["enabled"])

            channels = store.list_channels()
            self.assertEqual([item["name"] for item in channels], ["c1"])

            self.assertTrue(store.delete_skill("s1"))
            self.assertTrue(store.delete_channel("c1"))
            self.assertEqual(store.list_skills(), [])
            self.assertEqual(store.list_channels(), [])

    def test_sqlalchemy_store_health_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "audit.db"
            store = get_db_store(f"sqlite:///{db_path}", mode="sqlalchemy")
            result = store.health_check()
            self.assertTrue(result["ok"])
            self.assertTrue(result["sqlalchemy"])
