from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openclaw_guard import api
from openclaw_guard.services import build_services
from openclaw_guard.storage.db_store import SQLALCHEMY_AVAILABLE


class StorageRvMatrixIntegrationTests(unittest.TestCase):
    def _build(self, project: Path, *, db_store_mode: str) -> object:
        config_path = project / "openclaw.json"
        config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
        with patch.dict(os.environ, {"OPENCLAW_GUARD_DB_STORE_MODE": db_store_mode}, clear=False):
            return build_services(project, config_path=config_path)

    def _assert_key_apis(self, services: object, *, rule_mode: str) -> None:
        toggle_payload, status = api.rv_toggle(services, {"enabled": True, "rule_mode": rule_mode})
        self.assertEqual(int(status), 200)
        self.assertTrue(toggle_payload["ok"])

        status_payload, status = api.rv_status(services)
        self.assertEqual(int(status), 200)
        self.assertTrue(status_payload["ok"])
        engine = status_payload["engine"]
        self.assertIn(engine.get("rule_mode"), {"fsm", "dsl"})

        summary_payload, status = api.summary(services)
        self.assertEqual(int(status), 200)
        self.assertIn("audit", summary_payload)
        self.assertIn("rv", summary_payload)

        export_payload, status = api.audit_export(services)
        self.assertEqual(int(status), 200)
        self.assertTrue(Path(export_payload["json"]).exists())
        self.assertTrue(Path(export_payload["csv"]).exists())

    def test_native_backend_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            services = self._build(project, db_store_mode="native")

            self.assertEqual(services.audit_store._db.__class__.__name__, "SQLiteStore")

            for mode in ("fsm", "dsl"):
                self._assert_key_apis(services, rule_mode=mode)


@unittest.skipUnless(SQLALCHEMY_AVAILABLE, "sqlalchemy not installed")
class StorageRvMatrixIntegrationSqlalchemyTests(unittest.TestCase):
    def test_sqlalchemy_backend_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            with patch.dict(os.environ, {"OPENCLAW_GUARD_DB_STORE_MODE": "sqlalchemy"}, clear=False):
                services = build_services(project, config_path=config_path)

            self.assertEqual(services.audit_store._db.__class__.__name__, "SQLAlchemyStore")

            for mode in ("fsm", "dsl"):
                toggle_payload, status = api.rv_toggle(services, {"enabled": True, "rule_mode": mode})
                self.assertEqual(int(status), 200)
                self.assertTrue(toggle_payload["ok"])

                summary_payload, status = api.summary(services)
                self.assertEqual(int(status), 200)
                self.assertIn("audit", summary_payload)
                self.assertIn("rv", summary_payload)
