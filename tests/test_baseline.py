from __future__ import annotations

import json
import shlex
import tempfile
import unittest
from pathlib import Path

from openclaw_guard.manager import build_manager


class BaselineTests(unittest.TestCase):
    def test_baseline_generates_json_html_pdf_and_fix_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            root = project / "target"
            root.mkdir()
            config_path = root / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {"openai": {"baseUrl": "https://api.example.com/v1"}}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            report = manager.run_baseline()
            outputs = report["outputs"]
            self.assertTrue(Path(outputs["json"]).exists())
            self.assertTrue(Path(outputs["html"]).exists())
            self.assertTrue(Path(outputs["pdf"]).exists())
            self.assertTrue(Path(outputs["fix_script"]).exists())
            self.assertIn("checks", report)
            self.assertTrue(report["checks"])

    def test_fix_script_shell_quotes_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            root = project / "target dir"
            root.mkdir()
            config_path = root / "openclaw config.json"
            config_path.write_text("{}", encoding="utf-8")
            config_path.chmod(0o644)
            manager = build_manager(project, config_path=config_path)
            report = manager.run_baseline()
            script = Path(report["outputs"]["fix_script"]).read_text(encoding="utf-8")
            finding = next(item for item in report["findings"] if item["finding_id"] == "BASE-002")
            self.assertIn("chmod 600", script)
            self.assertIn(shlex.quote(finding["evidence"]["path"]), script)

    def test_baseline_does_not_flag_current_gateway_port_as_extra_open_port(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(
                json.dumps({"gateway": {"port": 18789}, "models": {"providers": {}}}),
                encoding="utf-8",
            )
            manager = build_manager(project, config_path=config_path)
            report = manager.run_baseline()
            finding_ids = {item["finding_id"] for item in report["findings"]}
            self.assertNotIn("BASE-004-18789", finding_ids)
