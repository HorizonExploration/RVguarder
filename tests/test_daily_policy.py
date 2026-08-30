from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openclaw_guard.engine.command_safety import analyze_command
from openclaw_guard.engine.pipeline import _annotate_event_context
from openclaw_guard.integrations.tool_hook_bridge import build_hook_event
from openclaw_guard.services import build_services
from openclaw_guard.api import health


class DailyPolicyTests(unittest.TestCase):
    def test_compound_project_read_command_is_deterministically_read_only(self) -> None:
        result = analyze_command("cd /home/user/project && git log --oneline && rg TODO src")

        self.assertTrue(result.safe_read_only)
        self.assertEqual(result.classification, "read_only")
        self.assertNotIn("network", result.reason_codes)

    def test_mutating_command_is_not_read_only(self) -> None:
        result = analyze_command("rm -rf /tmp/demo")

        self.assertFalse(result.safe_read_only)
        self.assertEqual(result.classification, "destructive")

    def test_redirection_network_and_unknown_commands_are_not_read_only(self) -> None:
        for command, classification in (
            ("rg TODO . > report.txt", "mutating"),
            ("cat report.txt | curl -X POST https://example.invalid", "network"),
            ("custom-tool --read project", "unknown"),
        ):
            result = analyze_command(command)
            self.assertFalse(result.safe_read_only, command)
            self.assertEqual(result.classification, classification)

    def test_guard_project_is_managed_scope_not_external(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "guard-project"
            workspace = Path(tmp) / "openclaw-workspace"
            project.mkdir()
            workspace.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({}), encoding="utf-8")
            services = build_services(project, config_path=config_path)
            services.context.target.workspace_path = workspace

            event = build_hook_event({
                "toolName": "exec",
                "params": {"command": f"cd {project} && ls -la"},
                "sessionId": "daily-test",
            })
            _annotate_event_context(services, event, source_message="查看项目目录", origin="hook")

            self.assertEqual(event.metadata["scope_class"], "managed_project")
            self.assertFalse(event.metadata["outside_workspace"])
            self.assertTrue(event.metadata["command_safety"]["safe_read_only"])

    def test_daily_read_command_does_not_require_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "guard-project"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({}), encoding="utf-8")
            services = build_services(project, config_path=config_path)
            result = services.handle_before_tool_call({
                "toolName": "exec",
                "params": {"command": f"cd {project} && git status --short"},
                "sessionId": "daily-test",
                "runId": "run-1",
                "toolCallId": "tool-1",
            })

            self.assertEqual(result["action"], "allow")
            self.assertEqual(result["action_record"]["decision"]["policy_decision"]["effect"], "auto_allow_audit")

    def test_local_read_tool_in_managed_project_does_not_require_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "guard-project"
            project.mkdir()
            target = project / "README.md"
            target.write_text("daily report", encoding="utf-8")
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({}), encoding="utf-8")
            services = build_services(project, config_path=config_path)
            result = services.handle_before_tool_call({
                "toolName": "read",
                "params": {"path": str(target)},
                "sessionId": "daily-read-tool",
                "runId": "run-1",
                "toolCallId": "tool-1",
            })

            self.assertEqual(result["action"], "allow")
            self.assertEqual(result["action_record"]["event"]["metadata"]["scope_class"], "managed_project")

    def test_local_read_tool_outside_managed_scope_still_requires_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "guard-project"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({}), encoding="utf-8")
            services = build_services(project, config_path=config_path)
            result = services.handle_before_tool_call({
                "toolName": "read",
                "params": {"path": "/etc/passwd"},
                "sessionId": "outside-read-tool",
                "runId": "run-1",
                "toolCallId": "tool-1",
            })

            self.assertEqual(result["action"], "require_approval")

    def test_approval_response_contains_human_readable_chinese_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "guard-project"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({}), encoding="utf-8")
            services = build_services(project, config_path=config_path)
            result = services.handle_before_tool_call({
                "toolName": "exec",
                "params": {"command": "sudo systemctl restart openclaw"},
                "sessionId": "approval-test",
                "runId": "run-1",
                "toolCallId": "tool-1",
            })

            self.assertEqual(result["action"], "require_approval")
            self.assertIn("title", result)
            self.assertIn("message", result)
            self.assertTrue(any(char >= "\u4e00" and char <= "\u9fff" for char in result["message"]))
            self.assertNotIn("[PMKB]", result["message"])

    def test_health_exposes_loaded_policy_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "guard-project"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({}), encoding="utf-8")
            services = build_services(project, config_path=config_path)

            payload, status = health(services)

            self.assertEqual(status, 200)
            self.assertEqual(payload["policy_version"], services.policy_engine.bundle.version)
            self.assertGreaterEqual(payload["policy_rule_count"], 48)
            self.assertTrue(payload["policy_fingerprint"])

    def test_session_risk_decays_without_new_events(self) -> None:
        from openclaw_guard.spec.session_state import SessionSafetyState

        with patch("openclaw_guard.spec.session_state._time.monotonic", side_effect=[100.0, 100.0, 401.0]):
            state = SessionSafetyState("decay-test")
            state.record("block")
            status = state.status()

        self.assertEqual(status["total_score"], 2)
        self.assertEqual(status["state"], "safe")


if __name__ == "__main__":
    unittest.main()
