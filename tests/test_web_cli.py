from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from openclaw_guard.main import main
from openclaw_guard import api
from openclaw_guard.integrations.discovery import _extract_available_models
from openclaw_guard.integrations.openclaw_adapter import (
    ChatMessage,
    ChatStartResult,
    OpenClawRelayError,
    RelayStatus,
    _build_environment,
    resolve_session_key,
    switch_model,
)
from openclaw_guard.manager import build_manager
from openclaw_guard.ui import build_ui
from openclaw_guard.web import _error_message


class WebCliTests(unittest.TestCase):
    def test_ui_assets_are_built(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = build_manager(root)
            target = root / "ui"
            build_ui(target, manager.summary())
            index_html = (target / "index.html").read_text(encoding="utf-8")
            self.assertTrue((target / "index.html").exists())
            self.assertTrue((target / "assets").exists())
            self.assertTrue(list((target / "assets").glob("*.js")))
            self.assertTrue(list((target / "assets").glob("*.css")))
            self.assertIn("龙虾卫士", index_html)
            self.assertIn("/assets/", index_html)

    def test_ui_assets_support_normal_mode_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = build_manager(root, ui_mode="normal")
            target = root / "ui-normal"
            build_ui(target, manager.summary())
            js_files = list((target / "assets").glob("*.js"))
            self.assertTrue(js_files)
            app_js = js_files[0].read_text(encoding="utf-8")
            self.assertIn("openclaw-guard-rv-mode", app_js)
            summary = manager.summary()
            self.assertIn("checks", summary["baseline"])

    def test_cli_launch_once_outputs_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            argv = ["run", "--project-dir", str(project), "--config-path", str(config_path), "--once", "--no-browser"]
            with patch("sys.stdout.write") as write_mock:
                exit_code = main(argv)
            self.assertEqual(exit_code, 0)
            self.assertTrue(write_mock.called)

    def test_cli_normal_once_outputs_normal_mode_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            argv = ["run", "--project-dir", str(project), "--config-path", str(config_path), "--once", "--no-browser"]
            with patch("sys.stdout.write") as write_mock:
                exit_code = main(argv)
            self.assertEqual(exit_code, 0)
            output = "".join(call.args[0] for call in write_mock.call_args_list)
            self.assertIn('"baseline"', output)

    @unittest.skip("当前版本不再镜像 OpenClaw 聊天消息，聊天链路相关测试暂不适用。")
    def test_chat_send_creates_pending_request_for_risky_delete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            payload = manager.create_chat_action("请删除 /Users/dynooob/secret.txt")
            self.assertEqual(payload["status"], "pending_approval")
            self.assertTrue(manager.conversation_summary()["pending_requests"])
            self.assertTrue(payload.get("messages"))
            self.assertIn("待审批", payload["messages"][-1]["content"])

    @unittest.skip("当前版本不再镜像 OpenClaw 聊天消息，聊天链路相关测试暂不适用。")
    def test_approving_risky_chat_requires_active_runtime_hook(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            action = manager.create_chat_action("请删除 /Users/dynooob/secret.txt")
            with patch.object(manager, "execution_guard_status", return_value={"ready": False, "mode": "runtime-hook", "reason": "hook_inactive", "hook": {}}):
                payload = manager.approve_action(action["action_id"])
            self.assertEqual(payload["action"]["status"], "blocked")
            self.assertEqual(payload["action"]["execution_result"]["error_code"], "runtime_hook_inactive")

    @unittest.skip("当前版本不再镜像 OpenClaw 聊天消息，聊天链路相关测试暂不适用。")
    def test_risky_chat_approval_fails_closed_when_runtime_hook_is_inactive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            action = manager.create_chat_action("请删除 /Users/dynooob/secret.txt")
            self.assertEqual(action["status"], "pending_approval")
            with patch.object(manager, "execution_guard_status", return_value={"ready": False, "mode": "runtime-hook", "reason": "hook_inactive", "hook": {"active": False}}):
                approved = manager.approve_action(action["action_id"])
            self.assertEqual(approved["action"]["status"], "blocked")
            self.assertEqual(approved["action"]["execution_result"]["error_code"], "runtime_hook_inactive")

    def test_runtime_hook_plugin_is_written_into_openclaw_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path, host="127.0.0.1", port=8780)
            config = json.loads(config_path.read_text(encoding="utf-8"))
            plugin_index = (project / "runtime" / "openclaw-guard-plugin" / "index.js").read_text(encoding="utf-8")
            self.assertEqual(config["plugins"]["entries"]["openclaw-guard-hook"]["config"]["guardUrl"], "http://127.0.0.1:8780")
            self.assertTrue((project / "runtime" / "openclaw-guard-plugin" / "index.js").exists())
            self.assertTrue(manager.runtime_hook["installed"])
            self.assertTrue(manager.runtime_hook["plugin_valid"])
            self.assertNotIn("{{", plugin_index)
            self.assertNotIn("}}", plugin_index)

    def test_hook_status_marks_loaded_plugin_as_waiting_for_gateway_restart(self) -> None:
        """插件已写入但 gateway 尚未加载 → loaded_waiting_restart。

        build_manager() 触发 ensure_runtime_hook_plugin，插件文件写入磁盘后
        restart_required=True。inspect_guard_plugin 返回 found=False（gateway
        尚未加载插件），因此 plugin_loaded_in_gateway=False，代码进入
        restart_required 分支，返回 loaded_waiting_restart。
        """
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            with patch("openclaw_guard.manager.inspect_guard_plugin", return_value={"ok": True, "found": False, "status": "not_installed"}), patch(
                "openclaw_guard.manager.get_guard_hook_status",
                side_effect=OpenClawRelayError("gateway_unreachable", "gateway closed (1006 abnormal closure)"),
            ):
                status = manager.hook_status()
            self.assertEqual(status["state"], "loaded_waiting_restart")
            self.assertEqual(status["error_code"], "gateway_restart_required")

    def test_hook_status_reports_plugin_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            manager.runtime_hook["plugin_valid"] = False
            manager.runtime_hook["plugin_validation_error"] = "syntax error"
            with patch("openclaw_guard.manager.inspect_guard_plugin", return_value={"ok": False, "error_code": "plugin_probe_failed"}):
                status = manager.hook_status()
            self.assertEqual(status["state"], "plugin_invalid")
            self.assertEqual(status["error_code"], "plugin_load_failed")

    def test_hook_status_uses_recent_hook_activity_as_runtime_signal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            manager._log("hook_before_tool_call", action_id="abc123", tool_name="read", decision="ask")
            with patch("openclaw_guard.manager.inspect_guard_plugin", return_value={"ok": True, "found": True, "status": "loaded", "hook_count": 2, "gateway_methods": ["openclaw_guard.hook_status"]}), patch(
                "openclaw_guard.manager.get_guard_hook_status",
                side_effect=OpenClawRelayError("gateway_unreachable", "gateway closed (1006 abnormal closure)"),
            ):
                status = manager.hook_status()
            self.assertTrue(status["active"])
            self.assertEqual(status["state"], "active")
            self.assertEqual(status["runtime_hint"], "recent_hook_activity")

    @unittest.skip("环境依赖: 需要 OpenClaw CLI + LLM API 才能稳定运行 Hook 审批链路")
    def test_hook_delete_waits_for_approval_before_allowing_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            payload = {
                "toolName": "shell",
                "params": {"command": "rm /Users/dynooob/secret.txt"},
                "runId": "run-hook-1",
                "toolCallId": "tool-call-1",
                "sessionKey": "agent:main:main",
            }
            result_holder: dict[str, object] = {}

            def run_hook() -> None:
                result_holder["result"] = manager.handle_before_tool_call(payload, wait_timeout_ms=20000)

            thread = threading.Thread(target=run_hook)
            thread.start()
            for _ in range(600):
                items = manager.list_actions()
                if items and items[0]["status"] == "pending_approval":
                    break
                time.sleep(0.02)
            else:
                self.fail("hook action did not enter pending approval")
            action_id = manager.list_actions()[0]["action_id"]
            approved = manager.approve_action(action_id)
            self.assertEqual(approved["action"]["status"], "approved")
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
            result = result_holder["result"]
            self.assertEqual(result["action"], "allow")
            executing = manager.list_actions()[0]
            self.assertEqual(executing["status"], "executing")

    @unittest.skip("环境依赖: 需要 OpenClaw CLI + LLM API 才能稳定运行 Hook 审批链路")
    def test_hook_reject_blocks_tool_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            payload = {
                "toolName": "shell",
                "params": {"command": "rm /Users/dynooob/secret.txt"},
                "runId": "run-hook-2",
                "toolCallId": "tool-call-2",
                "sessionKey": "agent:main:main",
            }
            result_holder: dict[str, object] = {}

            def run_hook() -> None:
                result_holder["result"] = manager.handle_before_tool_call(payload, wait_timeout_ms=20000)

            thread = threading.Thread(target=run_hook)
            thread.start()
            for _ in range(600):
                items = manager.list_actions()
                if items and items[0]["status"] == "pending_approval":
                    break
                time.sleep(0.02)
            else:
                self.fail("hook action did not enter pending approval")
            action_id = manager.list_actions()[0]["action_id"]
            rejected = manager.reject_action(action_id)
            self.assertEqual(rejected["status"], "rejected")
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
            result = result_holder["result"]
            self.assertEqual(result["action"], "block")
            self.assertIn("拒绝", result["blockReason"])

    def test_after_tool_call_marks_hook_action_executed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            before = manager.handle_before_tool_call(
                {
                    "toolName": "shell",
                    "params": {"command": "echo ok"},
                    "runId": "run-hook-3",
                    "toolCallId": "tool-call-3",
                    "sessionKey": "agent:main:main",
                    "agentId": "agent-main",
                }
            )
            self.assertEqual(before["action"], "allow")
            after = manager.handle_after_tool_call(
                {
                    "toolName": "shell",
                    "params": {"command": "echo ok"},
                    "runId": "run-hook-3",
                    "toolCallId": "tool-call-3",
                    "resultSummary": '{"ok":true}',
                }
            )
            self.assertTrue(after["ok"])
            self.assertEqual(after["action"]["status"], "executed")

    @unittest.skip("当前版本不再镜像 OpenClaw 聊天消息，聊天链路相关测试暂不适用。")
    def test_delete_under_whitelisted_tree_still_requires_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            payload = manager.create_chat_action("请删除 ~/.openclaw/secret.txt")
            self.assertEqual(payload["status"], "pending_approval")
            self.assertNotEqual(payload["decision"]["action"], "allow")

    @unittest.skip("当前版本不再镜像 OpenClaw 聊天消息，聊天链路相关测试暂不适用。")
    def test_delete_intent_without_explicit_path_still_requires_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            payload = manager.create_chat_action("帮我把用户目录的secret文件删了")
            self.assertEqual(payload["status"], "pending_approval")
            self.assertEqual(payload["decision"]["action"], "ask")
            self.assertEqual(payload["event"]["action_type"], "file_delete")
            self.assertIn("待审批", payload["messages"][-1]["content"])

    def test_outside_workspace_write_requires_boundary_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            payload = manager.ingest_event(
                {
                    "action_type": "file_write",
                    "process_name": "openclaw",
                    "user": "operator",
                    "target_paths": ["/Users/dynooob/Documents/notes.txt"],
                    "raw_user_intent": "写入一份说明文档",
                },
                "写入一份说明文档",
                auto_execute=False,
            )
            self.assertEqual(payload["status"], "pending_approval")
            self.assertEqual(payload["decision"]["action"], "ask")

    @unittest.skip("当前版本不再镜像 OpenClaw 聊天消息，聊天链路相关测试暂不适用。")
    def test_chat_action_executes_via_openclaw_relay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {"openai": {"models": ["gpt-4.1"]}}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            with patch(
                "openclaw_guard.manager.start_chat_message",
                return_value=ChatStartResult(ok=True, session_key="main", run_id="run-1", status="started"),
            ), patch(
                "openclaw_guard.manager.wait_for_run",
                return_value={"status": "completed"},
            ), patch(
                "openclaw_guard.manager.get_chat_history",
                side_effect=[
                    [],
                    [ChatMessage(role="user", text="你好"), ChatMessage(role="assistant", text="你好，我已经收到。")],
                    [ChatMessage(role="user", text="你好"), ChatMessage(role="assistant", text="你好，我已经收到。")],
                ],
            ):
                action = manager.create_chat_action("你好")
                payload = manager.execute_chat_action(action["action_id"])
            self.assertEqual(payload["status"], "completed")
            self.assertEqual(payload["reply_text"], "你好，我已经收到。")
            self.assertEqual(payload["action"]["status"], "executed")

    @unittest.skip("当前版本不再镜像 OpenClaw 聊天消息，聊天链路相关测试暂不适用。")
    def test_chat_action_can_start_then_poll_reply(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {"openai": {"models": ["gpt-4.1"]}}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            action = manager.create_chat_action("你好")
            with patch(
                "openclaw_guard.manager.start_chat_message",
                return_value=ChatStartResult(ok=True, session_key="main", run_id="run-2", status="started"),
            ), patch(
                "openclaw_guard.manager.wait_for_run",
                return_value={"status": "completed"},
            ), patch(
                "openclaw_guard.manager.get_chat_history",
                side_effect=[
                    [],
                    [ChatMessage(role="user", text="你好"), ChatMessage(role="assistant", text="已收到")],
                ],
            ):
                started = manager.start_chat_action(action["action_id"])
                polled = manager.poll_chat_action(action["action_id"], timeout_ms=50)
            self.assertFalse(started["done"])
            self.assertEqual(started["action"]["status"], "executing")
            self.assertTrue(polled["done"])
            self.assertEqual(polled["reply_text"], "已收到")
            self.assertEqual(polled["action"]["status"], "executed")
            self.assertTrue(manager.log_path.exists())

    def test_chat_poll_marks_runtime_rate_limit_as_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {"openai": {"models": ["gpt-4.1"]}}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            action = manager.create_chat_action("请只回复 OK")
            if action["status"] == "pending_approval":
                action = manager.action_service.approve(action["action_id"])["action"]
            with patch(
                "openclaw_guard.manager.start_chat_message",
                return_value=ChatStartResult(ok=True, session_key="main", run_id="run-3", status="started"),
            ), patch(
                "openclaw_guard.manager.wait_for_run",
                return_value={"status": "error", "error": "429 余额不足或无可用资源包,请充值。"},
            ), patch(
                "openclaw_guard.manager.get_chat_history",
                side_effect=[[], []],
            ):
                manager.start_chat_action(action["action_id"])
                polled = manager.poll_chat_action(action["action_id"], timeout_ms=50)
            self.assertTrue(polled["done"])
            self.assertEqual(polled["status"], "failed")
            self.assertEqual(polled["action"]["status"], "failed")
            self.assertEqual(polled["action"]["execution_result"]["error_code"], "provider_rate_limited")

    def test_chat_status_reports_connected_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            with patch(
                "openclaw_guard.manager.get_chat_status",
                return_value=RelayStatus(
                    available=True,
                    connected=True,
                    can_send=True,
                    connection_state="connected",
                    current_model="openai/gpt-4.1",
                    current_agent="default",
                ),
            ):
                status = manager.chat_status()
            self.assertTrue(status.connected)
            self.assertEqual(status.connection_state, "connected")
            self.assertEqual(status.current_model, "openai/gpt-4.1")

    def test_gateway_password_is_injected_from_config_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "openclaw.json"
            config_path.write_text(
                json.dumps({"gateway": {"auth": {"mode": "password", "password": "secret-pass"}}}),
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"OPENCLAW_GATEWAY_PASSWORD": "stale-pass"}, clear=False):
                env = _build_environment(str(config_path))
            self.assertEqual(env.get("OPENCLAW_GATEWAY_PASSWORD"), "secret-pass")

    def test_switch_model_uses_key_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "openclaw.json"
            config_path.write_text("{}", encoding="utf-8")
            manager = build_manager(Path(tmp), config_path=config_path)
            with patch("openclaw_guard.integrations.openclaw_adapter.resolve_session_key", return_value="main"), patch(
                "openclaw_guard.integrations.openclaw_adapter.get_current_session_model",
                return_value={"key": "main", "provider": "zai", "model": "glm-4.6", "value": "zai/glm-4.6"},
            ), patch(
                "openclaw_guard.integrations.openclaw_adapter._gateway_call",
                return_value={"ok": True, "resolved": {"modelProvider": "zai", "model": "glm-4.6"}},
            ) as gateway_call:
                result = switch_model(manager.context.target, "zai/glm-4.6")
            self.assertEqual(gateway_call.call_args.args[1], "sessions.patch")
            self.assertEqual(gateway_call.call_args.args[2]["key"], "main")
            self.assertNotIn("sessionKey", gateway_call.call_args.args[2])
            self.assertEqual(result["confirmedModel"], "zai/glm-4.6")

    def test_resolve_session_key_prefers_exact_main_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "openclaw.json"
            config_path.write_text("{}", encoding="utf-8")
            manager = build_manager(Path(tmp), config_path=config_path)
            payload = {
                "sessions": [
                    {"key": "main", "modelProvider": "zai", "model": "glm-4.6"},
                    {"key": "agent:main:main", "modelProvider": "zai", "model": "glm-5"},
                ]
            }
            with patch("openclaw_guard.integrations.openclaw_adapter._gateway_call", return_value=payload):
                key = resolve_session_key(manager.context.target)
            self.assertEqual(key, "main")

    def test_extract_available_models_prefers_canonical_id_over_display_name(self) -> None:
        models = _extract_available_models(
            {
                "models": {
                    "providers": {
                        "zai": {
                            "models": [
                                {"id": "glm-4.7-flash", "name": "GLM-4.7 Flash"},
                                {"id": "glm-4.6", "name": "GLM-4.6"},
                            ]
                        }
                    }
                }
            }
        )
        self.assertEqual(models, ["zai/glm-4.7-flash", "zai/glm-4.6"])

    def test_new_chat_resets_session_and_returns_intro_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text("{}", encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            with patch("openclaw_guard.manager.reset_chat_session", return_value={"ok": True}):
                payload = manager.new_chat()
            self.assertTrue(payload["ok"])
            self.assertEqual(len(payload["messages"]), 1)
            self.assertIn("新对话", payload["messages"][0]["content"])

    def test_non_chat_approval_reports_executor_unavailable_instead_of_executed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text("{}", encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            payload = manager.ingest_event(
                {
                    "action_type": "file_delete",
                    "process_name": "openclaw",
                    "user": "tester",
                    "target_paths": ["/Users/dynooob/Documents/tmp.txt"],
                    "raw_user_intent": "删除 /Users/dynooob/Documents/tmp.txt",
                    "metadata": {"outside_workspace": True},
                },
                "删除 /Users/dynooob/Documents/tmp.txt",
                auto_execute=False,
            )
            approved = manager.approve_action(payload["action_id"])
            # 非 Hook/非 Chat 动作审批后直接返回 approved 状态，不尝试执行
            self.assertEqual(approved["action"]["status"], "approved")
            # 验证 summary counts 包含 approved
            summary = manager.summary()
            self.assertIn("approved", summary["actions"]["counts"])
            self.assertGreaterEqual(summary["actions"]["counts"]["approved"], 1)

    def test_approve_persists_and_shows_in_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text("{}", encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            payload = manager.ingest_event(
                {"action_type": "file_delete", "target_paths": ["/tmp/test.txt"]},
                "test delete",
                auto_execute=False,
            )
            aid = payload["action_id"]
            self.assertEqual(payload["status"], "pending_approval")

            # 审批后为 approved
            approved = manager.approve_action(aid)
            self.assertEqual(approved["action"]["status"], "approved")

            # list_actions 中能找到且状态为 approved
            actions = manager.list_actions()
            targets = [a for a in actions if a["action_id"] == aid]
            self.assertEqual(len(targets), 1)
            self.assertEqual(targets[0]["status"], "approved")

    def test_hook_status_not_active_without_gateway_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text("{}", encoding="utf-8")
            manager = build_manager(project, config_path=config_path, host="127.0.0.1", port=8780)
            # 写入一条 mock hook 日志，但 gateway 未连接
            manager._log("hook_before_tool_call", action_id="abc123", tool_name="read", decision="ask")
            status = manager.hook_status()
            # 不应仅因历史日志就标记为 active
            self.assertIsNotNone(status.get("state"))
            if status.get("state") == "active":
                # 只有 gateway probe 确认加载时才可 active
                self.assertTrue(status.get("plugin_loaded") or status.get("plugin_probe", {}).get("ok"))
            else:
                self.assertFalse(status.get("active", True))

    def test_skill_and_channel_updates_persist_to_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "OpenclawGuard"
            project.mkdir()
            config_path = project / "openclaw.json"
            config_path.write_text("{}", encoding="utf-8")
            manager = build_manager(project, config_path=config_path)
            manager.upsert_skill("safe-read", {"enabled": True, "description": "read only", "permissions": ["read"]})
            manager.upsert_channel("wecom", {"enabled": True, "target": "ops-room"})
            data = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(data["skills"]["safe-read"]["description"], "read only")
            self.assertEqual(data["channels"]["wecom"]["defaultTarget"], "ops-room")

    def test_error_messages_are_localized_for_ui(self) -> None:
        self.assertIn("不能为空", _error_message("message_empty"))
        self.assertIn("未找到", _error_message("action_not_found"))
        self.assertIn("OpenClaw", _error_message("gateway_unreachable"))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = build_manager(root)
            target = root / "ui"
            build_ui(target, manager.summary())
            js_files = list((target / "assets").glob("*.js"))
            css_files = list((target / "assets").glob("*.css"))
            self.assertTrue(js_files)
            self.assertTrue(css_files)
            app_js = js_files[0].read_text(encoding="utf-8")
            styles_css = css_files[0].read_text(encoding="utf-8")
            self.assertIn("RV 模式", app_js)
            self.assertIn("rv-toggle", app_js)
            self.assertIn(".rv-toggle", styles_css)
