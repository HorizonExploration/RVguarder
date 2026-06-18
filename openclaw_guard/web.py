from __future__ import annotations

import json
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from openclaw_guard.manager import OpenclawGuardManager
from openclaw_guard.ui import build_ui
from openclaw_guard.utils import json_dumps


def launch_web(manager: OpenclawGuardManager, host: str, port: int, *, no_browser: bool = False) -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    ui_dir = manager.context.paths.runtime_dir / "ui"
    build_ui(ui_dir, manager.summary())
    handler = _build_handler(manager, ui_dir)
    server = ThreadingHTTPServer((host, port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    actual_host, actual_port = server.server_address
    url = f"http://{actual_host}:{actual_port}/"
    if not no_browser:
        webbrowser.open(url)
    return server, thread, url


def _build_handler(manager: OpenclawGuardManager, ui_dir: Path):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/":
                return self._serve_file(ui_dir / "index.html", "text/html; charset=utf-8")
            if self.path == "/app.js":
                return self._serve_file(ui_dir / "app.js", "application/javascript; charset=utf-8")
            if self.path == "/styles.css":
                return self._serve_file(ui_dir / "styles.css", "text/css; charset=utf-8")
            if self.path == "/api/health":
                return self._write_json(
                    {
                        "ok": True,
                        "product": "openclaw-guard",
                        "ui_mode": manager.context.settings.ui_mode,
                        "profile": manager.context.target.profile,
                        "has_target": bool(manager.context.target.config_path),
                    }
                )
            if self.path == "/api/summary":
                return self._write_json(manager.summary())
            if self.path == "/api/conversation":
                return self._write_json(manager.conversation_summary())
            if self.path == "/api/baseline/latest":
                return self._write_json(manager.ensure_baseline())
            if self.path == "/api/skills":
                return self._write_json(manager.skills_summary())
            if self.path == "/api/channels":
                return self._write_json(manager.channels_summary())
            if self.path == "/api/preferences":
                return self._write_json(manager.preferences())
            if self.path == "/api/chat/status":
                return self._write_json(manager.chat_status().to_dict())
            if self.path == "/api/chat/history":
                return self._write_json({"items": manager.chat_history(), "status": manager.chat_status().to_dict()})
            if self.path == "/api/chat/debug":
                return self._write_json(manager.chat_debug())
            if self.path == "/api/runtime/refresh":
                return self._write_json(manager.refresh_runtime_target())
            if self.path == "/api/debug/logs":
                return self._write_json({"path": str(manager.log_path), "items": manager.recent_logs()})
            if self.path == "/api/actions":
                return self._write_json({"items": manager.list_actions()})
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")

        def do_POST(self) -> None:
            if self.path.startswith("/api/hook/") and not self._guard_hook_authorized():
                return self._write_error("hook_unauthorized", HTTPStatus.UNAUTHORIZED)
            payload = self._read_json()
            if self.path == "/api/baseline/run":
                return self._write_json(manager.run_baseline())
            if self.path == "/api/hook/before-tool-call":
                return self._write_json(manager.handle_before_tool_call(payload))
            if self.path == "/api/hook/after-tool-call":
                return self._write_json(manager.handle_after_tool_call(payload))
            if self.path == "/api/chat/send":
                message = str(payload.get("message") or "").strip()
                if not message:
                    return self._write_error("message_empty", HTTPStatus.BAD_REQUEST)
                action = manager.create_chat_action(message)
                decision = (action.get("decision") or {}).get("action")
                if decision == "block":
                    return self._write_json(
                        {
                            "ok": False,
                            "status": "blocked",
                            "error_code": "action_blocked",
                            "message": _error_message("action_blocked"),
                            "reason": (action.get("decision") or {}).get("reason"),
                            "record": action,
                            "messages": manager.list_messages(),
                        }
                    )
                if decision in {"ask", "escalate"}:
                    return self._write_json(
                        {
                            "ok": False,
                            "status": "pending_confirmation",
                            "error_code": "action_confirmation_required",
                            "message": _error_message("action_confirmation_required"),
                            "reason": (action.get("decision") or {}).get("reason"),
                            "record": action,
                            "messages": manager.list_messages(),
                        }
                    )
                try:
                    result = manager.start_chat_action(str(action.get("action_id") or ""))
                except KeyError:
                    return self._write_error("action_not_found", HTTPStatus.NOT_FOUND)
                except ValueError as exc:
                    return self._write_error(str(exc), HTTPStatus.BAD_REQUEST)
                except Exception as exc:
                    code = getattr(exc, "code", "send_failed")
                    return self._write_error(str(code), HTTPStatus(getattr(exc, "status_code", 503)), getattr(exc, "detail", str(exc)))
                return self._write_json({"ok": True, **result})
            if self.path == "/api/chat/new":
                try:
                    result = manager.new_chat()
                except Exception as exc:
                    code = getattr(exc, "code", "gateway_call_failed")
                    return self._write_error(str(code), HTTPStatus(getattr(exc, "status_code", 503)), getattr(exc, "detail", str(exc)))
                return self._write_json(result)
            if self.path == "/api/chat/poll":
                action_id = str(payload.get("action_id") or "").strip()
                if not action_id:
                    return self._write_error("action_not_found", HTTPStatus.BAD_REQUEST)
                timeout_ms = int(payload.get("timeout_ms") or 1200)
                try:
                    result = manager.poll_chat_action(action_id, timeout_ms=timeout_ms)
                except KeyError:
                    return self._write_error("action_not_found", HTTPStatus.NOT_FOUND)
                except ValueError as exc:
                    return self._write_error(str(exc), HTTPStatus.BAD_REQUEST)
                except Exception as exc:
                    code = getattr(exc, "code", "send_failed")
                    return self._write_error(str(code), HTTPStatus(getattr(exc, "status_code", 503)), getattr(exc, "detail", str(exc)))
                return self._write_json({"ok": True, **result})
            if self.path == "/api/chat/model":
                model = str(payload.get("model") or "").strip()
                if not model:
                    return self._write_error("message_empty", HTTPStatus.BAD_REQUEST)
                try:
                    result = manager.switch_chat_model(model)
                except Exception as exc:
                    code = getattr(exc, "code", "gateway_call_failed")
                    return self._write_error(str(code), HTTPStatus(getattr(exc, "status_code", 503)), getattr(exc, "detail", str(exc)))
                return self._write_json(result)
            if self.path == "/api/skills/save":
                name = str(payload.get("name") or "").strip()
                try:
                    result = manager.upsert_skill(name, payload)
                except FileNotFoundError:
                    return self._write_error("config_not_found", HTTPStatus.BAD_REQUEST)
                except ValueError as exc:
                    return self._write_error(str(exc), HTTPStatus.BAD_REQUEST)
                return self._write_json(result)
            if self.path == "/api/skills/delete":
                name = str(payload.get("name") or "").strip()
                try:
                    result = manager.delete_skill(name)
                except FileNotFoundError:
                    return self._write_error("config_not_found", HTTPStatus.BAD_REQUEST)
                return self._write_json(result)
            if self.path == "/api/channels/save":
                name = str(payload.get("name") or "").strip()
                try:
                    result = manager.upsert_channel(name, payload)
                except FileNotFoundError:
                    return self._write_error("config_not_found", HTTPStatus.BAD_REQUEST)
                except ValueError as exc:
                    return self._write_error(str(exc), HTTPStatus.BAD_REQUEST)
                return self._write_json(result)
            if self.path == "/api/channels/delete":
                name = str(payload.get("name") or "").strip()
                try:
                    result = manager.delete_channel(name)
                except FileNotFoundError:
                    return self._write_error("config_not_found", HTTPStatus.BAD_REQUEST)
                return self._write_json(result)
            if self.path == "/api/preferences/save":
                return self._write_json(manager.save_preferences(payload))
            if self.path == "/api/actions/ingest":
                return self._write_json(manager.ingest_event(payload, str(payload.get("raw_user_intent") or "")))
            if self.path == "/api/actions/approve":
                try:
                    result = manager.approve_action(str(payload.get("action_id") or ""), str(payload.get("confirmation_text") or ""))
                except KeyError:
                    return self._write_error("action_not_found", HTTPStatus.NOT_FOUND)
                except ValueError as exc:
                    return self._write_error(str(exc), HTTPStatus.BAD_REQUEST)
                except Exception as exc:
                    code = getattr(exc, "code", "send_failed")
                    return self._write_error(str(code), HTTPStatus(getattr(exc, "status_code", 503)), getattr(exc, "detail", str(exc)))
                return self._write_json(result)
            if self.path == "/api/actions/reject":
                try:
                    result = manager.reject_action(str(payload.get("action_id") or ""))
                except KeyError:
                    return self._write_error("action_not_found", HTTPStatus.NOT_FOUND)
                except ValueError as exc:
                    return self._write_error(str(exc), HTTPStatus.BAD_REQUEST)
                return self._write_json(result)
            if self.path == "/api/audit/export":
                return self._write_json(manager.export_audit())
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")

        def log_message(self, format: str, *args) -> None:
            return

        def _serve_file(self, path: Path, content_type: str) -> None:
            if not path.exists():
                self.send_error(HTTPStatus.NOT_FOUND, "Missing asset")
                return
            data = path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _read_json(self) -> dict[str, object]:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                return {}
            return payload if isinstance(payload, dict) else {}

        def _write_json(self, payload: dict[str, object], status: HTTPStatus = HTTPStatus.OK) -> None:
            body = json_dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _write_error(self, code: str, status: HTTPStatus, detail: str | None = None) -> None:
            payload = {
                "error": code,
                "error_code": code,
                "message": _error_message(code),
            }
            if detail:
                payload["detail"] = detail
            self._write_json(payload, status)

        def _guard_hook_authorized(self) -> bool:
            token = self.headers.get("x-openclaw-guard-token", "").strip()
            auth_path = manager.runtime_hook.get("auth_token_path")
            if not auth_path:
                return True
            try:
                expected = json.loads(Path(str(auth_path)).read_text(encoding="utf-8")).get("auth_token", "")
            except Exception:
                return False
            return bool(token) and token == expected

    return Handler


def _error_message(code: str) -> str:
    mapping = {
        "message_empty": "消息内容不能为空。",
        "action_not_found": "未找到对应动作记录。",
        "action_not_pending": "该动作当前不在待审批状态。",
        "action_not_ready": "该动作当前不能执行。",
        "confirmation_word_required": "缺少正确的二次确认词。",
        "action_blocked": "这个动作风险过高，已被龙虾卫士拦截。",
        "action_confirmation_required": "这个动作需要你先确认，确认前不会继续执行。",
        "cli_not_found": "没有找到 OpenClaw 入口，请先确认 OpenClaw 已正确安装。",
        "config_not_found": "没有找到 OpenClaw 配置，请检查 openclaw.json 或当前 profile。",
        "gateway_unreachable": "当前无法连接到 OpenClaw 运行时，请先启动 OpenClaw gateway。",
        "hook_unauthorized": "Guard Hook 鉴权失败，当前工具调用未被接受。",
        "gateway_auth_failed": "已经连到 OpenClaw gateway，但鉴权没有通过，请检查 token 或 password。",
        "runtime_not_running": "当前无法确认 OpenClaw 正在运行，请先检查 gateway 状态。",
        "send_failed": "消息发送失败，请稍后重试。",
        "wait_timeout": "消息已经发出，但等待回复超时了，请稍后重试。",
        "history_fetch_failed": "消息已发送，但暂时拿不到会话记录，请稍后刷新。",
        "reply_not_found": "消息已发送，但暂时没有拿到回复内容。",
        "gateway_call_failed": "OpenClaw 调用失败，请检查 gateway 是否正常运行。",
        "gateway_invalid_response": "OpenClaw 返回了无法解析的响应。",
        "runtime_hook_inactive": "Guard Hook 当前未连接到 OpenClaw 真实执行链，危险动作不会继续执行。",
    }
    return mapping.get(code, "请求处理失败，请稍后重试。")
