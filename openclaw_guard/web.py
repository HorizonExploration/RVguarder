from __future__ import annotations

import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from openclaw_guard import api
from openclaw_guard.manager import OpenclawGuardManager


def launch_web(
    manager: OpenclawGuardManager,
    host: str,
    port: int,
    *,
    no_browser: bool = False,
) -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    from openclaw_guard.ui import build_ui

    ui_dir = manager.context.paths.runtime_dir / "ui"
    build_ui(ui_dir, manager.summary())
    class GuardHTTPServer(ThreadingHTTPServer):
        allow_reuse_address = True

    handler = _build_handler(manager, ui_dir)
    server = GuardHTTPServer((host, port), handler)
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
            served = _serve_static(self, self.path, ui_dir)
            if served:
                return

            handler_fn = _GET_ROUTES.get(self.path)
            if handler_fn is None:
                self.send_error(HTTPStatus.NOT_FOUND, "Not found")
                return
            payload, status = handler_fn(manager)
            self._write_json(payload, status)

        def do_POST(self) -> None:
            if self.path.startswith("/api/hook/") and not api.hook_authorized(
                manager, self.headers.get("x-openclaw-guard-token", "")
            ):
                self._write_json(
                    {"error": "hook_unauthorized", "error_code": "hook_unauthorized"},
                    HTTPStatus.UNAUTHORIZED,
                )
                return
            body = api.read_json_body(self._read_body())
            handler_fn = _POST_ROUTES.get(self.path)
            if handler_fn is None:
                self.send_error(HTTPStatus.NOT_FOUND, "Not found")
                return
            try:
                payload, status = handler_fn(manager, body)
            except Exception as exc:  # pragma: no cover - defensive
                code = getattr(exc, "code", "internal_error")
                payload = {"error": str(code), "error_code": str(code), "detail": str(exc)}
                status = HTTPStatus(getattr(exc, "status_code", 500))
            self._write_json(payload, status)

        # ---- base helpers ----

        def log_message(self, format: str, *args) -> None:  # noqa: A002 - 继承签名
            return

        def _read_body(self) -> bytes:
            length = int(self.headers.get("Content-Length", "0"))
            return self.rfile.read(length) if length else b""

        def _write_json(self, payload, status: HTTPStatus) -> None:
            try:
                body = api.dump_response(payload)
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                # 客户端（浏览器）提前关闭了连接，忽略此错误以保持日志清洁
                pass

    return Handler


def _serve_static(handler: BaseHTTPRequestHandler, path: str, ui_dir: Path) -> bool:
    raw_path = unquote((path or "/").split("?", 1)[0])
    if raw_path == "/":
        rel = "index.html"
    else:
        rel = raw_path.lstrip("/")
        if not rel:
            rel = "index.html"

    static_path = (ui_dir / rel).resolve()
    ui_root = ui_dir.resolve()
    try:
        static_path.relative_to(ui_root)
    except Exception:
        handler.send_error(HTTPStatus.NOT_FOUND, "Not found")
        return True

    if not static_path.exists() or not static_path.is_file():
        return False

    suffix = static_path.suffix.lower()
    if suffix in {".html"}:
        content_type = "text/html; charset=utf-8"
    elif suffix in {".js", ".mjs"}:
        content_type = "application/javascript; charset=utf-8"
    elif suffix in {".css"}:
        content_type = "text/css; charset=utf-8"
    elif suffix in {".json"}:
        content_type = "application/json; charset=utf-8"
    elif suffix in {".png"}:
        content_type = "image/png"
    elif suffix in {".jpg", ".jpeg"}:
        content_type = "image/jpeg"
    elif suffix in {".svg"}:
        content_type = "image/svg+xml; charset=utf-8"
    elif suffix in {".woff"}:
        content_type = "font/woff"
    elif suffix in {".woff2"}:
        content_type = "font/woff2"
    else:
        content_type = "application/octet-stream"

    data = static_path.read_bytes()
    handler.send_response(HTTPStatus.OK)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)
    return True


# ---- route maps ----

_GET_ROUTES = {
    "/api/health": api.health,
    "/api/summary": api.summary,
    "/api/baseline/latest": api.baseline_latest,
    "/api/actions": api.list_actions,
    "/api/audit/export": api.audit_export,
    "/api/runtime/refresh": api.refresh_runtime,
    "/api/debug/logs": api.debug_logs,
}

_POST_ROUTES = {
    "/api/baseline/run": api.baseline_run,
    "/api/hook/before-tool-call": api.hook_before_tool_call,
    "/api/hook/after-tool-call": api.hook_after_tool_call,
    "/api/hook/resolve-approval": api.resolve_hook_approval,
    "/api/actions/ingest": api.ingest_event,
    "/api/actions/approve": api.approve_action,
    "/api/actions/reject": api.reject_action,
    "/api/actions/clear": api.clear_actions,
    "/api/audit/export": api.audit_export,
    "/api/skills/upsert": api.skill_upsert,
    "/api/skills/delete": api.skill_delete,
    "/api/channels/upsert": api.channel_upsert,
    "/api/channels/delete": api.channel_delete,
}


def _error_message(code: str) -> str:
    mapping = {
        "message_empty": "输入不能为空。",
        "action_not_found": "未找到对应动作记录。",
        "gateway_unreachable": "无法连接 OpenClaw gateway，请检查 OpenClaw 是否启动。",
        "hook_unauthorized": "Hook 鉴权失败。",
        "internal_error": "服务内部错误。",
    }
    return mapping.get(code, code)
