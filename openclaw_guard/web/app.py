"""FastAPI 应用工厂 + launch_web 入口（替代旧 web.py）。

约束：
- workers 固定为 1（manager 持有内存状态：RV 窗口、ActionService 缓存）
- 同步路由端点，FastAPI 在线程池中运行（与旧 ThreadingHTTPServer 行为一致）
- 端口 0 自动分配支持（E2E 依赖）
"""

from __future__ import annotations

import threading
import time
import webbrowser
from typing import Any, TYPE_CHECKING

from fastapi import FastAPI

from openclaw_guard.services import GuardServices
from openclaw_guard.web import errors
from openclaw_guard.web.routes import actions, audit, baseline, events, health, hook, rv, static

if TYPE_CHECKING:
    import uvicorn  # noqa: F401

def create_app(manager: GuardServices) -> FastAPI:
    """创建 FastAPI 应用（依赖注入 manager 到 app.state.manager）。

    路由注册顺序：API 路由先注册，静态 catch-all 最后挂载。
    """
    app = FastAPI(
        title="OpenClaw Guard",
        version=getattr(manager, "__version__", "0.1.0"),
        # 避免 SPA catch-all 遮蔽 /docs 等内置路径
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.manager = manager  # type: ignore[attr-defined]

    # 全局 JSON 异常处理器
    errors.register_exception_handlers(app)

    # API 路由 —— 顺序不重要（路径不重叠）
    app.include_router(health.router)
    app.include_router(baseline.router)
    app.include_router(audit.router)
    app.include_router(rv.router)
    app.include_router(actions.router)
    app.include_router(events.router)
    app.include_router(hook.router)

    # 静态文件 catch-all —— 必须最后注册
    app.include_router(static.router)

    return app


class UvicornServerHandle:
    """适配 uvicorn 到与 ThreadingHTTPServer 兼容的 shutdown/server_close 接口。

    main.py 的 finally 块期望 server.shutdown() + server.server_close() 可用。
    """

    def __init__(self, server: Any, thread: threading.Thread) -> None:
        self._server = server
        self._thread = thread

    def shutdown(self) -> None:
        self._server.should_exit = True
        if self._thread.is_alive():
            self._thread.join(timeout=10)

    def server_close(self) -> None:
        # uvicorn 在 shutdown 时自动关闭套接字，此处为兼容占位
        pass


def launch_web(
    manager: GuardServices,
    host: str,
    port: int,
    *,
    no_browser: bool = False,
) -> tuple[UvicornServerHandle, threading.Thread, str]:
    """启动 FastAPI 服务（同旧 web.launch_web 签名和返回值）。

    Returns:
        (handle, thread, url) — handle 兼容 shutdown()/server_close()。
    """
    from openclaw_guard.ui import build_ui
    try:
        import uvicorn  # type: ignore[import-not-found]
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "FastAPI 模式依赖未安装：缺少 uvicorn。请执行：pip install uvicorn[standard]"
        ) from exc

    # 确保前端构建物存在
    ui_dir = manager.context.paths.runtime_dir / "ui"
    build_ui(ui_dir, manager.summary())

    # uvicorn 配置：单 worker（内存状态安全）、无访问日志、warnings 级别
    config = uvicorn.Config(
        create_app(manager),
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # 等待 server 启动（最长 10s）
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)

    if not server.started:
        raise RuntimeError("uvicorn failed to start within 10 seconds")

    # 解析实际绑定地址（支持 port=0 自动分配）
    actual_host, actual_port = host, port
    try:
        actual_host, actual_port = server.servers[0].sockets[0].getsockname()[:2]  # type: ignore[union-attr]
    except Exception:
        pass

    url = f"http://{actual_host}:{actual_port}/"
    if not no_browser:
        webbrowser.open(url)

    return UvicornServerHandle(server, thread), thread, url
