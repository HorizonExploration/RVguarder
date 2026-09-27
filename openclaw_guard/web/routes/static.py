"""SPA 静态文件托管 — 文件服务 + SPA fallback。

注册顺序约束：此 router 必须最后挂载，作为 catch-all。
非 /api/* 的路径均返回 index.html，实现 SPA 客户端路由。
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from openclaw_guard.web.dependencies import get_manager

router = APIRouter(tags=["static"])

_CONTENT_TYPES: dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".mjs": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".svg": "image/svg+xml; charset=utf-8",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
}


def _resolve(ui_dir: Path, path: str) -> Path | None:
    """在 ui_dir 中安全解析请求路径；路径遍历攻击返回 None。"""
    raw = unquote((path or "/").split("?", 1)[0])
    rel = "index.html" if raw in ("", "/") else raw.lstrip("/")
    candidate = (ui_dir / rel).resolve()
    try:
        candidate.relative_to(ui_dir.resolve())
    except (ValueError, OSError):
        return None
    return candidate if candidate.is_file() else None


@router.get("/")
def index(manager=Depends(get_manager)):
    ui_dir = manager.context.paths.runtime_dir / "ui"
    index_path = ui_dir / "index.html"
    if index_path.is_file():
        return FileResponse(index_path)
    # index.html not built yet — return a simple placeholder
    from fastapi.responses import HTMLResponse
    return HTMLResponse("<html><body><h1>RVguarder</h1><p>UI not built.</p></body></html>")


@router.get("/{full_path:path}")
def spa(full_path: str, manager=Depends(get_manager)):
    ui_dir = manager.context.paths.runtime_dir / "ui"
    # API 路径的 404 由 FastAPI 路由匹配自然处理；这里只服务非 API 路径
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="Not found")
    file = _resolve(ui_dir, full_path)
    if file is not None:
        return FileResponse(
            file,
            media_type=_CONTENT_TYPES.get(file.suffix.lower(), "application/octet-stream"),
        )
    # SPA fallback：非 API 未知路径返回 index.html
    return FileResponse(ui_dir / "index.html")
