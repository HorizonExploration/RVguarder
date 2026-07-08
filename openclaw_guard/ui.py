"""
内嵌式前端薄层：仅负责确保 runtime/ui/ 目录存在。
实际前端资源由前端工程 frontend/ 构建产出（pnpm build → runtime/ui/），
或直接手动放置静态文件。

web.py 负责托管 runtime/ui/ 目录下的 index.html / app.js / styles.css。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def build_ui(target_dir: Path, summary: dict[str, Any] | None = None) -> None:
    """确保前端静态资源目录存在。

    前端文件不再由 Python 生成，而是由独立前端工程构建。
    如果目录为空，web.py 会返回 404，此时运行 fnm build 即可。
    """
    target_dir.mkdir(parents=True, exist_ok=True)
