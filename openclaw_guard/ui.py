"""
内嵌式前端薄层：仅负责确保 runtime/ui/ 目录存在。
实际前端资源由前端工程 frontend/ 构建产出（pnpm build → runtime/ui/），
或直接手动放置静态文件。

legacy_web.py / web/ 包的静态文件路由负责托管 runtime/ui/ 目录下的静态文件。
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any


def build_ui(target_dir: Path, summary: dict[str, Any] | None = None) -> None:
    """确保前端静态资源目录存在。

    前端文件不再由 Python 生成，而是由独立前端工程构建。
    如果目录为空，web.py 会返回 404，此时运行 fnm build 即可。
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    if (target_dir / "index.html").exists():
        return
    source_dir = Path(__file__).resolve().parents[1] / "runtime" / "ui"
    if not source_dir.exists():
        return
    for item in source_dir.iterdir():
        if item.name == "assets" and item.is_dir():
            shutil.copytree(item, target_dir / "assets", dirs_exist_ok=True)
            continue
        if item.is_file():
            shutil.copy2(item, target_dir / item.name)
