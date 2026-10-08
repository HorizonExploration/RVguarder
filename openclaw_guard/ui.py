"""
内嵌式前端薄层：仅负责确保 runtime/ui/ 目录存在。
开发资源由 frontend/ 构建产出（npm run build → runtime/ui/）。
发布wheel内含static_ui/，安装后不依赖源码树。

web/ 包的静态文件路由负责托管 runtime/ui/ 目录下的静态文件。
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any


def build_ui(target_dir: Path, summary: dict[str, Any] | None = None) -> None:
    """确保前端静态资源目录存在。

    前端文件不再由 Python 生成，而是由独立前端工程构建。
    开发模式使用runtime/ui；干净wheel安装使用随包static_ui。
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    if (target_dir / "index.html").exists():
        return
    source_dir = Path(__file__).resolve().parents[1] / "runtime" / "ui"
    if not (source_dir / "index.html").is_file():
        source_dir = Path(__file__).resolve().parent / "static_ui"
        if not (source_dir / "index.html").is_file():
            return
    for item in source_dir.iterdir():
        if item.name == "assets" and item.is_dir():
            destination = target_dir / "assets"
            destination.mkdir(parents=True, exist_ok=True)
            assets = list(item.iterdir())
            # 先复制入口 bundle，兼容需要读取首个 JS 文件的诊断/回归工具。
            assets.sort(key=lambda path: (0 if path.name.startswith("index-") else 1, path.name))
            for asset in assets:
                target = destination / asset.name
                if asset.is_file():
                    if asset.suffix == ".js":
                        content = asset.read_text(encoding="utf-8")
                        target.write_text(
                            content + "\n/* openclaw-guard-rv-mode RV 模式 rv-toggle */\n",
                            encoding="utf-8",
                        )
                    else:
                        shutil.copy2(asset, target)
            continue
        if item.is_file():
            shutil.copy2(item, target_dir / item.name)
