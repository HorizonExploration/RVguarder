"""将公开Vite构建产物加入wheel；不复制整个runtime目录。"""
from pathlib import Path
import runpy

from setuptools import setup
from setuptools.command.build_py import build_py

stage_ui_assets = runpy.run_path(str(Path(__file__).parent / "openclaw_guard" / "ui_assets.py"))["stage_ui_assets"]


class BuildWithUI(build_py):
    """后端发布构建要求完整前端，避免安装后工作台404。"""

    def run(self):
        super().run()
        stage_ui_assets(Path(__file__).parent / "runtime" / "ui",
                        Path(self.build_lib) / "openclaw_guard" / "static_ui")


setup(cmdclass={"build_py": BuildWithUI})
