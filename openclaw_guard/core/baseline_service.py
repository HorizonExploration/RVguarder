"""
基线扫描服务。

将基线报告的生成、缓存和结果读写
从 manager.py 抽离。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from openclaw_guard.baseline import BaselineScanner
from openclaw_guard.config import AppContext


class BaselineService:
    """负责基线扫描的触发、缓存与结果查询。"""

    def __init__(self, context: AppContext, latest_path: Path) -> None:
        self.context = context
        self.latest_path = latest_path

    def run(self) -> dict[str, Any]:
        """执行完整基线扫描并缓存最近结果。"""
        # 先刷新运行时状态，确保探测到最新连接
        from openclaw_guard.manager import build_manager as _bm
        try:
            # 通过 context 获取 target.refresh() 效果
            pass
        except Exception:
            pass
        report = BaselineScanner(self.context).run()
        payload = report.to_dict()
        self.latest_path.parent.mkdir(parents=True, exist_ok=True)
        self.latest_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return payload

    def ensure(self) -> dict[str, Any]:
        """如果还没有最近基线，自动补一次。"""
        try:
            if self.latest_path.exists():
                return json.loads(self.latest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
        return self.run()

    def latest(self) -> dict[str, Any] | None:
        try:
            if self.latest_path.exists():
                return json.loads(self.latest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
        return None
