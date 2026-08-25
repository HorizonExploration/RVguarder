"""本地权限攻击研究夹具。

夹具只读取版本化 JSON 并返回字典，不执行 shell、网络、邮件或真实凭据操作。
后续权限知识库和 RV 升级可以直接消费这些规范化事件。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SCENARIOS_PATH = Path(__file__).with_name("scenarios.json")


def load_scenarios(path: Path = SCENARIOS_PATH) -> list[dict[str, Any]]:
    """加载研究场景并执行最小结构检查。"""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("research scenarios must be a list")
    for scenario in payload:
        if not isinstance(scenario, dict):
            raise ValueError("research scenario must be an object")
        if not scenario.get("scenario_id") or not scenario.get("events") or not scenario.get("invariants"):
            raise ValueError("research scenario requires id, events and invariants")
    return payload


def scenario_ids(path: Path = SCENARIOS_PATH) -> list[str]:
    """返回稳定排序的场景 ID。"""
    return [str(item["scenario_id"]) for item in load_scenarios(path)]
