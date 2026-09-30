"""五臂运行记录的统一 schema 与派生指标（office-attack-chain-v1）。

各臂驱动（``office_driver.run_scenario_b0`` / ``guard_driver.run_scenario_guard``）只负责
产出**原始观测**（Hook 事件、receipts、审批、延迟样本）；本模块把原始观测统一成一个扁平记录，
使 :mod:`testlab.office_chain.report` 可以在同一口径下计算指标。

纪律：

- 记录中同时保留**原始观测**（``events`` / ``receipts`` / 延迟样本数组）与**派生标量**
  （必要步骤数、首次有效阻断步距、审批计数……），派生标量可由原始观测复核重算。
- 决策词表在此收敛为 :data:`DECISIONS`；驱动侧的历史写法（``blocked`` / ``requireApproval``）
  在归一化时映射，SHALL NOT 让同一语义在不同臂上以不同字面量出现。
- 本模块 SHALL NOT 读取 ``scenario["variant"]`` 来推断结论；``variant`` 仅用于分组。
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .artifacts import canonical_json, digest_json

RUN_RECORD_SCHEMA_VERSION = 1

DECISION_ALLOW = "allow"
DECISION_REQUIRE_APPROVAL = "require_approval"
DECISION_BLOCK = "block"
DECISION_DENY = "deny"
DECISION_UNKNOWN = "unknown"

DECISIONS: tuple[str, ...] = (
    DECISION_ALLOW,
    DECISION_REQUIRE_APPROVAL,
    DECISION_BLOCK,
    DECISION_DENY,
    DECISION_UNKNOWN,
)

# 阻断语义：原生侧的历史字面量在此收敛。
_BLOCKING_DECISIONS = frozenset({DECISION_BLOCK, DECISION_DENY})

_DECISION_ALIASES: dict[str, str] = {
    "allow": DECISION_ALLOW,
    "allowed": DECISION_ALLOW,
    "requireapproval": DECISION_REQUIRE_APPROVAL,
    "require_approval": DECISION_REQUIRE_APPROVAL,
    "ask": DECISION_REQUIRE_APPROVAL,
    "block": DECISION_BLOCK,
    "blocked": DECISION_BLOCK,
    "deny": DECISION_DENY,
    "denied": DECISION_DENY,
}


def normalise_decision(value: Any) -> str:
    """把任一驱动侧的决策字面量收敛到 :data:`DECISIONS`。"""

    return _DECISION_ALIASES.get(str(value or "").strip().lower(), DECISION_UNKNOWN)


def _as_float_list(value: Any) -> list[float]:
    if not isinstance(value, (list, tuple)):
        return []
    samples: list[float] = []
    for item in value:
        try:
            samples.append(float(item))
        except (TypeError, ValueError):
            continue
    return samples


def _normalise_events(events: Sequence[Any]) -> list[dict[str, Any]]:
    normalised: list[dict[str, Any]] = []
    for index, raw in enumerate(events, start=1):
        if not isinstance(raw, Mapping):
            continue
        decision = normalise_decision(raw.get("decision"))
        applied = bool(raw.get("applied"))
        # ``decision`` 与 ``applied`` 必须自洽：被阻断的步骤不可能已应用。
        if decision in _BLOCKING_DECISIONS:
            applied = False
        entry: dict[str, Any] = {
            "index": int(raw.get("index") or index),
            "tool_name": str(raw.get("tool_name") or ""),
            "decision": decision,
            "applied": applied,
            "approval": raw.get("approval") if raw.get("approval") is None else str(raw.get("approval")),
            "applied_evidence": str(raw.get("applied_evidence") or "unknown"),
        }
        for key in ("before_hook_latency_ms", "guard_decision_latency_ms"):
            if raw.get(key) is not None:
                try:
                    entry[key] = float(raw[key])
                except (TypeError, ValueError):
                    pass
        normalised.append(entry)
    return normalised


def build_run_record(
    payload: Mapping[str, Any],
    scenario: Mapping[str, Any],
    *,
    arm: str,
    repeat: int = 0,
    approval_policy: str = "",
) -> dict[str, Any]:
    """把一个臂驱动的原始结果归一化为统一运行记录。

    ``payload`` 至少应提供 ``events``；其余字段（``admitted`` / ``attack_goal_achieved`` /
    ``receipts`` / 延迟样本 …）缺失时按"未观测到"处理，绝不以推断填充。
    ``approval_policy`` 是该次运行的审批人格，供审批负担按 arm × persona 分解。
    """

    events = _normalise_events(payload.get("events") or [])
    receipts = [dict(row) for row in (payload.get("receipts") or []) if isinstance(row, Mapping)]

    required_steps_total = len(scenario.get("events") or [])
    applied_required_steps = sum(1 for event in events if event["applied"])
    # ``applied`` 的推断成分必须可见：``hook_dispatch_assumed`` 表示既无收据也无
    # 成功工具名的兜底口径，方向保守（不利于本项目防护成绩），报告须与观测区分。
    assumed_applied_steps = sum(
        1 for event in events if event["applied_evidence"] == "hook_dispatch_assumed"
    )
    hard_blocked_required_steps = sum(
        1 for event in events if event["decision"] in _BLOCKING_DECISIONS
    )
    first_block = next(
        (
            event
            for event in events
            if event["decision"] in _BLOCKING_DECISIONS or not event["applied"]
        ),
        None,
    )

    component_hash = str(payload.get("component_config_hash") or "")
    projection = str(payload.get("config_projection_sha256") or "")

    record: dict[str, Any] = {
        "schema_version": RUN_RECORD_SCHEMA_VERSION,
        "arm": str(arm),
        "scenario_id": str(scenario.get("scenario_id") or payload.get("scenario_id") or ""),
        "family": str(scenario.get("family") or ""),
        "incident_id": str(scenario.get("incident_id") or ""),
        "split": str(scenario.get("split") or ""),
        "variant": str(scenario.get("variant") or ""),
        "repeat": int(repeat),
        "approval_policy": str(approval_policy or payload.get("approval_policy") or ""),
        "admitted": bool(payload.get("admitted")),
        "admission_checks": dict(payload.get("admission_checks") or {}),
        "required_steps_total": required_steps_total,
        "applied_required_steps": applied_required_steps,
        "assumed_applied_steps": assumed_applied_steps,
        "hard_blocked_required_steps": hard_blocked_required_steps,
        "business_task_completed": bool(
            required_steps_total > 0 and applied_required_steps == required_steps_total
        ),
        "attack_goal": scenario.get("attack_goal"),
        "attack_goal_achieved": bool(payload.get("attack_goal_achieved")),
        "first_effective_block_step": first_block["index"] if first_block else None,
        "first_effective_block_latency_ms": (
            first_block.get("guard_decision_latency_ms")
            if first_block and first_block.get("guard_decision_latency_ms") is not None
            else (first_block.get("before_hook_latency_ms") if first_block else None)
        ),
        "approvals_required": sum(
            1
            for event in events
            if event["decision"] == DECISION_REQUIRE_APPROVAL or event["approval"] is not None
        ),
        "hook_calls_eligible": len(events),
        "before_hook_latencies_ms": _as_float_list(payload.get("before_hook_latencies_ms")),
        "guard_decision_latencies_ms": _as_float_list(payload.get("guard_decision_latencies_ms")),
        "tool_categories": [str(item) for item in (payload.get("tool_categories") or [])],
        "external_effect_count": int(payload.get("external_effect_count") or 0),
        "receipts": receipts,
        "events": events,
        "component_config_hash": component_hash,
        "config_projection_sha256": projection,
        "runtime": dict(payload.get("runtime") or {}),
        "notes": [str(note) for note in (payload.get("notes") or [])],
        "error": payload.get("error"),
    }
    return record


def record_digest(record: Mapping[str, Any]) -> str:
    """单一运行记录的规范摘要。"""

    return digest_json(record)


def summarise_records(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """返回原始记录的计数概览，供 CLI 即时回显（SHALL NOT 替代正式指标）。"""

    by_arm: dict[str, int] = {}
    blocked_records = 0
    for record in records:
        arm = str(record.get("arm") or "")
        by_arm[arm] = by_arm.get(arm, 0) + 1
        blocked_records += int(record.get("attack_goal_achieved") is True)
    return {
        "record_count": len(records),
        "records_per_arm": by_arm,
        "attack_goal_achieved_records": blocked_records,
    }


def dump_records(records: Sequence[Mapping[str, Any]]) -> str:
    """把多条运行记录序列化为稳定 JSONL。"""

    return "".join(f"{canonical_json(record)}\n" for record in records)


__all__ = [
    "RUN_RECORD_SCHEMA_VERSION",
    "DECISIONS",
    "DECISION_ALLOW",
    "DECISION_REQUIRE_APPROVAL",
    "DECISION_BLOCK",
    "DECISION_DENY",
    "DECISION_UNKNOWN",
    "normalise_decision",
    "build_run_record",
    "record_digest",
    "summarise_records",
    "dump_records",
]
