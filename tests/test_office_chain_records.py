"""测试五臂运行记录 schema、派生标量与编排 CLI 的无副作用入口（Task 7）。

覆盖：

- :func:`records.normalise_decision` 的别名收敛与未知值兜底；
- :func:`records.build_run_record` 的派生标量、阻断事件的 ``applied`` 自洽；
- 派生结果不因 ``scenario["variant"]`` 改变；
- :func:`records.record_digest` / :func:`records.dump_records` 的稳定性；
- ``guard_driver.run_scenario_guard`` 拒绝 ``B0``（不加载 guard）；
- ``run`` CLI 的 ``--dry-run`` / ``--check`` 可无副作用调用。
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from testlab.office_chain import office_driver, run as run_module
from testlab.office_chain.guard_driver import run_scenario_guard
from testlab.office_chain.records import (
    DECISIONS,
    build_run_record,
    dump_records,
    normalise_decision,
    record_digest,
    summarise_records,
)


# --------------------------------------------------------------------------- #
# normalise_decision：别名收敛
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("allow", "allow"),
        ("allowed", "allow"),
        ("ALLOW", "allow"),
        ("requireApproval", "require_approval"),
        ("require_approval", "require_approval"),
        ("ask", "require_approval"),
        ("block", "block"),
        ("blocked", "block"),
        ("BLOCKED", "block"),
        ("deny", "deny"),
        ("denied", "deny"),
        # 未知 / 缺失一律兜底为 unknown，绝不臆测。
        ("", "unknown"),
        ("   ", "unknown"),
        (None, "unknown"),
        ("definitely-not-a-decision", "unknown"),
        (42, "unknown"),
    ],
)
def test_normalise_decision_aliases(raw: Any, expected: str) -> None:
    assert normalise_decision(raw) == expected
    assert expected in DECISIONS


# --------------------------------------------------------------------------- #
# build_run_record：派生标量
# --------------------------------------------------------------------------- #

def _scenario(*, variant: str = "attack") -> dict[str, Any]:
    return {
        "scenario_id": "UNIT-REC-1",
        "family": "data_chain",
        "incident_id": "UNIT-INC",
        "split": "calibration",
        "variant": variant,
        "attack_goal": "unauthorized_packet_sent",
        "events": [
            {"hook_payload": {"toolName": "read"}},
            {"hook_payload": {"toolName": "read"}},
            {"hook_payload": {"toolName": "office_document_share"}},
            {"hook_payload": {"toolName": "office_network_post"}},
        ],
    }


def _payload() -> dict[str, Any]:
    """4 步场景：1 步直接放行、1 步审批后放行、1 步硬阻断、1 步未落地。"""

    return {
        "admitted": True,
        "admission_checks": {
            "agent_run_observed": True,
            "hook_events_observed": True,
            "receipts_present": True,
            "automation_store_matchable": True,
        },
        "attack_goal_achieved": False,
        "receipts": [{"kind": "office_message_send", "external": False}],
        "external_effect_count": 0,
        "before_hook_latencies_ms": [1.0, 2.0, 3.0, 4.0],
        "guard_decision_latencies_ms": [1.5, 2.5, 12.5, 4.5],
        "tool_categories": ["read", "share"],
        "component_config_hash": "abc123",
        "config_projection_sha256": "def456",
        "events": [
            {"index": 1, "tool_name": "read", "decision": "allow", "applied": True},
            {
                "index": 2,
                "tool_name": "read",
                "decision": "requireApproval",
                "applied": True,
                "approval": "allow",
                "guard_decision_latency_ms": 2.5,
            },
            {
                "index": 3,
                "tool_name": "office_document_share",
                "decision": "blocked",
                "applied": False,
                "before_hook_latency_ms": 15.0,
                "guard_decision_latency_ms": 12.5,
            },
            {"index": 4, "tool_name": "office_network_post", "decision": "allow", "applied": False},
        ],
    }


def test_build_run_record_derived_scalars() -> None:
    record = build_run_record(_payload(), _scenario(), arm="Full", repeat=2)

    assert record["arm"] == "Full"
    assert record["scenario_id"] == "UNIT-REC-1"
    assert record["repeat"] == 2
    assert record["admitted"] is True

    assert record["required_steps_total"] == 4
    # 仅前两步真正落地（第 4 步 allow 但 applied=False）。
    assert record["applied_required_steps"] == 2
    assert record["business_task_completed"] is False
    assert record["hard_blocked_required_steps"] == 1

    # 首个"有效阻断"= 首个阻断或未落地步骤，即第 3 步。
    assert record["first_effective_block_step"] == 3
    assert record["first_effective_block_latency_ms"] == pytest.approx(12.5)

    # require_approval 或带 approval 字段的事件计一次。
    assert record["approvals_required"] == 1
    assert record["hook_calls_eligible"] == 4
    assert record["attack_goal_achieved"] is False
    assert record["component_config_hash"] == "abc123"
    assert record["config_projection_sha256"] == "def456"
    assert record["before_hook_latencies_ms"] == [1.0, 2.0, 3.0, 4.0]
    assert record["guard_decision_latencies_ms"] == [1.5, 2.5, 12.5, 4.5]


def test_build_run_record_completed_task() -> None:
    payload = _payload()
    payload["events"] = [
        {"index": 1, "tool_name": "read", "decision": "allow", "applied": True},
        {"index": 2, "tool_name": "write", "decision": "allow", "applied": True},
        {"index": 3, "tool_name": "office_document_share", "decision": "allow", "applied": True},
        {"index": 4, "tool_name": "office_network_post", "decision": "allow", "applied": True},
    ]
    record = build_run_record(payload, _scenario(), arm="B0")
    assert record["applied_required_steps"] == 4
    assert record["business_task_completed"] is True
    assert record["hard_blocked_required_steps"] == 0
    assert record["first_effective_block_step"] is None
    assert record["first_effective_block_latency_ms"] is None


@pytest.mark.parametrize(
    ("raw_decision", "expected"),
    [("block", "block"), ("blocked", "block"), ("deny", "deny"), ("denied", "deny")],
)
def test_blocking_decisions_force_applied_false(raw_decision: str, expected: str) -> None:
    """被阻断/拒绝的步骤哪怕上报 applied=True，也必须收敛为 False。"""

    payload = _payload()
    payload["events"] = [
        {"index": 1, "tool_name": "read", "decision": raw_decision, "applied": True},
    ]
    record = build_run_record(payload, _scenario(), arm="Full")
    assert record["events"][0]["decision"] == expected
    assert record["events"][0]["applied"] is False


def test_applied_evidence_marks_assumed_applications() -> None:
    """兜底口径的 ``applied`` 是推断而非观测，必须可被报告区分。"""

    payload = _payload()
    payload["events"] = [
        {"index": 1, "tool_name": "read", "decision": "allow", "applied": True,
         "applied_evidence": "receipt"},
        {"index": 2, "tool_name": "write", "decision": "allow", "applied": True,
         "applied_evidence": "successful_tools"},
        {"index": 3, "tool_name": "office_network_post", "decision": "allow", "applied": True,
         "applied_evidence": "hook_dispatch_assumed"},
        {"index": 4, "tool_name": "office_message_send", "decision": "allow", "applied": False,
         "applied_evidence": "approval_denied"},
    ]
    record = build_run_record(payload, _scenario(), arm="Full")

    assert record["applied_required_steps"] == 3
    assert record["assumed_applied_steps"] == 1
    assert [event["applied_evidence"] for event in record["events"]] == [
        "receipt", "successful_tools", "hook_dispatch_assumed", "approval_denied",
    ]
    # 缺省（历史记录）不冒充观测来源。
    legacy = build_run_record(_payload(), _scenario(), arm="B0")
    assert legacy["assumed_applied_steps"] == 0
    assert all(event["applied_evidence"] == "unknown" for event in legacy["events"])


def test_derived_scalars_ignore_scenario_variant() -> None:
    """派生标量必须只来自原始观测，不得因 ``variant`` 分组字段改变。"""

    payload = _payload()
    attack = build_run_record(payload, _scenario(variant="attack"), arm="Full")
    benign = build_run_record(payload, _scenario(variant="benign"), arm="Full")

    derived_keys = (
        "required_steps_total",
        "applied_required_steps",
        "hard_blocked_required_steps",
        "business_task_completed",
        "attack_goal_achieved",
        "first_effective_block_step",
        "first_effective_block_latency_ms",
        "approvals_required",
        "hook_calls_eligible",
    )
    for key in derived_keys:
        assert attack[key] == benign[key], key
    # 只有分组字段不同。
    assert attack["variant"] == "attack"
    assert benign["variant"] == "benign"


# --------------------------------------------------------------------------- #
# digest 与 JSONL 稳定性
# --------------------------------------------------------------------------- #

def test_record_digest_is_stable() -> None:
    record = build_run_record(_payload(), _scenario(), arm="Full", repeat=1)
    assert record_digest(record) == record_digest(record)
    assert record_digest(record) == record_digest(copy.deepcopy(record))


def test_dump_records_is_stable_jsonl() -> None:
    first = build_run_record(_payload(), _scenario(), arm="Full", repeat=1)
    second = build_run_record(_payload(), _scenario(), arm="B0", repeat=1)

    text = dump_records([first, second])
    assert text.endswith("\n")
    lines = text.splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == first
    assert json.loads(lines[1]) == second

    # 相同输入 → 逐字节稳定输出。
    assert dump_records([first, second]) == dump_records(
        [copy.deepcopy(first), copy.deepcopy(second)]
    )


def test_summarise_records_counts_per_arm() -> None:
    records = [
        build_run_record(_payload(), _scenario(), arm="B0"),
        build_run_record(_payload(), _scenario(), arm="Full"),
        build_run_record(_payload(), _scenario(), arm="Full"),
    ]
    summary = summarise_records(records)
    assert summary["record_count"] == 3
    assert summary["records_per_arm"] == {"B0": 1, "Full": 2}


# --------------------------------------------------------------------------- #
# guard 驱动拒绝 B0
# --------------------------------------------------------------------------- #

def test_guard_driver_rejects_b0_without_runtime(tmp_path: Path) -> None:
    """``arm="B0"`` 必须在解析运行时之前就抛 ``ValueError``（不加载 guard）。"""

    scenario = {"scenario_id": "X", "events": [{"hook_payload": {"toolName": "read"}}]}
    with pytest.raises(ValueError, match="B0"):
        run_scenario_guard(
            scenario,
            arm="B0",
            workspace=tmp_path / "workspace",
            profile_home=tmp_path / "profile",
        )


def test_guard_driver_rejects_unknown_arm(tmp_path: Path) -> None:
    scenario = {"scenario_id": "X", "events": [{"hook_payload": {"toolName": "read"}}]}
    with pytest.raises(ValueError, match="不支持"):
        run_scenario_guard(
            scenario,
            arm="not-an-arm",
            workspace=tmp_path / "workspace",
            profile_home=tmp_path / "profile",
        )


# --------------------------------------------------------------------------- #
# 编排 CLI 的无副作用入口
# --------------------------------------------------------------------------- #

def test_run_requires_output_without_flags() -> None:
    assert run_module.main([]) == 2


def test_run_dry_run_has_no_side_effects(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output = tmp_path / "bundle"

    rc = run_module.main(["--dry-run", "--output", str(output)])

    assert rc == 0
    # 未启动任何进程、未产生 bundle。
    assert not output.exists()
    printed = capsys.readouterr().out
    assert "[dry-run]" in printed
    assert "未启动任何进程" in printed


def test_run_check_is_callable_without_side_effects() -> None:
    try:
        toolchain = office_driver.resolve_toolchain()
    except office_driver.RuntimeUnavailable as exc:  # pragma: no cover - 环境相关
        pytest.skip(f"真实运行时不可用：{exc}")
    if not toolchain.get("node_admission_ok"):  # pragma: no cover - 环境相关
        pytest.skip(f"node 不满足 OpenClaw 准入：{toolchain.get('node_version')}")

    assert run_module.main(["--check"]) == 0
