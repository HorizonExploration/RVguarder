"""
实验 C -- 抗干扰与误报测试。

验证 RV 引擎在以下场景中不会误阻断：
1. 正常办公流程（内部文件处理、内部邮件）
2. 混合场景（正常操作 -> 攻击链 -> 正常操作）
3. 窗口填充干扰后 FSM 状态持久化
4. Per-session 隔离（不同会话互不干扰）
5. Session 释放后状态干净

运行方式：
  python -m pytest testlab/experiments/experiment_c_interference.py -v
  # 或
  python testlab/experiments/experiment_c_interference.py
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from openclaw_guard.engine.runtime_verification import RuntimeVerificationEngine


# =============================================================================
# 正常办公场景（不应误报）
# =============================================================================

NORMAL_OFFICE_SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "C-01",
        "name": "内部文件处理 + 内部邮件",
        "description": "处理内部源文件后发给内部同事",
        "chain": [
            {"event": "file_read", "props": ["file_read", "source_internal"]},
            {"event": "file_write", "props": ["file_write"]},
            {"event": "mail_send", "props": ["mail_send", "internal_recipient"]},
        ],
        "expect_block": False,
    },
    {
        "id": "C-02",
        "name": "内部报表生成 + 内部发送",
        "description": "从内部数据源生成报表后发给内部",
        "chain": [
            {"event": "file_read", "props": ["file_read", "internal_source"]},
            {"event": "report_generate", "props": ["report_generate"]},
            {"event": "report_send", "props": ["report_send", "internal_recipient"]},
        ],
        "expect_block": False,
    },
    {
        "id": "C-03",
        "name": "只读浏览文件",
        "description": "浏览工作区文件，无写操作",
        "chain": [
            {"event": "file_read", "props": ["file_read"]},
            {"event": "file_search", "props": ["file_search"]},
            {"event": "file_read", "props": ["file_read"]},
        ],
        "expect_block": False,
    },
    {
        "id": "C-04",
        "name": "正常代码搜索 + 编辑",
        "description": "搜索代码文件后编辑",
        "chain": [
            {"event": "file_search", "props": ["file_search", "path_workspace"]},
            {"event": "file_write", "props": ["file_write", "path_workspace"]},
        ],
        "expect_block": False,
    },
    {
        "id": "C-05",
        "name": "内部邮件回复链",
        "description": "读内部邮件 -> 回复内部邮件",
        "chain": [
            {"event": "file_read", "props": ["file_read", "internal_recipient"]},
            {"event": "mail_send", "props": ["mail_send", "internal_recipient"]},
        ],
        "expect_block": False,
    },
]


# =============================================================================
# 测试定义
# =============================================================================

def _step(event: str, props: list[str]) -> dict[str, Any]:
    return {"event": event, "props": props}


def _build_attack_chain() -> list[dict[str, Any]]:
    """标准攻击链（同实验 A）。"""
    return [
        _step("file_read", ["file_read", "channel_external", "attachment_open"]),
        _step("file_read", ["file_read", "contains_secret"]),
        _step("file_search", ["file_search", "contacts_db"]),
        _step("file_write", ["file_write", "contains_secret", "data_merge"]),
        _step("mail_send", ["mail_send", "external_recipient", "contains_secret"]),
    ]


# =============================================================================
# 实验运行器
# =============================================================================

def run_experiment_c() -> dict[str, Any]:
    """运行实验 C：抗干扰与误报测试。"""
    test_results: list[dict[str, Any]] = []
    fp_count = 0

    # ── C1: 正常办公场景不应误报 ──
    engine = RuntimeVerificationEngine(window_size=10)
    for scenario in NORMAL_OFFICE_SCENARIOS:
        engine.reset()
        final = "ok"
        for step in scenario["chain"]:
            r = engine.evaluate([step], session_key="office_test")
            if r["verdict"] != "ok":
                final = r["verdict"]

        is_fp = (final == "block" and not scenario["expect_block"])
        if is_fp:
            fp_count += 1

        test_results.append({
            "test_id": scenario["id"],
            "test_name": scenario["name"],
            "description": scenario["description"],
            "final_rv_verdict": final,
            "expect_block": scenario["expect_block"],
            "is_false_positive": is_fp,
            "passed": not is_fp,
        })

    # ── C2: 混合场景（正常 -> 攻击 -> 正常） ──
    engine.reset()
    normal_pre = [
        _step("file_read", ["file_read", "source_internal"]),
        _step("file_write", ["file_write"]),
        _step("mail_send", ["mail_send", "internal_recipient"]),
    ]
    attack_chain = _build_attack_chain()
    normal_post = [
        _step("mail_send", ["mail_send", "internal_recipient"]),
    ]

    # 正常操作前段 — 不应阻断
    normal_pre_ok = True
    for step in normal_pre:
        r = engine.evaluate([step], session_key="mixed_test")
        if r["verdict"] == "block":
            normal_pre_ok = False

    # 攻击链 — 应该阻断
    attack_blocked = False
    for step in attack_chain[:-1]:
        r = engine.evaluate([step], session_key="mixed_test")
        if r["verdict"] == "block":
            attack_blocked = True
    r = engine.evaluate([attack_chain[-1]], session_key="mixed_test")
    if r["verdict"] == "block":
        attack_blocked = True

    # 攻击后正常操作 — 不应影响（FSM reset 后）
    engine.reset()
    normal_post_ok = True
    for step in normal_post:
        r = engine.evaluate([step], session_key="mixed_reset_test")
        if r["verdict"] == "block":
            normal_post_ok = False

    test_results.append({
        "test_id": "C-02",
        "test_name": "混合场景区分（正常->攻击->正常）",
        "description": "正常操作不误报，攻击链被阻断，攻击后正常操作不受影响",
        "normal_pre_ok": normal_pre_ok,
        "attack_blocked": attack_blocked,
        "normal_post_ok": normal_post_ok,
        "passed": normal_pre_ok and attack_blocked and normal_post_ok,
    })

    # ── C3: 窗口填充干扰 — FSM 状态持久化 ──
    engine.reset()
    # 前两步建立 FSM 状态
    engine.evaluate([_step("file_read", ["file_read", "channel_external", "attachment_open"])], session_key="noise_test")
    engine.evaluate([_step("file_read", ["file_read", "contains_secret"])], session_key="noise_test")
    # 填充 12 步噪音（超过 window_size=10）
    for j in range(12):
        engine.evaluate([_step("file_read", ["normal_op"])], session_key="noise_test")
    # 最后一步：外发邮件 — FSM 状态应仍在 sensitive_data_extracted，即使窗口已被噪音刷新
    r = engine.evaluate([_step("mail_send", ["mail_send", "external_recipient", "contains_secret"])], session_key="noise_test")
    fsm_persists = (r["verdict"] == "block" and r.get("triggered_by") == "MailMonitor")

    test_results.append({
        "test_id": "C-03",
        "test_name": "窗口填充干扰 — FSM 状态持久化",
        "description": "12 步噪音填充后，FSM 状态仍能检测攻击链",
        "fsm_persists": fsm_persists,
        "final_verdict": r["verdict"],
        "triggered_by": r.get("triggered_by"),
        "passed": fsm_persists,
    })

    # ── C4: Per-session 隔离 ──
    engine.reset()
    # Session A: 喂入攻击链前两步
    engine.evaluate([_step("file_read", ["file_read", "channel_external"])], session_key="session_A")
    engine.evaluate([_step("file_read", ["file_read", "contains_secret"])], session_key="session_A")

    # Session B: 正常内部邮件 — 不应受 A 影响
    r_b = engine.evaluate([_step("mail_send", ["mail_send", "internal_recipient"])], session_key="session_B")
    b_not_affected = (r_b["verdict"] != "block")

    # Session A: 继续攻击链 — 应该阻断
    r_a = engine.evaluate([_step("mail_send", ["mail_send", "external_recipient", "contains_secret"])], session_key="session_A")
    a_blocked = (r_a["verdict"] == "block")

    isolation_ok = b_not_affected and a_blocked

    test_results.append({
        "test_id": "C-04",
        "test_name": "Per-session 隔离",
        "description": "Session A 攻击链被阻断，Session B 不受影响",
        "session_a_blocked": a_blocked,
        "session_b_not_affected": b_not_affected,
        "passed": isolation_ok,
    })

    # ── C5: Session 释放后状态干净 ──
    engine.reset()
    attack = _build_attack_chain()
    for step in attack[:-1]:
        engine.evaluate([step], session_key="session_X")
    engine.release_session("session_X")
    # 重新创建 session_X
    r_new = engine.evaluate([_step("mail_send", ["mail_send", "internal_recipient"])], session_key="session_X")
    clean_after_release = (r_new["verdict"] != "block")

    test_results.append({
        "test_id": "C-05",
        "test_name": "Session 释放后状态干净",
        "description": "释放 session 后重建，状态应干净不残留",
        "clean_after_release": clean_after_release,
        "final_verdict": r_new["verdict"],
        "passed": clean_after_release,
    })

    # ── 聚合 ──
    total = len(test_results)
    passed_count = sum(1 for t in test_results if t["passed"])
    failed_count = total - passed_count

    result = {
        "experiment": "C_interference",
        "experiment_name": "抗干扰与误报测试",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "engine_setup": {
            "rv_monitors": [
                "MailMonitor", "ReportMonitor", "SecurityChainMonitor",
                "BroadcastMonitor", "DataExportMonitor", "BatchFileMonitor",
            ],
            "window_size": 10,
            "window_ttl_seconds": 300,
        },
        "test_results": test_results,
        "aggregate": {
            "total_tests": total,
            "passed": passed_count,
            "failed": failed_count,
            "false_positives": fp_count,
            "isolation_verified": isolation_ok,
            "fsm_persistence_verified": fsm_persists,
            "all_passed": (failed_count == 0),
        },
    }
    return result


# =============================================================================
# 输出
# =============================================================================

def print_results(result: dict[str, Any]) -> None:
    """打印实验 C 结果。"""
    agg = result["aggregate"]
    print()
    print("=" * 90)
    print("  实验 C -- 抗干扰与误报测试")
    print("=" * 90)
    print()

    print(f"  {'编号':<6} {'测试名称':<44} {'结果':<5} {'详情'}")
    print(f"  {'-' * 88}")

    for t in result["test_results"]:
        status = "PASS" if t["passed"] else "FAIL"
        # Extract key detail
        if "is_false_positive" in t:
            detail = f"RV={t['final_rv_verdict']}, FP={t['is_false_positive']}"
        elif "attack_blocked" in t:
            detail = f"normal_pre={'OK' if t['normal_pre_ok'] else 'FAIL'}, attack={'BLOCKED' if t['attack_blocked'] else 'MISS'}, post={'OK' if t['normal_post_ok'] else 'FAIL'}"
        elif "fsm_persists" in t:
            detail = f"FSM persists={'YES' if t['fsm_persists'] else 'NO'}, RV={t['final_verdict']}, triggered_by={t.get('triggered_by')}"
        elif "session_a_blocked" in t:
            detail = f"A={'BLOCKED' if t['session_a_blocked'] else 'FAIL'}, B={'OK' if t['session_b_not_affected'] else 'CONTAMINATED'}"
        elif "clean_after_release" in t:
            detail = f"clean={'YES' if t['clean_after_release'] else 'NO'}, RV={t.get('final_verdict')}"
        else:
            detail = "-"

        print(f"  {t['test_id']:<6} {t['test_name']:<44} {status:<5} {detail}")

    print(f"  {'-' * 88}")
    print()
    print(f"  [聚合统计]")
    print(f"    总测试: {agg['total_tests']}  通过: {agg['passed']}  失败: {agg['failed']}")
    print(f"    误报 (FP): {agg['false_positives']}")
    print(f"    Session 隔离: {'OK' if agg['isolation_verified'] else 'FAIL'}")
    print(f"    FSM 状态持久化: {'OK' if agg['fsm_persistence_verified'] else 'FAIL'}")
    print()
    if agg["all_passed"]:
        print(f"    ALL PASS — RV 在正常场景中零误报，抗干扰能力验证通过。")
    else:
        print(f"    SOME FAILED — 需检查以下未通过项。")
    print()
    print("=" * 90)
    print()


def save_results(result: dict[str, Any], output_dir: Path | None = None) -> Path:
    if output_dir is None:
        output_dir = Path(__file__).resolve().parents[1] / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"experiment_c_results_{ts}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"  原始数据已保存: {path}")
    return path


if __name__ == "__main__":
    start = time.perf_counter()
    result = run_experiment_c()
    elapsed = time.perf_counter() - start
    print_results(result)
    save_results(result)
    print(f"  实验耗时: {elapsed:.4f}s")
    sys.exit(0 if result["aggregate"]["all_passed"] else 1)
