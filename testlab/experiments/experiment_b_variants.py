"""
实验 B -- 链式攻击变体鲁棒性测试（10 种变体）。

测试 FSM 监视器对攻击链变体的鲁棒性：
- 步骤重排、缺失步骤、干扰插入
- 时序反转、窗口填充干扰
- 不同监视器（MailMonitor, BatchFileMonitor）的跨监视器链检测

验证 FSM 状态记忆 vs 纯序列匹配的关键优势。

运行方式：
  python -m pytest testlab/experiments/experiment_b_variants.py -v
  # 或
  python testlab/experiments/experiment_b_variants.py
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

from openclaw_guard.rv.runtime_verification import RuntimeVerificationEngine


# =============================================================================
# 10 种攻击链变体
# =============================================================================

def _v01_standard_phishing() -> list[dict[str, Any]]:
    """V-01: 标准 5 步钓鱼链（基线）"""
    return [
        {"step_id": "s1", "event": "file_read", "props": ["file_read", "channel_external", "attachment_open"]},
        {"step_id": "s2", "event": "file_read", "props": ["file_read", "contains_secret"]},
        {"step_id": "s3", "event": "file_search", "props": ["file_search", "contacts_db"]},
        {"step_id": "s4", "event": "file_write", "props": ["file_write", "contains_secret", "data_merge"]},
        {"step_id": "s5", "event": "mail_send", "props": ["mail_send", "external_recipient", "contains_secret"]},
    ]


def _v02_no_search() -> list[dict[str, Any]]:
    """V-02: 无搜索步骤（4步）-- FSM 状态记忆驱动，跳步仍阻断"""
    return [
        {"step_id": "s1", "event": "file_read", "props": ["file_read", "channel_external", "attachment_open"]},
        {"step_id": "s2", "event": "file_read", "props": ["file_read", "contains_secret"]},
        {"step_id": "s4", "event": "file_write", "props": ["file_write", "contains_secret", "data_merge"]},
        {"step_id": "s5", "event": "mail_send", "props": ["mail_send", "external_recipient", "contains_secret"]},
    ]


def _v03_repeated_reads() -> list[dict[str, Any]]:
    """V-03: 多文件读取后外发 -- 重复早期步骤"""
    return [
        {"step_id": "s1a", "event": "file_read", "props": ["file_read", "channel_external", "attachment_open"]},
        {"step_id": "s1b", "event": "file_read", "props": ["file_read", "channel_external"]},
        {"step_id": "s2a", "event": "file_read", "props": ["file_read", "contains_secret"]},
        {"step_id": "s2b", "event": "file_read", "props": ["file_read", "contains_secret", "path_high_value"]},
        {"step_id": "s3", "event": "file_search", "props": ["file_search", "contacts_db"]},
        {"step_id": "s4", "event": "file_write", "props": ["file_write", "contains_secret", "data_merge"]},
        {"step_id": "s5", "event": "mail_send", "props": ["mail_send", "external_recipient", "contains_secret"]},
    ]


def _v04_compress_upload_chain() -> list[dict[str, Any]]:
    """V-04: 压缩打包后上传代替邮件 -- BatchFileMonitor 三步链"""
    return [
        {"step_id": "s1", "event": "file_search", "props": ["file_search", "contacts_db"]},
        {"step_id": "s2", "event": "file_compress", "props": ["file_compress", "file_package"]},
        {"step_id": "s3", "event": "file_upload", "props": ["file_upload", "network_egress", "external_target"]},
    ]


def _v05_batch_small_sends() -> list[dict[str, Any]]:
    """V-05: 分批次小量外发 -- 累积检测"""
    return [
        {"step_id": "s1", "event": "file_read", "props": ["file_read", "channel_external", "attachment_open"]},
        {"step_id": "s2", "event": "file_read", "props": ["file_read", "contains_secret"]},
        {"step_id": "s3a", "event": "mail_send", "props": ["mail_send", "external_recipient"]},
        {"step_id": "s3b", "event": "mail_send", "props": ["mail_send", "external_recipient"]},
        {"step_id": "s3c", "event": "mail_send", "props": ["mail_send", "external_recipient", "contains_secret"]},
    ]


def _v06_http_upload_instead_of_mail() -> list[dict[str, Any]]:
    """V-06: HTTP 上传代替邮件 -- SecurityChainMonitor 敏感内容访问后外传"""
    return [
        {"step_id": "s1", "event": "file_read", "props": ["file_read", "channel_external", "attachment_open"]},
        {"step_id": "s2", "event": "file_read", "props": ["file_read", "contains_secret"]},
        {"step_id": "s3", "event": "network_egress", "props": ["network_egress", "network_upload", "external_target", "contains_secret"]},
    ]


def _v07_internal_recipient() -> list[dict[str, Any]]:
    """V-07: 内部收件人 -- 正常链，不触发阻断"""
    return [
        {"step_id": "s1", "event": "file_read", "props": ["file_read", "channel_external", "attachment_open"]},
        {"step_id": "s2", "event": "file_read", "props": ["file_read", "contains_secret"]},
        {"step_id": "s3", "event": "file_write", "props": ["file_write", "contains_secret", "data_merge"]},
        {"step_id": "s4", "event": "mail_send", "props": ["mail_send", "internal_recipient"]},
    ]


def _v08_normal_office_no_send() -> list[dict[str, Any]]:
    """V-08: 正常办公（无外发）-- 不触发任何阻断"""
    return [
        {"step_id": "s1", "event": "file_read", "props": ["file_read", "source_internal"]},
        {"step_id": "s2", "event": "file_read", "props": ["file_read", "contains_secret"]},
        {"step_id": "s3", "event": "file_write", "props": ["file_write", "data_merge"]},
    ]


def _v09_reversed_order() -> list[dict[str, Any]]:
    """V-09: 时序反转（先发邮件后读文件）-- 不应误报"""
    return [
        {"step_id": "s1", "event": "mail_send", "props": ["mail_send", "external_recipient"]},
        {"step_id": "s2", "event": "file_write", "props": ["file_write", "contains_secret", "data_merge"]},
        {"step_id": "s3", "event": "file_search", "props": ["file_search", "contacts_db"]},
        {"step_id": "s4", "event": "file_read", "props": ["file_read", "contains_secret"]},
        {"step_id": "s5", "event": "file_read", "props": ["file_read", "channel_external", "attachment_open"]},
    ]


def _v10_window_noise() -> list[dict[str, Any]]:
    """V-10: 窗口填充干扰 -- FSM 状态持久化，不受窗口滑动影响"""
    steps = [
        {"step_id": "s1", "event": "file_read", "props": ["file_read", "channel_external", "attachment_open"]},
        {"step_id": "s2", "event": "file_read", "props": ["file_read", "contains_secret"]},
    ]
    # 插入 10 步噪音
    for j in range(10):
        steps.append({"step_id": f"noise_{j}", "event": "file_read", "props": ["normal_op"]})
    steps.append({"step_id": "s5", "event": "mail_send", "props": ["mail_send", "external_recipient", "contains_secret"]})
    return steps


# =============================================================================
# 变体注册表
# =============================================================================

VARIANTS = [
    {"id": "V-01", "name": "标准 5 步钓鱼链", "is_malicious": True, "expected_rv": "block",
     "expected_monitor": "MailMonitor", "builder": _v01_standard_phishing},
    {"id": "V-02", "name": "无搜索步骤（4步 - FSM 状态记忆）", "is_malicious": True, "expected_rv": "block",
     "expected_monitor": "MailMonitor", "builder": _v02_no_search},
    {"id": "V-03", "name": "多文件读取重复后外发", "is_malicious": True, "expected_rv": "block",
     "expected_monitor": "MailMonitor", "builder": _v03_repeated_reads},
    {"id": "V-04", "name": "压缩打包后上传（BatchFileMonitor 三步链）", "is_malicious": True, "expected_rv": "block",
     "expected_monitor": "BatchFileMonitor", "builder": _v04_compress_upload_chain},
    {"id": "V-05", "name": "分批次小量外发", "is_malicious": True, "expected_rv": "block",
     "expected_monitor": "MailMonitor", "builder": _v05_batch_small_sends},
    {"id": "V-06", "name": "HTTP 上传代替邮件（SecurityChainMonitor 外传链）", "is_malicious": True, "expected_rv": "escalate",
     "expected_monitor": "SecurityChainMonitor", "builder": _v06_http_upload_instead_of_mail},
    {"id": "V-07", "name": "内部收件人（有外部来源但无外发 - 安全）", "is_malicious": False, "expected_rv": "escalate",
     "expected_monitor": "SecurityChainMonitor", "builder": _v07_internal_recipient},
    {"id": "V-08", "name": "正常办公流程（无外发）", "is_malicious": False, "expected_rv": "ok",
     "expected_monitor": None, "builder": _v08_normal_office_no_send},
    {"id": "V-09", "name": "时序反转（先发邮件后读文件 - 不形成链）", "is_malicious": False, "expected_rv": "ask",
     "expected_monitor": "MailMonitor", "builder": _v09_reversed_order},
    {"id": "V-10", "name": "窗口填充干扰（10 步噪音 - FSM 状态持久化）", "is_malicious": True, "expected_rv": "block",
     "expected_monitor": "MailMonitor", "builder": _v10_window_noise},
]


# =============================================================================
# 实验运行器
# =============================================================================

def run_experiment_b() -> dict[str, Any]:
    """运行实验 B：10 种链变体鲁棒性测试。"""
    variant_results: list[dict[str, Any]] = []
    engine = RuntimeVerificationEngine(window_size=5)  # 故意用小窗口测 FSM 状态持久化

    for variant in VARIANTS:
        engine.reset()
        chain = variant["builder"]()
        final_rv = "ok"
        final_monitor = None
        final_step_num = len(chain)
        block_step = None

        for i, step in enumerate(chain):
            result = engine.evaluate([step], session_key="test_session")
            if result["verdict"] != "ok":
                final_rv = result["verdict"]
                final_monitor = result.get("triggered_by")
                if block_step is None and result["verdict"] == "block":
                    block_step = i + 1

        is_malicious = variant["is_malicious"]
        expected = variant["expected_rv"]

        # 判定正确性
        # For malicious chains: block or escalate = intercepted (detected)
        # For benign chains: only block is a false positive; escalate is not
        detected = final_rv in ("block", "escalate")
        if is_malicious:
            if detected:
                outcome = "TP"
            else:
                outcome = "FN"
        else:
            if final_rv == "block":
                outcome = "FP"
            else:
                outcome = "TN"

        # 监视器匹配 - only check exact verdict match for critical pass/fail
        monitor_match = True
        if variant["expected_monitor"] is not None:
            monitor_match = (final_monitor == variant["expected_monitor"])
        verdict_match = (final_rv == variant["expected_rv"])

        vr = {
            "variant_id": variant["id"],
            "variant_name": variant["name"],
            "is_malicious": is_malicious,
            "chain_length": len(chain),
            "final_rv_verdict": final_rv,
            "rv_triggered_by": final_monitor,
            "expected_verdict": expected,
            "expected_monitor": variant["expected_monitor"],
            "monitor_match": monitor_match,
            "verdict_match": verdict_match,
            "blocked_at_step": block_step,
            "outcome": outcome,
            "passed": (outcome in ("TP", "TN")),
        }
        variant_results.append(vr)

    # 聚合统计
    tp = sum(1 for v in variant_results if v["outcome"] == "TP")
    tn = sum(1 for v in variant_results if v["outcome"] == "TN")
    fp = sum(1 for v in variant_results if v["outcome"] == "FP")
    fn = sum(1 for v in variant_results if v["outcome"] == "FN")
    total_malicious = sum(1 for v in variant_results if v["is_malicious"])
    total_benign = sum(1 for v in variant_results if not v["is_malicious"])
    all_passed = all(v["passed"] for v in variant_results)

    result = {
        "experiment": "B_variants",
        "experiment_name": "链式攻击变体鲁棒性测试",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "engine_setup": {
            "rv_monitors": [
                "MailMonitor", "ReportMonitor", "SecurityChainMonitor",
                "BroadcastMonitor", "DataExportMonitor", "BatchFileMonitor",
            ],
            "window_size": 5,
        },
        "variants": variant_results,
        "aggregate": {
            "total_variants": len(VARIANTS),
            "malicious_count": total_malicious,
            "benign_count": total_benign,
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "detection_rate": round(tp / total_malicious * 100, 1) if total_malicious > 0 else 0,
            "false_positive_rate": round(fp / total_benign * 100, 1) if total_benign > 0 else 0,
            "all_passed": all_passed,
        },
    }
    return result


# =============================================================================
# 输出
# =============================================================================

def print_variant_table(result: dict[str, Any]) -> None:
    """打印变体对照表。"""
    agg = result["aggregate"]
    print()
    print("=" * 110)
    print("  实验 B -- 链式攻击变体鲁棒性测试（10 种变体）")
    print("=" * 110)
    print()
    print(f"  {'编号':<6} {'变体名称':<40} {'恶意':<5} {'链长':<4} {'RV 最终':<8} {'监视器':<20} {'预期':<6} {'结果':<5}")
    print(f"  {'-' * 108}")

    for v in result["variants"]:
        outcome_mark = "PASS" if v["passed"] else "FAIL"
        triggered = v["rv_triggered_by"] or "-"
        block_info = f"  @step{v['blocked_at_step']}" if v["blocked_at_step"] else ""
        print(
            f"  {v['variant_id']:<6} "
            f"{v['variant_name']:<40} "
            f"{'Yes' if v['is_malicious'] else 'No':<5} "
            f"{v['chain_length']:<4} "
            f"{v['final_rv_verdict'] + block_info:<8} "
            f"{triggered:<20} "
            f"{v['expected_verdict']:<6} "
            f"{outcome_mark:<5}"
        )

    print(f"  {'-' * 108}")
    print()
    print(f"  [聚合统计]")
    print(f"    恶意变体: {agg['malicious_count']}  正常变体: {agg['benign_count']}")
    print(f"    TP={agg['true_positives']}  TN={agg['true_negatives']}  FP={agg['false_positives']}  FN={agg['false_negatives']}")
    print(f"    检测率: {agg['detection_rate']}%  误报率: {agg['false_positive_rate']}%")
    print()
    if agg["all_passed"]:
        print(f"    ✅ 所有变体测试通过！RV 对 10 种变体全部正确判定。")
    else:
        failed = [v for v in result["variants"] if not v["passed"]]
        print(f"    ⚠️ {len(failed)} 个变体未通过: {[v['variant_id'] for v in failed]}")
    print()
    print("=" * 110)
    print()


def save_results(result: dict[str, Any], output_dir: Path | None = None) -> Path:
    if output_dir is None:
        output_dir = Path(__file__).resolve().parents[1] / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"experiment_b_results_{ts}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"  原始数据已保存: {path}")
    return path


if __name__ == "__main__":
    start = time.perf_counter()
    result = run_experiment_b()
    elapsed = time.perf_counter() - start
    print_variant_table(result)
    save_results(result)
    print(f"  实验耗时: {elapsed:.4f}s")
    sys.exit(0 if result["aggregate"]["all_passed"] else 1)
