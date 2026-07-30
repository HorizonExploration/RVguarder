#!/usr/bin/env python3
"""
RV 必要性实验 — 综合报告生成器。

读取 testlab/results/ 中的 JSON 实验数据，生成：
1. 控制台对比表
2. Markdown 综合报告
3. 聚合指标 JSON

运行方式:
  python testlab/experiments/generate_report.py
  python testlab/experiments/generate_report.py --output-dir testlab/results
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path


def find_latest_results(results_dir: Path) -> dict[str, Path]:
    """在 results 目录中找到每个实验的最新结果文件。"""
    latest: dict[str, tuple[str, Path]] = {}

    for path in sorted(results_dir.glob("experiment_*_results_*.json")):
        exp_type = path.stem.split("_results_")[0]  # experiment_a, experiment_b, etc.
        ts_str = path.stem.split("_results_")[1]
        if exp_type not in latest or ts_str > latest[exp_type][0]:
            latest[exp_type] = (ts_str, path)

    return {k: v[1] for k, v in latest.items()}


def load_results(results_dir: Path) -> dict[str, dict]:
    """加载所有实验数据。"""
    latest = find_latest_results(results_dir)
    data: dict[str, dict] = {}
    for exp_type, path in sorted(latest.items()):
        with open(path, "r", encoding="utf-8") as f:
            data[exp_type] = json.load(f)
    return data


def generate_markdown_report(data: dict[str, dict]) -> str:
    """生成 Markdown 格式的综合报告。"""
    lines: list[str] = []

    lines.append("# RV 必要性实验 — 综合报告\n")
    lines.append(f"**报告生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    lines.append("---\n")

    # ── 实验 A ──
    if "experiment_a" in data:
        a = data["experiment_a"]
        lines.append("## 实验 A — RV 必要性验证：静态 vs RV 对比\n")
        lines.append(f"**攻击链**: {a.get('chain_name', 'N/A')}")
        lines.append(f"**场景**: {a.get('chain_description', 'N/A')}\n")

        lines.append("| 步 | 步骤 ID | 事件 | 静态判定 | RV 判定 | RV 监视器 |")
        lines.append("|:---|:--------|:-----|:---------|:-------|:----------|")
        for s in a["steps"]:
            lines.append(
                f"| {s['step_number']} | {s['step_id']} | {s['event']} | "
                f"{s['static_verdict']} | {s['rv_verdict']} | "
                f"{s.get('rv_triggered_by', '-') or '-'} |"
            )
        lines.append("")

        fs = a["final_static"]
        fr = a["final_rv"]
        lines.append(f"- **静态最终判定**: {fs['verdict']} (风险等级: {fs['risk_level']})")
        lines.append(f"- **RV 最终判定**: {fr['verdict']} (触发者: {fr.get('triggered_by', 'N/A')})")
        lines.append(f"- **RV 必要性**: {'✅ 已证明' if a.get('rv_necessity_proven') else '❌ 未充分证明'}")
        lines.append("")
        lines.append(f"> {a.get('summary', '')}")
        lines.append("")

    # ── 实验 B ──
    if "experiment_b" in data:
        b = data["experiment_b"]
        lines.append("## 实验 B — 链式攻击变体鲁棒性测试\n")

        lines.append("| 编号 | 变体名称 | 恶意 | 链长 | RV 最终 | 监视器 | 预期 | 结果 |")
        lines.append("|:-----|:---------|:-----|:-----|:--------|:-------|:-----|:-----|")
        for v in b["variants"]:
            lines.append(
                f"| {v['variant_id']} | {v['variant_name']} | "
                f"{'Yes' if v['is_malicious'] else 'No'} | {v['chain_length']} | "
                f"{v['final_rv_verdict']} | {v.get('rv_triggered_by', '-') or '-'} | "
                f"{v['expected_verdict']} | "
                f"{'PASS' if v['passed'] else 'FAIL'} |"
            )
        lines.append("")

        agg = b["aggregate"]
        lines.append(f"| 指标 | 数值 |")
        lines.append(f"|:-----|:-----|")
        lines.append(f"| 总变体数 | {agg['total_variants']} |")
        lines.append(f"| TP (真阳性) | {agg['true_positives']} |")
        lines.append(f"| TN (真阴性) | {agg['true_negatives']} |")
        lines.append(f"| FP (误报) | {agg['false_positives']} |")
        lines.append(f"| FN (漏报) | {agg['false_negatives']} |")
        lines.append(f"| 检测率 | {agg['detection_rate']}% |")
        lines.append(f"| 误报率 | {agg['false_positive_rate']}% |")
        lines.append(f"| 全部通过 | {'✅ 是' if agg['all_passed'] else '⚠️ 否'} |")
        lines.append("")

    # ── 实验 C ──
    if "experiment_c" in data:
        c = data["experiment_c"]
        lines.append("## 实验 C — 抗干扰与误报测试\n")

        lines.append("| 测试 | 结果 | 说明 |")
        lines.append("|:-----|:-----|:-----|")
        for t in c["test_results"]:
            result_mark = "PASS" if t["passed"] else "FAIL"
            lines.append(f"| {t['test_id']} | {result_mark} | {t.get('test_name', '')} |")
        lines.append("")

        agg_c = c["aggregate"]
        lines.append(f"- **总测试数**: {agg_c['total_tests']}")
        lines.append(f"- **通过数**: {agg_c['passed']}")
        lines.append(f"- **失败数**: {agg_c['failed']}")
        lines.append(f"- **误报数 (FP)**: {agg_c['false_positives']}")
        lines.append(f"- **Session 隔离**: {'✅ 正确' if agg_c.get('isolation_verified') else '❌ 失败'}")
        lines.append(f"- **全部通过**: {'✅ 是' if agg_c['all_passed'] else '⚠️ 否'}")
        lines.append("")

    # ── 总结 ──
    lines.append("---\n")
    lines.append("## 综合结论\n")

    a_proven = data.get("experiment_a", {}).get("rv_necessity_proven", False)
    b_passed = data.get("experiment_b", {}).get("aggregate", {}).get("all_passed", False)
    c_passed = data.get("experiment_c", {}).get("aggregate", {}).get("all_passed", False)

    lines.append(f"| 实验 | 结论 |")
    lines.append(f"|:-----|:-----|")
    lines.append(f"| 实验 A (必要性) | {'✅ RV 必要性已证明' if a_proven else '⚠️ 需检查'} |")
    lines.append(f"| 实验 B (变体) | {'✅ 全部通过' if b_passed else '⚠️ 有未通过变体'} |")
    lines.append(f"| 实验 C (抗干扰) | {'✅ 全部通过' if c_passed else '⚠️ 有未通过项'} |")

    overall = a_proven and b_passed and c_passed
    lines.append("")
    if overall:
        lines.append("### ✅ RV 必要性实验全部通过！\n")
        lines.append("1. 静态单步检测无法识别多步攻击链（实验 A）")
        lines.append("2. RV 通过 FSM 状态记忆能阻断 10 种攻击链变体（实验 B）")
        lines.append("3. RV 在正常办公场景中不产生误报（实验 C）")
        lines.append("\n**核心结论**: Runtime Verification 是 AI Agent 安全的必要组件。")
    else:
        lines.append("### ⚠️ 部分实验未通过，需进一步分析\n")

    lines.append(f"\n---\n")
    lines.append(f"*报告由 `generate_report.py` 自动生成于 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

    return "\n".join(lines)


def main():
    results_dir = Path(__file__).resolve().parents[1] / "results"
    if len(sys.argv) > 1:
        results_dir = Path(sys.argv[1])

    if not results_dir.exists():
        print(f"[ERROR] 结果目录不存在: {results_dir}")
        print("请先运行实验脚本:")
        print("  python testlab/experiments/experiment_a_necessity.py")
        print("  python testlab/experiments/experiment_b_variants.py")
        print("  python testlab/experiments/experiment_c_interference.py")
        sys.exit(1)

    data = load_results(results_dir)

    if not data:
        print(f"[ERROR] 在 {results_dir} 中未找到实验结果文件")
        sys.exit(1)

    print(f"  已加载 {len(data)} 个实验结果: {list(data.keys())}")
    print()

    # 生成 Markdown 报告
    md = generate_markdown_report(data)
    md_path = results_dir / f"comprehensive_rv_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"  Markdown 报告已保存: {md_path}")

    # 生成聚合 JSON
    aggregate = {
        "generated_at": datetime.now().isoformat(),
        "experiments": list(data.keys()),
        "experiment_a": {
            "rv_necessity_proven": data.get("experiment_a", {}).get("rv_necessity_proven", False),
            "static_final": data.get("experiment_a", {}).get("final_static", {}).get("verdict"),
            "rv_final": data.get("experiment_a", {}).get("final_rv", {}).get("verdict"),
        } if "experiment_a" in data else None,
        "experiment_b": data["experiment_b"]["aggregate"] if "experiment_b" in data else None,
        "experiment_c": data["experiment_c"]["aggregate"] if "experiment_c" in data else None,
    }
    agg_path = results_dir / f"aggregate_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(agg_path, "w", encoding="utf-8") as f:
        json.dump(aggregate, f, ensure_ascii=False, indent=2)
    print(f"  聚合指标已保存: {agg_path}")

    # 打印综合结论
    print()
    print("=" * 80)
    print("  综合结论")
    print("=" * 80)
    a_proven = aggregate["experiment_a"]["rv_necessity_proven"] if aggregate["experiment_a"] else False
    b_passed = aggregate["experiment_b"]["all_passed"] if aggregate["experiment_b"] else False
    c_passed = aggregate["experiment_c"]["all_passed"] if aggregate["experiment_c"] else False
    print(f"  实验 A (RV 必要性): {'PASS' if a_proven else 'FAIL'}")
    print(f"  实验 B (变体鲁棒性): {'PASS' if b_passed else 'FAIL'}")
    print(f"  实验 C (抗干扰/误报): {'PASS' if c_passed else 'FAIL'}")
    print(f"  {'-' * 40}")
    overall = a_proven and b_passed and c_passed
    print(f"  综合结果: {'ALL PASS' if overall else 'SOME FAILED'}")
    print("=" * 80)

    sys.exit(0 if overall else 1)


if __name__ == "__main__":
    main()
