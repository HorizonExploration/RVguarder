"""Human-readable and machine-readable output for the office replay."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    metrics = summary.get("metrics") if isinstance(summary.get("metrics"), dict) else {}
    lines = [
        "# RVGuarder 个人办公价值小实验",
        "",
        "本报告来自离线、确定性的 Hook 重放；不会执行真实工具、写入真实业务文件或连接外部网络。",
        "",
        "## 模式对比",
        "",
        "| 模式 | 攻击静默放行 | 攻击干预覆盖 | 正常完成 | 误报硬阻断 | 审批次数 | 调用 p95 (ms) | 证据完整度 | 期望终态匹配 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for mode in summary.get("modes", []):
        item = metrics.get(mode, {})
        lines.append(
            (
                "| {mode} | {silent} | {intervention} | {benign} | {false_block} | "
                "{approvals} | {p95} | {evidence} | {expected} |"
            ).format(
                mode=mode,
                silent=_rate_text(item, "silent_unsafe_allow"),
                intervention=_rate_text(item, "intervention_coverage"),
                benign=_rate_text(item, "benign_completion"),
                false_block=_rate_text(item, "false_hard_block"),
                approvals=(item.get("approval_burden") or {}).get("count", 0),
                p95=(item.get("latency_ms") or {}).get("p95", 0),
                evidence=_rate_text(item, "evidence_completeness"),
                expected=_rate_text(item, "expected_outcome_match"),
            )
        )

    upgrades = summary.get("full_guard_upgrades_vs_pmkb") or []
    lines.extend(["", "## RV 跨步骤升级", ""])
    if upgrades:
        lines.append("Full Guard 将以下 PMKB-only 的非阻断终态升级为阻断：")
        lines.append("")
        for item in upgrades:
            lines.append(f"- `{item.get('scenario_id')}`：{item.get('from')} → block")
    else:
        lines.append("本次子集没有观察到额外的跨步骤升级。")

    trust_scope = report.get("trust_scope")
    if isinstance(trust_scope, dict):
        lines.extend(
            ["", "## 审批信任范围变形测试", "", "| 变形 | 结果 |", "| --- | --- |"]
        )
        for key, value in trust_scope.items():
            lines.append(f"| {key} | `{value}` |")

    lines.extend(
        [
            "",
            "## 解读边界",
            "",
            "- `pass_through` 只是无防护对照组；它的攻击静默放行率用于展示风险上界，不代表推荐配置。",
            "- `pmkb_only` 保留逐次 PMKB 审批，但关闭会话/主体 RV；重放会自动接受一次审批，以观察后续链条。",
            "- `full_guard` 运行真实的 before/after Hook 生命周期、审批呈现、主体状态与精确命令信任检查。",
            "- 域名使用 `.invalid`，凭据使用假值；任何 `after_tool_call` 只提交本地审计/RV 状态，不调用工具。",
        ]
    )
    return "\n".join(lines) + "\n"


def write_report_bundle(report: dict[str, Any], output_dir: str | Path) -> dict[str, str]:
    """Write JSON/JSONL/Markdown artifacts to an explicitly selected directory."""
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    summary_path = destination / "summary.json"
    raw_path = destination / "raw.jsonl"
    markdown_path = destination / "report.md"
    summary_path.write_text(
        json.dumps(report.get("summary", {}), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    rows = report.get("results") if isinstance(report.get("results"), list) else []
    raw_path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return {"summary": str(summary_path), "raw": str(raw_path), "markdown": str(markdown_path)}


def _rate_text(metrics: dict[str, Any], key: str) -> str:
    item = metrics.get(key) if isinstance(metrics.get(key), dict) else {}
    count = item.get("count", 0)
    rate = float(item.get("rate", 0.0)) * 100
    return f"{count} ({rate:.0f}%)"
