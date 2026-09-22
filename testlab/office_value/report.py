"""Markdown, HTML and machine-readable artifacts for the office replay."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from openclaw_guard.utils import html_escape


def render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    metrics = summary.get("metrics") if isinstance(summary.get("metrics"), dict) else {}
    lines = [
        "# RVGuarder 个人办公安全价值小实验",
        "",
        "本报告是公开漏洞派生的封闭回放：不会启动 shell，不连接真实网络，不调用办公 SDK；仅在临时目录中应用声明式副作用。",
        "",
        "## 公开事件与映射边界",
        "",
    ]
    for incident in report.get("incidents", []):
        lines.append(f"- `{incident.get('incident_id')}`：{incident.get('title')}")
        for url in incident.get("source_urls", []):
            lines.append(f"  - {url}")
        for boundary in incident.get("mapping_assumption", []):
            lines.append(f"  - 边界：{boundary}")
    lines.extend(["", "## 模式 / 审批人格对比", "", "| 模式 | 审批人格 | 攻击目标成功 | 约束率 | 正常完成 | 误报硬阻断 | 模拟外发命中（本地 sink） | before p95 (ms) |", "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |"])
    for mode in summary.get("modes", []):
        for persona in summary.get("approval_personas", []):
            item = ((metrics.get(mode) or {}).get(persona) or {})
            lines.append(
                f"| {mode} | {persona} | {_rate_text(item, 'attack_goal_success')} | {_rate_text(item, 'containment_rate')} | "
                f"{_rate_text(item, 'benign_completion')} | {_rate_text(item, 'false_hard_block')} | "
                f"{(item.get('external_effects') or {}).get('count', 0)} | {(item.get('latency_ms') or {}).get('p95', 0)} |"
            )
    lines.extend(["", "## Full Guard 的增量", ""])
    upgrades = summary.get("full_guard_upgrades_vs_pmkb") or []
    if upgrades:
        lines.extend(f"- `{item.get('scenario_id')}` / repeat {item.get('repeat_index')} / {item.get('approval_persona')}：目标成功 → 已约束" for item in upgrades)
    else:
        lines.append("当前子集未观察到额外升级。")
    trust_scope = report.get("trust_scope")
    if isinstance(trust_scope, dict):
        lines.extend(["", "## 审批信任范围变形测试", "", "| 变形 | 结果 |", "| --- | --- |"])
        lines.extend(f"| {key} | `{value}` |" for key, value in trust_scope.items())
    lines.extend([
        "", "## 安全边界", "",
        "- DSH 仅作为历史社区披露映射；官方 current master 已有浏览器令牌认证设计。本项目没有实现 DSH 原生适配，也不声称修复其控制面。",
        "- PraisonAI 与 mcp-shell 仍应优先升级到修复版本；RVGuarder 是危险下游动作的纵深/补偿控制。",
        "- 证明前提是危险调用经过可拦截 Hook，插件未被禁用；直接 OS 调用、绕过 Hook 或缺少来源上下文不在范围内。",
    ])
    return "\n".join(lines) + "\n"


def render_html(report: dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    metrics = summary.get("metrics") if isinstance(summary.get("metrics"), dict) else {}
    incident_rows: list[str] = []
    for incident in report.get("incidents", []):
        urls = " ".join(
            f'<a href="{html_escape(url)}">source</a>'
            for url in incident.get("source_urls", [])
            if str(url).lower().startswith(("https://", "http://"))
        )
        facts = " ".join(f"<li>{html_escape(fact)}</li>" for fact in incident.get("public_fact", []))
        incident_rows.append(f"<tr><td>{html_escape(incident.get('incident_id'))}</td><td>{html_escape(incident.get('title'))}</td><td>{urls}<ul>{facts}</ul></td></tr>")
    metric_rows: list[str] = []
    for mode in summary.get("modes", []):
        for persona in summary.get("approval_personas", []):
            item = ((metrics.get(mode) or {}).get(persona) or {})
            metric_rows.append(
                "<tr>" + "".join([
                    f"<td>{html_escape(mode)}</td>", f"<td>{html_escape(persona)}</td>",
                    f"<td>{html_escape(_rate_text(item, 'attack_goal_success'))}</td>",
                    f"<td>{html_escape(_rate_text(item, 'containment_rate'))}</td>",
                    f"<td>{html_escape(_rate_text(item, 'benign_completion'))}</td>",
                    f"<td>{html_escape(_rate_text(item, 'false_hard_block'))}</td>",
                    f"<td>{html_escape((item.get('external_effects') or {}).get('count', 0))}</td>",
                    f"<td>{html_escape((item.get('latency_ms') or {}).get('p95', 0))}</td>",
                ]) + "</tr>"
            )
    upgrade_rows = "".join(
        f"<li>{html_escape(item.get('scenario_id'))} / repeat {html_escape(item.get('repeat_index'))} / {html_escape(item.get('approval_persona'))}</li>"
        for item in summary.get("full_guard_upgrades_vs_pmkb", [])
    ) or "<li>当前子集未观察到额外升级。</li>"
    trust_scope = report.get("trust_scope") if isinstance(report.get("trust_scope"), dict) else {}
    trust_rows = "".join(f"<tr><td>{html_escape(key)}</td><td>{html_escape(value)}</td></tr>" for key, value in trust_scope.items())
    return """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>RVGuarder 办公安全价值实验</title>
<style>body{font-family:system-ui,sans-serif;max-width:1180px;margin:2rem auto;padding:0 1rem;color:#202124}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #ccd0d5;padding:.5rem;text-align:left;vertical-align:top}th{background:#f3f5f7}.note{background:#fff8e1;padding:1rem;border-left:4px solid #d99b00}</style></head>
<body><h1>RVGuarder 个人办公安全价值小实验</h1>
<p class="note">公开漏洞派生的封闭回放：不会启动 shell，不连接真实网络，不写入真实业务系统。外发只进入本地 capture sink，报告只保留分类与计数。</p>
<h2>公开事件与映射边界</h2><table><thead><tr><th>事件</th><th>标题</th><th>来源与事实</th></tr></thead><tbody>__INCIDENTS__</tbody></table>
<h2>模式 / 审批人格对比</h2><table><thead><tr><th>模式</th><th>审批人格</th><th>attack_goal_success</th><th>containment_rate</th><th>benign_completion</th><th>false_hard_block</th><th>模拟外发命中（本地 sink）</th><th>before p95 ms</th></tr></thead><tbody>__METRICS__</tbody></table>
<h2>Full Guard 增量</h2><ul>__UPGRADES__</ul>
<h2>审批信任范围变形测试</h2><table><thead><tr><th>变形</th><th>结果</th></tr></thead><tbody>__TRUST__</tbody></table>
<h2>解释边界</h2><ul><li>DSH 仅用于历史社区披露的下游后果映射；当前官方设计已有浏览器令牌认证，本轮没有 DSH 原生适配。</li><li>PraisonAI 与 mcp-shell 应优先升级到修复版本；本项目是纵深/补偿控制。</li><li>保护前提：危险调用经过可拦截 Hook，插件没有被禁用或绕过；直接 OS 调用不在证明范围。</li></ul>
</body></html>""".replace("__INCIDENTS__", "".join(incident_rows)).replace("__METRICS__", "".join(metric_rows)).replace("__UPGRADES__", upgrade_rows).replace("__TRUST__", trust_rows)


def write_report_bundle(report: dict[str, Any], output_dir: str | Path) -> dict[str, str]:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    summary_path = destination / "summary.json"
    raw_path = destination / "raw.jsonl"
    markdown_path = destination / "report.md"
    html_path = destination / "report.html"
    manifest_path = destination / "manifest.json"
    summary_path.write_text(json.dumps(report.get("summary", {}), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    rows = report.get("results") if isinstance(report.get("results"), list) else []
    raw_path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    html_path.write_text(render_html(report), encoding="utf-8")
    manifest = {"schema_version": 2, "artifact_files": [summary_path.name, raw_path.name, markdown_path.name, html_path.name], "incident_ids": [item.get("incident_id") for item in report.get("incidents", [])]}
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"manifest": str(manifest_path), "summary": str(summary_path), "raw": str(raw_path), "markdown": str(markdown_path), "html": str(html_path)}


def _rate_text(metrics: dict[str, Any], key: str) -> str:
    item = metrics.get(key) if isinstance(metrics.get(key), dict) else {}
    return f"{item.get('count', 0)} ({float(item.get('rate', 0.0)) * 100:.0f}%)"
