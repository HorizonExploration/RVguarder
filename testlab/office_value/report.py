"""Markdown, HTML and machine-readable artifacts for the office replay."""

from __future__ import annotations

import json
from pathlib import Path
import shlex
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
    lines.extend(["", "## 独立场景结果（主表）", "",
                  "repeat 不增加独立样本量；" + _split_limit_note(summary) + "本表仅说明封闭回放中的观察，不估计真实环境拦截率。",
                  "", "| split | 模式 | 审批人格 | 攻击目标成功 | 正常完成 | 正常误硬阻断 | 攻击 sink 命中 | 独立场景 / 运行 |",
                  "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |"])
    for split, mode, persona, item in _split_cells(summary):
        lines.append(f"| {split} | {mode} | {persona} | {_scenario_rate_text(item, 'attack_goal_success')} | "
                     f"{_scenario_rate_text(item, 'benign_completion')} | {_scenario_rate_text(item, 'false_hard_block')} | "
                     f"{_scenario_rate_text(item, 'attack_sink_hit')} | {item.get('unique_scenario_count', 0)} / {item.get('run_count', 0)} |")
    lines.extend(["", "## 审批与效果诊断（调用／运行级，非独立安全样本）", "",
                  "阻断、审批拒绝、依赖跳过和沙箱错误可在同一运行中并存；此表是观察次数，不作攻击未达的单一因果归因。",
                  "", "| split | 模式 | 审批人格 | 审批请求 / eligible Hook 调用 | 审批拒绝 / 请求 | Guard 硬阻断运行 / 运行 | 依赖跳过运行 / 运行 | 效果错误运行 / 运行 | before p95 ms / 调用数 |",
                  "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |"])
    for split, mode, persona, item in _split_cells(summary):
        lines.append("| " + " | ".join([split, mode, persona, *_diagnostic_cells(item)]) + " |")
    lines.extend(["", "## 重复运行诊断（非独立样本）", "",
                  "下表按运行次数计数，仅供确定性与 Hook 性能诊断；约束率混合了审批拒绝和 Guard 决策，不作为插件独立拦截率。",
                  "", "| 模式 | 审批人格 | 攻击目标成功 | 目标未达且曾阻断 | 正常完成 | 误报硬阻断 | sink 总次数 | before p95 (ms) |", "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |"])
    for mode in summary.get("modes", []):
        for persona in summary.get("approval_personas", []):
            if mode == "pass_through" and persona != "risk_aware" and "risk_aware" in summary.get("approval_personas", []):
                continue
            item = ((metrics.get(mode) or {}).get(persona) or {})
            lines.append(
                f"| {mode} | {persona} | {_rate_text(item, 'attack_goal_success')} | {_rate_text(item, 'containment_rate')} | "
                f"{_rate_text(item, 'benign_completion')} | {_rate_text(item, 'false_hard_block')} | "
                f"{(item.get('external_effects') or {}).get('count', 0)} | {(item.get('latency_ms') or {}).get('p95', 0)} |"
            )
    lines.extend(["", "## Full Guard 独立场景增量", "",
                  "以下只统计同一场景所有 repeat 均为 PMKB 目标成功、Full Guard 目标未达的配对；不能据此把差异全部归因于 ChainRule。", ""])
    stable_upgrades = summary.get("full_guard_upgrade_scenarios") or []
    if stable_upgrades:
        lines.extend(f"- `{item.get('split')}` / `{item.get('scenario_id')}` / `{item.get('approval_persona')}`"
                     for item in stable_upgrades)
    else:
        lines.append("本次未观察到稳定的独立场景增量。")
    lines.extend(["", "### 重复运行明细", ""])
    upgrades = summary.get("full_guard_upgrades_vs_pmkb") or []
    if upgrades:
        lines.extend(f"- `{item.get('scenario_id')}` / repeat {item.get('repeat_index')} / {item.get('approval_persona')}：目标成功 → 目标未达；原因需看事件链" for item in upgrades)
    else:
        lines.append("当前子集未观察到额外升级。")
    lines.extend(["", "## 关键案例时间线", ""])
    seen_timeline: set[tuple[str, str]] = set()
    for row in report.get("results", []):
        key = (str(row.get("scenario_id")), str(row.get("approval_persona")))
        if row.get("mode") != "full_guard" or row.get("variant") != "attack" or key in seen_timeline:
            continue
        seen_timeline.add(key)
        steps = " → ".join(_timeline_step(call) for call in row.get("calls", []))
        lines.append(f"- `{row.get('scenario_id')}` / `{row.get('approval_persona')}`：{steps}；首次阻断步骤={row.get('blocked_at_step')}（不代表因果归因）；losses={','.join(row.get('losses') or []) or 'none'}")
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
    split_rows: list[str] = []
    diagnostic_rows: list[str] = []
    for split, mode, persona, item in _split_cells(summary):
        split_rows.append("<tr>" + "".join(
            f"<td>{html_escape(value)}</td>" for value in (
                split, mode, persona,
                _scenario_rate_text(item, "attack_goal_success"),
                _scenario_rate_text(item, "benign_completion"),
                _scenario_rate_text(item, "false_hard_block"),
                _scenario_rate_text(item, "attack_sink_hit"),
                f"{item.get('unique_scenario_count', 0)} / {item.get('run_count', 0)}",
            )) + "</tr>")
        diagnostic_rows.append("<tr>" + "".join(f"<td>{html_escape(value)}</td>"
                                                    for value in (split, mode, persona, *_diagnostic_cells(item))) + "</tr>")
    for mode in summary.get("modes", []):
        for persona in summary.get("approval_personas", []):
            if mode == "pass_through" and persona != "risk_aware" and "risk_aware" in summary.get("approval_personas", []):
                continue
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
    stable_upgrade_rows = "".join(
        f"<li>{html_escape(item.get('split'))} / {html_escape(item.get('scenario_id'))} / {html_escape(item.get('approval_persona'))}</li>"
        for item in summary.get("full_guard_upgrade_scenarios", [])
    ) or "<li>本次未观察到稳定的独立场景增量。</li>"
    trust_scope = report.get("trust_scope") if isinstance(report.get("trust_scope"), dict) else {}
    trust_rows = "".join(f"<tr><td>{html_escape(key)}</td><td>{html_escape(value)}</td></tr>" for key, value in trust_scope.items())
    timeline_rows: list[str] = []
    seen_timeline: set[tuple[str, str]] = set()
    for row in report.get("results", []):
        key = (str(row.get("scenario_id")), str(row.get("approval_persona")))
        if row.get("mode") != "full_guard" or row.get("variant") != "attack" or key in seen_timeline:
            continue
        seen_timeline.add(key)
        steps = " → ".join(_timeline_step(call) for call in row.get("calls", []))
        timeline_rows.append(f"<tr><td>{html_escape(row.get('scenario_id'))}</td><td>{html_escape(row.get('approval_persona'))}</td><td>{html_escape(steps)}</td><td>{html_escape(row.get('blocked_at_step'))}</td></tr>")
    return """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>RVGuarder 办公安全价值实验</title>
<style>body{font-family:system-ui,sans-serif;max-width:1180px;margin:2rem auto;padding:0 1rem;color:#202124}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #ccd0d5;padding:.5rem;text-align:left;vertical-align:top}th{background:#f3f5f7}.note{background:#fff8e1;padding:1rem;border-left:4px solid #d99b00}</style></head>
<body><h1>RVGuarder 个人办公安全价值小实验</h1>
<p class="note">公开漏洞派生的封闭回放：不会启动 shell，不连接真实网络，不写入真实业务系统。外发只进入本地 capture sink，报告只保留分类与计数。</p>
<h2>公开事件与映射边界</h2><table><thead><tr><th>事件</th><th>标题</th><th>来源与事实</th></tr></thead><tbody>__INCIDENTS__</tbody></table>
<h2>独立场景结果（主表）</h2><p>repeat 不增加独立样本量；__SPLIT_NOTE__结果仅限封闭回放，不估计真实环境拦截率。</p><table><thead><tr><th>split</th><th>模式</th><th>审批人格</th><th>攻击目标成功</th><th>正常完成</th><th>正常误硬阻断</th><th>攻击 sink 命中</th><th>独立场景 / 运行</th></tr></thead><tbody>__SPLIT_METRICS__</tbody></table>
<h2>审批与效果诊断（调用／运行级）</h2><p>以下观察可并存，不作攻击未达的单一因果归因。</p><table><thead><tr><th>split</th><th>模式</th><th>审批人格</th><th>审批请求 / eligible 调用</th><th>审批拒绝 / 请求</th><th>Guard 阻断运行 / 运行</th><th>依赖跳过运行 / 运行</th><th>效果错误运行 / 运行</th><th>before p95 ms / 调用数</th></tr></thead><tbody>__DIAGNOSTICS__</tbody></table>
<h2>重复运行诊断（非独立样本）</h2><p>约束率混合审批拒绝与 Guard 决策，不代表插件独立拦截率。</p><table><thead><tr><th>模式</th><th>审批人格</th><th>attack_goal_success</th><th>containment_rate</th><th>benign_completion</th><th>false_hard_block</th><th>模拟外发命中（本地 sink）</th><th>before p95 ms</th></tr></thead><tbody>__METRICS__</tbody></table>
<h2>Full Guard 独立场景增量</h2><p>仅统计所有 repeat 均有相同方向差异的配对；不能把差异全部归因于 ChainRule。</p><ul>__STABLE_UPGRADES__</ul><h3>重复运行明细</h3><ul>__UPGRADES__</ul>
<h2>关键案例时间线</h2><p>首次阻断步骤不是攻击目标未达的因果归因。</p><table><thead><tr><th>场景</th><th>审批人格</th><th>工具链与最终动作</th><th>首次阻断步骤</th></tr></thead><tbody>__TIMELINE__</tbody></table>
<h2>审批信任范围变形测试</h2><table><thead><tr><th>变形</th><th>结果</th></tr></thead><tbody>__TRUST__</tbody></table>
<h2>解释边界</h2><ul><li>DSH 仅用于历史社区披露的下游后果映射；当前官方设计已有浏览器令牌认证，本轮没有 DSH 原生适配。</li><li>PraisonAI 与 mcp-shell 应优先升级到修复版本；本项目是纵深/补偿控制。</li><li>保护前提：危险调用经过可拦截 Hook，插件没有被禁用或绕过；直接 OS 调用不在证明范围。</li></ul>
</body></html>""".replace("__INCIDENTS__", "".join(incident_rows)).replace("__SPLIT_NOTE__", html_escape(_split_limit_note(summary))).replace("__SPLIT_METRICS__", "".join(split_rows)).replace("__DIAGNOSTICS__", "".join(diagnostic_rows)).replace("__METRICS__", "".join(metric_rows)).replace("__STABLE_UPGRADES__", stable_upgrade_rows).replace("__UPGRADES__", upgrade_rows).replace("__TIMELINE__", "".join(timeline_rows)).replace("__TRUST__", trust_rows)


def write_report_bundle(report: dict[str, Any], output_dir: str | Path) -> dict[str, str]:
    """Write one immutable replay evidence bundle to a new directory."""
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=False)
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
    policy_versions = sorted({str(policy.get("policy_version"))
                              for row in rows for call in row.get("calls", [])
                              for policy in [(call.get("evidence") or {}).get("policy_decision")]
                              if isinstance(policy, dict) and policy.get("policy_version")})
    run_spec = report.get("run_spec") if isinstance(report.get("run_spec"), dict) else {}
    rerun_command = None
    if run_spec.get("built_in_scenarios"):
        rerun_output = destination.with_name(destination.name + "-rerun")
        rerun_command = " ".join([
            "python -m testlab.office_value.run",
            "--mode", shlex.quote(str(run_spec.get("mode", "all"))),
            "--approval-persona", shlex.quote(str(run_spec.get("approval_persona", "all"))),
            "--split", shlex.quote(str(run_spec.get("split", "all"))),
            "--repeat", shlex.quote(str(run_spec.get("repeats", 1))),
            "--output", shlex.quote(str(rerun_output)),
            "--root", shlex.quote("/tmp/rvguard-office-value-v3-rerun"),
        ])
    manifest = {"schema_version": 3, "scenario_schema_version": report.get("scenario_schema_version"),
                "scenario_digest": report.get("scenario_digest"), "policy_versions": policy_versions,
                "run_spec": run_spec, "rerun_command": rerun_command,
                "artifact_files": [summary_path.name, raw_path.name, markdown_path.name, html_path.name],
                "incident_ids": [item.get("incident_id") for item in report.get("incidents", [])]}
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"manifest": str(manifest_path), "summary": str(summary_path), "raw": str(raw_path), "markdown": str(markdown_path), "html": str(html_path)}


def _rate_text(metrics: dict[str, Any], key: str) -> str:
    item = metrics.get(key) if isinstance(metrics.get(key), dict) else {}
    rate = item.get("rate")
    return "N/A" if rate is None else f"{item.get('count', 0)} ({float(rate) * 100:.0f}%)"


def _scenario_rate_text(cell: dict[str, Any], key: str) -> str:
    """Render one independent-scenario ratio with its actual denominator."""
    metric = cell.get(key) if isinstance(cell.get(key), dict) else {}
    rate = metric.get("rate")
    if rate is None:
        return "N/A"
    return f"{metric.get('count', 0)}/{metric.get('denominator', 0)} ({float(rate) * 100:.0f}%)"


def _split_cells(summary: dict[str, Any]) -> list[tuple[str, str, str, dict[str, Any]]]:
    """Return display arms while folding the duplicate no-approval baseline."""
    cells: list[tuple[str, str, str, dict[str, Any]]] = []
    for split, modes in (summary.get("by_split") or {}).items():
        for mode, personas in modes.items():
            for persona, item in personas.items():
                if mode == "pass_through" and persona != "risk_aware" and "risk_aware" in personas:
                    continue
                cells.append((split, mode, persona, item))
    return cells


def _split_limit_note(summary: dict[str, Any]) -> str:
    """Mention absent normal holdout samples only when the selected data has none."""
    holdout = (summary.get("by_split") or {}).get("holdout", {})
    cells = [item for personas in holdout.values() for item in personas.values()]
    if cells and all(int(item.get("unique_benign_count") or 0) == 0 for item in cells):
        return "当前 holdout 没有正常场景，相关比率记为 N/A。"
    return ""


def _timeline_step(call: dict[str, Any]) -> str:
    """Show a dependency skip without inventing a Hook decision."""
    if call.get("status") == "skipped_dependency":
        return f"{call.get('event_id')}:skipped_dependency"
    return f"{call.get('tool_name')}:{call.get('action')}"


def _diagnostic_cells(cell: dict[str, Any]) -> list[str]:
    """Format denominators for split-level operational observations."""
    approval = cell.get("approval_burden") or {}
    observed = cell.get("observed_events_run_level") or {}
    latency = cell.get("latency_ms") or {}
    runs = int(cell.get("run_count") or 0)
    requested = int(approval.get("required") or 0)
    samples = int(latency.get("sample_count") or 0)
    return [
        f"{requested}/{approval.get('eligible_calls', 0)}",
        f"{approval.get('denied', 0)}/{requested}" if requested else "N/A",
        f"{observed.get('guard_hard_block', 0)}/{runs}",
        f"{observed.get('dependency_skipped', 0)}/{runs}",
        f"{observed.get('effect_error', 0)}/{runs}",
        f"{latency.get('p95', 0)}/{samples}" if samples else "N/A",
    ]
