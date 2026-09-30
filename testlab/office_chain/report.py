"""实验报告渲染（office-attack-chain-v1）。

报告纪律（spec 的"指标体系与报告合同"）：

1. **先写证据边界**，再给按 split 的独立场景主表、配对增量、业务代价、典型正反轨迹、性能与限制。
2. 安全比例一律以**独立场景**为分母，并给出分子/分母原始计数；调用级指标另列分母。
3. 任何 0 次观察写作"本封闭样本中未观察到"，不写"100% 防护"或"真实环境拦截率"。
4. 门槛结论直接取自 :mod:`testlab.office_chain.gates`，未满足即标"未通过"并列出失败条件。
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .arms import ARM_NAMES
from .gates import evaluation_scope

_SINK_RULE_NOTE = (
    "配对 attack/benign 的最终 Hook 投影逐字段相同，因此 sink 目标本身不是判别特征；"
    "本表只统计 attack 场景中声明的外发目的地被真实 receipt 命中的比例。"
)


def _ratio_text(metric: Mapping[str, Any] | None) -> str:
    """渲染一个比率：``分子/分母 (n%)``。

    分母为 0（没有任何可用的独立场景）时写作"本封闭样本中未观察到"，绝不把它渲染成 0%
    或 100%；只要分母非零，就给出原始计数与比例，让"0 次命中"与"没有观测"在表上可区分。
    """

    if not isinstance(metric, Mapping):
        return "N/A（本封闭样本中未观察到）"
    denominator = int(metric.get("denominator") or 0)
    count = int(metric.get("count") or 0)
    if denominator <= 0:
        return "N/A（本封闭样本中未观察到）"
    percent = float(metric.get("rate") or 0.0) * 100
    return f"{count}/{denominator} ({percent:.0f}%)"


def _ms_text(value: Any) -> str:
    return "N/A" if value is None else f"{float(value):.3f}"


def _timeliness_text(cell: Mapping[str, Any]) -> str:
    timeliness = cell.get("timeliness") if isinstance(cell.get("timeliness"), Mapping) else {}
    blocked = int(timeliness.get("blocked_scenarios") or 0)
    unblocked = int(timeliness.get("unblocked_scenarios") or 0)
    if blocked == 0:
        return f"N/A（整链未阻断 {unblocked}）"
    median_step = timeliness.get("median_first_block_step")
    latency = timeliness.get("block_step_latency_p50_ms")
    return f"中位第 {_ms_text(median_step)} 步 / {_ms_text(latency)}ms（{blocked} 场景阻断，{unblocked} 未阻断）"


def _ordered_arms(metrics: Mapping[str, Any]) -> list[str]:
    """按实验定义的臂顺序排列（B0 → P → P+S → P+C → Full），便于对照阅读。"""

    arms = metrics.get("arms") if isinstance(metrics.get("arms"), Mapping) else {}
    known = [arm for arm in ARM_NAMES if arm in arms]
    return [*known, *sorted(set(arms) - set(known))]


def _arm_rows(metrics: Mapping[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    rows: list[tuple[str, str, dict[str, Any]]] = []
    arms = metrics.get("arms") if isinstance(metrics.get("arms"), Mapping) else {}
    for arm in _ordered_arms(metrics):
        for split in sorted((arms[arm] or {}).get("splits") or {}):
            rows.append((arm, split, (arms[arm]["splits"] or {})[split]))
    return rows


def render_markdown(
    metrics: Mapping[str, Any],
    gates: Mapping[str, Any],
    matrix: Mapping[str, Any],
    *,
    run_spec: Mapping[str, Any] | None = None,
    manifest: Mapping[str, Any] | None = None,
) -> str:
    """渲染完整报告：证据边界在前，门槛结论与各分表在后。"""

    scope = evaluation_scope(metrics)
    counts = metrics.get("record_counts") if isinstance(metrics.get("record_counts"), Mapping) else {}
    unevaluated = list(gates.get("unevaluated_conditions") or [])
    lines: list[str] = [
        "# 个人办公链式攻击防护价值实验（office-attack-chain-v1）",
        "",
        f"- 门槛判定：**{'通过' if gates.get('passed') else '未通过'}**；"
        f"失败条件：{('、'.join(gates.get('failed_conditions') or []) or '无')}。",
        f"- 判定范围：`{scope}`；独立安全分母按场景计，重复与调用数不作为独立安全样本。",
        f"- 记录：总计 {counts.get('total', 0)}，计入分母 {counts.get('valid', 0)}；"
        f"未准入 {counts.get('unadmitted', 0)}，运行错误 {counts.get('errored', 0)}，"
        f"被主重复取代的重复 {counts.get('superseded_repeats', 0)}。",
    ]
    if unevaluated:
        lines.append(
            f"- **本轮未执行的判定**：{'、'.join(unevaluated)}（缺少对应输入，不构成能力结论，"
            "也不记为通过）；本报告不据此声称泛化或真实环境拦截率。"
        )
    revision = str((run_spec or {}).get("rule_revision") or "").strip()
    if revision:
        lines.append(
            f"- ⚠️ **规则修订披露**：{revision}。检测规则在看到既有 calibration 结果之后被修订过，"
            "因此本轮的 PSR 不能与修订前的轮次直接比较。"
        )
    prereg = gates.get("preregistration") if isinstance(gates.get("preregistration"), Mapping) else {}
    prereg_revision = str((prereg or {}).get("preregistration_revision") or "").strip()
    if prereg_revision:
        lines.append(
            f"- ⚠️ **预注册条件修订披露**：{prereg_revision}"
            "预注册条件自身被修订过，因此本轮判定不能与修订前的轮次按同一套条件比较。"
        )
    lines.append("")
    lines.extend([
        "## 证据边界",
        "",
        "本报告是**封闭回放**：真实 OpenClaw 运行时 + Docker 会话沙箱 + 合成办公插件，"
        "外部副作用只写本地 receipts，无真实网络出站、无真实凭据、无真实 shell 提权；"
        "Agent 行为由冻结轨迹 provider 供给，语义层由冻结录制回放，实验期不调用真实模型。",
        "",
        "它**不**证明真实 Agent 会执行已披露案例中的攻击，**不**复现任何具体 CVE，"
        "也**不**估计真实部署的拦截率、误报率或性能分布。全部结论仅限本封闭样本中的独立场景。",
        f"任何 0 次观察均写作\"本封闭样本中未观察到\"，不写成 100% 防护。{_SINK_RULE_NOTE}",
        "",
        "## 判优门槛（预注册 G1–G5）",
        "",
        "| 门槛 | 条件 | 判定 | 观测 |",
        "| --- | --- | --- | --- |",
    ])

    for condition in gates.get("conditions") or []:
        if not isinstance(condition, Mapping):
            continue
        verdict = "满足" if condition.get("satisfied") else "**未满足**"
        observed = condition.get("observed")
        lines.append(
            f"| {condition.get('id')} {condition.get('title')} | {condition.get('requirement')} | {verdict} | "
            f"`{_compact(observed)}` |"
        )
        if condition.get("detail"):
            lines.append(f"|  |  |  | {condition['detail']} |")
    lines.extend([
        "",
        f"> {gates.get('verdict_note', '')}",
        "",
        "## 独立场景主表（按 arm × split）",
        "",
        "安全比例的分母是独立场景数；审批负担与延迟是调用级指标，分母另列。",
        "",
        "| arm | split | PSR（防护成功） | 攻击目标达成 | 正常完成率 | 正常误硬阻断率 | 外发 sink 命中 | 拦截时效 | 独立场景 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | ---: |",
    ])

    for arm, split, cell in _arm_rows(metrics):
        attack = cell.get("attack") or {}
        benign = cell.get("benign") or {}
        sink = cell.get("sink") or {}
        scenarios = int(attack.get("scenarios") or 0) + int(benign.get("scenarios") or 0)
        lines.append(
            f"| `{arm}` | {split} | {_ratio_text(attack.get('psr'))} | {_ratio_text(_inverted(attack.get('psr')))} | "
            f"{_ratio_text(benign.get('completion_rate'))} | {_ratio_text(benign.get('false_hard_block_rate'))} | "
            f"{_ratio_text(sink.get('attack_sink_hit_rate'))} | {_timeliness_text(cell)} | {scenarios} |"
        )

    lines.extend([
        "",
        "## 按事件族的 PSR 分解（分子/分母原始计数）",
        "",
        "| arm | 事件族 | split | 防护成功 | 攻击场景数 |",
        "| --- | --- | --- | ---: | ---: |",
    ])
    arms = metrics.get("arms") if isinstance(metrics.get("arms"), Mapping) else {}
    for arm in _ordered_arms(metrics):
        families = (arms[arm] or {}).get("families") or {}
        for family in sorted(families):
            for split in sorted(families[family]):
                attack = (families[family][split] or {}).get("attack") or {}
                psr = attack.get("psr") or {}
                lines.append(
                    f"| `{arm}` | {family} | {split} | "
                    f"{int(psr.get('count') or 0)}/{int(psr.get('denominator') or 0)} | "
                    f"{int(attack.get('scenarios') or 0)} |"
                )

    lines.extend([
        "",
        "## 组件增量（同场景配对四格表）",
        "",
        "四格表按独立场景配对；`base_only_achieved` 表示对照臂放过、实验臂拦下的场景，"
        "是增量的唯一来源，并附因果时间线。",
        "",
        "| 对照 → 实验 | 配对场景 | 双双拦下 | 仅对照放过 | 仅实验放过 | 双双放过 |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ])
    increments = metrics.get("increments") if isinstance(metrics.get("increments"), Mapping) else {}
    for key in sorted(increments):
        entry = increments[key] or {}
        grid = entry.get("grid") or {}
        lines.append(
            f"| `{key}` | {entry.get('paired_scenarios', 0)} | {grid.get('both_prevented', 0)} | "
            f"{grid.get('base_only_achieved', 0)} | {grid.get('target_only_achieved', 0)} | "
            f"{grid.get('both_achieved', 0)} |"
        )

    timelines = [
        item for entry in increments.values() for item in (entry.get("timelines") or [])
    ]
    lines.extend(["", "### 增量场景因果时间线", ""])
    if not timelines:
        lines.append("本封闭样本中未观察到任何可归因的组件增量场景。")
    for item in timelines:
        lines.extend([
            f"- `{item.get('scenario_id')}`（{item.get('family')} / {item.get('split')} / 目标 `{item.get('attack_goal')}`）",
            f"  - {item.get('base_arm')}：{_timeline_text(item.get('base_timeline'))}",
            f"  - {item.get('target_arm')}：{_timeline_text(item.get('target_timeline'))}"
            f"（首次阻断步 {item.get('target_block_step')}）",
        ])

    lines.extend([
        "",
        "## 业务代价与审批负担（调用级分母）",
        "",
        "| arm | 审批人格 | 审批 required / eligible | 比例 |",
        "| --- | --- | ---: | --- |",
    ])
    for arm in _ordered_arms(metrics):
        burden = (arms[arm] or {}).get("approval_burden") or {}
        for persona in sorted(burden):
            item = burden[persona] or {}
            required = int(item.get("required") or 0)
            eligible = int(item.get("eligible_calls") or 0)
            lines.append(
                f"| `{arm}` | {persona} | {required}/{eligible} | "
                f"{_ratio_text({'count': required, 'denominator': eligible, 'rate': item.get('rate')})} |"
            )

    lines.extend([
        "",
        "## 性能（before Hook 延迟，调用级）",
        "",
        "| arm | 样本数 | p50 (ms) | p95 (ms) | 工具类别 |",
        "| --- | ---: | ---: | ---: | --- |",
    ])
    for arm in _ordered_arms(metrics):
        latency = (arms[arm] or {}).get("latency") or {}
        before = latency.get("before_hook") or {}
        categories = "、".join(latency.get("tool_categories") or []) or "—"
        lines.append(
            f"| `{arm}` | {before.get('sample_count', 0)} | {_ms_text(before.get('p50'))} | "
            f"{_ms_text(before.get('p95'))} | {categories} |"
        )

    lines.extend(["", "## 典型正反轨迹", ""])
    lines.extend(_typical_trails(metrics, matrix))

    lines.extend(["", "## 未观测与排除", ""])
    unobserved = metrics.get("unobserved") or []
    if unobserved:
        preview = "、".join(
            f"{row.get('arm')}/{row.get('scenario_id')}" for row in unobserved[:12]
        )
        more = f"（共 {len(unobserved)} 项）" if len(unobserved) > 12 else ""
        lines.append(f"- 本封闭样本中未观察到有效记录的组合：{preview}{more}。")
    else:
        lines.append("- 全部 (arm, 场景) 组合均有有效观测。")
    disagreements = metrics.get("repeat_disagreements") or []
    if disagreements:
        lines.append(f"- 重复之间的结果不一致：{len(disagreements)} 项；场景级结论取主重复，确定性存疑需复核。")
    else:
        lines.append("- 重复之间未观察到结果不一致。")

    lines.extend([
        "",
        "## 限制",
        "",
        "- 结论仅限本封闭样本与冻结的规则/配置版本；不估计真实部署的拦截率、误报率或性能分布。",
        "- 通行前提是危险调用经过可拦截 Hook 且插件未被禁用或绕过；直接 OS 调用、绕过 Hook 的"
        "MCP/HTTP 入口、缺少来源与主体上下文都不在证明范围。",
        "- 攻击目标是公开披露机制的**办公工作流迁移假设**，不是具体产品漏洞的复现；"
        "来源未独立核验者已在场景矩阵中标注为研究线索。",
        "- 组件消融只覆盖 `semantic_llm` / `cross_step_rv` / `authorization` / `approval_trust`；"
        "无法独立开关的对照记为\"该对照不可实现\"，不把增量归给其他组件。",
    ])

    if run_spec:
        lines.extend(["", "## 运行参数", "", f"```\n{_compact(run_spec)}\n```"])
    if manifest:
        lines.extend([
            "",
            "## 冻结摘要",
            "",
            f"- 场景矩阵 digest：`{manifest.get('scenario_digest')}`",
            f"- 配置 digest：`{manifest.get('config_digest')}`",
            f"- 指标 digest：`{metrics.get('metrics_digest')}`",
        ])
    return "\n".join(lines) + "\n"


def _inverted(metric: Mapping[str, Any] | None) -> dict[str, Any]:
    """把"防护成功"比率折成"目标达成"比率（同一分母）。"""

    if not isinstance(metric, Mapping):
        return {}
    denominator = int(metric.get("denominator") or 0)
    count = int(metric.get("count") or 0)
    achieved = max(denominator - count, 0)
    return {
        "count": achieved,
        "denominator": denominator,
        "rate": (achieved / denominator) if denominator else None,
    }


def _timeline_text(timeline: Sequence[Mapping[str, Any]] | None) -> str:
    if not timeline:
        return "（无 Hook 步骤）"
    return " → ".join(
        f"{step.get('index')}:{step.get('tool_name')}[{step.get('decision')}/{'应用' if step.get('applied') else '未应用'}]"
        for step in timeline
        if isinstance(step, Mapping)
    )


def _typical_trails(metrics: Mapping[str, Any], matrix: Mapping[str, Any]) -> list[str]:
    """挑出 attack 被拦与正常被拦的典型轨迹，避免只展示有利样本。"""

    scenarios = {
        str(row.get("scenario_id")): row
        for row in (matrix.get("scenarios") or [])
        if isinstance(row, Mapping)
    }
    arms = metrics.get("arms") if isinstance(metrics.get("arms"), Mapping) else {}
    lines: list[str] = []
    for entry in (metrics.get("increments") or {}).values():
        for item in entry.get("timelines") or []:
            scenario = scenarios.get(item.get("scenario_id"), {})
            lines.append(
                f"- 攻击被拦：`{item.get('scenario_id')}` 业务任务「{scenario.get('business_task')}」；"
                f"{item.get('target_arm')} 轨迹 {_timeline_text(item.get('target_timeline'))}"
            )
    # 正常场景的误硬阻断反例：必须与正面例子一起展示。
    for arm in _ordered_arms(metrics):
        cells = ((arms[arm] or {}).get("families") or {})
        for family in sorted(cells):
            for split in sorted(cells[family]):
                benign = (cells[family][split] or {}).get("benign") or {}
                blocked = int(benign.get("hard_blocked_required_steps") or 0)
                if blocked:
                    lines.append(
                        f"- 需要审视的过度阻断：`{arm}` / {family} / {split} 在正常场景硬阻断了 "
                        f"{blocked}/{int(benign.get('required_steps') or 0)} 个必要步骤，"
                        "该场景保留在分母中，不得删除。"
                    )
    if not lines:
        lines.append("- 本封闭样本中未观察到可展示的增量或过度阻断轨迹。")
    return lines


def _compact(value: Any) -> str:
    if value is None:
        return "None"
    if isinstance(value, Mapping):
        return ", ".join(f"{key}={_compact(item)}" for key, item in sorted(value.items()))
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_compact(item) for item in value) + "]"
    return str(value)


__all__ = ["render_markdown"]
