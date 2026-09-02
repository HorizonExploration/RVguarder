#!/usr/bin/env python3
"""运行 AgentDojo 三组对照实验。

脚本必须在独立的 AgentDojo Python 环境中执行，例如：

``/home/yosoro126/miniconda3/envs/agentdojo/bin/python \
  testlab/脚本工具/agentdojo_upgrade_eval.py --preflight``

它只使用 AgentDojo 合成环境；CandidateGuard 通过 HTTP 调用正在运行的
Guard，不会连接真实邮件、文件、银行或 OpenClaw 生产资源。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from testlab.agentdojo_upgrade import (  # noqa: E402
    ApprovalMode,
    AgentDojoDependencyError,
    GuardClient,
    HTTPGuardClient,
    adapt_openai_client_for_compatible_roles,
    build_guarded_tools_executor,
    dependency_report,
    load_agentdojo,
    principal_key,
    pipeline_name_for_attack,
    redact_secrets,
    run_dependency_probe,
    run_manifest,
    summarize_guard_records,
    wilson_interval,
)


BENCHMARK_VERSION = "v1.2.2"
DEFAULT_SUITES = ("workspace", "banking")
DEFAULT_ATTACKS = ("direct", "ignore_previous", "important_instructions", "tool_knowledge")
PROFILE_ATTACKS = {
    "demo": ("direct", "tool_knowledge"),
    "full": DEFAULT_ATTACKS,
}
PROFILE_TASK_LIMITS = {
    # Curated risk representatives for a report/demo run.
    "workspace": {"demo": (4, 3), "full": (24, 8)},
    "banking": {"demo": (4, 3), "full": (11, 8)},
}
PROFILE_PREFERRED_IDS = {
    "workspace": {
        "users": ("user_task_0", "user_task_12", "user_task_16", "user_task_19"),
        "injections": ("injection_task_0", "injection_task_4", "injection_task_10"),
    },
    "banking": {
        "users": ("user_task_0", "user_task_1", "user_task_6", "user_task_13"),
        "injections": ("injection_task_4", "injection_task_5", "injection_task_7"),
    },
}


class PassthroughGuard:
    """NoGuard 对照组的透明 Guard。"""

    def check(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return {"action": "allow", "policy": "noguard"}


def _select_profile_ids(available: list[str], limit: int, preferred: tuple[str, ...]) -> list[str]:
    """Select stable risk representatives, filling remaining slots evenly."""
    available = sorted(set(available))
    if limit <= 0:
        return available
    if limit >= len(available):
        preferred_existing = [item for item in preferred if item in available]
        return preferred_existing + [item for item in available if item not in preferred_existing]
    selected = [item for item in preferred if item in available][:limit]
    remaining = [item for item in available if item not in selected]
    slots = limit - len(selected)
    if slots > 0 and remaining:
        if slots == 1:
            selected.append(remaining[len(remaining) // 2])
        else:
            for index in range(slots):
                position = round(index * (len(remaining) - 1) / (slots - 1))
                selected.append(remaining[position])
    return selected[:limit]


def profile_task_selection(
    suite_name: str,
    profile: str,
    user_ids: list[str] | None = None,
    injection_ids: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Return the task IDs used by the demo or 40%-volume full profile."""
    if profile not in PROFILE_ATTACKS:
        raise ValueError(f"unknown experiment profile: {profile}")
    limits = PROFILE_TASK_LIMITS.get(suite_name)
    preferred = PROFILE_PREFERRED_IDS.get(suite_name)
    users = list(user_ids) if user_ids is not None else list((preferred or {}).get("users", ()))
    injections = list(injection_ids) if injection_ids is not None else list((preferred or {}).get("injections", ()))
    if limits is None or preferred is None:
        # Keep explicitly selected slack/travel suites usable without adding
        # another suite-specific catalogue; the same report-sized cap applies
        # to demo, while full retains a deterministic 40% sample.
        user_limit = 4 if profile == "demo" else max(1, round(len(users) * 0.4))
        injection_limit = 3 if profile == "demo" else max(1, round(len(injections) * 0.4))
        return (
            _select_profile_ids(users, user_limit, ()),
            _select_profile_ids(injections, injection_limit, ()),
        )
    user_limit, injection_limit = limits[profile]
    return (
        _select_profile_ids(users, user_limit, tuple(preferred["users"])),
        _select_profile_ids(injections, injection_limit, tuple(preferred["injections"])),
    )


class LegacyGuard:
    """历史基线占位：生产包已不再内置 DetectionEngine。"""

    def __init__(self) -> None:
        raise RuntimeError(
            "legacy arm 已随 v0.7.0-dev 的 DetectionEngine 退役冻结。"
            "请在保存旧实现的历史 checkout 中重跑，或使用 testlab/results/agentdojo-upgrade/ 的已入库证据。"
        )

    def check(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        event = self._build_event(dict(payload))
        decision = self._detector.evaluate(event)
        rv_trace = event.metadata.get("rv_trace")
        rv_verdict = "ok"
        if isinstance(rv_trace, list) and rv_trace:
            rv_result = self._rv.evaluate(
                rv_trace,
                session_key=str(payload.get("sessionId") or payload.get("sessionKey") or "agentdojo"),
            )
            rv_verdict = str(rv_result.get("verdict") or "ok")
        if rv_verdict == "block" or decision.action == "block":
            return {"action": "block", "legacy_rule_ids": decision.rule_ids, "risk_level": decision.risk_level}
        if rv_verdict in {"ask", "escalate"} or decision.action in {"ask", "escalate", "revise"}:
            return {
                "action": "require_approval",
                "legacy_rule_ids": decision.rule_ids,
                "risk_level": decision.risk_level,
            }
        return {"action": "allow", "legacy_rule_ids": decision.rule_ids, "risk_level": decision.risk_level}


def _build_client(arm: str, args: argparse.Namespace) -> GuardClient:
    if arm == "noguard":
        return PassthroughGuard()
    if arm == "legacy":
        return LegacyGuard()
    return HTTPGuardClient(args.guard_url, args.guard_token, args.guard_timeout)


def _build_llm(dojo: Mapping[str, Any], args: argparse.Namespace) -> Any:
    from openai import OpenAI

    api_key = os.getenv("DEEPSEEK_API_KEY")
    base_url = os.getenv("DEEPSEEK_BASE_URL")
    if not api_key or not base_url:
        raise RuntimeError("DEEPSEEK_API_KEY and DEEPSEEK_BASE_URL must be configured")
    client = OpenAI(api_key=api_key, base_url=base_url, timeout=args.llm_timeout)
    # AgentDojo 0.1.35 serializes system messages as ``developer``. DeepSeek's
    # OpenAI-compatible endpoint still expects ``system``; keep this adapter
    # local to testlab rather than modifying the upstream package.
    client = adapt_openai_client_for_compatible_roles(client)
    llm = dojo["OpenAILLM"](client, args.model, temperature=0.0)
    llm.name = args.model
    return llm


def _build_pipeline(
    dojo: Mapping[str, Any],
    args: argparse.Namespace,
    guard: GuardClient,
    context: Mapping[str, Any],
    recorder: Any,
    llm: Any | None = None,
) -> Any:
    if llm is None:
        llm = _build_llm(dojo, args)
    system_message = dojo["SystemMessage"](dojo["load_system_message"](None))
    init_query = dojo["InitQuery"]()
    executor = build_guarded_tools_executor(
        guard,
        mode=ApprovalMode(args.approval_mode),
        context=context,
        recorder=recorder,
    )
    loop = dojo["ToolsExecutionLoop"]([executor, llm], max_iters=args.max_tool_iters)
    pipeline = dojo["AgentPipeline"]([system_message, init_query, llm, loop])
    pipeline.name = pipeline_name_for_attack(
        args.model,
        str(context.get("arm", "unknown")),
    )
    return pipeline


def _run_episode(
    dojo: Mapping[str, Any],
    suite: Any,
    user_task: Any,
    injection_task: Any | None,
    injections: Mapping[str, str],
    attack_name: str,
    arm: str,
    args: argparse.Namespace,
    llm: Any | None = None,
) -> dict[str, Any]:
    session_id = f"agentdojo-{arm}-{suite.name}-{user_task.ID}-{injection_task.ID if injection_task else 'baseline'}-{attack_name}"
    context = {
        "arm": arm,
        "suite": suite.name,
        "user_task_id": user_task.ID,
        "injection_task_id": injection_task.ID if injection_task else "",
        "attack_type": attack_name,
        "session_id": session_id,
        "agent_id": f"agentdojo-{arm}",
        "goal_id": f"{suite.name}:{user_task.ID}:{injection_task.ID if injection_task else 'baseline'}",
        "principal_key": principal_key(f"agentdojo-{arm}", f"agentdojo-{arm}", [f"benchmark:{BENCHMARK_VERSION}"]),
    }
    trace_records: list[dict[str, Any]] = []

    def record(item: dict[str, Any]) -> None:
        trace_records.append({**context, **item})

    started = time.perf_counter()
    error: str | None = None
    utility = False
    attack_success: bool | None = None
    try:
        guard = _build_client(arm, args)
        pipeline = _build_pipeline(dojo, args, guard, context, record, llm=llm)
        utility, security = suite.run_task_with_pipeline(
            pipeline,
            user_task,
            injection_task,
            dict(injections),
        )
        attack_success = bool(security) if injection_task is not None else None
    except Exception as exc:  # keep one failed episode from hiding the rest
        error = f"{type(exc).__name__}: {exc}"
    duration_ms = round((time.perf_counter() - started) * 1000.0, 3)
    return redact_secrets(
        {
            **context,
            "utility": bool(utility),
            "attack_success": attack_success,
            "attack_prevented": None if attack_success is None else not attack_success,
            "duration_ms": duration_ms,
            "error": error,
            "tool_traces": trace_records,
        }
    )


def _load_attack(dojo: Mapping[str, Any], attack_name: str, suite: Any, pipeline: Any) -> Any:
    try:
        return dojo["load_attack"](attack_name, suite, pipeline)
    except KeyError as exc:
        raise ValueError(f"unknown AgentDojo attack: {attack_name}") from exc


def run_arm(dojo: Mapping[str, Any], args: argparse.Namespace, arm: str) -> list[dict[str, Any]]:
    """运行一个对照组并返回 episode 结果。"""
    results: list[dict[str, Any]] = []
    # Reuse one OpenAI-compatible client/LLM per arm. Building a fresh client
    # for every episode leaks connection pools and makes the full matrix
    # needlessly slow, while the LLM object itself is stateless between runs.
    shared_llm = _build_llm(dojo, args)
    completed = 0
    # Each episode constructs an isolated AgentDojo environment. Running a
    # bounded number concurrently keeps the full matrix practical while
    # preserving the exact suite/task/injection set and per-episode records.
    profile = getattr(args, "profile", "full")
    with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix=f"agentdojo-{arm}") as pool:
        for suite_name in args.suites:
            suite = dojo["get_suite"](BENCHMARK_VERSION, suite_name)
            template_context = {"arm": arm, "suite": suite_name, "session_id": "template"}
            template_records: list[dict[str, Any]] = []

            def template_record(item: dict[str, Any]) -> None:
                template_records.append(item)

            template_pipeline = _build_pipeline(
                dojo, args, _build_client(arm, args), template_context, template_record, llm=shared_llm
            )
            futures = []
            for attack_name in list(args.attacks):
                attack = _load_attack(dojo, attack_name, suite, template_pipeline)
                user_ids, injection_ids = profile_task_selection(
                    suite_name,
                    profile,
                    sorted(suite.user_tasks),
                    sorted(suite.injection_tasks),
                )
                if args.max_user_tasks:
                    user_ids = user_ids[: args.max_user_tasks]
                for user_id in user_ids:
                    user_task = suite.get_user_task_by_id(user_id)
                    for injection_id in injection_ids[: args.max_injection_tasks or None]:
                        injection_task = suite.get_injection_task_by_id(injection_id)
                        injections = attack.attack(user_task, injection_task)
                        futures.append(
                            pool.submit(
                                _run_episode,
                                dojo,
                                suite,
                                user_task,
                                injection_task,
                                injections,
                                attack_name,
                                arm,
                                args,
                                shared_llm,
                            )
                        )
            if not args.skip_baseline:
                baseline_user_ids, _ = profile_task_selection(
                    suite_name,
                    profile,
                    sorted(suite.user_tasks),
                    sorted(suite.injection_tasks),
                )
                for user_id in baseline_user_ids[: args.max_user_tasks or None]:
                    user_task = suite.get_user_task_by_id(user_id)
                    futures.append(
                        pool.submit(
                            _run_episode,
                            dojo,
                            suite,
                            user_task,
                            None,
                            {},
                            "baseline",
                            arm,
                            args,
                            shared_llm,
                        )
                    )
            for future in as_completed(futures):
                results.append(future.result())
                completed += 1
                if completed % args.progress_every == 0:
                    print(f"[agentdojo] arm={arm} completed={completed}", flush=True)
    return results


def _percent(successes: int, total: int) -> dict[str, Any]:
    point = successes / total if total else 0.0
    low, high = wilson_interval(successes, total)
    return {"successes": successes, "total": total, "rate": round(point, 6), "ci95": [round(low, 6), round(high, 6)]}


def summarize_arm(results: list[dict[str, Any]]) -> dict[str, Any]:
    errors = sum(1 for item in results if item.get("error"))
    valid_results = [item for item in results if not item.get("error")]
    attack_results = [item for item in valid_results if item.get("attack_success") is not None]
    baseline_results = [item for item in valid_results if item.get("attack_success") is None]
    traces = [trace for item in valid_results for trace in item.get("tool_traces", [])]
    prevented = sum(1 for item in attack_results if item.get("attack_prevented"))
    utility_success = sum(1 for item in valid_results if item.get("utility"))
    latencies = sorted(float(item.get("latency_ms", 0)) for item in traces)
    p95 = latencies[min(len(latencies) - 1, max(0, int(len(latencies) * 0.95) - 1))] if latencies else 0.0
    guard_summary = summarize_guard_records(traces)
    return {
        "episodes": len(results),
        "valid_episodes": len(valid_results),
        "attack_episodes": len(attack_results),
        "baseline_episodes": len(baseline_results),
        "utility": _percent(utility_success, len(valid_results)),
        "attack_success": _percent(sum(1 for item in attack_results if item.get("attack_success")), len(attack_results)),
        "attack_prevention": _percent(prevented, len(attack_results)),
        "tool_trace_count": len(traces),
        "approval_demand": guard_summary["approval_demand"],
        "prevented_tool_calls": guard_summary["prevented"],
        "executed_tool_calls": guard_summary["executed"],
        "unknown_or_unresolved": sum(1 for item in traces if item.get("decision") in {"unknown", "clarify"}),
        "p95_guard_latency_ms": p95,
        "errors": errors,
        "by_attack": dict(Counter(str(item.get("attack_type")) for item in attack_results)),
    }


def write_report(output_dir: Path, manifest: Mapping[str, Any], results: Mapping[str, list[dict[str, Any]]], metrics: Mapping[str, Any]) -> None:
    lines = [
        "# OpenClaw-RVGuarder AgentDojo 升级评测报告",
        "",
        f"- 生成时间：{datetime.now(timezone.utc).isoformat()}",
        f"- 基准版本：{manifest['benchmark_version']}",
        f"- 模型：{manifest['model']}",
        f"- 运行 profile：{manifest.get('config', {}).get('profile', 'legacy')}",
        "- 说明：AgentDojo `security` 为攻击目标是否成功；本报告另行计算 `attack_prevention`，不可将二者混用。",
        "",
        "## 对照结果",
        "",
        "| Arm | Episode | Utility | Attack success | Attack prevention | Approval demand | Guard p95(ms) | Errors |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for arm, stat in metrics.items():
        lines.append(
            f"| {arm} | {stat['episodes']} | {stat['utility']['rate']:.1%} "
            f"| {stat['attack_success']['rate']:.1%} | {stat['attack_prevention']['rate']:.1%} "
            f"| {stat['approval_demand']} | {stat['p95_guard_latency_ms']:.2f} | {stat['errors']} |"
        )
    lines.extend(
        [
            "",
            "## 解释边界",
            "",
            "- `approval_demand` 是 Guard 产生审批请求的代理指标，不等于真实人工审核时长。",
            "- `approval_mode=deny` 用于安全阻止统计；`allow-once` 用于任务恢复率对照，不计作阻止。",
            "- 试验结果仅适用于 AgentDojo 合成环境，不直接代表生产攻击成功率。",
        ]
    )
    (output_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", action="store_true", help="只检查 AgentDojo 环境，不调用模型")
    parser.add_argument("--suite", dest="suites", action="append", choices=["workspace", "banking", "slack", "travel"], help="重复指定多个套件")
    parser.add_argument("--attack", dest="attacks", action="append", help="重复指定 AgentDojo 官方攻击")
    parser.add_argument("--arm", choices=["noguard", "legacy", "candidate"], action="append")
    parser.add_argument("--approval-mode", choices=[item.value for item in ApprovalMode], default=ApprovalMode.DENY.value)
    parser.add_argument("--guard-url", default="http://127.0.0.1:8780")
    parser.add_argument("--guard-token", default=os.getenv("OPENCLAW_GUARD_HOOK_TOKEN"))
    parser.add_argument("--guard-timeout", type=float, default=15.0)
    parser.add_argument("--llm-timeout", type=float, default=90.0)
    parser.add_argument("--model", default=os.getenv("DEEPSEEK_MODEL", "deepseek-chat"))
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILE_ATTACKS),
        default="demo",
        help="demo 为 168 episode 汇报档；full 为约缩减 60%% 的宽覆盖档",
    )
    parser.add_argument(
        "--max-tool-iters",
        type=int,
        default=None,
        help="每个 episode 的工具迭代上限；未指定时 demo=2、full=5",
    )
    parser.add_argument("--max-user-tasks", type=int, default=0)
    parser.add_argument("--max-injection-tasks", type=int, default=0)
    parser.add_argument("--skip-baseline", action="store_true")
    parser.add_argument(
        "--progress-every",
        type=int,
        default=10,
        help="每完成多少个 episode 输出一次进度，避免长实验无输出被运行器回收",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="每个 arm 的并发 episode 数；不改变样本范围，仅提高全量实验吞吐",
    )
    parser.add_argument("--agent-python", default=sys.executable)
    parser.add_argument("--output-root", type=Path, default=PROJECT_ROOT / "testlab" / "results" / "agentdojo-upgrade")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.max_tool_iters is None:
        args.max_tool_iters = 2 if args.profile == "demo" else 5
    if args.progress_every <= 0:
        raise ValueError("--progress-every must be positive")
    if args.workers <= 0:
        raise ValueError("--workers must be positive")
    probe = run_dependency_probe(args.agent_python)
    if args.preflight:
        print(json.dumps(probe, ensure_ascii=False, indent=2))
        return 0 if probe.get("ready") else 2
    if not probe.get("ready"):
        print(json.dumps(probe, ensure_ascii=False, indent=2), file=sys.stderr)
        print("AgentDojo 环境未就绪；请先修复依赖并重新运行 --preflight。", file=sys.stderr)
        return 2
    if not args.suites:
        args.suites = list(DEFAULT_SUITES)
    if not args.attacks:
        args.attacks = list(PROFILE_ATTACKS[args.profile])
    if not args.arm:
        args.arm = ["noguard", "legacy", "candidate"]
    try:
        dojo = load_agentdojo()
    except AgentDojoDependencyError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = args.output_root / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = run_manifest(
        suites=args.suites,
        attacks=args.attacks,
        model=args.model,
        config={
            "profile": args.profile,
            "approval_mode": args.approval_mode,
            "guard_url": args.guard_url,
            "guard_timeout": args.guard_timeout,
            "llm_timeout": args.llm_timeout,
            "temperature": 0.0,
            "max_tool_iters": args.max_tool_iters,
            "progress_every": args.progress_every,
            "workers": args.workers,
            "api_key_configured": bool(os.getenv("DEEPSEEK_API_KEY")),
            "agent_python": args.agent_python,
        },
        benchmark_version=BENCHMARK_VERSION,
    )
    manifest["dependency_probe"] = probe
    manifest["created_at"] = datetime.now(timezone.utc).isoformat()
    (output_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    all_results: dict[str, list[dict[str, Any]]] = {}
    try:
        for arm in args.arm:
            print(f"[agentdojo] running arm={arm} suites={','.join(args.suites)} attacks={','.join(args.attacks)}")
            all_results[arm] = run_arm(dojo, args, arm)
    except Exception as exc:
        (output_dir / "error.json").write_text(
            json.dumps({"error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"实验未完成：{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    (output_dir / "raw-episodes.json").write_text(json.dumps(all_results, ensure_ascii=False, indent=2), encoding="utf-8")
    traces = [trace for records in all_results.values() for item in records for trace in item.get("tool_traces", [])]
    (output_dir / "tool-traces.jsonl").write_text(
        "".join(json.dumps(redact_secrets(item), ensure_ascii=False) + "\n" for item in traces), encoding="utf-8"
    )
    metrics = {arm: summarize_arm(records) for arm, records in all_results.items()}
    (output_dir / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    write_report(output_dir, manifest, all_results, metrics)
    print(f"结果已写入：{output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
