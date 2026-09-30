"""五臂实验编排 CLI（office-attack-chain-v1）。

用法::

    python -m testlab.office_chain.run --output <bundle_dir> [选项]

选项：
    --arms B0,P,P+S,P+C,Full       要运行的臂（默认全部五臂）
    --scenarios <id,...>           只运行指定场景
    --split calibration|holdout|all    按矩阵 split 过滤（默认 all）
    --repeats N                    每个（臂, 场景）重复次数（默认 1）
    --timeout SEC                  单个会话段 Agent 超时（默认 300）
    --approval-policy allow-once|deny  原生审批人格（默认 allow-once）
    --dry-run                      不启动任何进程，只打印计划与配置等价性校验
    --check                        只做环境与配置校验，不运行场景

编排纪律：

- 单臂串行；端口动态分配；每个（臂, 场景, 重复）使用一棵独立临时运行根，结束立即整体清理。
- 每个臂运行前用 :func:`arms.assert_arm_equivalence` 校验五臂原生配置等价性，不通过则中止。
- 统一记录由 :func:`records.build_run_record` 归一化，落盘为扁平的 ``raw/<arm>__<id>__r<n>.json``。
- 指标（:mod:`metrics`）与预注册门槛（:mod:`gates`）只从统一记录派生，报告（:mod:`report`）
  再由同一份指标渲染，避免出现"报告口径"与"判定口径"两个版本。
- 结束时用 :func:`artifacts.write_immutable_bundle` 一次性写出整个 bundle（拒绝覆盖既有目录）。
- 失败/中断时把已完成的部分结果与失败原因如实写入 bundle，summary 中标记场景 ``error``。
"""

from __future__ import annotations

import argparse
import json
import signal
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence

from . import arms as arms_module
from .artifacts import build_manifest, source_revision, write_immutable_bundle
from .gates import evaluate_gates
from .guard_driver import SANDBOX_IMAGE, cleanup_new_sandboxes, run_scenario_guard
from .matrix import SUITE_ID, load_matrix, matrix_digest, scenario_index
from .metrics import compute_metrics
from .native_baseline import default_plugin_dir, resolve_b0_config
from .office_driver import _docker_ps_ids, run_scenario_b0, resolve_toolchain
from .records import build_run_record, dump_records, summarise_records
from .report import render_markdown
from .semantic_recording import load_recording, recording_digest


_DEFAULT_ARMS = "B0,P,P+S,P+C,Full"

#: bundle 的代码修订范围：报告由哪一版套件与策略代码产生，必须可复核。
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SOURCE_PATHS: tuple[str, ...] = (
    "testlab/office_chain",
    "openclaw_guard/engine/experiment_components.py",
    "openclaw_guard/engine/pipeline.py",
    "openclaw_guard/engine/semantic_enhancer.py",
    "openclaw_guard/engine/semantic_models.py",
    "openclaw_guard/integrations/tool_hook_bridge.py",
    "openclaw_guard/rv/rv_rules.json",
    "openclaw_guard/policy/data/permissions/catalog/operation-catalog.json",
    "openclaw_guard/services.py",
)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m testlab.office_chain.run",
        description="office-attack-chain-v1 五臂实验编排（真实 OpenClaw + RVguarder）。",
    )
    parser.add_argument("--output", default=None, help="bundle 输出目录（--check 时可省略）")
    parser.add_argument("--arms", default=_DEFAULT_ARMS, help="逗号分隔的臂名，例如 B0,P,P+S,P+C,Full")
    parser.add_argument("--scenarios", default=None, help="逗号分隔的场景 ID 白名单")
    parser.add_argument("--split", default="all", choices=("calibration", "holdout", "all"))
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--approval-policy", default="allow-once", choices=("allow-once", "deny"))
    parser.add_argument("--dry-run", action="store_true", help="不启动进程，只打印计划")
    parser.add_argument("--check", action="store_true", help="只做环境与配置校验")
    parser.add_argument(
        "--rule-revision",
        default="",
        help=(
            "规则修订披露：本轮的检测规则相对既有 calibration 结果做过何种修订。"
            "留空表示规则在本轮之前从未改动；填写后报告会在结论之前显著标注，"
            "使'看过结果再改规则'这件事无法被静默省略。"
        ),
    )
    return parser.parse_args(argv)


def _select_scenarios(
    matrix: dict[str, Any], *, split: str, only: list[str] | None,
) -> list[dict[str, Any]]:
    scenarios = [row for row in matrix.get("scenarios", []) if isinstance(row, dict)]
    if split != "all":
        scenarios = [row for row in scenarios if row.get("split") == split]
    if only:
        wanted = set(only)
        scenarios = [row for row in scenarios if str(row.get("scenario_id")) in wanted]
    return scenarios


def _arm_configs(matrix: dict[str, Any], *, workspace: Path, profile_home: Path, provider_port: int) -> dict[str, dict[str, Any]]:
    """为五臂各构造一份原生配置，用于配置等价性校验。

    组件开关不改动 OpenClaw 原生配置，因此五臂应完全一致；guard 插件条目由
    :func:`arms.normalise_native_config` 剥离。这里用同一 workspace/provider 构造，
    以便校验逻辑本身可复现。
    """

    plugin_dir = default_plugin_dir()
    return {
        name: resolve_b0_config(
            workspace, plugin_dir=plugin_dir, profile_home=profile_home, provider_port=provider_port,
        )
        for name in arms_module.ARM_NAMES
    }


def _verify_arm_equivalence(*, tmp_root: Path) -> dict[str, str]:
    workspace = tmp_root / "equivalence-workspace"
    profile_home = tmp_root / "equivalence-profile"
    configs = _arm_configs(
        {}, workspace=workspace, profile_home=profile_home, provider_port=1,
    )
    return arms_module.assert_arm_equivalence(configs)


def _run_check() -> int:
    """只做环境与配置校验，不运行场景。"""

    print("[check] 解析运行时工具链…")
    toolchain = resolve_toolchain()
    print(
        f"[check] node={toolchain['node_version']} (admission_ok={toolchain['node_admission_ok']}) "
        f"openclaw={toolchain['openclaw_version']} docker={toolchain['docker_version']}"
    )
    if not toolchain.get("node_admission_ok"):
        print("[check] 失败：node 不满足 OpenClaw 准入（需 >=24.16.0 <25 或 >=26.1.0）", file=sys.stderr)
        return 1

    print("[check] 加载并校验场景矩阵…")
    matrix = load_matrix()
    index = scenario_index(matrix)
    print(f"[check] 场景数={len(index)} matrix_digest={matrix_digest(matrix)[:16]}…")

    print("[check] 加载语义录制工件…")
    recording = load_recording()
    entries = recording.get("entries", {})
    success = sum(1 for entry in entries.values() if entry.get("llm_status") == "success")
    print(f"[check] 录制条目={len(entries)} success={success} digest={recording_digest(recording)[:16]}…")

    print("[check] 校验五臂原生配置等价性…")
    with tempfile.TemporaryDirectory(prefix="office-chain-check-") as tmp:
        projections = _verify_arm_equivalence(tmp_root=Path(tmp))
    print(f"[check] 五臂投影一致：{sorted(set(projections.values()))[0][:16]}…")

    print("[check] 通过。")
    return 0


def _run_dry_run(args: argparse.Namespace) -> int:
    """不启动任何进程，只打印计划与配置等价性校验结果。"""

    matrix = load_matrix()
    scenario_list = _select_scenarios(matrix, split=args.split, only=_split_csv(args.scenarios))
    arm_names = _split_csv(args.arms) or list(arms_module.ARM_NAMES)
    unknown = [name for name in arm_names if name not in arms_module.ARM_NAMES]
    if unknown:
        print(f"[dry-run] 未知臂：{', '.join(unknown)}", file=sys.stderr)
        return 1

    print(f"[dry-run] 输出目录：{args.output}")
    print(f"[dry-run] 臂：{', '.join(arm_names)}")
    print(f"[dry-run] split={args.split} repeats={args.repeats} timeout={args.timeout} approval_policy={args.approval_policy}")
    print(f"[dry-run] 计划运行 {len(arm_names) * len(scenario_list) * args.repeats} 次（臂×场景×重复）")
    for scenario in scenario_list:
        tools = [event.get("hook_payload", {}).get("toolName") for event in scenario.get("events", [])]
        print(f"  - {scenario.get('scenario_id')} [{scenario.get('split')}/{scenario.get('variant')}] tools={tools}")

    print(
        f"[dry-run] 沙箱镜像：{SANDBOX_IMAGE}"
    )
    with tempfile.TemporaryDirectory(prefix="office-chain-dryrun-") as tmp:
        projections = _verify_arm_equivalence(tmp_root=Path(tmp))
    print(f"[dry-run] 五臂配置等价：OK（投影 {sorted(set(projections.values()))[0][:16]}…）")
    print("[dry-run] 未启动任何进程，未产生 bundle。")
    return 0


def _split_csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    items = [item.strip() for item in value.split(",") if item.strip()]
    return items or None


def _run_suite(args: argparse.Namespace, bundle_dir: Path) -> int:
    if not args.output:
        print("必须提供 --output <bundle_dir>", file=sys.stderr)
        return 2
    if args.repeats < 1:
        print("--repeats 必须 >= 1", file=sys.stderr)
        return 2

    matrix = load_matrix()
    scenario_list = _select_scenarios(matrix, split=args.split, only=_split_csv(args.scenarios))
    arm_names = _split_csv(args.arms) or list(arms_module.ARM_NAMES)
    unknown = [name for name in arm_names if name not in arms_module.ARM_NAMES]
    if unknown:
        print(f"未知臂：{', '.join(unknown)}", file=sys.stderr)
        return 2

    toolchain = resolve_toolchain()
    plugin_dir = default_plugin_dir()
    recording = load_recording()
    command = "python -m testlab.office_chain.run " + " ".join(sys.argv[1:])

    # 中断安全：SIGINT/SIGTERM 转成 KeyboardInterrupt，保证 finally 清理与部分产物落盘。
    def _on_signal(signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt(f"收到信号 {signum}")

    previous_handlers: dict[int, Any] = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            previous_handlers[signum] = signal.signal(signum, _on_signal)
        except (ValueError, OSError):
            pass

    tmp_root = Path(tempfile.mkdtemp(prefix="office-chain-run-"))
    records: list[dict[str, Any]] = []
    raw_files: dict[str, Any] = {}
    failed: list[dict[str, Any]] = []
    interrupted = False

    try:
        for arm in arm_names:
            print(f"[run] 臂 {arm}：校验五臂配置等价性…")
            _verify_arm_equivalence(tmp_root=tmp_root / "equivalence")
            for scenario in scenario_list:
                scenario_id = str(scenario.get("scenario_id"))
                for repeat in range(1, args.repeats + 1):
                    working_root = tmp_root / arm / f"{scenario_id}-r{repeat}"
                    workspace = working_root / "workspace"
                    profile_home = working_root / "profile"
                    docker_before = _docker_ps_ids(toolchain)
                    try:
                        if arm == "B0":
                            payload = run_scenario_b0(
                                scenario,
                                workspace=workspace,
                                profile_home=profile_home,
                                toolchain=toolchain,
                                plugin_dir=plugin_dir,
                                timeout=args.timeout,
                                approval_policy=args.approval_policy,
                            )
                        else:
                            payload = run_scenario_guard(
                                scenario,
                                arm=arm,
                                workspace=workspace,
                                profile_home=profile_home,
                                toolchain=toolchain,
                                plugin_dir=plugin_dir,
                                working_root=working_root,
                                timeout=args.timeout,
                                approval_policy=args.approval_policy,
                            )
                    except Exception as exc:  # 单次运行失败：记录并继续。
                        payload = {"error": f"{type(exc).__name__}: {exc}", "events": []}
                        failed.append({
                            "arm": arm, "scenario_id": scenario_id, "repeat": repeat,
                            "error": payload["error"],
                        })
                        print(f"[run]   {arm}/{scenario_id}/r{repeat} 失败：{payload['error']}", file=sys.stderr)
                    finally:
                        cleanup_new_sandboxes(docker_before, toolchain=toolchain)
                        shutil.rmtree(working_root, ignore_errors=True)

                    record = build_run_record(
                        payload, scenario, arm=arm, repeat=repeat,
                        approval_policy=args.approval_policy,
                    )
                    records.append(record)
                    name = f"raw/{arm}__{scenario_id}__r{repeat}.json"
                    raw_files[name] = record
                    if payload.get("error"):
                        failed.append({
                            "arm": arm, "scenario_id": scenario_id, "repeat": repeat,
                            "error": payload["error"],
                        })
    except KeyboardInterrupt as exc:
        interrupted = True
        print(f"[run] 被中断：{exc}", file=sys.stderr)
    finally:
        for signum, handler in previous_handlers.items():
            try:
                signal.signal(signum, handler)
            except (ValueError, OSError):
                pass

    summary = {
        "suite_id": SUITE_ID,
        "arms": arm_names,
        "scenario_count": len(scenario_list),
        "repeats": args.repeats,
        "records": summarise_records(records),
        "failed": failed,
        "interrupted": interrupted,
    }

    # 指标与门槛：全部从统一记录派生，报告不另算一套口径。
    metrics = compute_metrics(records, matrix)
    gates = evaluate_gates(metrics)
    summary["gates_passed"] = gates["passed"]
    summary["failed_conditions"] = gates["failed_conditions"]
    summary["metrics_digest"] = metrics["metrics_digest"]

    manifest = build_manifest(
        suite_id=SUITE_ID,
        scenario_digest=matrix_digest(matrix),
        run_spec={
            "command": command,
            "arms": arm_names,
            "scenarios": [str(row.get("scenario_id")) for row in scenario_list],
            "split": args.split,
            "repeats": args.repeats,
            "timeout": args.timeout,
            "approval_policy": args.approval_policy,
            "rule_revision": args.rule_revision,
            "matrix_digest": matrix_digest(matrix),
            "arms_digest": arms_module.arms_digest(),
            "recording_digest": recording_digest(recording),
        },
        component_sets=arms_module.arms_manifest(),
        artifact_files=sorted([
            *raw_files, "manifest.json", "arms.json", "records.jsonl", "summary.json",
            "metrics.json", "gates.json", "report.md",
        ]),
        openclaw_version=str(toolchain.get("openclaw_version", "")),
        docker_version=str(toolchain.get("docker_version", "")),
        image=SANDBOX_IMAGE,
        claims={
            "no_real_external_side_effects": True,
            "statement": (
                "全部运行使用本地冻结轨迹 provider 与合成办公插件；外部副作用只写本地 receipts，"
                "无真实网络出站、无真实凭据、无真实 shell 提权。"
            ),
        },
        source_revision=source_revision(_REPO_ROOT, _SOURCE_PATHS),
    )

    report_markdown = render_markdown(
        metrics, gates, matrix, run_spec=manifest["run_spec"], manifest=manifest,
    )

    files: dict[str, Any] = dict(raw_files)
    files["manifest.json"] = manifest
    files["arms.json"] = arms_module.arms_manifest()
    files["records.jsonl"] = dump_records(records)
    files["summary.json"] = summary
    files["metrics.json"] = metrics
    files["gates.json"] = gates
    files["report.md"] = report_markdown

    try:
        written = write_immutable_bundle(bundle_dir, files)
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    print(f"[run] bundle 写出 {len(written)} 个文件到 {bundle_dir}")
    print(f"[run] 记录数={len(records)} 失败数={len(failed)} interrupted={interrupted}")
    print(f"[run] 门槛：{'通过' if gates['passed'] else '未通过'}；失败条件={gates['failed_conditions'] or '无'}")
    return 0 if not failed else 1


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)

    if args.check:
        return _run_check()
    if args.dry_run:
        return _run_dry_run(args)
    if not args.output:
        print("必须提供 --output <bundle_dir>", file=sys.stderr)
        return 2
    return _run_suite(args, Path(args.output))


if __name__ == "__main__":
    raise SystemExit(main())
