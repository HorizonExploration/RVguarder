"""分split冻结真实原生矩阵；进程隔离组件配置，原始运行一次且不覆盖。"""
from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path

from testlab.office_chain.arms import arm_spec, component_matrix
from testlab.office_chain.authorized_driver import run_authorized_scenario, resolve_toolchain
from testlab.office_chain.native_oracles import evaluate_native_oracles, validate_observation_inputs


def sha(path: Path) -> str:
    """文件字节hash进入冻结清单。"""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_job(job: dict) -> dict:
    """每个worker拥有自己的组件门、Gateway、Docker沙箱和宿主授权库。"""
    scenario, arm = job["scenario"], job["arm"]
    raw = Path(job["raw"])
    disabled = arm_spec(arm).disabled_components
    observation = json.loads(raw.read_text()) if raw.exists() else run_authorized_scenario(scenario,
        output=raw, rules_path=Path(job["rules"]), arm=arm, disabled=disabled, recording=job["recording"])
    row = {"scenario_id": scenario["scenario_id"], "workflow": scenario["workflow"],
        "variant": scenario["variant"], "mechanism": scenario["mechanism"], "arm": arm, "raw": str(raw),
        **evaluate_native_oracles(scenario, observation)}
    try:
        row["input_verification"] = validate_observation_inputs(scenario, observation, arm=arm, disabled=disabled)
        if observation["rules_sha256"] != job["rules_sha256"]:
            raise ValueError("rules hash mismatch")
    except ValueError as error:
        row.update(admitted=False, input_verification_error=str(error))
    return row


def main() -> None:
    """先保存冻结清单，再交错执行；holdout效果只在全批完成后写一次。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--recording", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--split", choices=("calibration", "holdout"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, choices=(1, 2), default=2)
    args = parser.parse_args()
    matrix = json.loads(args.inputs.read_text())
    if matrix.get("status") not in {"native_mapped_calibration", "frozen_holdout_ready"}:
        parser.error("native mapping/exclusion pre-registration missing")
    if args.split == "holdout" and matrix["status"] != "frozen_holdout_ready":
        parser.error("holdout requires completed calibration and final freeze")
    all_scenarios = [s for s in matrix["scenarios"] if s["split"] == args.split]
    admitted = [s for s in all_scenarios if s["native_comparability"]["status"] == "eligible"]
    exclusions = [s for s in all_scenarios if s not in admitted]
    recording = json.loads(args.recording.read_text())
    if recording["native_inputs_sha256"] != sha(args.inputs) or recording["split"] != args.split:
        parser.error("recording input/split drift")
    files = sorted(set(Path("openclaw_guard").rglob("*.py")) | set(Path("openclaw_guard/policy/data").rglob("*.json"))
        | set(Path("policies").rglob("*.json")) | set(Path("testlab/office_chain").rglob("*.py"))
        | set(Path("testlab/office_chain/native_office_plugin").glob("*.js"))
        | {Path("testlab/office_chain/native_office_plugin/openclaw.plugin.json"), args.rules, args.inputs, args.recording, Path(__file__)})
    freeze = {"files": {str(p): sha(p) for p in files}, "split": args.split,
        "runtime_toolchain": json.loads(json.dumps(resolve_toolchain(), default=str)),
        "requested_semantic_model": recording.get("model_id"),
        "semantic_recording_sha256": sha(args.recording),
        "arm_components": component_matrix(), "planned_independent_scenarios": len(all_scenarios),
        "eligible_independent_scenarios": len(admitted), "planned_runs": len(admitted) * 5,
        "excluded_before_unblinding": [{"scenario_id": s["scenario_id"], **s["native_comparability"]} for s in exclusions],
        "native_approval_adjudication": "allow-once for each actual native prompt; no actual human decisions",
        "semantic_mode": "frozen replay of authorized deepseek/deepseek-v4-flash; online latency reported separately",
        "oracle_unblinding": "holdout outcome report written only after all raw runs finish",
        "release_qualified": False}
    args.output.mkdir(parents=True, exist_ok=True)
    frozen_path = args.output / "freeze.json"
    if frozen_path.exists():
        if json.loads(frozen_path.read_text()) != freeze:
            parser.error("freeze drift; preserve batch and create a new calibration instead")
    else:
        with frozen_path.open("x") as stream:
            stream.write(json.dumps(freeze, ensure_ascii=False, indent=2) + "\n")
    if (args.output / "results.json").exists():
        parser.error("completed batch must not be unblinded again or overwritten")
    jobs = []
    for index, scenario in enumerate(admitted):
        arms = ["B0", "P", "P+C", "P+S", "Full"]
        arms = arms[index % 5:] + arms[:index % 5]
        for arm in arms:
            jobs.append({"scenario": scenario, "arm": arm, "recording": recording,
                "rules": str(args.rules), "rules_sha256": sha(args.rules),
                "raw": str(args.output / "raw" / f"{arm}__{scenario['scenario_id']}.json")})
    results = []
    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(run_job, job) for job in jobs]
        for future in as_completed(futures):
            row = future.result()
            results.append(row)
            progress = {"completed_runs": len(results), "planned_runs": len(jobs), "split": args.split}
            (args.output / "progress.json").write_text(json.dumps(progress) + "\n")
            print(json.dumps(progress if args.split == "holdout" else row, ensure_ascii=False), flush=True)
    # Decision files must stay frozen for the entire native run.
    changed = [p for p, digest in freeze["files"].items() if sha(Path(p)) != digest]
    summary = {"split": args.split, "source_drift": changed, "freeze": str(frozen_path),
        "results": sorted(results, key=lambda r: (r["scenario_id"], r["arm"])), "release_qualified": False}
    with (args.output / "results.json").open("x") as stream:
        stream.write(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"completed": len(results), "admitted": sum(r["admitted"] for r in results), "source_drift": changed}), flush=True)


if __name__ == "__main__":
    main()
