#!/usr/bin/env python3
"""Replay a completed AgentDojo trace matrix through Guard arms.

This is a model-free supplement for runs interrupted by provider quota. It
reuses the exact tool traces emitted by a completed NoGuard arm, so it measures
Guard classification/latency on the full matrix without inventing agent
utility or security outcomes.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Mapping

# Allow direct execution from the repository root, matching the main
# AgentDojo evaluator's import behavior.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from testlab.agentdojo_upgrade import HTTPGuardClient, classify_guard_response, redact_secrets
from testlab.脚本工具.agentdojo_upgrade_eval import LegacyGuard


def _replay_episode(episode: Mapping[str, Any], arm: str, guard_url: str, token: str | None) -> dict[str, Any]:
    guard = HTTPGuardClient(guard_url, token, timeout=15.0) if arm == "candidate" else LegacyGuard()
    traces: list[dict[str, Any]] = []
    errors = 0
    for source in episode.get("tool_traces", []):
        payload = source.get("payload") if isinstance(source, Mapping) else None
        if not isinstance(payload, Mapping):
            continue
        try:
            response = dict(guard.check(payload))
            outcome = classify_guard_response(response)
            action_record = response.get("action_record")
            action_record = action_record if isinstance(action_record, Mapping) else {}
            nested = action_record.get("decision")
            nested = nested if isinstance(nested, Mapping) else {}
            risk_level = (
                response.get("risk_level") or response.get("riskLevel")
                or nested.get("risk_level") or nested.get("riskLevel")
            )
            rule_ids = (
                response.get("rule_ids") or response.get("ruleIds")
                or nested.get("rule_ids") or nested.get("ruleIds") or []
            )
            traces.append({
                "decision": outcome.decision,
                "executed": outcome.execute,
                "risk_level": risk_level,
                "rule_ids": rule_ids,
                "latency_ms": source.get("latency_ms", 0.0),
                "response": response,
                "payload": payload,
            })
        except Exception as exc:  # preserve one failed replay without hiding the matrix
            errors += 1
            traces.append({"decision": "error", "executed": False, "error": f"{type(exc).__name__}: {exc}"})
    return {
        "arm": arm,
        "suite": episode.get("suite"),
        "user_task_id": episode.get("user_task_id"),
        "injection_task_id": episode.get("injection_task_id"),
        "attack_type": episode.get("attack_type"),
        "trace_count": len(traces),
        "errors": errors,
        "tool_traces": traces,
    }


def _summarize(records: list[Mapping[str, Any]]) -> dict[str, Any]:
    traces = [trace for record in records for trace in record.get("tool_traces", [])]
    counts: dict[str, int] = {}
    for trace in traces:
        decision = str(trace.get("decision") or "unknown")
        counts[decision] = counts.get(decision, 0) + 1
    latencies = sorted(float(trace.get("latency_ms") or 0.0) for trace in traces)
    p95 = latencies[min(len(latencies) - 1, max(0, int(len(latencies) * 0.95) - 1))] if latencies else 0.0
    return {
        "episodes": len(records),
        "tool_trace_count": len(traces),
        "decision_counts": counts,
        "approval_demand": counts.get("ask", 0),
        "prevented_tool_calls": sum(1 for trace in traces if not trace.get("executed")),
        "executed_tool_calls": sum(1 for trace in traces if trace.get("executed")),
        "unknown_or_unresolved": counts.get("unknown", 0) + counts.get("clarify", 0),
        "p95_replay_latency_ms": p95,
        "errors": sum(int(record.get("errors") or 0) for record in records),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="completed NoGuard raw-episodes.json")
    parser.add_argument("--guard-url", default="http://127.0.0.1:8780")
    parser.add_argument("--guard-token", default=os.getenv("OPENCLAW_GUARD_HOOK_TOKEN"))
    parser.add_argument("--arm", action="append", choices=["legacy", "candidate"], default=None)
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument("--output-root", type=Path, default=Path("testlab/results/agentdojo-upgrade"))
    args = parser.parse_args()
    if args.workers <= 0:
        raise SystemExit("--workers must be positive")
    data = json.loads(args.source.read_text(encoding="utf-8"))
    episodes = data.get("noguard")
    if not isinstance(episodes, list):
        raise SystemExit("source must contain a noguard episode list")
    arms = args.arm or ["legacy", "candidate"]
    # Keep a deterministic, collision-free directory without depending on the
    # model run timestamp encoded in the source path.
    output_dir = args.output_root / f"replay-{args.source.parent.name}"
    output_dir.mkdir(parents=True, exist_ok=True)
    all_records: dict[str, list[dict[str, Any]]] = {}
    for arm in arms:
        records: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix=f"replay-{arm}") as pool:
            futures = [pool.submit(_replay_episode, episode, arm, args.guard_url, args.guard_token) for episode in episodes]
            for future in as_completed(futures):
                records.append(future.result())
        all_records[arm] = records
        print(f"[replay] arm={arm} episodes={len(records)}", flush=True)
    (output_dir / "raw-replay.json").write_text(
        json.dumps(redact_secrets(all_records), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    metrics = {arm: _summarize(records) for arm, records in all_records.items()}
    (output_dir / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    (output_dir / "manifest.json").write_text(
        json.dumps({
            "source": str(args.source),
            "source_episodes": len(episodes),
            "arms": arms,
            "workers": args.workers,
            "model_free": True,
            "note": "Guard classification replay only; source utility/security is not re-evaluated.",
        }, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"结果已写入：{output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
