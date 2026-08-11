#!/usr/bin/env python3
"""基线 DFA 离线训练脚本。

从审计日志 JSON 文件中提取正常会话 trace 序列，
经过 trace_abstractor 抽象后训练紧凑 DFA，保存到文件。

Usage:
    python scripts/train_baseline.py --input audit_normal.json --output baseline.json
    python scripts/train_baseline.py --input audit.json --output baseline.dfa.json
    python scripts/train_baseline.py --input audit.json --output baseline.json --verbose
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# 确保 openclaw_guard 在路径中
_SCRIPT_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from openclaw_guard.engine.trace_abstractor import abstract_trace
from openclaw_guard.engine.baseline_learner import BaselineLearner


def load_audit_traces(path: str | Path) -> list[list[dict]]:
    """从审计日志 JSON 文件加载会话 trace 列表。

    预期格式：
    [
      {
        "session_id": "sess-1",
        "rv_trace": [
          {"step_id": "s1", "event": "mail_send", "props": [...], ...},
          ...
        ]
      },
      ...
    ]

    也支持直接 JSON 数组格式：
    [
      [{"step_id": "s1", ...}, ...],
      ...
    ]
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"Expected JSON array, got {type(data).__name__}")

    traces: list[list[dict]] = []
    for item in data:
        if isinstance(item, list):
            # 直接是步骤列表
            traces.append(item)
        elif isinstance(item, dict):
            # 含 rv_trace 字段的会话记录
            rv = item.get("rv_trace")
            if isinstance(rv, list):
                traces.append(rv)
        else:
            print(f"Warning: skipping unrecognized item type: {type(item).__name__}")
    return traces


def main() -> None:
    parser = argparse.ArgumentParser(
        description="从审计日志训练基线行为 DFA",
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="输入审计日志 JSON 文件路径",
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="输出 DFA JSON 文件路径",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="打印详细统计信息",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"Error: input file not found: {input_path}")
        sys.exit(1)

    # 加载审计日志
    print(f"Loading audit traces from {input_path} ...")
    traces = load_audit_traces(input_path)
    print(f"Loaded {len(traces)} session traces.")

    if not traces:
        print("Error: no traces found in input file.")
        sys.exit(1)

    # 抽象
    print("Abstracting traces ...")
    symbol_traces = [abstract_trace(t) for t in traces]

    # 训练
    print("Training baseline DFA ...")
    learner = BaselineLearner()
    total_steps = 0
    for symbols in symbol_traces:
        total_steps += len(symbols)
        learner.add_trace(symbols)

    trie_size = learner.trie_size()
    dfa = learner.learn()
    dfa_stats = dfa.stats()

    # 保存
    output_path = Path(args.output)
    dfa.save(output_path)
    print(f"Saved DFA to {output_path}")

    if args.verbose:
        symbol_count = len(dfa.symbol_set)
        print(f"\n=== Training Summary ===")
        print(f"  Sessions:     {len(traces)}")
        print(f"  Total steps:  {total_steps}")
        print(f"  Unique symbols: {symbol_count}")
        print(f"  Trie nodes:   {trie_size}")
        print(f"  DFA states:   {dfa_stats['state_count']}")
        print(f"  DFA transitions: {dfa_stats['transition_count']}")
        if trie_size > 0:
            reduction = (1 - dfa_stats["state_count"] / trie_size) * 100
            print(f"  State reduction: {reduction:.1f}%")
        print(f"  Output file:  {output_path.resolve()}")

    print("Done.")


if __name__ == "__main__":
    main()
