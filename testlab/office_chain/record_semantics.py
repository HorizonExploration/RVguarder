"""CLI：一次性离线录制语义 LLM 输出为冻结证据工件。

用法::

    python -m testlab.office_chain.record_semantics
    python -m testlab.office_chain.record_semantics --output testlab/office_chain/semantic_recording.json
    python -m testlab.office_chain.record_semantics --dry-run   # 不调网络，仅本地 fallback 条目

真实录制需要访问 DeepSeek（从 ``.env`` / 环境读取 ``DEEPSEEK_API_KEY``、
``DEEPSEEK_BASE_URL``、``DEEPSEEK_MODEL``）。失败/超时的条目会如实记为
``llm_status: "fallback"``，绝不伪造 ``success``。
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Sequence

from .semantic_recording import (
    DEFAULT_RECORDING_PATH,
    record_matrix,
    recording_digest,
    write_recording,
)


def _load_dotenv(path: Path) -> None:
    """Load ``KEY=VALUE`` lines into ``os.environ`` without overriding existing vars."""
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key or key in os.environ:
            continue
        os.environ[key] = value.strip().strip('"').strip("'")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="一次性离线录制语义 LLM 输出为冻结证据工件（office-attack-chain-v1）。"
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_RECORDING_PATH),
        help="录制工件输出路径（默认 testlab/office_chain/semantic_recording.json）",
    )
    parser.add_argument("--limit", type=int, default=None, help="最多录制的事件条目数")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="不调用网络，仅生成本地 fallback 条目，便于离线验证",
    )
    args = parser.parse_args(argv)

    _load_dotenv(Path.cwd() / ".env")

    recording = record_matrix(limit=args.limit, dry_run=args.dry_run)
    write_recording(recording, args.output)

    entries = recording["entries"]
    success = sum(1 for entry in entries.values() if entry.get("llm_status") == "success")
    fallback = len(entries) - success
    print(
        f"已写出 {len(entries)} 条语义录制到 {args.output} "
        f"(success={success}, fallback={fallback}, model={recording['model_id']})"
    )
    print(f"recording_digest={recording_digest(recording)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
