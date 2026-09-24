"""CLI entry point: ``python -m testlab.office_value.run``."""

from __future__ import annotations

import argparse
import json

from .report import render_markdown, write_report_bundle
from .runner import APPROVAL_PERSONAS, MODES, run_experiment, run_trust_scope_checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the offline personal-office RVGuarder value replay")
    parser.add_argument("--mode", choices=["all", *MODES], default="all")
    parser.add_argument("--approval-persona", choices=["all", *APPROVAL_PERSONAS], default="all")
    parser.add_argument("--split", choices=["all", "calibration", "holdout"], default="all")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--scenario-path", help="explicit frozen scenario matrix JSON")
    parser.add_argument("--output", help="write summary.json, raw.jsonl and report.md to this directory")
    parser.add_argument("--root", help="base directory for disposable scenario sandboxes")
    args = parser.parse_args()

    report = run_experiment(mode=args.mode, approval_persona=args.approval_persona, split=args.split, repeats=args.repeat, root=args.root, scenario_path=args.scenario_path)
    report["trust_scope"] = run_trust_scope_checks()
    if args.output:
        paths = write_report_bundle(report, args.output)
        print(
            json.dumps(
                {"summary": report["summary"], "trust_scope": report["trust_scope"], "artifacts": paths},
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print(render_markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
