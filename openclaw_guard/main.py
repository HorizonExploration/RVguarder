from __future__ import annotations

import argparse
import json
from pathlib import Path

from openclaw_guard.manager import build_manager
from openclaw_guard.web import launch_web


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="openclaw-guard", description="Openclaw Guard / 龙虾卫士")
    subparsers = parser.add_subparsers(dest="command", required=True)

    launch_parser = subparsers.add_parser("launch", help="启动本地管理台")
    _add_launch_arguments(launch_parser, default_ui_mode="pro")

    normal_parser = subparsers.add_parser("normal", help="一键启动简洁模式，适合普通用户")
    _add_launch_arguments(normal_parser, default_ui_mode="normal")

    baseline_parser = subparsers.add_parser("baseline", help="运行基线扫描")
    baseline_parser.add_argument("--project-dir", type=Path, default=Path(__file__).resolve().parents[1])
    baseline_parser.add_argument("--openclaw-root", type=Path)
    baseline_parser.add_argument("--config-path", type=Path)
    baseline_parser.add_argument("--profile")

    action_parser = subparsers.add_parser("action", help="模拟摄入行为事件")
    action_parser.add_argument("--project-dir", type=Path, default=Path(__file__).resolve().parents[1])
    action_parser.add_argument("--config-path", type=Path)
    action_parser.add_argument("--event-file", type=Path)

    export_parser = subparsers.add_parser("export-audit", help="导出审计数据")
    export_parser.add_argument("--project-dir", type=Path, default=Path(__file__).resolve().parents[1])
    export_parser.add_argument("--config-path", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    manager = build_manager(
        args.project_dir,
        openclaw_root=getattr(args, "openclaw_root", None),
        config_path=getattr(args, "config_path", None),
        profile=getattr(args, "profile", None),
        ui_mode=getattr(args, "ui_mode", "pro"),
        host=getattr(args, "host", "127.0.0.1"),
        port=getattr(args, "port", 8780),
    )

    if args.command in {"launch", "normal"}:
        if args.command == "normal":
            manager.ensure_baseline()
        if args.once:
            print(json.dumps(manager.summary(), ensure_ascii=False, indent=2))
            return 0
        server, thread, url = launch_web(manager, args.host, args.port, no_browser=args.no_browser)
        print(json.dumps({"url": url, "project_dir": str(args.project_dir)}, ensure_ascii=False))
        try:
            thread.join()
        finally:
            server.shutdown()
            server.server_close()
        return 0
    if args.command == "baseline":
        print(json.dumps(manager.run_baseline(), ensure_ascii=False, indent=2))
        return 0
    if args.command == "action":
        payload = json.loads(args.event_file.read_text(encoding="utf-8")) if args.event_file else {}
        print(json.dumps(manager.ingest_event(payload, str(payload.get("raw_user_intent") or "")), ensure_ascii=False, indent=2))
        return 0
    if args.command == "export-audit":
        print(json.dumps(manager.export_audit(), ensure_ascii=False, indent=2))
        return 0
    parser.print_help()
    return 1


def _add_launch_arguments(parser: argparse.ArgumentParser, *, default_ui_mode: str) -> None:
    parser.add_argument("--project-dir", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--openclaw-root", type=Path)
    parser.add_argument("--config-path", type=Path)
    parser.add_argument("--profile")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8780)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--ui-mode", choices=("normal", "pro"), default=default_ui_mode)


if __name__ == "__main__":
    raise SystemExit(main())
