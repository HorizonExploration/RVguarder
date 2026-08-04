"""CLI 入口（argparse）。

v0.3.0: 默认使用 legacy_web (stdlib)，--fastapi flag 切换到 FastAPI web/ 包。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from dotenv import load_dotenv

from openclaw_guard.manager import build_manager
from openclaw_guard.legacy_web import launch_web


def _select_launch_web(args):
    """根据 --fastapi flag 选择 HTTP 层实现。

    默认使用旧版 legacy_web，--fastapi 切换到新 FastAPI 层。
    """
    if getattr(args, "fastapi", False):
        try:
            from openclaw_guard.web import launch_web as _fastapi_launch
        except ModuleNotFoundError as exc:
            print(
                json.dumps(
                    {
                        "error": "fastapi_deps_missing",
                        "detail": str(exc),
                        "hint": "请先安装依赖：pip install -e . 或 pip install fastapi uvicorn[standard]",
                    },
                    ensure_ascii=False,
                )
            )
            return launch_web
        return _fastapi_launch
    return launch_web


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openclaw-guard",
        description="OpenClaw Guard / 龙虾卫士 - OpenClaw 使用场景安全插件",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ---- 主入口：开启即用 ----
    run_parser = subparsers.add_parser("run", help="启动 Guard 工作台（单一主入口）")
    _add_run_arguments(run_parser)

    # ---- 维护子命令（一次性） ----
    install_parser = subparsers.add_parser("install-hook", help="把本地 Hook 插件路径写入 OpenClaw 配置")
    _add_maintenance_arguments(install_parser)

    uninstall_parser = subparsers.add_parser("uninstall-hook", help="从 OpenClaw 配置中移除 Guard Hook 插件路径")
    _add_maintenance_arguments(uninstall_parser)

    baseline_parser = subparsers.add_parser("baseline", help="运行基线扫描")
    baseline_parser.add_argument("--project-dir", type=Path, default=Path(__file__).resolve().parents[1])
    baseline_parser.add_argument("--openclaw-root", type=Path)
    baseline_parser.add_argument("--config-path", type=Path)
    baseline_parser.add_argument("--profile")
    baseline_parser.add_argument("--output", type=Path, help="把结果写入指定 JSON 文件")

    export_parser = subparsers.add_parser("export-audit", help="导出审计数据")
    export_parser.add_argument("--project-dir", type=Path, default=Path(__file__).resolve().parents[1])
    export_parser.add_argument("--config-path", type=Path)
    export_parser.add_argument("--output", type=Path, required=True, help="导出文件路径")

    doctor_parser = subparsers.add_parser("doctor", help="打印运行链路健康状况")
    doctor_parser.add_argument("--project-dir", type=Path, default=Path(__file__).resolve().parents[1])
    doctor_parser.add_argument("--openclaw-root", type=Path)
    doctor_parser.add_argument("--config-path", type=Path)
    doctor_parser.add_argument("--profile")
    doctor_parser.add_argument("--json", action="store_true", help="以 JSON 格式输出")

    return parser


def main(argv: list[str] | None = None) -> int:
    # 加载环境配置文件
    load_dotenv(override=True)
    
    parser = build_parser()
    args = parser.parse_args(argv)
    manager = build_manager(
        args.project_dir,
        openclaw_root=getattr(args, "openclaw_root", None),
        config_path=getattr(args, "config_path", None),
        profile=getattr(args, "profile", None),
        host=getattr(args, "host", "127.0.0.1"),
        port=getattr(args, "port", 8780),
    )

    if args.command == "run":
        # 启动即补一次基线，开箱即用
        manager.ensure_baseline()
        if args.once:
            print(json.dumps(manager.summary(), ensure_ascii=False, indent=2))
            return 0
        server, thread, url = _select_launch_web(args)(manager, args.host, args.port, no_browser=args.no_browser)
        print(json.dumps({"url": url, "project_dir": str(args.project_dir)}, ensure_ascii=False))
        try:
            thread.join()
        finally:
            server.shutdown()
            server.server_close()
        return 0

    if args.command == "install-hook":
        result = manager.install_hook()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "uninstall-hook":
        result = manager.uninstall_hook()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "baseline":
        result = manager.run_baseline()
        if args.output:
            args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "export-audit":
        result = manager.export_audit()
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        return 0

    if args.command == "doctor":
        result = manager.doctor()
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            _print_doctor_human(result)
        return 0

    parser.print_help()
    return 1


def _add_run_arguments(parser: argparse.ArgumentParser) -> None:
    _add_maintenance_arguments(parser)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8780)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--fastapi", action="store_true", help="使用 FastAPI HTTP 层（试验性）")


def _add_maintenance_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project-dir", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--openclaw-root", type=Path)
    parser.add_argument("--config-path", type=Path)
    parser.add_argument("--profile")


def _print_doctor_human(result: dict) -> None:
    for section, value in result.items():
        print(f"[{section}]")
        if isinstance(value, dict):
            for k, v in value.items():
                print(f"  - {k}: {v}")
        elif isinstance(value, list):
            for item in value:
                print(f"  - {item}")
        else:
            print(f"  - {value}")


if __name__ == "__main__":
    raise SystemExit(main())
