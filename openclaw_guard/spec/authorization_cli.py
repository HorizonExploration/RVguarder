"""受控宿主授权命令，不注册为Agent工具或HTTP写接口。"""
from __future__ import annotations

import argparse
from pathlib import Path

from openclaw_guard.rv.tool_events import OPERATION_EFFECTS
from openclaw_guard.spec.host_authorization import HostAuthorizationStore, TaskBinding
from openclaw_guard.spec.resource_evidence import HostResourceObserver


def add_authorization_parser(subparsers: argparse._SubParsersAction) -> None:
    """注册宿主签发、查询和撤销命令，存储路径须显式提供。"""
    parser = subparsers.add_parser("authorization", help="宿主受控授权管理（不向Agent开放）")
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--agent-workspace", type=Path, action="append", required=True, help="所有Agent可写工作区，存储必须在其外")
    commands = parser.add_subparsers(dest="authorization_command", required=True)
    issue = commands.add_parser("issue", help="绑定单任务及真实内容版本签发授权")
    issue.add_argument("--namespace", required=True)
    issue.add_argument("--resource-root", type=Path, required=True)
    issue.add_argument("--resource", required=True, help="命名空间内相对路径")
    for name in ("task-id", "principal-id", "agent-id", "recipient"):
        issue.add_argument(f"--{name}", required=True)
    issue.add_argument("--session-id", default="")
    issue.add_argument("--run-id", default="")
    issue.add_argument("--operation", choices=sorted(OPERATION_EFFECTS), required=True)
    issue.add_argument("--ttl-seconds", type=float, default=3600)
    query = commands.add_parser("query", help="查询记录及当前有效状态")
    query.add_argument("--grant-id")
    revoke = commands.add_parser("revoke", help="持久撤销已有授权")
    revoke.add_argument("--grant-id", required=True)
    link = commands.add_parser("link-task", help="宿主绑定多会话任务及确切敏感版本；不授予工具权限")
    for name in ("task-id", "principal-id", "agent-id", "namespace"):
        link.add_argument(f"--{name}", required=True)
    link.add_argument("--session-id", action="append", required=True)
    link.add_argument("--resource-root", type=Path, required=True)
    link.add_argument("--resource", action="append", required=True)
    link.add_argument("--classification", choices=["sensitive"], required=True)
    link.add_argument("--ttl-seconds", type=float, default=300)
    unlink = commands.add_parser("revoke-task-link", help="撤销跨会话任务关联")
    unlink.add_argument("--link-id", required=True)


def execute_authorization_command(args: argparse.Namespace) -> dict:
    """执行本机授权管理，不构建Guard manager或改动Gateway配置。"""
    store = HostAuthorizationStore(args.state_dir, agent_workspaces=args.agent_workspace)
    if args.authorization_command in {"link-task", "revoke-task-link"}:
        from openclaw_guard.spec.task_history import HostTaskHistory
        from openclaw_guard.spec.content_receipts import ContentVersion
        history = HostTaskHistory(store, None)
        if args.authorization_command == "revoke-task-link":
            return {"revoked": history.revoke(args.link_id), "link_id": args.link_id}
        observer = HostResourceObserver({args.namespace: args.resource_root})
        versions = []
        for path in args.resource:
            observed = observer.observe(args.namespace, path)
            versions.append(ContentVersion(namespace=observed.namespace, resource_id=observed.resource_id,
                sha256=observed.content_version.removeprefix("sha256:"), size_bytes=observed.size_bytes,
                full_resource=True, offset=0).model_dump(mode="json"))
        return history.register([TaskBinding(args.task_id, args.principal_id, args.agent_id, sid) for sid in args.session_id],
                                sensitive_versions=versions, ttl_seconds=args.ttl_seconds)
    if args.authorization_command == "query":
        return {"grants": store.query(args.grant_id)}
    if args.authorization_command == "revoke":
        return {"revoked": store.revoke(args.grant_id), "grant_id": args.grant_id}
    observer = HostResourceObserver({args.namespace: args.resource_root})
    return store.issue(observer, args.namespace, args.resource,
                       binding=TaskBinding(args.task_id, args.principal_id, args.agent_id, args.session_id, args.run_id),
                       operation=args.operation, recipient=args.recipient, ttl_seconds=args.ttl_seconds)
