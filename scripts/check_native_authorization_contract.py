"""真实OpenClaw/Docker/认证Hook/原生审批的授权消费契约验收。

使用专用测试规约验证接口，不计安全实验分母，不替代M1场景验收。
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from uuid import uuid4

from openclaw_guard.integrations.hook_runtime import HOOK_PLUGIN_ID
from openclaw_guard.integrations.host_authorization_bridge import HostAuthorizationBridge
from openclaw_guard.manager import build_manager
from openclaw_guard.rv.rv_dsl import Ruleset
from openclaw_guard.spec.authorization_preparation import BoundedAuthorizationPreparation
from openclaw_guard.spec.call_authorizer import HostCallAuthorizer
from openclaw_guard.spec.content_receipts import ExecutedContentLedger, HostContentReceiptAuthority
from openclaw_guard.spec.execution_proposals import HostExecutionProposalVerifier
from openclaw_guard.spec.host_authorization import HostAuthorizationStore, TaskBinding
from openclaw_guard.spec.resource_evidence import HostResourceObserver
from openclaw_guard.web.app import launch_web
from testlab.office_chain.frozen_provider import FrozenTrajectoryProvider, serve
from testlab.office_chain.native_baseline import default_plugin_dir, resolve_b0_config
from testlab.office_chain.office_driver import (_Gateway, _child_env, _cleanup_sandboxes, _docker_ps_ids,
    _free_port, _json_rows, _run_agent_with_approvals, _wait_http, resolve_toolchain)


def main() -> None:
    """真实正常消费及等待原生审批时撤销，分别记录首次结果。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revoke", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; preserve prior evidence")
    root = Path(tempfile.mkdtemp(prefix="rv-native-authorization-"))
    gateway = server = bridge = web = toolchain = None
    before_containers = set()
    report = {"passed": False, "scope": "native authorization interface contract; not security denominator"}
    try:
        workspace = root / "workspace"
        workspace.mkdir()
        content = b"Synthetic authorized office digest.\n"
        (workspace / "summary.txt").write_bytes(content)
        params = {"recipient": "partner@example.test", "sourcePath": "summary.txt"}
        scenario = {"scenario_id": "M1-AUTHORIZATION-CONTRACT", "events": [
            {"hook_payload": {"toolName": "read", "params": {"path": "summary.txt"}}},
            {"hook_payload": {"toolName": "office_message_send", "params": params}}]}
        toolchain = resolve_toolchain()
        before_containers = _docker_ps_ids(toolchain)
        env = _child_env(toolchain)
        gateway = _Gateway(toolchain=toolchain, env=env)
        server, port, _ = serve(FrozenTrajectoryProvider(scenario), host="127.0.0.1", port=0)
        profile_root = root / "profile"
        config = resolve_b0_config(workspace, plugin_dir=default_plugin_dir(), profile_home=profile_root, provider_port=port)
        gateway.write_config(config, port=_free_port())
        guard_port = _free_port()
        # Guard与它自己的临时profile同目录，满足生产安装器的临时配置作用域。
        # 不更改HOME，也不绕过安装器对日常Gateway配置的保护。
        manager = build_manager(gateway.profile_dir, config_path=gateway.config_path,
                                host="127.0.0.1", port=guard_port, ui_mode="pro")
        manager.install_hook()
        token = json.loads(Path(manager.runtime_hook["auth_token_path"]).read_text())["auth_token"]
        session_id = str(uuid4())
        binding = TaskBinding("native-authorized-task", "hook:" + hashlib.sha256(token.encode()).hexdigest()[:32], "main", session_id)
        token = None
        store = HostAuthorizationStore(root / "host-private", agent_workspaces=[workspace])
        observer = HostResourceObserver({"office": workspace})
        grant = store.issue(observer, "office", "summary.txt", binding=binding, operation="message.send", recipient=params["recipient"])
        authority = HostContentReceiptAuthority(store, issuer="office-executor", tool_operations={
            "office_message_send": "message.send", "office_network_post": "network.egress", "office_document_share": "network.egress"})
        bridge = HostAuthorizationBridge(store, observer, tool_namespaces={"office_message_send": "office"})
        bridge.execution_proposal_verifier = HostExecutionProposalVerifier(authority)
        bridge.content_evidence_ledger = ExecutedContentLedger(authority, background=True)
        bridge.decision_preparation = BoundedAuthorizationPreparation(HostCallAuthorizer(bridge.execution_proposal_verifier))
        manager.host_authorization_bridge = bridge
        manager.content_evidence_ledger = bridge.content_evidence_ledger
        rules = Ruleset.model_validate({"version": 2, "event_model": "tool-call-v1", "monitors": [{"name": "authorization-contract-only", "initial": "idle",
            "rules": [{"id": "requires_exact_authorization", "from": "*", "when": {"tool": {"operation_families": ["message.send"]}},
                       "verdict": "block", "unless_authorized": {"tool_name": "office_message_send", "operation_family": "message.send"}}]}]})
        engine = manager.rv_engine._get()
        engine._authorization_checker = bridge.decision_preparation.authorization_for_step
        engine._spec_ruleset = rules
        engine._spec_monitors_template = None
        config = json.loads(gateway.config_path.read_text())
        config["plugins"]["entries"][HOOK_PLUGIN_ID].setdefault("config", {})["startupHealthCheck"] = True
        config["plugins"]["entries"]["rvguard-office-chain-simulator"]["config"].update(snapshotExecution=True,
            executionEvidence={"keyPath": str(store.state_dir / "content-signing.key"), "authorizationDatabase": str(store.database),
              "issuer": authority.issuer, "namespace": "office", "principalId": binding.principal_id, "taskBindings": [asdict(binding)]})
        gateway.write_config(config, port=gateway.port)
        revoked = []
        def approval_callback(pending):
            if args.revoke and not revoked:
                revoked.append({"pending_kind": pending.get("kind"), "pending_tool": pending.get("toolName"),
                                "revoked": store.revoke(grant["id"])})
        report.update({"scope": "native authorization interface contract, dedicated fixture rules; not Q5 or M1 attack denominator",
                  "recorded_at": datetime.now(timezone.utc).isoformat(), "mode": "revoke-during-native-approval" if args.revoke else "authorized-consumption",
                  "runtime": toolchain, "rules": rules.model_dump(by_alias=True), "human_adjudicator": False,
                  "model": "local frozen provider; no paid API", "passed": False})
        web, _, _ = launch_web(manager, "127.0.0.1", guard_port, no_browser=True)
        _wait_http(f"http://127.0.0.1:{guard_port}/api/health", timeout=30, label="Guard")
        gateway.start()
        run = _run_agent_with_approvals(profile=gateway.profile, session_key=f"agent:main:auth-contract-{uuid4().hex}",
            session_id=session_id, message="Send the explicitly authorized synthetic summary to partner@example.test.",
            timeout=120, approval_policy="allow-once", toolchain=toolchain, env=env, approval_callback=approval_callback)
        receipts = _json_rows(profile_root / "office-receipts.jsonl")
        executions = _json_rows(Path(str(profile_root / "office-receipts.jsonl") + ".executions.jsonl"))
        actions = manager.list_actions()
        report.update(receipts=receipts, execution_observations=executions, actions=actions,
                      approvals=run.get("approvals", []), revoked=revoked, agent_returncode=run.get("returncode"),
                      agent_run_observed=isinstance(run.get("response"), dict), agent_timed_out=run.get("timed_out"))
        authorized = [item for item in actions if (item.get("event", {}).get("metadata", {}).get("rv_result") or {}).get("authorization_exceptions")]
        checks = {"authenticated_authorization_exception": bool(authorized),
                  "native_prompt_observed": bool(run.get("approvals")), "agent_run_observed": report["agent_run_observed"]}
        if args.revoke:
            checks.update(revocation_applied=bool(revoked and revoked[0]["revoked"]), no_side_effect=not receipts,
                          actual_executor_failed=any(row["toolName"] == "office_message_send" and row["success"] is False for row in executions))
        else:
            checks.update(exact_authorized_receipt=len(receipts) == 1 and receipts[0]["sourceSha256"] == hashlib.sha256(content).hexdigest())
        report.update(checks=checks, passed=all(checks.values()))
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n")
        if gateway is not None:
            gateway.stop()
            _cleanup_sandboxes(before_containers, profile=gateway.profile, toolchain=toolchain)
        if web is not None:
            web.shutdown()
        if server is not None:
            server.shutdown()
            server.server_close()
        if bridge is not None:
            bridge.close()
        if gateway is not None:
            gateway.cleanup()
        # 所有签名/Hook私有材料必须在任何ownership修复容器挂载之前删除。
        if (root / "host-private").exists():
            shutil.rmtree(root / "host-private")
        try:
            shutil.rmtree(root)
        except PermissionError:
            subprocess.run(["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
                "--cap-add=CHOWN", "--cap-add=DAC_OVERRIDE", "--user=0", "--security-opt=no-new-privileges",
                "--mount", f"type=bind,source={root},target=/cleanup", "--entrypoint=/bin/chown",
                "openclaw-sandbox:bookworm-slim", "-R", "-P", f"{os.getuid()}:{os.getgid()}", "/cleanup"], check=True, capture_output=True, timeout=30)
            shutil.rmtree(root)
        report["cleanup_passed"] = not root.exists()
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n")
    print(json.dumps({"passed": report["passed"], "checks": report.get("checks"), "error": report.get("error"), "output": str(args.output)}))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
