"""隔离Docker原生场景驱动：宿主授权、真实收据、生产Hook，无HOME替换。

固定轨迹仅决定Agent尝试的实际工具；Oracle与授权签发输入分别记录。
本模块不自行判定Q5、改变既有场景或将接口检查并入安全分母。
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
from uuid import uuid4

from openclaw_guard.engine import experiment_components as ec
from openclaw_guard.integrations.hook_runtime import HOOK_PLUGIN_ID
from openclaw_guard.integrations.host_authorization_bridge import HostAuthorizationBridge
from openclaw_guard.manager import build_manager
from openclaw_guard.rv.rv_dsl import load_ruleset
from openclaw_guard.spec.authorization_preparation import BoundedAuthorizationPreparation
from openclaw_guard.spec.call_authorizer import HostCallAuthorizer
from openclaw_guard.spec.content_receipts import ExecutedContentLedger, HostContentReceiptAuthority
from openclaw_guard.spec.execution_proposals import HostExecutionProposalVerifier
from openclaw_guard.spec.host_authorization import HostAuthorizationStore, TaskBinding
from openclaw_guard.spec.resource_evidence import HostResourceObserver, ResourceEvidenceError
from openclaw_guard.web.app import launch_web
from testlab.office_chain.frozen_provider import FrozenTrajectoryProvider, serve
from testlab.office_chain.native_baseline import default_plugin_dir, resolve_b0_config
from testlab.office_chain.office_driver import (
    _Gateway, _adjudicate_attack_goal, _build_events, _child_env, _cleanup_sandboxes, _docker_ps_ids, _free_port, _json_rows,
    _successful_tool_names,
    _segments,
    _run_agent_with_approvals, _wait_http, _list_automations, compose_task_message, resolve_toolchain, seed_workspace,
)
from testlab.office_chain.semantic_recording import apply_recording


OPERATIONS = {"office_message_send": "message.send", "office_network_post": "network.egress",
              "office_document_share": "network.egress"}


def run_authorized_scenario(scenario: dict, *, output: Path, rules_path: Path, arm: str = "Full",
                            disabled: str = "", recording: dict | None = None, timeout: int = 180,
                            evidence_layer: str = "fixed_trajectory_native_tools") -> dict:
    """单场景单臂真实运行，先保留观测再清理；每臂独立授权库/profile。"""
    output = Path(output)
    if evidence_layer not in {"fixed_trajectory_native_tools", "real_autonomous_agent"}:
        raise ValueError("unsupported evidence layer")
    if output.exists():
        raise FileExistsError("preserve existing native result")
    rules_sha256 = hashlib.sha256(Path(rules_path).read_bytes()).hexdigest()
    for item in scenario.get("host_grants", []):
        if not isinstance(item.get("expected_content_sha256"), str) or len(item["expected_content_sha256"]) != 64:
            raise ValueError("host preapproval requires exact expected content hash")
    root = Path(tempfile.mkdtemp(prefix="rv-office-acceptance-"))
    gateway = server = bridge = web = manager = toolchain = None
    containers = set()
    report = {"scenario_id": scenario["scenario_id"], "arm": arm, "passed": False,
              "evidence_layer": evidence_layer, "human_adjudicator": False,
              "loads_guard": arm != "B0",
              "scenario_sha256": hashlib.sha256(json.dumps(scenario, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
              "components": asdict(ec.ExperimentComponents.from_disabled(disabled)),
              "rules_sha256": rules_sha256,
              "semantic_mode": "frozen_recording" if recording else "local_heuristic_no_paid_api"}
    try:
        with ec.using(ec.ExperimentComponents.from_disabled(disabled)):
            workspace, profile_home = root / "workspace", root / "observations"
            seed_workspace(workspace, scenario)
            segments = _segments(scenario)
            session_ids = [str(uuid4()) for _ in segments]
            session_id = session_ids[0]
            toolchain = resolve_toolchain()
            containers = _docker_ps_ids(toolchain)
            env = _child_env(toolchain)
            gateway = _Gateway(toolchain=toolchain, env=env)
            grants, issued = [], set()
            grant_lock = threading.Lock()
            def issue_preapproved_versions():
                # 控制表是宿主输入，必须明确预批准字节hash；Agent不能签发。
                with grant_lock:
                    for index, item in enumerate(scenario.get("host_grants", [])):
                        if index in issued:
                            continue
                        try:
                            descriptor = observer.observe("office", item["path"])
                        except ResourceEvidenceError:
                            continue  # 未生成/不可读取的版本不获得授权；不改原生轨迹。
                        if descriptor.content_version != "sha256:" + item["expected_content_sha256"]:
                            continue
                        grant_binding = TaskBinding(**{**asdict(binding),
                            "session_id": session_ids[item.get("session_index", 0)], **item.get("binding_overrides", {})})
                        grant = store.issue(observer, "office", item["path"], binding=grant_binding,
                            operation=item["operation"], recipient=item["recipient"], ttl_seconds=item.get("ttl_seconds", 3600))
                        if grant["resource"]["content_version"] != descriptor.content_version:
                            store.revoke(grant["id"])
                            continue
                        grants.append(grant)
                        issued.add(index)
                        if item.get("revoked") is True:
                            store.revoke(grant["id"])
            class PreapprovedProvider(FrozenTrajectoryProvider):
                """冻结调度前由宿主落实已批准的确切版本，不能读取Oracle签发。"""
                def chat_completion(self, request):
                    issue_preapproved_versions()
                    tools_by_id = {call.get("id"): call.get("function", {}).get("name")
                        for message in request.get("messages", []) if message.get("role") == "assistant"
                        for call in message.get("tool_calls", [])}
                    for message in request.get("messages", []):
                        name = message.get("name") or tools_by_id.get(message.get("tool_call_id"))
                        if message.get("role") == "tool" and name in {"automations", "cron"}:
                            row = {"tool_name": name, "content": str(message.get("content", ""))[:3000]}
                            diagnostics = report.setdefault("scheduler_tool_results", [])
                            if row not in diagnostics:
                                diagnostics.append(row)
                    return super().chat_completion(request)
            provider = PreapprovedProvider({**scenario, "events": segments[0]})
            server, provider_port, _ = serve(provider, host="127.0.0.1", port=0)
            config = resolve_b0_config(workspace, plugin_dir=default_plugin_dir(),
                                       profile_home=profile_home, provider_port=provider_port)
            gateway.write_config(config, port=_free_port())
            if arm != "B0":
                guard_port = _free_port()
                manager = build_manager(gateway.profile_dir, config_path=gateway.config_path,
                                        host="127.0.0.1", port=guard_port, ui_mode="pro")
                # 未配置录制的阶段检查明确使用本地语义，不能伪称P+S增量。
                if recording is not None:
                    apply_recording(manager.semantic_enhancer, recording)
                else:
                    manager.semantic_enhancer._llm_enabled = False
                manager.install_hook()
                token = json.loads(Path(manager.runtime_hook["auth_token_path"]).read_text())["auth_token"]
                principal = "hook:" + hashlib.sha256(token.encode()).hexdigest()[:32]
                token = None
                config = json.loads(gateway.config_path.read_text())
                config["plugins"]["entries"][HOOK_PLUGIN_ID].setdefault("config", {})["startupHealthCheck"] = True
            else:
                principal = "host-baseline:" + session_id
            binding = TaskBinding(scenario.get("task_id", scenario["scenario_id"]), principal, "main", session_id)
            store = HostAuthorizationStore(root / "host-private", agent_workspaces=[workspace])
            observer = HostResourceObserver({"office": workspace})
            observed_paths = (scenario.get("oracle") or {}).get("observed_paths", [])
            report["initial_workspace_hashes"] = {}
            for path in observed_paths:
                try:
                    report["initial_workspace_hashes"][path] = observer.observe("office", path).content_version.removeprefix("sha256:")
                except ResourceEvidenceError:
                    report["initial_workspace_hashes"][path] = None
            # 仅受控host_grants签发；不从工具参数、附件或Oracle推导授权。
            task_history = None
            history_spec = scenario.get("host_task_links")
            authority = HostContentReceiptAuthority(store, issuer="office-executor",
                tool_operations={**OPERATIONS, **({"read": "file.read"} if history_spec else {})})
            if history_spec:
                from openclaw_guard.spec.content_receipts import ContentVersion
                from openclaw_guard.spec.task_history import HostTaskHistory
                task_history = HostTaskHistory(store, authority)
                versions = []
                for item in history_spec["sensitive_resources"]:
                    resource = observer.observe("office", item["path"])
                    if resource.content_version != "sha256:" + item["expected_content_sha256"]:
                        raise ValueError("host classification must bind the preapproved exact version")
                    versions.append(ContentVersion(namespace="office", resource_id=resource.resource_id,
                        sha256=item["expected_content_sha256"], size_bytes=resource.size_bytes,
                        full_resource=True, offset=0).model_dump(mode="json"))
                indices = history_spec.get("session_indices", list(range(len(session_ids))))
                link = task_history.register([TaskBinding(**{**asdict(binding), "session_id": session_ids[i],
                    **history_spec.get("binding_overrides", {})})
                    for i in indices], sensitive_versions=versions,
                    ttl_seconds=history_spec.get("ttl_seconds", 300))
                authority.task_resolver = task_history.resolve_task_binding
                report["host_task_link"] = link
            if manager is not None:
                def attach_backend(active_manager):
                    """冷启动/恢复均走相同生产后端、私有历史和规则路径。"""
                    active_bridge = HostAuthorizationBridge(store, observer, tool_namespaces={tool: "office" for tool in OPERATIONS})
                    active_bridge.execution_proposal_verifier = HostExecutionProposalVerifier(authority)
                    active_bridge.content_evidence_ledger = ExecutedContentLedger(authority, background=True)
                    active_bridge.decision_preparation = BoundedAuthorizationPreparation(HostCallAuthorizer(active_bridge.execution_proposal_verifier))
                    if task_history is not None:
                        from openclaw_guard.spec.cross_history import BoundedHistoryRecorder, HostCrossHistoryAuthorizer
                        active_bridge.history_recorder = BoundedHistoryRecorder(authority, task_history)
                        active_bridge.history_preparation = BoundedAuthorizationPreparation(
                            HostCrossHistoryAuthorizer(active_bridge.execution_proposal_verifier, task_history), component="cross_session_rv")
                    active_manager.host_authorization_bridge = active_bridge
                    active_manager.content_evidence_ledger = active_bridge.content_evidence_ledger
                    engine = active_manager.rv_engine._get()
                    engine._authorization_checker = active_bridge.decision_preparation.authorization_for_step
                    engine._history_checker = active_bridge.history_preparation.authorization_for_step if active_bridge.history_preparation else None
                    engine._spec_ruleset = load_ruleset(rules_path)
                    engine._spec_monitors_template = None
                    return active_bridge
                bridge = attach_backend(manager)
                web, _, _ = launch_web(manager, "127.0.0.1", guard_port, no_browser=True)
                _wait_http(f"http://127.0.0.1:{guard_port}/api/health", timeout=30, label="Guard")
            config["plugins"]["entries"]["rvguard-office-chain-simulator"]["config"].update(snapshotExecution=True,
                nativeReadEvidence=task_history is not None,
                executionEvidence={"keyPath": str(store.state_dir / "content-signing.key"),
                  "authorizationDatabase": str(store.database), "issuer": authority.issuer, "namespace": "office",
                  "principalId": binding.principal_id, "taskBindings": [
                      {**asdict(binding), "session_id": sid} for sid in session_ids]})
            if scenario.get("measure_hook_boundary"):
                config["plugins"]["entries"]["rvguard-office-chain-simulator"]["config"]["hookBoundaryTiming"] = True
            gateway.write_config(config, port=gateway.port)
            report.update(runtime=toolchain, host_grants=grants, native_config=config)
            # Gateway auth及Hook运行令牌不写证据包。
            report["native_config"] = json.loads(json.dumps(config))
            report["native_config"].get("gateway", {}).pop("auth", None)
            if HOOK_PLUGIN_ID in report["native_config"]["plugins"]["entries"]:
                report["native_config"]["plugins"]["entries"][HOOK_PLUGIN_ID].get("config", {}).pop("authToken", None)
            runs = []
            guard_restarts = 0
            for index, segment in enumerate(segments):
                if index:
                    gateway.stop()
                    if task_history is not None and history_spec.get("revoke_before_segment") == index:
                        report.setdefault("host_task_link_revocations", []).append({"id": link["id"],
                            "before_segment": index, "success": task_history.revoke(link["id"])})
                    if manager is not None and scenario.get("restart_guard_before_segment"):
                        if bridge.history_recorder is not None and not bridge.history_recorder.wait_idle(timeout=1):
                            raise RuntimeError("history queue not drained before cold backend restart")
                        web.shutdown()
                        bridge.close()
                        from openclaw_guard.spec.task_history import HostTaskHistory
                        if task_history is not None:
                            task_history = HostTaskHistory(store, authority)
                            authority.task_resolver = task_history.resolve_task_binding
                        manager = build_manager(gateway.profile_dir, config_path=gateway.config_path,
                            host="127.0.0.1", port=guard_port, ui_mode="pro")
                        if recording is not None:
                            apply_recording(manager.semantic_enhancer, recording)
                        else:
                            manager.semantic_enhancer._llm_enabled = False
                        bridge = attach_backend(manager)
                        web, _, _ = launch_web(manager, "127.0.0.1", guard_port, no_browser=True)
                        _wait_http(f"http://127.0.0.1:{guard_port}/api/health", timeout=30, label="restored Guard")
                        guard_restarts += 1
                    provider.__init__({**scenario, "events": segment})
                gateway.start()
                run = _run_agent_with_approvals(profile=gateway.profile, session_key=f"agent:main:acceptance-{uuid4().hex}",
                    session_id=session_ids[index], message=compose_task_message(scenario, segment=index, total=len(segments)),
                    timeout=timeout, approval_policy="allow-once", toolchain=toolchain, env=env)
                runs.append(run)
            if scenario.get("observe_native_automations"):
                ok, jobs = _list_automations(gateway.profile, env=env, cli=toolchain["openclaw"])
                report["native_automations"] = {"query_succeeded": ok, "jobs": jobs}
            # Shutdown flushes passive timing records outside the measured Hook.
            gateway.stop()
            approvals = [item for run in runs for item in run.get("approvals", [])]
            receipts = _json_rows(profile_home / "office-receipts.jsonl")
            executions = _json_rows(Path(str(profile_home / "office-receipts.jsonl") + ".executions.jsonl"))
            hooks = _json_rows(Path(str(profile_home / "office-receipts.jsonl") + ".hooks.jsonl"))
            if scenario.get("measure_hook_boundary"):
                report["hook_boundary_timings"] = _json_rows(Path(str(profile_home / "office-receipts.jsonl") + ".hook-timings.jsonl"))
            actions = manager.list_actions() if manager is not None else []
            report["host_grant_issuances"] = grants
            report["host_grants"] = store.query()
            events = _build_events(hooks, receipts, approvals, _successful_tool_names(runs),
                                   execution_observations=executions)
            workspace_hashes = {}
            for path in set((scenario.get("oracle") or {}).get("created_paths", []) + observed_paths):
                try:
                    workspace_hashes[path] = observer.observe("office", path).content_version.removeprefix("sha256:")
                except ResourceEvidenceError:
                    workspace_hashes[path] = None
            report.update(receipts=receipts, executions=executions, hooks=hooks, actions=actions,
                          events=events, workspace_hashes=workspace_hashes,
                          approvals=approvals, session_ids=session_ids, actual_gateway_restarts=max(0, len(segments)-1),
                          actual_guard_backend_restarts=guard_restarts,
                          agent_run_observed=all(isinstance(run.get("response"), dict) for run in runs),
                          agent_returncodes=[run.get("returncode") for run in runs],
                          agent_timed_out=any(run.get("timed_out") for run in runs))
            report["agent_diagnostics"] = [{"response": run.get("response"),
                "stderr_tail": run.get("stderr_tail"), "stdout_tail": run.get("stdout_tail")}
                for run in runs]
            report["plugin_diagnostics"] = [line for line in gateway._log_tail(20000).splitlines()
                if "rvguard-office-chain-simulator" in line or "hook timing observer" in line]
            report["passed"] = (report["agent_run_observed"] and not report["agent_timed_out"] and bool(hooks)
                                and all(run.get("returncode") == 0 for run in runs)
                                and (not scenario.get("observe_native_automations") or report["native_automations"]["query_succeeded"]))
            if scenario.get("attack_goal"):
                report["legacy_attack_goal_achieved"] = bool(_adjudicate_attack_goal(scenario,
                    attack_goal=scenario["attack_goal"], receipts=receipts,
                    external_receipts=[r for r in receipts if r.get("external") is True], workspace=workspace, events=events))
                report["legacy_oracle_limit"] = "original capture oracle; not upgraded to content exfiltration proof"
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n")
        cleanup_errors = []
        callbacks = []
        if gateway is not None:
            callbacks.extend([gateway.stop, lambda: _cleanup_sandboxes(containers, profile=gateway.profile, toolchain=toolchain)])
        if web is not None:
            callbacks.append(web.shutdown)
        if server is not None:
            callbacks.extend([server.shutdown, server.server_close])
        if bridge is not None:
            callbacks.append(bridge.close)
        if gateway is not None:
            callbacks.append(gateway.cleanup)
        for callback in callbacks:
            try:
                callback()
            except Exception as error:
                cleanup_errors.append(f"{type(error).__name__}: {error}")
        try:
            private = root / "host-private"
            if private.exists():
                shutil.rmtree(private)  # 密钥先删除，再挂载临时公共工作区修复所有权。
            try:
                shutil.rmtree(root)
            except PermissionError:
                subprocess.run(["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
                    "--cap-drop=ALL", "--cap-add=CHOWN", "--cap-add=DAC_OVERRIDE", "--user=0",
                    "--security-opt=no-new-privileges", "--mount", f"type=bind,source={root},target=/cleanup",
                    "--entrypoint=/bin/chown", "openclaw-sandbox:bookworm-slim", "-R", "-P",
                    f"{os.getuid()}:{os.getgid()}", "/cleanup"], check=True, capture_output=True, timeout=30)
                shutil.rmtree(root)
        except Exception as error:
            cleanup_errors.append(f"{type(error).__name__}: {error}")
        report.update(cleanup_passed=not root.exists() and not cleanup_errors, cleanup_errors=cleanup_errors)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n")
    return report
