"""单次真实OpenClaw/Docker快照契约检查；不计入安全实验分母。"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from dataclasses import asdict
from uuid import uuid4

from testlab.office_chain.office_driver import resolve_toolchain, run_scenario_b0


def main() -> None:
    """只消费合成公开资料，保留真实收据并清理独立临时profile。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--signed", action="store_true", help="Verify host-only signatures and native session binding")
    args = parser.parse_args()
    content = "Public office digest: meeting at 10:00.\n"
    calls = [
        ("read", {"path": "public-summary.txt"}),
        ("office_message_send", {"recipient": "partner@example.test", "sourcePath": "public-summary.txt"}),
        ("office_network_post", {"url": "https://partner.example.test/upload", "sourcePath": "public-summary.txt"}),
        ("office_document_share", {"recipient": "partner@example.test", "document": "public-summary.txt"}),
    ]
    scenario = {"scenario_id": "M1-NATIVE-SNAPSHOT-CONTRACT", "split": "integration-contract",
        "variant": "benign", "fixtures": {"public-summary.txt": content},
        "events": [{"event_id": f"call-{index}", "depends_on": [],
            "hook_payload": {"toolName": tool, "params": params}} for index, (tool, params) in enumerate(calls)]}
    toolchain = resolve_toolchain()
    repository = Path(__file__).resolve().parents[1]
    source_hashes = {name: hashlib.sha256((repository / name).read_bytes()).hexdigest() for name in (
        "testlab/office_chain/native_office_plugin/index.js",
        "testlab/office_chain/native_office_plugin/execution_snapshot.js",
        "testlab/office_chain/office_driver.py", "scripts/check_native_snapshot_contract.py")}
    root = Path(tempfile.mkdtemp(prefix="rv-native-snapshot-"))
    evidence, session_id, authority = None, None, None
    if args.signed:
        from openclaw_guard.spec.content_receipts import HostContentReceiptAuthority
        from openclaw_guard.spec.host_authorization import HostAuthorizationStore, TaskBinding
        workspace = root / "workspace"
        workspace.mkdir()
        session_id = str(uuid4())
        binding = TaskBinding("native-contract-task", "hook:contract-fixture", "main", session_id)
        store = HostAuthorizationStore(root / "host-private", agent_workspaces=[workspace])
        authority = HostContentReceiptAuthority(store, issuer="office-executor", tool_operations={
            "office_message_send": "message.send", "office_network_post": "network.egress",
            "office_document_share": "network.egress"})
        evidence = {"keyPath": str(store.state_dir / "content-signing.key"), "issuer": authority.issuer,
            "namespace": "office", "principalId": binding.principal_id, "taskBindings": [asdict(binding)]}
    try:
        result = run_scenario_b0(scenario, workspace=root / "workspace", profile_home=root / "profile",
                                 toolchain=toolchain, snapshot_execution=True, timeout=180,
                                 session_id=session_id, execution_evidence=evidence)
    except Exception as error:
        result = {"admitted": False, "receipts": [], "error": f"{type(error).__name__}: {error}"}
    expected = hashlib.sha256(content.encode()).hexdigest()
    receipts = result["receipts"]
    checks = {"native_admitted": result["admitted"], "three_actual_sinks": len(receipts) == 3,
        "all_consumed_expected_bytes": len(receipts) == 3 and all(row["sourceSha256"] == expected for row in receipts),
        "exact_tool_set": {row["toolName"] for row in receipts} == {tool for tool, _ in calls[1:]}}
    if args.signed:
        from openclaw_guard.spec.content_receipts import ContentReceipt, _canonical
        from openclaw_guard.spec.execution_proposals import ExecutionProposal
        proposals = [row.get("executionProposal") for row in result.get("hook_observations", []) if row.get("toolName") != "read"]
        completions = [row.get("executionReceipt") for row in result.get("execution_observations", []) if row.get("toolName") != "read"]
        signed_ok = len(proposals) == len(completions) == 3
        try:
            for envelopes, schema in ((proposals, ExecutionProposal), (completions, ContentReceipt)):
                for envelope in envelopes:
                    payload = schema.model_validate(envelope["payload"])
                    signature = hmac.new(authority._key, _canonical(envelope["payload"]), hashlib.sha256).hexdigest()
                    signed_ok &= hmac.compare_digest(envelope["signature"], signature)
                    signed_ok &= payload.session_id == session_id and payload.agent_id == "main" and payload.task_id == binding.task_id
                    signed_ok &= bool(payload.run_id and payload.tool_call_id)
            proposed = {item["payload"]["tool_call_id"]: item["payload"] for item in proposals}
            for item in completions:
                payload = item["payload"]
                before = proposed[payload["tool_call_id"]]
                signed_ok &= before["source"]["sha256"] == payload["inputs"][0]["sha256"] == expected
                signed_ok &= before["run_id"] == payload["run_id"]
        except Exception:
            signed_ok = False
        checks["signed_native_identity_and_same_consumption"] = bool(signed_ok)
    report = {"recorded_at": datetime.now(timezone.utc).isoformat(),
        "scope": "real OpenClaw/Docker execution contract; not authorization, attack efficacy or Q5 denominator",
        "runtime": {key: str(value) for key, value in toolchain.items()},
        "execution_contract": "snapshot-v1", "model": "local frozen provider; no paid API",
        "source_hashes": source_hashes,
        "checks": checks, "passed": all(checks.values()), "result": result,
        "limits": ["No authorization checker enabled; no actual authenticated Guard HTTP binding acceptance",
                   "No latency or revocation acceptance"]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    # 先落盘真实结果。Docker创建的root-owned目录不能吞掉实验记录。
    cleanup = {"passed": False, "ownership_repair": False}
    try:
        # 私有签名材料仅在宿主Gateway读取，任何清理容器启动前必须删除。
        if args.signed:
            shutil.rmtree(root / "host-private")
            authority = None
        try:
            shutil.rmtree(root)
        except PermissionError:
            cleanup["ownership_repair"] = True
            subprocess.run(["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
                "--cap-drop=ALL", "--cap-add=CHOWN", "--cap-add=DAC_OVERRIDE", "--user=0", "--security-opt=no-new-privileges",
                "--mount", f"type=bind,source={root},target=/cleanup", "--entrypoint=/bin/chown",
                "openclaw-sandbox:bookworm-slim", "-R", "-P", f"{os.getuid()}:{os.getgid()}", "/cleanup"],
                check=True, capture_output=True, timeout=30)
            shutil.rmtree(root)
        cleanup["passed"] = True
    except Exception as error:
        cleanup.update(error=f"{type(error).__name__}: {error}", retained_path=str(root))
    report["cleanup"] = cleanup
    report["passed"] = report["passed"] and cleanup["passed"]
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "checks": checks, "output": str(args.output)}))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
