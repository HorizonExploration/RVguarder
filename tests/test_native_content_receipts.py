"""真实Node办公模拟工具消费字节与Python宿主签名的互通验收。

执行实际工具实现但不经过OpenClaw调度；不计入原生安全样本分母。
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from openclaw_guard.spec.content_receipts import ExecutedContentLedger, HostContentReceiptAuthority
from openclaw_guard.spec.host_authorization import HostAuthorizationStore, TaskBinding
from openclaw_guard.spec.resource_evidence import HostResourceObserver


NODE_RUNNER = r'''
import {readFileSync, writeFileSync, existsSync} from "node:fs";
import {join} from "node:path";
import {createHmac} from "node:crypto";
const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` :
  value && typeof value === "object" ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
const input = JSON.parse(readFileSync(0, "utf8"));
const plugin = (await import(input.plugin)).default;
const tools = new Map(), hooks = {};
try {
  plugin.register({pluginConfig: input.config, registerTool(t) {tools.set(t.name, t);}, on(n, h) {hooks[n] = h;}});
  let secondTools, secondHooks;
  if (input.duplicateRegister) {
    secondTools = new Map(); secondHooks = {};
    plugin.register({pluginConfig: input.secondConfig ?? input.config,
      registerTool(t) {secondTools.set(t.name, t);}, on(n, h) {secondHooks[n] = h;}});
  }
  const sdk = {toolName: input.tool, toolCallId: "call", runId: "run", params: input.params};
  const ctx = {agentId: "agent", sessionId: "session", runId: "run"};
  if (input.eventContext) sdk.context = input.eventContext;
  if (input.contextOverrides) Object.assign(ctx, input.contextOverrides);
  if (!input.missingContext) hooks.before_tool_call(sdk, ctx);
  if (input.duplicateBefore) secondHooks.before_tool_call(sdk, ctx);
  if (input.ambiguous) hooks.before_tool_call({...sdk, runId: "other"}, ctx);
  if (input.reverseConflict) hooks.before_tool_call({...sdk, toolCallId: "other"}, {...ctx, toolCallId: "call"});
  if (input.replaceContent) writeFileSync(join(input.config.workspaceRoot, "note.txt"), input.replaceContent);
  const registry = globalThis[Symbol.for("rvguard.execution-proposals.v1")];
  const proposal = registry?.get(input.tool)?.(sdk, ctx) ?? null;
  if (input.grantId && proposal) {
    const payload = {format_version: 1, purpose: "authorized_snapshot_use", proposal: proposal.payload,
      grant_id: input.grantId, issued_at_ms: Date.now(), expires_at_ms: proposal.payload.expires_at_ms};
    if (input.permitExpired) { payload.issued_at_ms -= 10000; payload.expires_at_ms = Date.now() - 1; }
    if (input.permitWrongRecipient) payload.proposal = {...payload.proposal, recipient: "other@example.test"};
    const envelope = {payload, signature: createHmac("sha256", readFileSync(input.config.executionEvidence.keyPath)).update(canonical(payload)).digest("hex")};
    registry.get(input.tool).acceptPermit(envelope, sdk, ctx);
    if (input.revokeAfterPermit || input.ambiguousTaskAfterPermit) {
      const {DatabaseSync} = await import("node:sqlite");
      const db = new DatabaseSync(input.config.executionEvidence.authorizationDatabase);
      if (input.revokeAfterPermit) db.prepare("UPDATE grants SET revoked=1 WHERE id=?").run(input.grantId);
      else {
        const row = db.prepare("SELECT payload,expires FROM grants WHERE id=?").get(input.grantId);
        const grant = JSON.parse(row.payload); grant.id = "other-grant"; grant.binding.task_id = "other-task";
        db.prepare("INSERT INTO grants(id,payload,expires,revoked) VALUES(?,?,?,0)").run(grant.id, JSON.stringify(grant), row.expires);
      }
      db.close();
    }
  }
  if (input.executeParams) input.params = input.executeParams;
  if (input.expireDuringGrantCheck) {
    const {DatabaseSync} = await import("node:sqlite");
    const prepare = DatabaseSync.prototype.prepare, realNow = Date.now;
    DatabaseSync.prototype.prepare = function(sql) {
      const statement = prepare.call(this, sql);
      if (sql.includes("payload,expires,revoked")) {
        const get = statement.get.bind(statement);
        statement.get = (...args) => {
          const row = get(...args);
          Date.now = () => Math.max(realNow() + 600000, Math.ceil(row.expires * 1000));
          return row;
        };
      }
      return statement;
    };
  }
  if (input.stopFirst) { hooks.gateway_stop(); hooks.gateway_stop(); }
  const result = await (secondTools ?? tools).get(input.tool).execute("call", input.params);
  const completionRegistry = globalThis[Symbol.for("rvguard.execution-receipts.v1")];
  const publicResultHadEvidence = Boolean(result.details.rvExecutionReceipt);
  const signedReceipt = completionRegistry?.get(input.tool)?.({...sdk, result, ...input.receiptEventOverrides},
    {...ctx, ...input.receiptContextOverrides});
  if (signedReceipt) result.details.rvExecutionReceipt = signedReceipt;
  let replayError;
  if (input.replayFirst) {
    try { await tools.get(input.tool).execute("call", input.params); }
    catch (error) { replayError = error.message; }
  }
  if (input.stopAll) { hooks.gateway_stop(); secondHooks.gateway_stop(); }
  console.log(JSON.stringify({result, proposal, replayError, publicResultHadEvidence,
    providerRemaining: registry?.has(input.tool) ?? false,
    sideEffect: JSON.parse(readFileSync(input.config.receiptPath, "utf8").trim())}));
} catch (error) {console.log(JSON.stringify({error: String(error.message), sideEffectExists: existsSync(input.config.receiptPath)}));}
'''


@pytest.fixture
def native_producer(tmp_path):
    """仅配置受控宿主签发器，不输出私有密钥。"""
    if shutil.which("node") is None:
        pytest.skip("Node is required for actual producer execution")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "note.txt").write_bytes("真实内容\n".encode())
    store = HostAuthorizationStore(tmp_path / "host", agent_workspaces=[workspace])
    operations = {"office_message_send": "message.send", "office_network_post": "network.egress", "office_document_share": "network.egress"}
    authority = HostContentReceiptAuthority(store, issuer="office-executor", tool_operations=operations)
    binding = TaskBinding("task", "hook:binding", "agent", "session", "run")
    store.issue(HostResourceObserver({"office": workspace}), "office", "note.txt", binding=binding,
                operation="message.send", recipient="partner@example.test")
    config = {"workspaceRoot": str(workspace), "receiptPath": str(tmp_path / "sink.jsonl"), "executionEvidence": {
        "keyPath": str(store.state_dir / "content-signing.key"), "issuer": authority.issuer, "namespace": "office",
        "principalId": binding.principal_id, "taskBindings": [asdict(binding)]}}
    return authority, config


def run_producer(config, tool, params, **options):
    """JSON stdin传配置，仅回传公开签名收据和本地效果。"""
    plugin = Path(__file__).resolve().parents[1] / "testlab/office_chain/native_office_plugin/index.js"
    result = subprocess.run(["node", "--input-type=module", "-e", NODE_RUNNER],
                            input=json.dumps({"plugin": plugin.as_uri(), "config": config, "tool": tool,
                                              "params": params, **options}),
                            text=True, capture_output=True, timeout=10, check=False)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("tool", ["office_message_send", "office_network_post", "office_document_share"])
def test_node_actual_file_bytes_have_verifiable_python_receipt(native_producer, tool):
    """三个有限办公操作消费的文件字节，与签名和实际sink hash一致。"""
    authority, config = native_producer
    params = {"recipient": "partner@example.test", "sourcePath": "note.txt", "body": "NOT the file", "subject": "中文"}
    if tool == "office_network_post":
        params = {"url": "https://partner.example.test/upload", "sourcePath": "note.txt", "body": "NOT the file"}
    elif tool == "office_document_share":
        params = {"recipient": "partner@example.test", "document": "note.txt", "access": "external"}
    observed = run_producer(config, tool, params)
    envelope = observed["result"]["details"]["rvExecutionReceipt"]
    event = SimpleNamespace(raw_payload={"params": params}, metadata={"hook_auth_verified": True,
        "hook_auth_binding": "binding", "agent_id": "agent", "session_id": "session", "run_id": "run", "tool_call_id": "call"})
    step = {"event_model": "tool-call-v1", "execution_state": "succeeded", "tool_name": tool,
            "operation_family": authority.tool_operations[tool], "effects": ["egress"]}
    ledger = ExecutedContentLedger(authority)
    result = ledger.commit(envelope, event=event, step=step)
    expected = hashlib.sha256("真实内容\n".encode()).hexdigest()
    assert result["status"] == "verified"
    assert observed["sideEffect"]["sourceSha256"] == result["inputs"][0]["sha256"] == expected
    assert result["inputs"][0]["resource_id"] == "office:note.txt"
    assert len(ledger.snapshot()) == 1
    assert result["classification_evidence"] == "not_provided"


@pytest.mark.parametrize("options", [{"missingContext": True}, {"ambiguous": True}])
def test_missing_or_ambiguous_sdk_context_does_not_issue_content_evidence(native_producer, options):
    """业务副作用仍真实记录，但缺失/歧义SDK上下文不能签发内容事实。"""
    authority, config = native_producer
    observed = run_producer(config, "office_message_send", {"recipient": "partner@example.test", "sourcePath": "note.txt"}, **options)
    assert observed["result"]["details"]["delivered"] is True
    assert "rvExecutionReceipt" not in observed["result"]["details"]


def test_node_rejects_key_under_symlink_parent(native_producer, tmp_path):
    """受控签发配置不能经父目录软链接读取私有密钥。"""
    authority, config = native_producer
    link = tmp_path / "alias"
    link.symlink_to(authority._store.state_dir, target_is_directory=True)
    config["executionEvidence"]["keyPath"] = str(link / "content-signing.key")
    observed = run_producer(config, "office_message_send", {"recipient": "partner@example.test"})
    assert "symlink ancestors" in observed["error"]


def test_executor_checks_consumed_version_before_side_effect(native_producer):
    """before后换内容，在首次实际发送收据之前失败，旧hash不证明新字节。"""
    authority, config = native_producer
    params = {"recipient": "partner@example.test", "sourcePath": "note.txt",
              "expectedSourceSha256": hashlib.sha256("真实内容\n".encode()).hexdigest()}
    observed = run_producer(config, "office_message_send", params, replaceContent="changed sensitive content")
    assert "source version changed" in observed["error"]
    assert observed["sideEffectExists"] is False


def test_executor_valid_version_uses_same_consumed_buffer(native_producer):
    """精确版本约束不改变实际文件字节；签名包含约束参数。"""
    authority, config = native_producer
    expected = hashlib.sha256("真实内容\n".encode()).hexdigest()
    params = {"recipient": "partner@example.test", "sourcePath": "note.txt", "body": "ignored",
              "expectedSourceSha256": expected}
    observed = run_producer(config, "office_message_send", params)
    assert observed["sideEffect"]["sourceSha256"] == expected
    assert observed["result"]["details"]["rvExecutionReceipt"]["payload"]["inputs"][0]["sha256"] == expected


def test_expected_file_cannot_silently_fallback_to_body(native_producer):
    """受版本约束的缺失文件不能退回同hash的body并宣称引用文件有效。"""
    authority, config = native_producer
    observed = run_producer(config, "office_message_send", {"recipient": "partner@example.test", "sourcePath": "missing.txt",
        "body": "body", "expectedSourceSha256": hashlib.sha256(b"body").hexdigest()})
    assert "expected source resource is unavailable" in observed["error"]
    assert observed["sideEffectExists"] is False


@pytest.mark.parametrize("tool", ["office_message_send", "office_network_post", "office_document_share"])
def test_snapshot_executor_consumes_original_bytes_after_file_replacement(native_producer, tool):
    """检查与执行期间换文件不改变固定Buffer，三个sink的真实hash一致。"""
    _, config = native_producer
    config["snapshotExecution"] = True
    params = {"recipient": "partner@example.test", "sourcePath": "note.txt"}
    if tool == "office_network_post":
        params = {"url": "https://partner.example.test/upload", "sourcePath": "note.txt"}
    elif tool == "office_document_share":
        params["document"] = "note.txt"
    result = run_producer(config, tool, params, replaceContent="replaced secret")
    expected = hashlib.sha256("真实内容\n".encode()).hexdigest()
    assert result["sideEffect"]["sourceSha256"] == expected
    assert result["result"]["details"]["rvExecutionReceipt"]["payload"]["inputs"][0]["sha256"] == expected


@pytest.mark.parametrize("options", [{"missingContext": True}, {"ambiguous": True},
    {"executeParams": {"recipient": "attacker@example.test", "sourcePath": "note.txt"}}])
def test_snapshot_missing_ambiguous_or_changed_arguments_have_no_side_effect(native_producer, options):
    """强契约缺失、错run或接收方被更换时，首次副作用前失败。"""
    _, config = native_producer
    config["snapshotExecution"] = True
    result = run_producer(config, "office_message_send", {"recipient": "partner@example.test", "sourcePath": "note.txt"}, **options)
    assert "snapshot" in result["error"]
    assert result["sideEffectExists"] is False


@pytest.mark.parametrize("source", ["missing.txt", "fifo", "oversize"])
def test_snapshot_rejects_unavailable_nonregular_or_large_file(native_producer, source):
    """缺失文件不能回退body，FIFO不能阻塞读取，资源预算明确有界。"""
    import os
    _, config = native_producer
    config["snapshotExecution"] = True
    path = Path(config["workspaceRoot"]) / source
    if source == "fifo":
        os.mkfifo(path)
    elif source == "oversize":
        path.write_bytes(b"x" * (1024 * 1024 + 1))
    result = run_producer(config, "office_message_send", {"recipient": "partner@example.test", "sourcePath": source, "body": "fallback"})
    assert "snapshot" in result["error"]
    assert result["sideEffectExists"] is False


@pytest.mark.parametrize("duplicate_before", [False, True])
def test_duplicate_sdk_registries_share_one_consumable_snapshot(native_producer, duplicate_before):
    """一个注册表准备，另一个执行，证明与实际同Buffer且不能跨注册表重放。"""
    _, config = native_producer
    config["snapshotExecution"] = True
    observed = run_producer(config, "office_message_send",
        {"recipient": "partner@example.test", "sourcePath": "note.txt"},
        duplicateRegister=True, duplicateBefore=duplicate_before,
        replaceContent="later replacement", replayFirst=True, stopAll=True)
    assert "error" not in observed
    assert observed["proposal"]["payload"]["source"]["sha256"] == observed["sideEffect"]["sourceSha256"]
    assert observed["sideEffect"]["sourceSha256"] == hashlib.sha256("真实内容\n".encode()).hexdigest()
    assert "snapshot" in observed["replayError"]
    assert observed["providerRemaining"] is False


def test_stopping_one_registry_preserves_other_live_owner(native_producer):
    """生命周期引用计数，重复stop不能删除另一注册表仍使用的证明接口。"""
    _, config = native_producer
    config["snapshotExecution"] = True
    observed = run_producer(config, "office_message_send",
        {"recipient": "partner@example.test", "sourcePath": "note.txt"},
        duplicateRegister=True, stopFirst=True)
    assert "error" not in observed
    assert observed["providerRemaining"] is True


def test_conflicting_sdk_registry_config_cannot_replace_provider(native_producer):
    """不同受控主体不能按相同工具名替换已注册签名提供者。"""
    _, config = native_producer
    config["snapshotExecution"] = True
    other = json.loads(json.dumps(config))
    other["executionEvidence"]["principalId"] = "other-principal"
    observed = run_producer(config, "office_message_send",
        {"recipient": "partner@example.test", "sourcePath": "note.txt"},
        duplicateRegister=True, secondConfig=other)
    assert "conflicting execution proposal provider" in observed["error"]
    assert observed["sideEffectExists"] is False


@pytest.mark.parametrize("mode", ["unsigned-snapshot", "legacy"])
def test_unsigned_or_legacy_registration_cannot_execute_with_another_proof(native_producer, tmp_path, mode):
    """签名配置之后的无签名/旧执行器不得保留A证明却实际发送B字节。"""
    _, config = native_producer
    config["snapshotExecution"] = True
    other_workspace = tmp_path / "other-workspace"
    other_workspace.mkdir()
    (other_workspace / "note.txt").write_text("other bytes")
    other = {"workspaceRoot": str(other_workspace), "receiptPath": str(tmp_path / "other-sink.jsonl"),
             "snapshotExecution": mode == "unsigned-snapshot"}
    observed = run_producer(config, "office_message_send",
        {"recipient": "partner@example.test", "sourcePath": "note.txt"},
        duplicateRegister=True, secondConfig=other)
    assert "conflicting execution proposal provider" in observed["error"]
    assert observed["sideEffectExists"] is False
    assert not Path(other["receiptPath"]).exists()


def test_content_signature_is_only_available_on_private_host_channel(native_producer):
    """模型可见工具结果不携带HMAC；宿主同调用接口获取完整真实签名。"""
    _, config = native_producer
    result = run_producer(config, "office_message_send", {"recipient": "partner@example.test", "sourcePath": "note.txt"})
    assert result["publicResultHadEvidence"] is False
    assert len(result["result"]["details"]["rvExecutionReceipt"]["signature"]) == 64


@pytest.mark.parametrize("options", [
    {"receiptContextOverrides": {"sessionId": "other"}},
    {"receiptContextOverrides": {"agentId": "other"}},
    {"receiptContextOverrides": {"runId": "other"}},
    {"receiptEventOverrides": {"toolCallId": "other"}},
    {"receiptEventOverrides": {"error": "failed"}},
    {"receiptEventOverrides": {"result": {"details": {"receiptId": "forged"}}}},
    {"receiptEventOverrides": {"result": {"isError": True}}},
])
def test_private_receipt_channel_rejects_mismatched_or_failed_callbacks(native_producer, options):
    """其他身份、失败回调和错误实际收据ID均不能获得成功证据。"""
    _, config = native_producer
    result = run_producer(config, "office_message_send", {"recipient": "partner@example.test", "sourcePath": "note.txt"}, **options)
    assert "rvExecutionReceipt" not in result["result"]["details"]
    assert result["sideEffect"]["sourceBytes"] > 0


def test_permit_executor_checks_current_grant_before_actual_side_effect(native_producer):
    """实际Node执行器持有同宿主数据库事务并消费确定授权字节。"""
    authority, config = native_producer
    config["snapshotExecution"] = True
    config["executionEvidence"]["authorizationDatabase"] = str(authority._store.database)
    grant = authority._store.query()[0]
    result = run_producer(config, "office_message_send", {"recipient": "partner@example.test", "sourcePath": "note.txt"}, grantId=grant["id"])
    assert "error" not in result
    assert result["proposal"]["payload"]["enforcement"] == "snapshot-grant-v1"
    assert result["sideEffect"]["sourceSha256"] == grant["resource"]["content_version"].removeprefix("sha256:")


@pytest.mark.parametrize("options", [
    {"revokeAfterPermit": True}, {"ambiguousTaskAfterPermit": True},
    {"permitExpired": True}, {"permitWrongRecipient": True},
    {"expireDuringGrantCheck": True},
])
def test_permit_revocation_or_scope_change_has_no_actual_side_effect(native_producer, options):
    """before已签许可后撤销/换任务，或签错范围，都在首次副作用前失败。"""
    authority, config = native_producer
    config["snapshotExecution"] = True
    config["executionEvidence"]["authorizationDatabase"] = str(authority._store.database)
    grant = authority._store.query()[0]
    result = run_producer(config, "office_message_send", {"recipient": "partner@example.test", "sourcePath": "note.txt"}, grantId=grant["id"], **options)
    assert "error" in result
    assert result["sideEffectExists"] is False
