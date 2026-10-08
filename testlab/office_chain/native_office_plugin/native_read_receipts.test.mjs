import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync, mkdirSync, writeFileSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {createHash} from "node:crypto";
import plugin from "./index.js";

function setup(t) {
  const root = mkdtempSync(join(tmpdir(), "native-read-proof-"));
  const workspace = join(root, "workspace"), host = join(root, "host");
  mkdirSync(workspace); mkdirSync(host, {mode: 0o700});
  writeFileSync(join(workspace, "note.txt"), "fixture content");
  // Public test constant; never any project or deployment key.
  writeFileSync(join(host, "key"), Buffer.alloc(32, 7), {mode: 0o600});
  const hooks = new Map();
  plugin.register({pluginConfig: {workspaceRoot: workspace, receiptPath: join(root, "receipts"), nativeReadEvidence: true,
    executionEvidence: {keyPath: join(host, "key"), issuer: "executor", namespace: "office", principalId: "principal",
      taskBindings: [{task_id: "task", principal_id: "principal", agent_id: "agent", session_id: "session", run_id: "run"}]}},
    registerTool() {}, on(name, callback) {hooks.set(name, callback);}});
  t.after(() => {hooks.get("gateway_stop")(); rmSync(root, {recursive: true, force: true});});
  const event = {toolName: "read", toolCallId: "call", runId: "run", params: {path: "note.txt"}};
  const ctx = {agentId: "agent", sessionId: "session", runId: "run"};
  const completed = {...event, result: {content: [{type: "text", text: "fixture content"}], details: {kind: "text", content: "fixture content"}}};
  const provider = globalThis[Symbol.for("rvguard.execution-receipts.v1")].get("read");
  return {hooks, event, ctx, completed, provider, workspace};
}

test("full native read proof remains in the private host channel", t => {
  const f = setup(t); f.hooks.get("before_tool_call")(f.event, f.ctx);
  const proof = f.provider(f.completed, f.ctx);
  assert.equal(proof.payload.kind, "read");
  assert.equal(proof.payload.inputs[0].sha256, createHash("sha256").update("fixture content").digest("hex"));
  assert.equal(proof.payload.task_id, "task");
  assert.equal(f.completed.result.details.rvExecutionReceipt, undefined);
  assert.deepEqual(f.provider(f.completed, f.ctx), proof);
});

for (const mechanism of ["partial", "failed", "truncated", "other_agent", "changed_bytes", "changed_params"]) {
  test(`native read does not attest ${mechanism}`, t => {
    const f = setup(t);
    if (mechanism === "partial") f.event.params.offset = 1;
    f.hooks.get("before_tool_call")(f.event, f.ctx);
    if (mechanism === "failed") f.completed.result.isError = true;
    if (mechanism === "truncated") f.completed.result.details.kind = "truncated";
    if (mechanism === "other_agent") f.ctx.agentId = "other";
    if (mechanism === "changed_bytes") writeFileSync(join(f.workspace, "note.txt"), "changed");
    if (mechanism === "changed_params") f.hooks.get("before_tool_call")({...f.event, params: {path: "other.txt"}}, f.ctx);
    assert.equal(f.provider(f.completed, f.ctx), null);
  });
}

test("native redacted dotenv access is separate from consumed bytes", t => {
  const f = setup(t);
  writeFileSync(join(f.workspace, ".env"), "API_KEY=fixture-secret\n");
  const event = {...f.event, params: {path: ".env"}};
  f.hooks.get("before_tool_call")(event, f.ctx);
  const completed = {...event, result: {content: [{type: "text", text: "API_KEY=[REDACTED]\n"}],
    details: {kind: "text", content: "API_KEY=[REDACTED]\n"}}};
  const proof = f.provider(completed, f.ctx);
  assert.equal(proof.payload.kind, "read_access");
  assert.equal(proof.payload.observation, "observed_before_after");
  assert.deepEqual(proof.payload.inputs, []);
  assert.equal(proof.payload.accessed_resource.sha256, createHash("sha256").update("API_KEY=fixture-secret\n").digest("hex"));
  assert.notEqual(proof.payload.details_content_sha256, proof.payload.accessed_resource.sha256);
  assert.deepEqual(f.provider(completed, f.ctx), proof);
});

test("changed dotenv version cannot be signed as stable access", t => {
  const f = setup(t);
  writeFileSync(join(f.workspace, ".env"), "API_KEY=fixture-secret\n");
  const event = {...f.event, params: {path: ".env"}};
  f.hooks.get("before_tool_call")(event, f.ctx);
  writeFileSync(join(f.workspace, ".env"), "API_KEY=changed-secret\n");
  const completed = {...event, result: {details: {kind: "text", content: "API_KEY=[REDACTED]\n"}}};
  assert.equal(f.provider(completed, f.ctx), null);
});
