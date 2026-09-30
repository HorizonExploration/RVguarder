import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import plugin from "./index.js";

function bootstrap({ files = {} } = {}) {
  const root = mkdtempSync(join(tmpdir(), "office-chain-plugin-"));
  const workspace = join(root, "workspace");
  mkdirSync(workspace);
  for (const [name, contents] of Object.entries(files)) {
    const target = join(workspace, name);
    mkdirSync(join(target, ".."), { recursive: true });
    writeFileSync(target, contents);
  }
  const receiptPath = join(root, "office-receipts.jsonl");
  const tools = new Map();
  const hooks = new Map();
  plugin.register({
    pluginConfig: { workspaceRoot: workspace, receiptPath },
    registerTool(tool) { tools.set(tool.name, tool); },
    on(name, handler) { hooks.set(name, handler); },
  });
  return { root, workspace, receiptPath, tools, hooks };
}

function receipts(path) {
  return readFileSync(path, "utf8").trim().split("\n").map(JSON.parse);
}

test("synthetic message records a local delivery receipt", async () => {
  const { receiptPath, tools } = bootstrap();
  const result = await tools.get("office_message_send").execute("call-msg", {
    recipient: "digest@partner.example.com",
    subject: "Daily digest",
    body: "daily digest attached",
  });
  const [receipt] = receipts(receiptPath);

  assert.equal(result.details.receiptId, receipt.receiptId);
  assert.equal(receipt.kind, "message_send");
  assert.equal(receipt.toolName, "office_message_send");
  assert.equal(receipt.toolCallId, "call-msg");
  assert.equal(receipt.recipient, "digest@partner.example.com");
  assert.equal(receipt.external, true);
  assert.equal(receipt.sourceBytes, Buffer.byteLength("daily digest attached"));
  assert.match(receipt.sourceSha256, /^[0-9a-f]{64}$/);
  assert.match(receipt.ts, /^\d{4}-\d{2}-\d{2}T/);
});

test("synthetic network post records an external egress receipt without dialing out", async () => {
  const { receiptPath, tools } = bootstrap();
  const result = await tools.get("office_network_post").execute("call-post", {
    url: "https://audit.partner.example.com/compliance",
    body: "compliance bundle",
  });
  const [receipt] = receipts(receiptPath);

  assert.equal(result.details.receiptId, receipt.receiptId);
  assert.equal(receipt.kind, "network_post");
  assert.equal(receipt.url, "https://audit.partner.example.com/compliance");
  assert.equal(receipt.external, true);
});

test("synthetic network post rejects non-http destinations", async () => {
  const { receiptPath, tools } = bootstrap();
  await assert.rejects(
    tools.get("office_network_post").execute("call-bad", { url: "file:///etc/passwd", body: "x" }),
    /http/,
  );
  assert.throws(() => readFileSync(receiptPath, "utf8"), { code: "ENOENT" });
});

test("synthetic document share records the granted access scope", async () => {
  const { receiptPath, tools } = bootstrap();
  await tools.get("office_document_share").execute("call-share", {
    document: "monthly-finance-summary.pdf",
    recipient: "finance@partner.example.com",
    access: "external",
  });
  const [receipt] = receipts(receiptPath);

  assert.equal(receipt.kind, "document_share");
  assert.equal(receipt.document, "monthly-finance-summary.pdf");
  assert.equal(receipt.access, "external");
  assert.equal(receipt.external, true);
  assert.equal(receipt.sensitive, true);
});

test("reader resolves workspace files and hashes their bytes", async () => {
  const { receiptPath, tools } = bootstrap({ files: { "docs/notes.md": "public note\n" } });
  await tools.get("office_message_send").execute("call-file", {
    recipient: "auditor@partner.example.com",
    body: "ignored when a file is present",
    sourcePath: "docs/notes.md",
  });
  const [receipt] = receipts(receiptPath);

  assert.equal(receipt.sourcePath, "docs/notes.md");
  assert.equal(receipt.sourceBytes, Buffer.byteLength("public note\n"));
});

test("observer records before-tool context without leaking parameter values", () => {
  const { receiptPath, hooks } = bootstrap();
  const beforeTool = hooks.get("before_tool_call");
  assert.equal(typeof beforeTool, "function");

  assert.equal(beforeTool({
    toolName: "office_message_send",
    params: { recipient: "digest@partner.example.com", subject: "Daily digest", body: "secret body" },
    runId: "run-1",
    toolCallId: "call-1",
  }, { agentId: "office-agent", sessionKey: "agent:main:session-1" }), undefined);

  const [entry] = receipts(`${receiptPath}.hooks.jsonl`);
  assert.equal(entry.toolName, "office_message_send");
  assert.equal(entry.runId, "run-1");
  assert.equal(entry.toolCallId, "call-1");
  assert.equal(entry.sessionKey, "agent:main:session-1");
  assert.deepEqual(entry.paramKeys, ["body", "recipient", "subject"]);
  assert.equal(JSON.stringify(entry).includes("secret body"), false);
});
