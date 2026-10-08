import assert from "node:assert/strict";
import test from "node:test";
import { ExecutionSnapshots } from "./execution_snapshot.js";

const ctx = { runId: "run", agentId: "agent", sessionId: "session" };
const event = (call, params = { body: "digest", recipient: "partner@example.test" }) =>
  ({ toolName: "office_message_send", toolCallId: call, runId: "run", params });

test("snapshot rejects nested and oversized parameters before hashing", () => {
  const snapshots = new ExecutionSnapshots("unused-inline-workspace");
  for (const params of [{ body: "x".repeat(1024 * 1024 + 1) }, { body: { nested: "content" } }]) {
    assert.throws(() => snapshots.prepare(event("call", params), ctx), /arguments/);
    assert.throws(() => snapshots.take("office_message_send", "call", params), /arguments|snapshot/);
  }
});

test("snapshots are bounded, expire and are consumed once", () => {
  const snapshots = new ExecutionSnapshots("unused-inline-workspace");
  const start = Date.now();
  const originalNow = Date.now;
  try {
    Date.now = () => start;
    for (let i = 0; i < 16; i++) snapshots.prepare(event(`call-${i}`), ctx);
    assert.throws(() => snapshots.prepare(event("overflow"), ctx), /capacity/);
    assert.equal(snapshots.take("office_message_send", "call-0", event("").params).bytes.toString(), "digest");
    assert.throws(() => snapshots.take("office_message_send", "call-0", event("").params), /snapshot/);
    Date.now = () => start + 300000;
    assert.throws(() => snapshots.take("office_message_send", "call-1", event("").params), /snapshot/);
    snapshots.prepare(event("new"), ctx);
    assert.equal(snapshots.calls.size, 1);
  } finally { Date.now = originalNow; }
});

test("invalid repeated before invalidates an existing snapshot", () => {
  const snapshots = new ExecutionSnapshots("unused-inline-workspace");
  snapshots.prepare(event("call"), ctx);
  assert.throws(() => snapshots.prepare(event("call", { body: {} }), ctx), /arguments/);
  assert.throws(() => snapshots.take("office_message_send", "call", event("").params), /snapshot/);
});

test("conflicting SDK identity invalidates a prior snapshot", () => {
  const snapshots = new ExecutionSnapshots("unused-inline-workspace");
  snapshots.prepare(event("call"), ctx);
  assert.throws(() => snapshots.prepare({...event("call"), context: {agentId: "other"}}, ctx), /identity/);
  assert.throws(() => snapshots.take("office_message_send", "call", event("").params), /snapshot/);
});

test("reverse call-ID conflict invalidates both candidate snapshots", () => {
  const snapshots = new ExecutionSnapshots("unused-inline-workspace");
  snapshots.prepare(event("C"), {...ctx, toolCallId: "C"});
  snapshots.prepare(event("D"), {...ctx, toolCallId: "D"});
  assert.throws(() => snapshots.prepare(event("D"), {...ctx, toolCallId: "C"}), /identity/);
  for (const id of ["C", "D"]) assert.throws(() => snapshots.take("office_message_send", id, event("").params), /snapshot/);
});
