import test from "node:test";
import assert from "node:assert/strict";
import {installHookBoundaryTiming} from "./hook_boundary_timing.js";

test("passive callback observer covers continued and block short circuit", () => {
  const hooks=[], flushed=[];
  const observer=installHookBoundaryTiming({on(name,fn,options){hooks.push({name,fn,options});}}, rows=>flushed.push(...rows));
  const before=hooks.filter(h=>h.name==="before_tool_call").sort((a,b)=>b.options.priority-a.options.priority);
  const ctx={runId:"run",sessionId:"session"};
  const allow={toolName:"read",toolCallId:"allow"};
  assert.equal(before[0].fn(allow,ctx),undefined);
  assert.equal(before[1].fn(allow,ctx),undefined);
  const block={toolName:"exec",toolCallId:"block"};
  before[0].fn(block,ctx);observer.finish(block,ctx,"guard_block");
  assert.equal(flushed.length,0);
  hooks.find(h=>h.name==="gateway_stop").fn();
  assert.equal(flushed.length,2);
  assert.deepEqual(flushed.map(r=>r.outcome),["continued","guard_block"]);
  assert.ok(flushed.every(r=>r.elapsed_ms>=0));
  assert.ok(flushed.every(r=>r.excludes.includes("human_approval_wait")));
});

test("discovery and live runtime registrations share an observer and flush once", () => {
  const discovery=[], live=[], flushed=[];
  const api = list => ({on(name,fn,options){list.push({name,fn,options});}});
  const first=installHookBoundaryTiming(api(discovery), rows=>flushed.push(...rows));
  assert.equal(installHookBoundaryTiming(api(live), rows=>flushed.push(...rows)),first);
  const event={toolName:"read",toolCallId:"call"},ctx={runId:"run"};
  for (const hook of live.filter(h=>h.name==="before_tool_call").sort((a,b)=>b.options.priority-a.options.priority)) hook.fn(event,ctx);
  live.find(h=>h.name==="gateway_stop").fn();
  discovery.find(h=>h.name==="gateway_stop").fn();
  assert.equal(flushed.length,1);
  assert.equal(globalThis[Symbol.for("rvguard.hook-boundary-timing.v1")],undefined);
});
