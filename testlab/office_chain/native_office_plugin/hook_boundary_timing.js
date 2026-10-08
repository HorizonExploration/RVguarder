// Passive common callback boundary observer. No tool execution, decision, or
// synchronous file IO; flushing belongs to the isolated Gateway shutdown.
import {performance} from "node:perf_hooks";
const KEY = Symbol.for("rvguard.hook-boundary-timing.v1");

export function installHookBoundaryTiming(api, flush) {
  // OpenClaw may register one plugin during discovery and again for the live
  // tool runtime in the same process. Share measurements, register callbacks
  // on each API, and flush once from the live Gateway's shutdown.
  const existing = globalThis[KEY];
  if (existing) {
    if (typeof existing.register !== "function") throw new Error("conflicting hook timing observer");
    existing.register(api, flush);
    return existing;
  }
  const pending = new Map(), rows = [];
  let closed = false;
  const identity = (event, ctx) => {
    const run = event?.runId || ctx?.runId;
    const call = event?.toolCallId || ctx?.toolCallId;
    return run && call ? `${run}:${call}` : null;
  };
  const finish = (event, ctx, outcome = "continued") => {
    const id = identity(event, ctx), value = pending.get(id);
    if (!value || closed) return;
    pending.delete(id);
    if (rows.length < 4096) rows.push({...value, outcome,
      elapsed_ms: performance.now() - value.started_ms});
  };
  const register = (activeApi, activeFlush) => {
    activeApi.on("before_tool_call", (event, ctx) => {
    const id = identity(event, ctx);
    if (closed || !id || pending.has(id) || pending.size >= 256) return;
    pending.set(id, {step_id: id, tool_name: event.toolName,
      session_id: ctx?.sessionId, started_ms: performance.now(),
      boundary: "first_before_callback_entry_to_terminal_callback_exit",
      excludes: ["SDK_dispatch_prologue_and_epilogue", "human_approval_wait", "tool_execution"]});
    }, {priority: 10000});
    activeApi.on("before_tool_call", (event, ctx) => finish(event, ctx), {priority: -10000});
    activeApi.on("gateway_stop", () => {
      if (closed) return;
      closed = true;
      try { activeFlush(rows); }
      finally {
        if (globalThis[KEY] === observer) delete globalThis[KEY];
        pending.clear();
      }
    });
  };
  const observer = Object.freeze({finish, register});
  globalThis[KEY] = observer;
  register(api, flush);
  return observer;
}
