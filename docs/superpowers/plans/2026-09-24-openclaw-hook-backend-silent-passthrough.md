# OpenClaw Hook Backend-Silent Passthrough Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the installed Guard plugin transparent to every OpenClaw Agent's tool behavior, including writes and execution, whenever the Guard backend is unreachable, while preserving decisions when it responds.

**Architecture:** Change only the generated JavaScript bridge's availability state and its local status/config presentation; do not change Python PMKB/RV policy. Begin in a silent pass-through state, use background health checks to activate or recover, and immediately return `undefined` on transport failure. Distinguish transport failure from a received HTTP error, and skip all backend callbacks while silent. Test generated JavaScript with an in-memory `fetch` stub and no real tools/network.

**Tech Stack:** Python 3.13+, pytest, Node.js ES modules for generated-plugin behavior tests, existing OpenClaw Plugin SDK bridge.

**Spec:** `docs/superpowers/specs/2026-09-24-openclaw-hook-backend-silent-passthrough-design.md`.

## Global Constraints

- User-confirmed priority: when Guard is unreachable, return `undefined` for every `before_tool_call`, regardless of tool, Agent ID, or legacy `failClosed=true`; OpenClaw's own controls remain unchanged.
- Do not run a real shell command, tool, office SDK, Guard server, or network request in tests; Node executes only the generated plugin against fake callbacks and `fetch`.
- Startup is silent until a successful background health check; first failure after a healthy check may cost one bounded decision timeout (default 2000 ms), but subsequent calls must not retry synchronously.
- A received HTTP error is not a transport outage: keep the previous tiered error treatment, including the legacy `failClosed=true` override for that case only.
- Preserve backend-available `allow`, `require_approval`, and `block` decisions and all existing PMKB/RV code.
- Do not modify `docs/architecture/permission-kb-runtime-architecture.md` or `testlab/.tmp-ppt/`; both are unrelated user work in the current tree.
- Keep the work on the current `master` as the user requested. Do not count silent-mode calls as Guard security interceptions in `office_value` claims.

## Review Focus

1. A backend process missing at startup must allow the very first `write`/`shell_exec` without a synchronous backend POST (Task 1 test).
2. An active bridge's first transport failure must allow that call and make all later tool and audit callbacks immediate, regardless of `failClosed=true` (Tasks 1–2 tests).
3. HTTP 401 and 500 responses must not silently allow high-impact actions or label the backend unreachable (Task 1 test).
4. A previously issued OpenClaw approval must not wait for Guard result synchronization once the bridge is silent (Task 2 test).
5. Recovery must restore real Guard `block` and `require_approval`, and a bad health response must not falsely claim healthy protection (Task 2 test).

---

### Task 1: Transport-Aware Silent Before Hook

**Files:**
- Modify: `openclaw_guard/integrations/hook_runtime.py` (`_plugin_source`: `postJson`, availability state, `before_tool_call`).
- Create: `tests/test_hook_silent_passthrough.py` (Node-driven generated-plugin contract).
- Modify: `tests/test_review_blockers.py` (replace the old tiered-outage expectation, preserve available-backend approval-bound checks).

**Interfaces:**
- Consumes: `_plugin_source(guard_url: str, auth_token: str) -> str`, `api.on("before_tool_call", handler)`, `postJson(...)`.
- Produces in generated JS: `transportFailure(error) -> Error` with `kind="transport"`; `httpFailure(status, detail) -> Error` with `kind="http"`; `enterSilent(reason) -> void`; `enterActive() -> void`; `backendState` string `"silent"|"active"`; `backendResponseError` boolean. These are plugin-private and not exposed as a Python API.

- [ ] **Step 1: Write failing runtime tests.** Add a Python helper in `tests/test_hook_silent_passthrough.py` that writes `_plugin_source(...)` to a temporary `.mjs`, then uses `subprocess.run(["node", "--input-type=module", "-e", script, str(plugin_path)], capture_output=True, text=True, check=False, timeout=10)`; skip only when `shutil.which("node") is None`. The Node script registers fake `api.on` callbacks, stubs `globalThis.fetch`, and never invokes a real tool. Test A: with `failClosed: true` and a `fetch` stub that throws, call `before_tool_call` for `read`, `write`, and `shell_exec` before `gateway_start`; all results are `undefined` and the fetch-call count is zero. Test B: after a health success and a successful `allow`, make decision POST throw; the first `shell_exec` returns `undefined`, and a later `write` returns `undefined` without another POST. Test C: make decision POST return status 401 or 500; `shell_exec` still yields `{block: true}` under the existing tiered policy and the next decision POST is attempted (no silent transition).

```javascript
const result = await hooks.before_tool_call({toolName: "shell_exec", params: {command: "echo fixture"}}, {});
if (result !== undefined) process.exit(1);
if (decisionPosts !== 0) process.exit(2); // startup silent: no synchronous POST
```

- [ ] **Step 2: Run red test.** `python -m pytest -q tests/test_hook_silent_passthrough.py tests/test_review_blockers.py -k 'silent or tiered_failure'`. Expected: startup/shell tests fail because the current plugin tries the backend and blocks high-impact calls.
- [ ] **Step 3: Implement the minimal before-hook state machine.** In the generated JS template, initialize `backendState="silent"`. In `postJson`, catch `fetch` rejection/abort as a typed `kind="transport"` failure; classify a received non-2xx response as `kind="http"` and a response-body/read/parse problem as `kind="protocol"`. Do not classify all `Error` objects as outages. At the start of `before_tool_call`, if `backendState==="silent"`, return `undefined` before POST. On `transport` failure call `enterSilent("decision_transport")` and return `undefined` for that same call. On `http`/`protocol` failure retain the old rule: low-impact call returns `undefined`; high-impact or `failClosed=true` returns `{block:true}`. On a valid `allow`/approval/block response preserve the current code path. Make `enterSilent` idempotent and log only a bounded, non-sensitive reason code.

```javascript
if (backendState === "silent") return undefined;
try {
  const result = await postJson(beforeUrl, payload, decisionTimeoutMs, authToken);
  // Continue through the existing allow / require_approval / block handling.
} catch (error) {
  if (error?.kind === "transport") {
    enterSilent("decision_transport");
    return undefined;
  }
  return failClosed || isHighImpactTool(event) ? {block: true, blockReason: "Guard backend response error"} : undefined;
}
```

Here `beforeUrl` is `${guardUrl}/api/hook/before-tool-call` and `payload` is the existing Hook payload object; keep its current fields. Retain bounded approval text, audit-safe logging and `action_record` handling in the actual template.

- [ ] **Step 4: Run green and focused compatibility tests.** `python -m pytest -q tests/test_hook_silent_passthrough.py tests/test_review_blockers.py tests/test_hook_runtime.py`. Expected: the new behavior and all available-backend approval tests pass. Update existing Node tests that call `before_tool_call` without `gateway_start` to first deliver a fake healthy check; do not weaken their approval assertions.
- [ ] **Step 5: Commit.** `git add openclaw_guard/integrations/hook_runtime.py tests/test_hook_silent_passthrough.py tests/test_review_blockers.py && git commit -m "feat: pass through tools when Guard transport is unavailable"`.

### Task 2: Recovery, After Hook, Approval Sync and Status

**Files:**
- Modify: `openclaw_guard/integrations/hook_runtime.py` (`doHealthCheck`, `gateway_start`, `gateway_stop`, `after_tool_call`, `onResolution`, status method).
- Modify: `openclaw_guard/integrations/openclaw_adapter.py` (`get_guard_hook_status` fallback).
- Test: `tests/test_hook_silent_passthrough.py`.
- Test: `tests/test_review_blockers.py`.

**Interfaces:**
- Consumes: Task 1 `enterSilent`, `enterActive`, `backendState`, `backendResponseError`, and existing `RECOVERY_THRESHOLD` (default 2).
- Produces: status response `{state: "silent"|"active", backendResponseError: boolean, circuitOpen: boolean, ...}`; `circuitOpen` is true exactly while silent. A fallback status inferred merely from plugin installation reports `state: "unknown"`, `failClosed: null`, not fabricated protection settings.

- [ ] **Step 1: Write failing lifecycle tests.** With fake `fetch` routes, call `gateway_start`, await its returned health-check promise, and verify one successful initial health check activates the bridge. Capture `registerGatewayMethod`'s handler and read status using its `respond` callback. While active, make `after_tool_call` throw a transport error; the subsequent write `before_tool_call` returns `undefined` with zero decision POSTs. Repeat for approval `onResolution`: after entering silent, invoke the saved callback, assert no POST and immediate resolution; when active, sync remains attempted. From silent after an outage, deliver two consecutive successful health checks by replacing `globalThis.setInterval` with a function that captures its callback before plugin registration; invoke that callback twice and await both returned promises. Then a Guard `block` response and a `require_approval` response must be honored again. A 500 health response must set `backendResponseError=true` without claiming `active` protection is healthy. Assert status fallback has `state="unknown"`, `failClosed is None` when only a loaded-plugin listing is known.

```javascript
const hooks = {};
let statusHandler;
const api = {
  pluginConfig: {guardUrl: "http://guard.test", failClosed: true},
  on(name, handler) { hooks[name] = handler; },
  registerGatewayMethod(_name, handler) { statusHandler = handler; },
  logger: {info() {}, warn() {}},
};
plugin.register(api); // plugin is the imported generated .mjs default export
await hooks.gateway_start();
let status;
await statusHandler({respond(_ok, value) { status = value; }});
if (status.state !== "active") process.exit(1);
await hooks.after_tool_call({toolName: "write", params: {}}, {}); // fake transport error
const result = await hooks.before_tool_call({toolName: "write", params: {}}, {});
if (result !== undefined || decisionPosts !== 0) process.exit(2);
hooks.gateway_stop();
```

- [ ] **Step 2: Run red test.** `python -m pytest -q tests/test_hook_silent_passthrough.py -k 'recovery or after or approval_sync or status'`. Expected: missing state fields and continued callback POSTs while silent.
- [ ] **Step 3: Implement lifecycle behavior.** Make `gateway_start` return the initial `doHealthCheck()` promise and schedule later background checks. One successful initial health response calls `enterActive`; after a transport outage require two consecutive successful checks before clearing the recovery diagnostic. A received non-2xx health response proves transport reachability, so set `backendState="active"` with `backendResponseError=true` and let the next before Hook receive and handle its HTTP error through the tiered path; do not claim protection is healthy. In silent state, `after_tool_call` and `onResolution` return without POST; in active state a transport error calls `enterSilent`, while HTTP errors keep the responsive-error diagnostic and do not reverse an already executed action. Return state and `circuitOpen` from the status method. Change `get_guard_hook_status`'s loaded-plugin fallback to `state="unknown"`, `failClosed=None`.

```javascript
if (backendState === "silent") return;
try { await postJson(callbackUrl, payload, callbackTimeoutMs, authToken); }
catch (error) { if (error?.kind === "transport") enterSilent("callback_transport"); }
```

- [ ] **Step 4: Run focused and full regression.** `python -m pytest -q tests/test_hook_silent_passthrough.py tests/test_review_blockers.py tests/test_hook_runtime.py`; then `python -m pytest -q`. Expected: all tests pass (environment-dependent skips documented). Also generate one plugin bundle in a temporary test project and validate `node --check` with the existing `_validate_plugin_bundle`; do not install it into the user's OpenClaw.
- [ ] **Step 5: Commit.** `git add openclaw_guard/integrations/hook_runtime.py openclaw_guard/integrations/openclaw_adapter.py tests/test_hook_silent_passthrough.py tests/test_review_blockers.py && git commit -m "feat: recover Guard bridge without blocking silent agents"`.

### Task 3: Configuration, Documentation and Non-Interference Evidence

**Files:**
- Modify: `openclaw_guard/integrations/hook_runtime.py` (manifest/config description and deprecation log, no new decision rules).
- Modify: `README.md`, `AGENTS.md`, `docs/features/runtime-hook.md`, `docs/architecture/index.md`, `docs/architecture/project-memory.md`.
- Modify: `docs/architecture/pmkb-e2e-audit-2026-09-15.md` (append a dated supersession note; preserve historical observations).
- Modify: `testlab/office_value/README.md` (availability evidence boundary only).
- Modify: `tests/test_hook_silent_passthrough.py`.

**Interfaces:**
- Consumes: Tasks 1–2 generated-plugin behavior and status fields.
- Produces: user-facing documented contract and one regression test comparing plugin-silent outcomes against no-plugin pass-through for `read`, `write`, `shell_exec`, `message`, and two Agent IDs.

- [ ] **Step 1: Write failing contract tests.** For each tool and Agent ID, collect the callback result in silent mode and compare with the no-plugin result (`undefined`); verify no `fetch` POST, no `requireApproval`, and no `{block:true}`. Check `failClosed=true` in the same matrix. Verify an HTTP 401 with `failClosed=true` still blocks, and a valid Guard `block` after recovery still blocks. Add a generated-config assertion that the default is not described as tiered blocking during transport outage, while old `failClosed` input remains accepted.

```javascript
for (const agentId of ["agent-a", "agent-b"]) {
  for (const toolName of ["read", "write", "shell_exec", "message"]) {
    const outcome = await hooks.before_tool_call({toolName, params: {}, context: {agentId}}, {});
    if (outcome !== undefined) process.exit(1);
  }
}
if (decisionPosts !== 0) process.exit(2);
```

- [ ] **Step 2: Run red test.** `python -m pytest -q tests/test_hook_silent_passthrough.py -k 'non_interference or config_contract'`. Expected: outdated generated config and documentation contract tests fail, or the test reports the current old wording.
- [ ] **Step 3: Update presentation without rewriting history.** Replace README and Hook/architecture current-behavior text with the precise contract: transport-unreachable means all tools pass through and Guard protection is paused; HTTP errors are distinct; a first in-flight failure may spend at most the configured decision timeout. Update `AGENTS.md`'s core principle and key pattern. Append a dated supersession notice to the 2026-09-15 audit, not a rewrite of what was observed then. Keep `failClosed` in the manifest for old configs but mark it deprecated for transport outages and active only on responsive errors; status and logs must not claim otherwise. In the office-value README, add one sentence that silent pass-through is an availability check, not a Guard containment result; do not regenerate or overwrite prior experiment bundles.
- [ ] **Step 4: Verify user-visible behavior and docs.** `python -m pytest -q`; `rg -n '后端不可达.*高影响.*阻断|后端不可达.*全量阻断|tiered failure safety' README.md AGENTS.md docs/features/runtime-hook.md docs/architecture/index.md docs/architecture/project-memory.md openclaw_guard/integrations/hook_runtime.py`. Expected: no unqualified current-behavior claim of tiered transport failure blocking. Inspect generated JS status and Node test logs to confirm no command, message body, or credential value leaks.
- [ ] **Step 5: Commit.** `git add openclaw_guard/integrations/hook_runtime.py README.md AGENTS.md docs/features/runtime-hook.md docs/architecture/index.md docs/architecture/project-memory.md docs/architecture/pmkb-e2e-audit-2026-09-15.md testlab/office_value/README.md tests/test_hook_silent_passthrough.py && git commit -m "docs: explain silent Guard availability boundary"`.

## Final verification and evidence boundary

Run `python -m pytest -q` on the final tree and inspect `git diff --check`, `git status --short`, and the generated plugin's Node runtime outcomes before reporting completion. Preserve the user's unrelated dirty files. Report separately: (1) backend-unreachable pass-through parity, (2) backend-available enforcement still working, and (3) the remaining one-call detection-timeout race. This work demonstrates an availability property in a hermetic plugin test, not real-deployment security efficacy.
