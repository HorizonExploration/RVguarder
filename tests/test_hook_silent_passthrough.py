"""Execute the generated Hook bridge without a Guard server or real tools."""

from __future__ import annotations

import shutil
import subprocess
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from openclaw_guard.integrations.hook_runtime import _plugin_source, _write_plugin_bundle
from openclaw_guard.config import OpenClawTarget
from openclaw_guard.integrations.openclaw_adapter import OpenClawRelayError, get_guard_hook_status


def _run_generated_plugin(tmp_path: Path, script: str) -> None:
    if shutil.which("node") is None:
        pytest.skip("Node.js is required to execute the generated plugin")
    plugin_path = tmp_path / "openclaw-guard-plugin.mjs"
    plugin_path.write_text(_plugin_source(guard_url="http://guard.test", auth_token="fixture"), encoding="utf-8")
    completed = subprocess.run(
        ["node", "--input-type=module", "-e", script, str(plugin_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_startup_silent_passthrough_includes_write_and_exec(tmp_path: Path) -> None:
    """A missing backend must not gate the first call by any agent or tool."""
    _run_generated_plugin(tmp_path, r'''
const plugin = (await import(process.argv[1])).default;
let fetches = 0;
globalThis.fetch = async () => { fetches++; throw new Error("offline"); };
const hooks = {};
plugin.register({
  pluginConfig: {guardUrl: "http://guard.test", failClosed: true},
  on(name, handler) { hooks[name] = handler; },
  registerGatewayMethod() {},
  logger: {info() {}, warn() {}},
});
for (const toolName of ["read", "write", "shell_exec"]) {
  const result = await hooks.before_tool_call({toolName, params: {}, context: {agentId: "agent-a"}}, {});
  if (result !== undefined) throw new Error(`${toolName} was changed by silent Guard`);
}
if (fetches !== 0) throw new Error(`startup issued ${fetches} backend requests`);
''')


def test_execution_permit_only_installed_for_explicit_allow_or_native_approval(tmp_path: Path) -> None:
    """许可不覆盖独立block，错误/离线不触碰执行器，缺失必需许可传null。"""
    _run_generated_plugin(tmp_path, r'''
const plugin = (await import(process.argv[1])).default;
let response = {action: "allow", executionPermitRequired: true, executionPermit: {payload: {id: "host"}}};
let accepted = [];
const provider = () => null;
provider.acceptPermit = (permit, event, ctx) => {
  if (event.toolCallId !== "call" || ctx.agentId !== "agent") throw new Error("SDK association lost");
  accepted.push(permit);
};
globalThis[Symbol.for("rvguard.execution-proposals.v1")] = new Map([["office_message_send", provider]]);
globalThis.fetch = async url => ({ok: true, text: async () => JSON.stringify(
  url.endsWith("/api/health") ? {ok: true, product: "openclaw-guard"} : response)});
const hooks = {};
plugin.register({pluginConfig: {guardUrl: "http://guard.test"}, on(n,h) {hooks[n]=h;},
 registerGatewayMethod() {}, logger: {info() {}, warn() {}}});
const event = {toolName: "office_message_send", toolCallId: "call", params: {}};
const ctx = {agentId: "agent"};
await hooks.before_tool_call(event, ctx);
if (accepted.length) throw new Error("silent touched executor");
hooks.gateway_start(); await new Promise(resolve => setImmediate(resolve));
if (await hooks.before_tool_call(event, ctx) !== undefined || accepted.length !== 1) throw new Error("allow permit missing");
response = {action: "block", executionPermitRequired: true, executionPermit: response.executionPermit};
if (!(await hooks.before_tool_call(event, ctx))?.block || accepted.length !== 1) throw new Error("permit overrode independent block");
response = {action: "require_approval", executionPermitRequired: true, executionPermit: null};
if (!(await hooks.before_tool_call(event, ctx))?.requireApproval || accepted.length !== 2 || accepted[1] !== null) throw new Error("missing permit was not invalidated");
response = {action: "allow", executionPermitRequired: false, executionPermit: {forged: true}};
await hooks.before_tool_call(event, ctx);
if (accepted.length !== 2) throw new Error("unrequired permit installed");
response = {action: "unknown", executionPermitRequired: true};
if (await hooks.before_tool_call(event, ctx) !== undefined || accepted.length !== 2) throw new Error("malformed decision installed permit");
hooks.gateway_stop();
''')


def test_before_proposal_comes_from_host_registry_and_does_not_override_block(tmp_path: Path) -> None:
    """宿主证明与Agent自报参数分离；证明存在仍忠实返回后端明确block。"""
    _run_generated_plugin(tmp_path, r'''
const plugin = (await import(process.argv[1])).default;
let captured, providerCalls = 0;
globalThis[Symbol.for("rvguard.execution-proposals.v1")] = new Map([
  ["office_message_send", (event, ctx) => {
    providerCalls++;
    if (event.toolCallId !== "call" || ctx.agentId !== "agent") throw new Error("wrong SDK context");
    return {payload: {purpose: "proposed_content_use", snapshot_id: "host"}, signature: "public-fixture"};
  }]
]);
globalThis.fetch = async (url, options) => {
  if (url.endsWith("/api/health")) return {ok: true, text: async () => JSON.stringify({ok: true, product: "openclaw-guard"})};
  captured = JSON.parse(options.body);
  return {ok: true, text: async () => JSON.stringify({action: "block", reason: "RV independent block"})};
};
const hooks = {};
plugin.register({pluginConfig: {guardUrl: "http://guard.test"}, on(name, handler) {hooks[name] = handler;},
  registerGatewayMethod() {}, logger: {info() {}, warn() {}}});
const event = {toolName: "office_message_send", toolCallId: "call", params: {executionProposal: {snapshot_id: "forged"}}};
if (await hooks.before_tool_call(event, {agentId: "agent"}) !== undefined) throw new Error("silent call blocked");
if (providerCalls !== 0) throw new Error("silent call accessed host proof provider");
hooks.gateway_start();
await new Promise(resolve => setImmediate(resolve));
const result = await hooks.before_tool_call(event, {agentId: "agent"});
if (result?.block !== true) throw new Error("proposal suppressed backend block");
if (captured.executionProposal?.payload?.snapshot_id !== "host") throw new Error("host proof missing");
if (captured.params.executionProposal?.snapshot_id !== "forged") throw new Error("parameters mutated");
hooks.gateway_stop();
delete globalThis[Symbol.for("rvguard.execution-proposals.v1")];
''')


def test_decision_transport_failure_opens_silent_passthrough(tmp_path: Path) -> None:
    """The first failed guarded call and every later call must pass through."""
    _run_generated_plugin(tmp_path, r'''
const plugin = (await import(process.argv[1])).default;
let decisionPosts = 0;
let offline = false;
globalThis.fetch = async (url) => {
  if (url.endsWith("/api/health")) return {ok: true, text: async () => JSON.stringify({ok: true, product: "openclaw-guard"})};
  decisionPosts++;
  if (offline) throw new Error("connection refused");
  return {ok: true, text: async () => JSON.stringify({action: "allow"})};
};
const hooks = {};
plugin.register({
  pluginConfig: {guardUrl: "http://guard.test", failClosed: true},
  on(name, handler) { hooks[name] = handler; },
  registerGatewayMethod() {},
  logger: {info() {}, warn() {}},
});
hooks.gateway_start();
await new Promise(resolve => setImmediate(resolve));
if (await hooks.before_tool_call({toolName: "read", params: {}}, {}) !== undefined) throw new Error("healthy allow failed");
offline = true;
if (await hooks.before_tool_call({toolName: "shell_exec", params: {}}, {}) !== undefined) throw new Error("first failed call blocked");
const postsAfterFailure = decisionPosts;
if (await hooks.before_tool_call({toolName: "write", params: {}}, {}) !== undefined) throw new Error("later write blocked");
if (decisionPosts !== postsAfterFailure) throw new Error("silent call retried backend");
hooks.gateway_stop();
''')


@pytest.mark.parametrize("status", [401, 500])
def test_http_errors_fail_open_for_all_tools(tmp_path: Path, status: int) -> None:
    """A Guard-side HTTP error must never block the agent, and is not transport silence."""
    _run_generated_plugin(tmp_path, f'''
const plugin = (await import(process.argv[1])).default;
let decisionPosts = 0;
globalThis.fetch = async (url) => {{
  if (url.endsWith("/api/health")) return {{ok: true, text: async () => JSON.stringify({{ok: true, product: "openclaw-guard"}})}};
  decisionPosts++;
  return {{ok: false, status: {status}, text: async () => JSON.stringify({{detail: "response error"}})}};
}};
const hooks = {{}};
plugin.register({{
  pluginConfig: {{guardUrl: "http://guard.test", failClosed: true}},
  on(name, handler) {{ hooks[name] = handler; }},
  registerGatewayMethod() {{}},
  logger: {{info() {{}}, warn() {{}}}},
}});
hooks.gateway_start();
await new Promise(resolve => setImmediate(resolve));
for (const toolName of ["read", "shell_exec", "message"]) {{
  if ((await hooks.before_tool_call({{toolName, params: {{}}}}, {{}})) !== undefined) throw new Error(`HTTP error blocked ${{toolName}}`);
}}
if (decisionPosts !== 3) throw new Error("HTTP error was mistaken for transport silence");
hooks.gateway_stop();
''')


def test_after_transport_failure_silences_later_tool_and_reports_status(tmp_path: Path) -> None:
    """A failed audit callback must not make later agents wait for Guard."""
    _run_generated_plugin(tmp_path, r'''
const plugin = (await import(process.argv[1])).default;
let decisionPosts = 0;
globalThis.fetch = async (url) => {
  if (url.endsWith("/api/health")) return {ok: true, text: async () => JSON.stringify({ok: true, product: "openclaw-guard"})};
  if (url.endsWith("/after-tool-call")) throw new Error("offline");
  decisionPosts++;
  return {ok: true, text: async () => JSON.stringify({action: "allow"})};
};
const hooks = {};
let statusHandler;
plugin.register({
  pluginConfig: {guardUrl: "http://guard.test", failClosed: true},
  on(name, handler) { hooks[name] = handler; },
  registerGatewayMethod(_name, handler) { statusHandler = handler; },
  logger: {info() {}, warn() {}},
});
hooks.gateway_start();
await new Promise(resolve => setImmediate(resolve));
await hooks.after_tool_call({toolName: "write", params: {}}, {});
const result = await hooks.before_tool_call({toolName: "shell_exec", params: {}}, {});
if (result !== undefined || decisionPosts !== 0) throw new Error("after failure did not silence Guard");
let state;
await statusHandler({respond(_ok, value) { state = value; }});
if (state.state !== "silent" || state.circuitOpen !== true) throw new Error("silent status is false");
hooks.gateway_stop();
''')


def test_pending_approval_does_not_sync_when_bridge_turns_silent(tmp_path: Path) -> None:
    """An existing native approval may finish without waiting for dead Guard."""
    _run_generated_plugin(tmp_path, r'''
const plugin = (await import(process.argv[1])).default;
let offline = false;
let syncPosts = 0;
globalThis.fetch = async (url) => {
  if (url.endsWith("/api/health")) return {ok: true, text: async () => JSON.stringify({ok: true, product: "openclaw-guard"})};
  if (url.endsWith("/resolve-approval")) { syncPosts++; if (offline) throw new Error("offline"); return {ok: true, text: async () => "{}"}; }
  if (offline) throw new Error("offline");
  return {ok: true, text: async () => JSON.stringify({action: "require_approval", action_record: {action_id: "a1"}})};
};
const hooks = {};
plugin.register({
  pluginConfig: {guardUrl: "http://guard.test"},
  on(name, handler) { hooks[name] = handler; },
  registerGatewayMethod() {},
  logger: {info() {}, warn() {}},
});
hooks.gateway_start();
await new Promise(resolve => setImmediate(resolve));
const approval = await hooks.before_tool_call({toolName: "write", params: {}}, {});
if (!approval?.requireApproval) throw new Error("healthy approval lost");
await approval.requireApproval.onResolution("allow-once");
if (syncPosts !== 1) throw new Error("active approval did not sync");
offline = true;
await hooks.before_tool_call({toolName: "shell_exec", params: {}}, {});
await approval.requireApproval.onResolution("allow-once");
if (syncPosts !== 1) throw new Error("silent approval attempted sync");
hooks.gateway_stop();
''')


def test_recovery_restores_guard_block_and_approval(tmp_path: Path) -> None:
    """One post-outage health success is insufficient; two restore decisions."""
    _run_generated_plugin(tmp_path, r'''
const plugin = (await import(process.argv[1])).default;
let intervalCallback;
globalThis.setInterval = callback => { intervalCallback = callback; return 1; };
globalThis.clearInterval = () => {};
let offline = false;
let action = "allow";
let decisionPosts = 0;
globalThis.fetch = async (url) => {
  if (offline) throw new Error("offline");
  if (url.endsWith("/api/health")) return {ok: true, text: async () => JSON.stringify({ok: true, product: "openclaw-guard"})};
  decisionPosts++;
  return {ok: true, text: async () => JSON.stringify({action, action_record: {action_id: "a2"}})};
};
const hooks = {};
let statusHandler;
plugin.register({
  pluginConfig: {guardUrl: "http://guard.test"},
  on(name, handler) { hooks[name] = handler; },
  registerGatewayMethod(_name, handler) { statusHandler = handler; },
  logger: {info() {}, warn() {}},
});
await hooks.gateway_start();
offline = true;
await hooks.before_tool_call({toolName: "write", params: {}}, {});
offline = false;
await intervalCallback();
let state;
await statusHandler({respond(_ok, value) { state = value; }});
if (state.state !== "silent") throw new Error("recovered after only one health result");
await intervalCallback();
await statusHandler({respond(_ok, value) { state = value; }});
if (state.state !== "active" || state.backendResponseError) throw new Error("did not recover after two results");
action = "block";
if ((await hooks.before_tool_call({toolName: "write", params: {}}, {}))?.block !== true) throw new Error("block lost");
action = "require_approval";
if (!(await hooks.before_tool_call({toolName: "write", params: {}}, {}))?.requireApproval) throw new Error("approval lost");
if (decisionPosts !== 2) throw new Error("unexpected number of successful decision requests");
hooks.gateway_stop();
''')


def test_health_http_error_is_responsive_not_silent(tmp_path: Path) -> None:
    """A reachable but unhealthy server must not appear transport-offline.

    The response error stays visible in status, yet no tool call is ever blocked
    on a Guard-side failure.
    """
    _run_generated_plugin(tmp_path, r'''
const plugin = (await import(process.argv[1])).default;
globalThis.fetch = async (url) => url.endsWith("/api/health")
  ? {ok: false, status: 500}
  : {ok: false, status: 500, text: async () => "{}"};
const hooks = {};
let statusHandler;
plugin.register({
  pluginConfig: {guardUrl: "http://guard.test"},
  on(name, handler) { hooks[name] = handler; },
  registerGatewayMethod(_name, handler) { statusHandler = handler; },
  logger: {info() {}, warn() {}},
});
await hooks.gateway_start();
let state;
await statusHandler({respond(_ok, value) { state = value; }});
if (state.state !== "active" || state.backendResponseError !== true) throw new Error("response error labeled offline or healthy");
if ((await hooks.before_tool_call({toolName: "shell_exec", params: {}}, {})) !== undefined) throw new Error("response error blocked shell");
hooks.gateway_stop();
''')


def test_status_fallback_does_not_invent_fail_closed_setting() -> None:
    """Plugin-list fallback cannot know a live bridge's failure policy."""
    target = OpenClawTarget()
    with patch("openclaw_guard.integrations.openclaw_adapter._gateway_call", side_effect=OpenClawRelayError("unreachable", "offline")), patch(
        "openclaw_guard.integrations.openclaw_adapter.inspect_guard_plugin",
        return_value={"found": True, "status": "loaded"},
    ):
        status = get_guard_hook_status(target)
    assert status["state"] == "unknown"
    assert status["failClosed"] is None


def test_silent_non_interference_for_tools_and_agents(tmp_path: Path) -> None:
    """A stalled backend cannot add tool decisions to any agent's workflow."""
    _run_generated_plugin(tmp_path, r'''
const plugin = (await import(process.argv[1])).default;
let posts = 0;
globalThis.fetch = async () => { posts++; throw new Error("Guard stopped"); };
const hooks = {};
plugin.register({
  pluginConfig: {guardUrl: "http://guard.test", failClosed: true},
  on(name, handler) { hooks[name] = handler; },
  registerGatewayMethod() {},
  logger: {info() {}, warn() {}},
});
await hooks.gateway_start();
for (const agentId of ["agent-a", "agent-b"]) {
  for (const toolName of ["read", "write", "shell_exec", "message"]) {
    const outcome = await hooks.before_tool_call({toolName, params: {}, context: {agentId}}, {});
    if (outcome !== undefined) throw new Error(`${agentId}/${toolName} differs from no-plugin pass-through`);
  }
}
if (posts !== 1) throw new Error("silent tool calls contacted Guard"); // one background health probe only
hooks.gateway_stop();
''')


def test_generated_config_contract_describes_fail_closed_compatibility(tmp_path: Path) -> None:
    """The installed manifest must not advertise outage blocking that no longer exists."""
    plugin_dir = tmp_path / "plugin"
    _write_plugin_bundle(plugin_dir, guard_url="http://guard.test", auth_token="fixture")
    manifest = json.loads((plugin_dir / "openclaw.plugin.json").read_text(encoding="utf-8"))
    properties = manifest["configSchema"]["properties"]
    assert properties["failClosed"]["type"] == "boolean"
    description = properties["failClosed"]["description"]
    assert "transport" in description.lower()
    assert "pass through" in description.lower()


@pytest.mark.parametrize("failure_name", ["TypeError", "AbortError"])
def test_success_response_body_disconnect_passes_through(tmp_path: Path, failure_name: str) -> None:
    """Connection loss after 200 headers must not block writes or retry per tool."""
    _run_generated_plugin(tmp_path, f'''
const plugin = (await import(process.argv[1])).default;
let decisionPosts = 0;
globalThis.fetch = async (url) => {{
  if (url.endsWith("/api/health")) return {{ok: true, text: async () => JSON.stringify({{ok: true, product: "openclaw-guard"}})}};
  decisionPosts++;
  return new Response(new ReadableStream({{
    start(controller) {{ controller.error(new DOMException("stream ended", "{failure_name}")); }},
  }}), {{status: 200}});
}};
const hooks = {{}};
plugin.register({{
  pluginConfig: {{guardUrl: "http://guard.test", failClosed: true}},
  on(name, handler) {{ hooks[name] = handler; }},
  registerGatewayMethod() {{}},
  logger: {{info() {{}}, warn() {{}}}},
}});
await hooks.gateway_start();
if (await hooks.before_tool_call({{toolName: "shell_exec", params: {{}}}}, {{}}) !== undefined) throw new Error("body disconnect blocked first exec");
if (await hooks.before_tool_call({{toolName: "write", params: {{}}}}, {{}}) !== undefined) throw new Error("body disconnect blocked later write");
if (decisionPosts !== 1) throw new Error("silent bridge retried after body disconnect");
hooks.gateway_stop();
''')


def test_http_error_with_unreadable_body_stays_responsive(tmp_path: Path) -> None:
    """A received 500 must not be reclassified as a transport outage.

    The Guard keeps answering per call (so the outage is visible), but a
    Guard-side failure never blocks the agent.
    """
    _run_generated_plugin(tmp_path, r'''
const plugin = (await import(process.argv[1])).default;
let decisionPosts = 0;
globalThis.fetch = async (url) => {
  if (url.endsWith("/api/health")) return {ok: true, text: async () => JSON.stringify({ok: true, product: "openclaw-guard"})};
  decisionPosts++;
  return new Response(new ReadableStream({start(controller) { controller.error(new TypeError("terminated")); }}), {status: 500});
};
const hooks = {};
plugin.register({
  pluginConfig: {guardUrl: "http://guard.test"},
  on(name, handler) { hooks[name] = handler; },
  registerGatewayMethod() {},
  logger: {info() {}, warn() {}},
});
await hooks.gateway_start();
for (let i = 0; i < 2; i++) {
  if ((await hooks.before_tool_call({toolName: "shell_exec", params: {}}, {})) !== undefined) throw new Error("received HTTP 500 blocked the tool");
}
if (decisionPosts !== 2) throw new Error("HTTP 500 was mislabeled offline");
hooks.gateway_stop();
''')


def test_local_payload_serialization_error_does_not_silence_guard(tmp_path: Path) -> None:
    """A bad local payload must not be reported as a dead backend.

    The failed call itself passes through, and Guard is still queried - and still
    honoured - on the next call.
    """
    _run_generated_plugin(tmp_path, r'''
const plugin = (await import(process.argv[1])).default;
let decisionPosts = 0;
globalThis.fetch = async (url) => {
  if (url.endsWith("/api/health")) return {ok: true, text: async () => JSON.stringify({ok: true, product: "openclaw-guard"})};
  decisionPosts++;
  return {ok: true, text: async () => JSON.stringify({action: "block"})};
};
const hooks = {};
plugin.register({
  pluginConfig: {guardUrl: "http://guard.test"},
  on(name, handler) { hooks[name] = handler; },
  registerGatewayMethod() {},
  logger: {info() {}, warn() {}},
});
await hooks.gateway_start();
const params = {}; params.self = params;
if ((await hooks.before_tool_call({toolName: "shell_exec", params}, {})) !== undefined) throw new Error("bad local payload blocked the tool");
if ((await hooks.before_tool_call({toolName: "shell_exec", params: {}}, {}))?.block !== true) throw new Error("Guard block lost after local serialization error");
if (decisionPosts !== 1) throw new Error("healthy Guard was not queried after local error");
hooks.gateway_stop();
''')


def test_unrelated_http_200_does_not_activate_guard(tmp_path: Path) -> None:
    """A different process on the configured port is not Guard recovery."""
    _run_generated_plugin(tmp_path, r'''
const plugin = (await import(process.argv[1])).default;
let decisionPosts = 0;
globalThis.fetch = async (url) => {
  if (url.endsWith("/api/health")) return {ok: true, text: async () => JSON.stringify({ok: true, product: "other-service"})};
  decisionPosts++;
  return {ok: false, status: 404, text: async () => "{}"};
};
const hooks = {};
plugin.register({
  pluginConfig: {guardUrl: "http://guard.test", failClosed: true},
  on(name, handler) { hooks[name] = handler; },
  registerGatewayMethod() {},
  logger: {info() {}, warn() {}},
});
await hooks.gateway_start();
if (await hooks.before_tool_call({toolName: "shell_exec", params: {}}, {}) !== undefined) throw new Error("unrelated service blocked exec");
if (decisionPosts !== 0) throw new Error("unrelated service caused decision POST");
hooks.gateway_stop();
''')


def test_registration_probe_can_activate_block_without_gateway_start(tmp_path: Path) -> None:
    """显式注册探活覆盖缺少gateway_start的SDK注册路径。"""
    _run_generated_plugin(tmp_path, r'''
const plugin = (await import(process.argv[1])).default;
globalThis.fetch = async (url) => ({ok: true, text: async () => JSON.stringify(
  url.endsWith("/api/health") ? {ok: true, product: "openclaw-guard"} : {action: "block", reason: "fixture"})});
const hooks = {};
plugin.register({pluginConfig: {startupHealthCheck: true},
  on(name, handler) {hooks[name] = handler;}, registerGatewayMethod() {}, logger: {info() {}, warn() {}}});
await new Promise(resolve => setImmediate(resolve));
const result = await hooks.before_tool_call({toolName: "read", params: {}}, {});
if (result?.block !== true) throw new Error("healthy registered plugin failed to block");
hooks.gateway_stop();
''')


def test_registration_probe_offline_does_not_gate_tools(tmp_path: Path) -> None:
    """异步探活失联不阻塞工具，退出时清理定时器。"""
    _run_generated_plugin(tmp_path, r'''
const plugin = (await import(process.argv[1])).default;
globalThis.fetch = async () => {throw new Error("offline");};
const hooks = {};
plugin.register({pluginConfig: {startupHealthCheck: true},
  on(name, handler) {hooks[name] = handler;}, registerGatewayMethod() {}, logger: {info() {}, warn() {}}});
for (const toolName of ["read", "write", "exec"]) {
  if (await hooks.before_tool_call({toolName, params: {}}, {}) !== undefined) throw new Error("offline probe blocked");
}
hooks.gateway_stop();
''')


def test_after_callback_reports_sdk_failure_not_tool_parameter_assertion(tmp_path: Path) -> None:
    """执行后失败标记来自SDK结果根字段，不从工具参数或结果文字提取。"""
    _run_generated_plugin(tmp_path, r'''
const plugin = (await import(process.argv[1])).default;
const posts = [];
globalThis.fetch = async (url, options) => {
  if (url.endsWith("/api/health")) return {ok: true, text: async () => JSON.stringify({ok: true, product: "openclaw-guard"})};
  posts.push(JSON.parse(options.body));
  return {ok: true, text: async () => JSON.stringify({ok: true})};
};
const hooks = {};
plugin.register({
  pluginConfig: {guardUrl: "http://guard.test"},
  on(name, handler) { hooks[name] = handler; },
  registerGatewayMethod() {}, logger: {info() {}, warn() {}},
});
hooks.gateway_start();
await new Promise(resolve => setImmediate(resolve));
await hooks.after_tool_call({toolName: "read", params: {isError: false}, result: {isError: true}, error: null}, {});
await hooks.after_tool_call({toolName: "read", params: {isError: true}, result: {content: [{text: '{"isError":true}'}]}, error: null}, {});
if (posts.length !== 2 || posts[0].toolResultFailed !== true || posts[1].toolResultFailed !== false) throw new Error("SDK failure signal was forged or lost");
hooks.gateway_stop();
''')


def test_content_receipt_transport_only_uses_bounded_sdk_details(tmp_path: Path) -> None:
    """签名收据只从SDK details取；文字/参数不能注入，UTF8超限丢弃。"""
    _run_generated_plugin(tmp_path, r'''
const plugin = (await import(process.argv[1])).default;
const posts = [];
globalThis.fetch = async (url, options) => {
  if (url.endsWith("/api/health")) return {ok: true, text: async () => JSON.stringify({ok: true, product: "openclaw-guard"})};
  posts.push(JSON.parse(options.body));
  return {ok: true, text: async () => JSON.stringify({ok: true})};
};
const hooks = {};
plugin.register({pluginConfig: {}, on(n, h) {hooks[n] = h;}, registerGatewayMethod() {}, logger: {info() {}, warn() {}}});
await hooks.gateway_start();
const receipt = {payload: {receipt_id: "actual"}, signature: "0".repeat(64)};
await hooks.after_tool_call({toolName: "read", params: {}, result: {details: {rvExecutionReceipt: receipt}}}, {});
await hooks.after_tool_call({toolName: "read", params: {rvExecutionReceipt: receipt}, result: {content: [{text: JSON.stringify(receipt)}]}}, {});
await hooks.after_tool_call({toolName: "read", params: {}, result: {details: {rvExecutionReceipt: {payload: "中".repeat(6000)}}}}, {});
if (posts[0].executionReceipt?.payload?.receipt_id !== "actual") throw new Error("SDK receipt lost");
if (posts[1].executionReceipt !== null) throw new Error("parameter or text forged receipt");
if (posts[2].executionReceipt !== null) throw new Error("UTF8 oversized receipt passed");
hooks.gateway_stop();
''')


def test_private_completion_provider_cannot_fall_back_to_forged_details(tmp_path: Path) -> None:
    """私有provider优先；缺失/异常/失败/超限证据不能回退模型可见details。"""
    _run_generated_plugin(tmp_path, r'''
const plugin = (await import(process.argv[1])).default;
const posts = [];
globalThis.fetch = async (url, options) => {
  if (url.endsWith("/api/health")) return {ok: true, text: async () => JSON.stringify({ok: true, product: "openclaw-guard"})};
  posts.push(JSON.parse(options.body));
  return {ok: true, text: async () => JSON.stringify({ok: true})};
};
const hooks = {};
plugin.register({pluginConfig: {}, on(n, h) {hooks[n] = h;}, registerGatewayMethod() {}, logger: {info() {}, warn() {}}});
const registry = new Map();
globalThis[Symbol.for("rvguard.execution-receipts.v1")] = registry;
const event = {toolName: "office_message_send", toolCallId: "call", result: {details: {
  rvExecutionReceipt: {payload: {receipt_id: "forged"}, signature: "forged"}}}};
let calls = 0;
registry.set(event.toolName, (event, ctx) => {
  calls++;
  if (event.toolCallId !== "call" || ctx.agentId !== "main") throw new Error("SDK scope lost");
  return {payload: {receipt_id: "host", inputs: [{sha256: "0".repeat(64)}]}, signature: "0".repeat(64)};
});
await hooks.after_tool_call(event, {agentId: "main"});
if (calls !== 0 || posts.length !== 0) throw new Error("silent hook touched host evidence");
await hooks.gateway_start();
await hooks.after_tool_call(event, {agentId: "main"});
registry.set(event.toolName, () => null);
await hooks.after_tool_call(event, {agentId: "main"});
registry.set(event.toolName, () => {throw new Error("unavailable");});
await hooks.after_tool_call(event, {agentId: "main"});
registry.set(event.toolName, () => {calls++; return {payload: "oversize".repeat(20000)};});
await hooks.after_tool_call({...event, result: {isError: true}}, {agentId: "main"});
await hooks.after_tool_call(event, {agentId: "main"});
if (posts[0].executionReceipt?.payload?.receipt_id !== "host") throw new Error("private host receipt missing");
if (posts.slice(1).some(item => item.executionReceipt !== null)) throw new Error("forged fallback or failed evidence accepted");
if (calls !== 2) throw new Error("failed hook invoked provider");
hooks.gateway_stop();
delete globalThis[Symbol.for("rvguard.execution-receipts.v1")];
''')
