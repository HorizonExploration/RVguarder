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
def test_http_errors_are_not_transport_silence(tmp_path: Path, status: int) -> None:
    """An HTTP response must retain the old high-impact error safety path."""
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
  pluginConfig: {{guardUrl: "http://guard.test", failClosed: false}},
  on(name, handler) {{ hooks[name] = handler; }},
  registerGatewayMethod() {{}},
  logger: {{info() {{}}, warn() {{}}}},
}});
hooks.gateway_start();
await new Promise(resolve => setImmediate(resolve));
for (let i = 0; i < 2; i++) {{
  const result = await hooks.before_tool_call({{toolName: "shell_exec", params: {{}}}}, {{}});
  if (result?.block !== true) throw new Error("HTTP error silently allowed shell");
}}
if (decisionPosts !== 2) throw new Error("HTTP error was mistaken for transport silence");
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
    """A reachable but unhealthy server must not appear transport-offline."""
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
if ((await hooks.before_tool_call({toolName: "shell_exec", params: {}}, {}))?.block !== true) throw new Error("response error allowed shell");
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
    """A received 500 must not be reclassified as a transport outage."""
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
  if ((await hooks.before_tool_call({toolName: "shell_exec", params: {}}, {}))?.block !== true) throw new Error("received HTTP 500 silently allowed");
}
if (decisionPosts !== 2) throw new Error("HTTP 500 was mislabeled offline");
hooks.gateway_stop();
''')


def test_local_payload_serialization_error_does_not_silence_guard(tmp_path: Path) -> None:
    """A bad local payload must not be reported as a dead backend."""
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
if ((await hooks.before_tool_call({toolName: "shell_exec", params}, {}))?.block !== true) throw new Error("bad local payload opened Guard");
if ((await hooks.before_tool_call({toolName: "shell_exec", params: {}}, {}))?.block !== true) throw new Error("Guard stayed silent after local serialization error");
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
