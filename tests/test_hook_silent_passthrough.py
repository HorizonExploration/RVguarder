"""Execute the generated Hook bridge without a Guard server or real tools."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from openclaw_guard.integrations.hook_runtime import _plugin_source


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
  if (url.endsWith("/api/health")) return {ok: true};
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
  if (url.endsWith("/api/health")) return {{ok: true}};
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
