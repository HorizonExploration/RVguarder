"""本机安装SDK的Hook派发契约检查；无Agent、模型、真实审批或网络效果。"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from openclaw_guard.integrations.hook_runtime import _plugin_source


NODE_CHECK = r'''
import {readFileSync} from "node:fs";
const input = JSON.parse(readFileSync(0, "utf8"));
const module = await import(input.sdkModule);
const createRunner = module[input.exportName];
if (typeof createRunner !== "function") throw new Error("SDK hook runner export not found");
const registry = {plugins: [{id: "guard-fixture", status: "loaded", packageVersion: "fixture"}], typedHooks: []};
const posts = [];
let block = false;
globalThis.fetch = async (url, options) => {
  if (url.endsWith("/api/health")) return {ok: true, text: async () => JSON.stringify({ok: true, product: "openclaw-guard"})};
  posts.push({url, payload: JSON.parse(options.body)});
  return {ok: true, text: async () => JSON.stringify(url.endsWith("/before-tool-call") ? {action: block ? "block" : "allow", reason: "fixture"} : {ok: true})};
};
const plugin = (await import(input.plugin)).default;
plugin.register({pluginConfig: {startupHealthCheck: true}, on(hookName, handler, options) {
  registry.typedHooks.push({pluginId: "guard-fixture", hookName, handler, registrationId: options?.registrationId});
}, registerGatewayMethod() {}, logger: {info() {}, warn() {}}});
await new Promise(resolve => setImmediate(resolve));
const runner = createRunner(registry, {catchErrors: false});
const event = {toolName: "read", toolCallId: "call", runId: "run", params: {path: "note.txt"}};
const ctx = {toolName: "read", agentId: "agent", sessionId: "session", sessionKey: "agent:agent:session", runId: "run", toolCallId: "call"};
const allowed = await runner.runBeforeToolCall(event, ctx);
const receipt = {payload: {receipt_id: "transport-fixture"}, signature: "0".repeat(64)};
await runner.runAfterToolCall({...event, result: {details: {rvExecutionReceipt: receipt}, isError: true}}, ctx);
block = true;
const blocked = await runner.runBeforeToolCall({...event, toolCallId: "next-call"}, ctx);
const callback = posts.find(row => row.url.endsWith("/after-tool-call"))?.payload;
if (!callback || callback.executionReceipt?.payload?.receipt_id !== "transport-fixture" || callback.toolResultFailed !== true) throw new Error("SDK changed result-details/failure contract");
for (const [key, value] of Object.entries({agentId: "agent", sessionId: "session", sessionKey: "agent:agent:session", runId: "run", toolCallId: "call"})) {
  if (callback[key] !== value) throw new Error(`SDK lost ${key}`);
}
if (allowed?.block === true || blocked?.block !== true) throw new Error("SDK changed block/allow contract");
await runner.runGatewayStop({}, {});
console.log(JSON.stringify({passed: true, dispatch_allow: true, dispatch_block: true, sdk_details_preserved: true, sdk_failure_preserved: true, identity_context_preserved: true, decision_posts: posts.filter(row => row.url.endsWith("/before-tool-call")).length}));
'''


def main() -> None:
    """固定实际安装版本和文件hash，执行实际SDK runner并保存有限结论。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openclaw-root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.openclaw_root
    if root is None:
        executable = shutil.which("openclaw")
        if executable is None:
            parser.error("openclaw is not installed")
        root = Path(executable).resolve().parent
    version = json.loads((root / "package.json").read_text())["version"]
    candidates = []
    for path in sorted((root / "dist").glob("hooks-*.mjs")):
        source = path.read_text()
        match = re.search(r"createHookRunner as ([A-Za-z_$][A-Za-z0-9_$]*)", source)
        if match:
            candidates.append((path, match.group(1)))
    if len(candidates) != 1:
        parser.error("one exact installed SDK hook runner is required")
    module, export_name = candidates[0]
    with tempfile.TemporaryDirectory(prefix="rv-sdk-contract-") as temporary:
        plugin = Path(temporary) / "plugin.mjs"
        plugin.write_text(_plugin_source(guard_url="http://fixture.invalid", auth_token="public-test-fixture"))
        result = subprocess.run(["node", "--input-type=module", "-e", NODE_CHECK],
                                input=json.dumps({"sdkModule": module.as_uri(), "exportName": export_name, "plugin": plugin.as_uri()}),
                                text=True, capture_output=True, timeout=30, check=False)
        if result.returncode:
            raise RuntimeError(f"local SDK contract failed (exit {result.returncode}): {result.stderr[:1000]}")
        outcomes = json.loads(result.stdout)
    report = {"schema_version": 1, "recorded_at": datetime.now(timezone.utc).isoformat(), "openclaw_version": version,
              "sdk_module": module.name, "sdk_sha256": hashlib.sha256(module.read_bytes()).hexdigest(),
              "scope": "actual installed SDK runner contract; mocked HTTP, no Gateway/Agent/native approval or side effect",
              "outcomes": outcomes, "signature_fixture_is_valid": False,
              "limits": ["SDK context fields remain optional", "Transport preservation does not prove issuer trust or native approval behavior",
                         "This check is not a B0 comparison or security experiment sample"]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"passed": outcomes["passed"], "openclaw_version": version, "output": str(args.output)}))


if __name__ == "__main__":
    main()
