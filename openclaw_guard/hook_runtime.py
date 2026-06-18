from __future__ import annotations

import secrets
import subprocess
from pathlib import Path
from typing import Any

from openclaw_guard import __version__
from openclaw_guard.config import AppContext
from openclaw_guard.utils import read_json, write_json


HOOK_PLUGIN_ID = "openclaw-guard-hook"
HOOK_METHOD_STATUS = "openclaw_guard.hook_status"


def ensure_runtime_hook_plugin(context: AppContext) -> dict[str, Any]:
    config_path = context.target.config_path
    if config_path is None:
        return {
            "installed": False,
            "active": False,
            "plugin_id": HOOK_PLUGIN_ID,
            "reason": "config_not_found",
        }

    plugin_dir = context.paths.runtime_dir / "openclaw-guard-plugin"
    bridge_state_path = context.paths.runtime_dir / "hook-bridge.json"
    bridge_state = _load_or_create_bridge_state(bridge_state_path)
    _write_plugin_bundle(
        plugin_dir,
        guard_url=_guard_callback_url(context),
        auth_token=str(bridge_state["auth_token"]),
    )
    plugin_validation = _validate_plugin_bundle(plugin_dir)

    config_data = read_json(config_path) or {}
    changed = _ensure_plugin_config(
        config_data,
        plugin_dir=plugin_dir,
        guard_url=_guard_callback_url(context),
        auth_token=str(bridge_state["auth_token"]),
    )
    if changed:
        try:
            write_json(config_path, config_data)
        except OSError as exc:
            return {
                "installed": False,
                "active": False,
                "plugin_id": HOOK_PLUGIN_ID,
                "plugin_dir": str(plugin_dir),
                "guard_url": _guard_callback_url(context),
                "config_path": str(config_path),
                "config_changed": True,
                "restart_required": False,
                "reason": "config_write_failed",
                "error_detail": str(exc),
                "auth_token_path": str(bridge_state_path),
                "plugin_valid": plugin_validation["ok"],
                "plugin_validation_error": plugin_validation["detail"],
            }

    return {
        "installed": True,
        "active": False,
        "plugin_id": HOOK_PLUGIN_ID,
        "plugin_dir": str(plugin_dir),
        "guard_url": _guard_callback_url(context),
        "config_path": str(config_path),
        "config_changed": changed,
        "restart_required": changed,
        "auth_token_path": str(bridge_state_path),
        "plugin_valid": plugin_validation["ok"],
        "plugin_validation_error": plugin_validation["detail"],
    }


def _ensure_plugin_config(
    config_data: dict[str, Any],
    *,
    plugin_dir: Path,
    guard_url: str,
    auth_token: str,
) -> bool:
    changed = False
    plugins = config_data.get("plugins")
    if not isinstance(plugins, dict):
        plugins = {}
        config_data["plugins"] = plugins
        changed = True

    if plugins.get("enabled") is not True:
        plugins["enabled"] = True
        changed = True

    load = plugins.get("load")
    if not isinstance(load, dict):
        load = {}
        plugins["load"] = load
        changed = True
    paths = load.get("paths")
    if not isinstance(paths, list):
        paths = []
        load["paths"] = paths
        changed = True
    plugin_path = str(plugin_dir)
    if plugin_path not in paths:
        paths.append(plugin_path)
        changed = True

    allow = plugins.get("allow")
    if isinstance(allow, list) and HOOK_PLUGIN_ID not in allow:
        allow.append(HOOK_PLUGIN_ID)
        changed = True

    entries = plugins.get("entries")
    if not isinstance(entries, dict):
        entries = {}
        plugins["entries"] = entries
        changed = True
    entry = entries.get(HOOK_PLUGIN_ID)
    if not isinstance(entry, dict):
        entry = {}
        entries[HOOK_PLUGIN_ID] = entry
        changed = True
    if entry.get("enabled") is not True:
        entry["enabled"] = True
        changed = True
    entry_config = entry.get("config")
    if not isinstance(entry_config, dict):
        entry_config = {}
        entry["config"] = entry_config
        changed = True

    desired = {
        "guardUrl": guard_url,
        "authToken": auth_token,
        "decisionTimeoutMs": 180000,
        "callbackTimeoutMs": 15000,
        "failClosed": True,
    }
    for key, value in desired.items():
        if entry_config.get(key) != value:
            entry_config[key] = value
            changed = True

    return changed


def _guard_callback_url(context: AppContext) -> str:
    host = context.settings.host
    if host in {"0.0.0.0", "::", ""}:
        host = "127.0.0.1"
    return f"http://{host}:{context.settings.port}"


def _load_or_create_bridge_state(path: Path) -> dict[str, Any]:
    state = read_json(path) or {}
    token = state.get("auth_token")
    if not isinstance(token, str) or not token.strip():
        token = secrets.token_hex(16)
        state["auth_token"] = token
        write_json(path, state)
    return state


def _write_plugin_bundle(plugin_dir: Path, *, guard_url: str, auth_token: str) -> None:
    package_json = {
        "name": "@dynooob/openclaw-guard-hook",
        "version": __version__,
        "type": "module",
        "openclaw": {
            "extensions": ["./index.js"],
        },
    }
    manifest = {
        "id": HOOK_PLUGIN_ID,
        "name": "Openclaw Guard Hook",
        "description": "Pre-execution tool approval bridge for OpenClaw Guard.",
        "configSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "guardUrl": {"type": "string"},
                "authToken": {"type": "string"},
                "decisionTimeoutMs": {"type": "integer"},
                "callbackTimeoutMs": {"type": "integer"},
                "failClosed": {"type": "boolean"},
            },
        },
    }
    index_js = _plugin_source(
        guard_url=guard_url,
        auth_token=auth_token,
    )
    write_json(plugin_dir / "package.json", package_json)
    write_json(plugin_dir / "openclaw.plugin.json", manifest)
    (plugin_dir / "index.js").parent.mkdir(parents=True, exist_ok=True)
    (plugin_dir / "index.js").write_text(index_js, encoding="utf-8")


def _validate_plugin_bundle(plugin_dir: Path) -> dict[str, Any]:
    index_js = plugin_dir / "index.js"
    if not index_js.exists():
        return {"ok": False, "detail": "Plugin entry file is missing."}
    try:
        completed = subprocess.run(
            ["node", "--check", str(index_js)],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except OSError as exc:
        return {"ok": False, "detail": str(exc)}
    except subprocess.TimeoutExpired:
        return {"ok": False, "detail": "Node syntax validation timed out."}
    if completed.returncode == 0:
        return {"ok": True, "detail": None}
    detail = (completed.stderr or completed.stdout or "Unknown plugin syntax error.").strip()
    return {"ok": False, "detail": detail}


def _plugin_source(*, guard_url: str, auth_token: str) -> str:
    template = """const PLUGIN_ID = "__PLUGIN_ID__";
const STATUS_METHOD = "__STATUS_METHOD__";
const DEFAULT_GUARD_URL = "__GUARD_URL__";
const DEFAULT_AUTH_TOKEN = "__AUTH_TOKEN__";

function trimTrailingSlash(value) {{
  return String(value || "").replace(/\\/+$/, "");
}}

function summarizeResult(value) {{
  if (value == null) {{
    return null;
  }}
  try {{
    const text = JSON.stringify(value);
    return text.length > 1200 ? text.slice(0, 1200) + "..." : text;
  }} catch (_error) {{
    return String(value);
  }}
}}

async function postJson(url, payload, timeoutMs, authToken) {{
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), Math.max(timeoutMs, 1000));
  try {{
    const response = await fetch(url, {{
      method: "POST",
      headers: {{
        "content-type": "application/json",
        ...(authToken ? {{ "x-openclaw-guard-token": authToken }} : {{}}),
      }},
      body: JSON.stringify(payload),
      signal: controller.signal,
    }});
    const text = await response.text();
    let data = {{}};
    if (text) {{
      try {{
        data = JSON.parse(text);
      }} catch (_error) {{
        data = {{ raw: text }};
      }}
    }}
    if (!response.ok) {{
      throw new Error(data.detail || data.message || `guard endpoint failed: ${{response.status}}`);
    }}
    return data;
  }} finally {{
    clearTimeout(timeout);
  }}
}}

export default {{
  id: PLUGIN_ID,
  name: "Openclaw Guard Hook",
  description: "Pre-execution approval bridge for Openclaw Guard.",
  configSchema: {{
    validate(value) {{
      if (value && typeof value === "object" && !Array.isArray(value)) {{
        return {{ ok: true, value }};
      }}
      return {{ ok: false, errors: ["config must be an object"] }};
    }},
  }},
  register(api) {{
    const pluginConfig = api.pluginConfig || {{}};
    const guardUrl = trimTrailingSlash(pluginConfig.guardUrl || DEFAULT_GUARD_URL);
    const authToken = String(pluginConfig.authToken || DEFAULT_AUTH_TOKEN || "");
    const failClosed = pluginConfig.failClosed !== false;
    const decisionTimeoutMs = Number(pluginConfig.decisionTimeoutMs || 180000);
    const callbackTimeoutMs = Number(pluginConfig.callbackTimeoutMs || 15000);

    api.registerGatewayMethod(STATUS_METHOD, (ctx) => {{
      ctx.respond(true, {{
        ok: true,
        pluginId: PLUGIN_ID,
        guardUrl,
        failClosed,
        decisionTimeoutMs,
      }});
    }});

    api.on("before_tool_call", async (event, hookCtx) => {{
      try {{
        const result = await postJson(
          `${{guardUrl}}/api/hook/before-tool-call`,
          {{
            toolName: event.toolName,
            params: event.params,
            runId: event.runId,
            toolCallId: event.toolCallId,
            agentId: hookCtx.agentId,
            sessionKey: hookCtx.sessionKey,
            sessionId: hookCtx.sessionId,
          }},
          decisionTimeoutMs,
          authToken,
        );
        if (result.action === "allow") {{
          return result.params && typeof result.params === "object"
            ? {{ params: result.params }}
            : undefined;
        }}
        return {{
          block: true,
          blockReason: String(result.blockReason || "Blocked by Openclaw Guard."),
        }};
      }} catch (error) {{
        const detail = error instanceof Error ? error.message : String(error);
        api.logger.warn(`[${{PLUGIN_ID}}] before_tool_call bridge failed: ${{detail}}`);
        if (!failClosed) {{
          return undefined;
        }}
        return {{
          block: true,
          blockReason: `Openclaw Guard unavailable: ${{detail}}`,
        }};
      }}
    }});

    api.on("after_tool_call", async (event, hookCtx) => {{
      try {{
        await postJson(
          `${{guardUrl}}/api/hook/after-tool-call`,
          {{
            toolName: event.toolName,
            params: event.params,
            runId: event.runId,
            toolCallId: event.toolCallId,
            agentId: hookCtx.agentId,
            sessionKey: hookCtx.sessionKey,
            sessionId: hookCtx.sessionId,
            error: event.error || null,
            durationMs: event.durationMs || null,
            resultSummary: summarizeResult(event.result),
          }},
          callbackTimeoutMs,
          authToken,
        );
      }} catch (error) {{
        const detail = error instanceof Error ? error.message : String(error);
        api.logger.warn(`[${{PLUGIN_ID}}] after_tool_call bridge failed: ${{detail}}`);
      }}
    }});
  },
}};
"""
    rendered = (
        template.replace("__PLUGIN_ID__", HOOK_PLUGIN_ID)
        .replace("__STATUS_METHOD__", HOOK_METHOD_STATUS)
        .replace("__GUARD_URL__", guard_url)
        .replace("__AUTH_TOKEN__", auth_token)
    )
    return rendered.replace("{{", "{").replace("}}", "}")
