from __future__ import annotations

import secrets
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from openclaw_guard import __version__
from openclaw_guard.config import AppContext
from openclaw_guard.utils import read_json, write_json


HOOK_PLUGIN_ID = "openclaw-guard-hook"
HOOK_METHOD_STATUS = "openclaw_guard.hook_status"
# Keep the synchronous before_tool_call bridge bounded. Interactive approval
# has its own timeout and is intentionally configured separately below.
DEFAULT_DECISION_TIMEOUT_MS = 2_000


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
    bridge_state = _load_or_create_bridge_state(bridge_state_path, host=context.settings.host, port=context.settings.port)
    _write_plugin_bundle(
        plugin_dir,
        guard_url=_guard_callback_url(context),
        auth_token=str(bridge_state["auth_token"]),
    )
    plugin_validation = _validate_plugin_bundle(plugin_dir)

    config_data = read_json(config_path) or {}
    config_skipped = _is_transient_plugin_config_scope(config_path, plugin_dir)
    changed = False
    if not config_skipped:
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
        "config_skipped": config_skipped,
        "config_skip_reason": "transient_project_scope" if config_skipped else None,
        "auth_token_path": str(bridge_state_path),
        "plugin_valid": plugin_validation["ok"],
        "plugin_validation_error": plugin_validation["detail"],
    }


def _is_transient_plugin_config_scope(config_path: Path, plugin_dir: Path) -> bool:
    """避免临时测试项目把即将删除的插件路径写入外部 OpenClaw 配置。

    正式仓库路径仍可更新用户级配置；仅当插件目录位于系统临时目录，且
    OpenClaw 配置不在该项目目录内时跳过写入。这样 Guard 即使被测试夹具
    或短期任务以临时 project_dir 构建，也不会污染真实 gateway 配置。
    """
    try:
        plugin_path = plugin_dir.resolve()
        config_resolved = config_path.resolve()
        project_root = plugin_path.parent.parent
        config_is_project_local = config_resolved.is_relative_to(project_root)
    except (OSError, RuntimeError, ValueError):
        return False
    return _is_transient_path(plugin_path) and not config_is_project_local


def _is_transient_path(path: Path) -> bool:
    """Return whether a path is below the platform's temporary directory."""
    try:
        return path.resolve().is_relative_to(Path(tempfile.gettempdir()).resolve())
    except (OSError, RuntimeError, ValueError):
        return False


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
    cleaned_paths: list[Any] = []
    seen_paths: set[str] = set()
    for raw_path in paths:
        path_value = str(raw_path)
        # Pytest and temporary integration runs leave stale generated plugin
        # paths in OpenClaw's config. Remove only missing Guard paths below the
        # platform temp directory; preserve all other plugin paths and history.
        is_stale_tmp_guard_path = (
            path_value != plugin_path
            and path_value.endswith("/runtime/openclaw-guard-plugin")
            and not Path(path_value).exists()
            and _is_transient_path(Path(path_value))
        )
        if is_stale_tmp_guard_path or path_value in seen_paths:
            changed = True
            continue
        seen_paths.add(path_value)
        cleaned_paths.append(raw_path)
    if plugin_path not in seen_paths:
        cleaned_paths.append(plugin_path)
        changed = True
    if cleaned_paths != paths:
        load["paths"] = cleaned_paths
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
        "decisionTimeoutMs": DEFAULT_DECISION_TIMEOUT_MS,
        "callbackTimeoutMs": 15000,
        "failClosed": False,
        "failClosedGracePeriodMs": 30000,
        "failThreshold": 3,
        "recoveryThreshold": 2,
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


def register_runtime_hook_in_config(config_path: Path, plugin_dir: Path) -> bool:
    """把 Guard Hook 插件路径写入 OpenClaw 配置。返回是否真正修改了文件。"""
    config_data = read_json(config_path)
    if not isinstance(config_data, dict):
        return False
    bridge_state_path = plugin_dir.parent / "hook-bridge.json"
    bridge_state = _load_or_create_bridge_state(bridge_state_path)
    if _is_transient_plugin_config_scope(config_path, plugin_dir):
        return False
    changed = _ensure_plugin_config(
        config_data,
        plugin_dir=plugin_dir,
        guard_url=_guard_callback_url_from_bridge(bridge_state_path),
        auth_token=str(bridge_state["auth_token"]),
    )
    if changed:
        try:
            write_json(config_path, config_data)
        except OSError:
            return False
    return changed


def unregister_runtime_hook_in_config(config_path: Path) -> bool:
    """从 OpenClaw 配置中移除 Guard Hook 插件相关字段。返回是否真正修改了文件。"""
    config_data = read_json(config_path)
    if not isinstance(config_data, dict):
        return False
    changed = False
    plugins = config_data.get("plugins")
    if isinstance(plugins, dict):
        load = plugins.get("load")
        if isinstance(load, dict):
            paths = load.get("paths")
            if isinstance(paths, list):
                keep = [p for p in paths if not str(p).endswith("/openclaw-guard-plugin")]
                if keep != paths:
                    load["paths"] = keep
                    changed = True
        entries = plugins.get("entries")
        if isinstance(entries, dict) and HOOK_PLUGIN_ID in entries:
            del entries[HOOK_PLUGIN_ID]
            changed = True
        allow = plugins.get("allow")
        if isinstance(allow, list) and HOOK_PLUGIN_ID in allow:
            allow.remove(HOOK_PLUGIN_ID)
            changed = True
    if changed:
        try:
            write_json(config_path, config_data)
        except OSError:
            return False
    return changed


def _guard_callback_url_from_bridge(bridge_state_path: Path) -> str:
    """从 bridge_state 中读取 host/port，回退到 127.0.0.1:8780。"""
    state = read_json(bridge_state_path) or {}
    host = str(state.get("host") or "127.0.0.1")
    port = int(state.get("port") or 8780)
    return f"http://{host}:{port}"


def _load_or_create_bridge_state(path: Path, *, host: str | None = None, port: int | None = None) -> dict[str, Any]:
    state = read_json(path) or {}
    changed = False
    token = state.get("auth_token")
    if not isinstance(token, str) or not token.strip():
        token = secrets.token_hex(16)
        state["auth_token"] = token
        changed = True
    if host is not None and state.get("host") != host:
        state["host"] = host
        changed = True
    if port is not None and state.get("port") != port:
        state["port"] = port
        changed = True
    if changed:
        write_json(path, state)
    return state


def _write_plugin_bundle(plugin_dir: Path, *, guard_url: str, auth_token: str) -> None:
    package_json = {
        "name": "@dynooob/openclaw-guard-hook",
        "version": __version__,
        "type": "module",
        "openclaw": {
            "extensions": ["./index.js"],
            "compat": {"pluginApi": ">=2026.4.0"},
        },
    }
    manifest = {
        "activation": {"onStartup": True},
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
                "failClosed": {"type": "boolean", "description": "Legacy setting: transport outages always pass through; responsive HTTP errors may block all tools when true."},
                "failClosedGracePeriodMs": {"type": "integer", "description": "Deprecated; transport outages immediately pass through."},
                "failThreshold": {"type": "integer", "description": "Deprecated; transport outages immediately pass through."},
                "recoveryThreshold": {"type": "integer"},
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
const DEFAULT_DECISION_TIMEOUT_MS = __DECISION_TIMEOUT_MS__;
const MAX_APPROVAL_DESCRIPTION_CHARS = 512;
const MAX_APPROVAL_TITLE_CHARS = 80;
const HIGH_IMPACT_TOOLS = new Set([
  "write", "edit", "apply_patch", "file_write", "file_delete",
  "exec", "shell", "shell_exec", "process", "terminal", "code_execution",
  "network.request", "web_search", "web_fetch", "browser",
  "message", "sessions_send", "sessions_spawn", "gateway", "nodes", "computer",
]);

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

function boundedApprovalText(value, fallback, maxChars) {{
  const text = String(value || fallback || "").trim();
  if (text.length <= maxChars) {{
    return text;
  }}
  return text.slice(0, Math.max(1, maxChars - 1)).trimEnd() + "…";
}}

function isHighImpactTool(event) {{
  const toolName = String(event?.toolName || "").trim().toLowerCase();
  if (HIGH_IMPACT_TOOLS.has(toolName) || /(^|[._-])(write|edit|delete|exec|shell|process|terminal|browser|message|send|upload|download)([._-]|$)/.test(toolName)) {{
    return true;
  }}
  let serialized = "";
  try {{
    serialized = JSON.stringify(event?.params || {{}}).toLowerCase();
  }} catch (_error) {{
    serialized = "";
  }}
  return /(^|[^a-z])(rm|sudo|chmod|chown|curl|wget|invoke-webrequest)([^a-z]|$)/.test(serialized);
}}

async function postJson(url, payload, timeoutMs, authToken) {{
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), Math.max(timeoutMs, 1000));
  try {{
    let requestBody;
    try {{
      requestBody = JSON.stringify(payload);
    }} catch (_error) {{
      const failure = new Error("Guard request payload invalid");
      failure.kind = "protocol";
      throw failure;
    }}
    let response;
    try {{
      response = await fetch(url, {{
        method: "POST",
        headers: {{
          "content-type": "application/json",
          ...(authToken ? {{ "x-openclaw-guard-token": authToken }} : {{}}),
        }},
        body: requestBody,
        signal: controller.signal,
      }});
    }} catch (error) {{
      const failure = new Error("Guard transport unavailable");
      failure.kind = "transport";
      throw failure;
    }}
    let responseText;
    try {{
      responseText = await response.text();
    }} catch (error) {{
      const failure = new Error("Guard response unreadable");
      // A successful response whose body stream aborts is a lost connection.
      // An explicit non-2xx response still follows the HTTP error policy.
      failure.kind = response.ok ? "transport" : "http";
      failure.status = response.status;
      throw failure;
    }}
    let data = {{}};
    if (responseText) {{
      try {{
        data = JSON.parse(responseText);
      }} catch (_error) {{
        if (response.ok) {{
          const failure = new Error("Guard response invalid");
          failure.kind = "protocol";
          throw failure;
        }}
      }}
    }}
    if (!response.ok) {{
      const failure = new Error(`Guard HTTP ${{response.status}}`);
      failure.kind = "http";
      failure.status = response.status;
      throw failure;
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
    const failClosed = pluginConfig.failClosed === true;
    if (failClosed) api.logger.warn(`[${{PLUGIN_ID}}] failClosed is deprecated for transport outages; agent tools pass through while Guard is unreachable`);
    const decisionTimeoutMs = Number(pluginConfig.decisionTimeoutMs || DEFAULT_DECISION_TIMEOUT_MS);
    const callbackTimeoutMs = Number(pluginConfig.callbackTimeoutMs || 15000);

    // The bridge is transparent until a background health check confirms availability.
    let backendState = "silent";
    let backendResponseError = false;
    let recoveryRequired = false;
    function enterSilent(reason) {{
      if (backendState !== "silent") {{
        api.logger.warn(`[${{PLUGIN_ID}}] Guard transport unavailable (${{reason}}); agent tools pass through`);
        recoveryRequired = true;
      }}
      backendState = "silent";
      backendResponseError = false;
      circuitOpen = true;
      consecutiveSuccesses = 0;
    }}
    function enterActive() {{
      backendState = "active";
      backendResponseError = false;
      circuitOpen = false;
      recoveryRequired = false;
    }}

    // A silent bridge never blocks tools or synchronously probes Guard.
    let circuitOpen = true;
    let consecutiveSuccesses = 0;
    const RECOVERY_THRESHOLD = Number(pluginConfig.recoveryThreshold || 2);
    let healthCheckTimer = null;

    async function doHealthCheck() {{
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      try {{
        const response = await fetch(`${{guardUrl}}/api/health`, {{
          method: "GET",
          signal: controller.signal,
        }});
        if (response.ok) {{
          let health;
          try {{
            health = JSON.parse(await response.text());
          }} catch (_error) {{
            enterSilent("health_identity");
            return;
          }}
          if (health?.ok !== true || health?.product !== "openclaw-guard") {{
            enterSilent("health_identity");
            return;
          }}
          consecutiveSuccesses++;
          if (!recoveryRequired || consecutiveSuccesses >= RECOVERY_THRESHOLD) {{
            const wasSilent = backendState === "silent";
            enterActive();
            if (wasSilent) api.logger.info(`[${{PLUGIN_ID}}] Guard backend healthy; protection resumed`);
          }}
        }} else {{
          // An HTTP response is not a transport outage. Keep the error visible.
          backendState = "active";
          backendResponseError = true;
          circuitOpen = false;
          recoveryRequired = true;
          consecutiveSuccesses = 0;
        }}
      }} catch (_err) {{
        enterSilent("health_transport");
      }} finally {{
        clearTimeout(timeout);
      }}
    }}

    try {
      api.registerGatewayMethod(STATUS_METHOD, async ({ respond }) => {{
        api.logger.info(`[${PLUGIN_ID}] responding to status request`);
        respond(true, {
          ok: true,
          pluginId: PLUGIN_ID,
          guardUrl,
          failClosed,
          state: backendState,
          backendResponseError,
          circuitOpen,
          decisionTimeoutMs,
        });
      });
      api.logger.info(`[${PLUGIN_ID}] registered gateway method: ${STATUS_METHOD}`);
    } catch (e) {
      api.logger.warn(`[${{PLUGIN_ID}}] registerGatewayMethod not available, status check via plugins list`);
    }

    // before_tool_call: main approval gate
    api.on(
      "before_tool_call",
      async (event, hookCtx) => {{
        if (backendState === "silent") {{
          return undefined;
        }}
        api.logger.info(`[${{PLUGIN_ID}}] before_tool_call FIRED: ${{event.toolName}}`);
        try {{
          const result = await postJson(
            `${{guardUrl}}/api/hook/before-tool-call`,
            {{
              toolName: event.toolName || "tool",
              params: event.params || {{}},
              toolKind: event.toolKind || "",
              toolInputKind: event.toolInputKind || "",
              derivedPaths: event.derivedPaths || [],
              runId: event.runId || hookCtx.runId || "",
              toolCallId: event.toolCallId || "",
              agentId: event.context?.agentId || hookCtx.agentId || "",
              sessionKey: event.context?.sessionKey || hookCtx.sessionKey || "",
              sessionId: event.context?.sessionId || hookCtx.sessionId || "",
            }},
            decisionTimeoutMs,
            authToken,
          );
          if (result.action === "allow") {{
            return undefined;
          }}

          if (result.action === "require_approval") {{
            api.logger.info(`[${{PLUGIN_ID}}] requiring approval for: ${{event.toolName}}`);
            return {{
              requireApproval: {{
                pluginId: PLUGIN_ID,
                title: boundedApprovalText(result.title, "龙虾卫士安全确认", MAX_APPROVAL_TITLE_CHARS),
                description: boundedApprovalText(result.message, "该工具调用需要确认，请查看操作目标和风险后决定。", MAX_APPROVAL_DESCRIPTION_CHARS),
                severity: result.severity || "warning",
                allowedDecisions: result.allowed_decisions || ["allow-once", "deny"],
                timeoutMs: 300000,
                onResolution: async (decision) => {{
                  if (backendState === "silent") return;
                  try {{
                    const normalizedDecision = decision === "allow-always" ? "allow-always" : decision;
                    await postJson(
                      `${{guardUrl}}/api/hook/resolve-approval`,
                      {{
                        actionId: result.action_record?.action_id || result.action_id,
                        decision: normalizedDecision,
                      }},
                      5000,
                      authToken,
                    );
                  }} catch (error) {{
                    if (error?.kind === "transport") enterSilent("approval_transport");
                    else backendResponseError = true;
                  }}
                }},
              }},
            }};
          }}

          return {{
            block: true,
            blockReason: boundedApprovalText(result.blockReason || result.message, "龙虾卫士已阻止该操作，请查看风险说明。", MAX_APPROVAL_DESCRIPTION_CHARS),
          }};
        }} catch (error) {{
          if (error?.kind === "transport") {{
            enterSilent("decision_transport");
            return undefined;
          }}
          backendResponseError = true;
          api.logger.warn(`[${{PLUGIN_ID}}] before_tool_call response error (${{error?.kind || "unknown"}})`);
          if (!failClosed && !isHighImpactTool(event)) {{
            return undefined;
          }}
          api.logger.warn(`[${{PLUGIN_ID}}] Guard responded with an error — blocking high-impact tool call`);
          return {{
            block: true,
            blockReason: boundedApprovalText(
              "龙虾卫士服务返回错误，已按安全策略暂停该操作。",
              "龙虾卫士服务返回错误，已按安全策略暂停该操作。",
              MAX_APPROVAL_DESCRIPTION_CHARS,
            ),
          }};
        }}
      }},
      {{ registrationId: "openclaw_guard_before_tool_call" }},
    );

    // after_tool_call: audit logging (non-blocking)
    api.on(
      "after_tool_call",
      async (event, hookCtx) => {{
        if (backendState === "silent") return;
        try {{
          await postJson(
            `${{guardUrl}}/api/hook/after-tool-call`,
            {{
              toolName: event.toolName || "tool",
              params: event.params || {{}},
              toolKind: event.toolKind || "",
              toolInputKind: event.toolInputKind || "",
              derivedPaths: event.derivedPaths || [],
              runId: event.runId || hookCtx.runId || "",
              toolCallId: event.toolCallId || "",
              agentId: event.context?.agentId || hookCtx.agentId || "",
              sessionKey: event.context?.sessionKey || hookCtx.sessionKey || "",
              sessionId: event.context?.sessionId || hookCtx.sessionId || "",
              error: event.error || null,
              durationMs: event.durationMs || null,
              resultSummary: summarizeResult(event.result),
            }},
            callbackTimeoutMs,
            authToken,
          );
        }} catch (error) {{
          if (error?.kind === "transport") enterSilent("audit_transport");
          else backendResponseError = true;
        }}
      }},
      {{ registrationId: "openclaw_guard_after_tool_call" }},
    );

    // gateway_start: initialize health check
    api.on(
      "gateway_start",
      () => {{
        api.logger.info(`[${{PLUGIN_ID}}] Gateway started — initializing health check (30s interval)`);
        // Immediate first check
        const initialCheck = doHealthCheck();
        healthCheckTimer = setInterval(doHealthCheck, 30000);
        return initialCheck;
      }},
      {{ registrationId: "openclaw_guard_gateway_start" }},
    );

    // gateway_stop: cleanup
    api.on(
      "gateway_stop",
      () => {{
        api.logger.info(`[${{PLUGIN_ID}}] Gateway stopping — cleaning up health check timer`);
        if (healthCheckTimer) {{
          clearInterval(healthCheckTimer);
          healthCheckTimer = null;
        }}
      }},
      {{ registrationId: "openclaw_guard_gateway_stop" }},
    );

    api.logger.info(`[${{PLUGIN_ID}}] registered all hooks (5) via api.on()`);
  },
}};
"""
    rendered = (
        template.replace("__PLUGIN_ID__", HOOK_PLUGIN_ID)
        .replace("__STATUS_METHOD__", HOOK_METHOD_STATUS)
        .replace("__GUARD_URL__", guard_url)
        .replace("__AUTH_TOKEN__", auth_token)
        .replace("__DECISION_TIMEOUT_MS__", str(DEFAULT_DECISION_TIMEOUT_MS))
    )
    return rendered.replace("{{", "{").replace("}}", "}")
