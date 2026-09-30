"""OpenClaw 原生安全机制基线（B0）配置构建（office-attack-chain-v1）。

B0 是实验的**唯一对照基线**：在真实 OpenClaw 运行时上执行场景，完整启用其原生
安全机制——工具 allow/deny 分组、Docker 沙箱 ``mode: all`` + ``workspaceAccess: rw``、
``exec.security: allowlist`` 且 ``ask: always``、elevated 关闭、原生审批——并
**不加载 RVguarder 插件**。

外部副作用由合成办公插件以本地 receipts 记录，不产生真实网络请求；本模块只负责
构建配置与拒绝把 v3 遗留离线工具名当作原生路径，不启动任何进程。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .frozen_provider import DEFAULT_MODEL_ID


#: B0 原生模型 provider 键（OpenAI 兼容路由名）。
PROVIDER_KEY = "office-chain-fixed"

#: B0 必须可用的原生工具路径（准入要求这些工具经真实原生路径执行）。
REQUIRED_TOOL_PATHS = frozenset({
    "read",
    "write",
    "office_message_send",
    "office_network_post",
    "office_document_share",
    "automations",
})

#: v3 遗留离线工具名：它们不等同于原生路径，出现在启用集合中即不可比。
LEGACY_NON_COMPARABLE = {"network.request", "secrets", "gateway", "shell"}

#: B0 允许的原生工具（含合成办公工具与 automations）。
ALLOWED_TOOLS: tuple[str, ...] = (
    "read",
    "write",
    "exec",
    "web_fetch",
    "message",
    "cron",
    "office_message_send",
    "office_network_post",
    "office_document_share",
    "automations",
)

#: B0 明确拒绝的原生工具。
DENIED_TOOLS: tuple[str, ...] = (
    "apply_patch",
    "edit",
    "browser",
    "gateway",
    "nodes",
    "sessions_spawn",
)


def default_plugin_dir() -> Path:
    """返回套件内置的合成办公插件目录。"""
    return Path(__file__).resolve().with_name("native_office_plugin")


def resolve_b0_config(
    workspace: Path,
    *,
    plugin_dir: Path,
    profile_home: Path,
    provider_port: int,
) -> dict[str, Any]:
    """构建 B0 原生基线配置（不含 RVguarder，不含真实凭据）。

    参数：
    - ``workspace``：合成工作区（仅此目录被沙箱挂载）。
    - ``plugin_dir``：合成办公插件目录。
    - ``profile_home``：运行期临时 profile 根；receipts 写入此处，不在用户 home 留痕。
    - ``provider_port``：冻结轨迹端点的本地端口；模型 base URL 指向它。
    """
    workspace = Path(workspace).resolve()
    plugin_dir = Path(plugin_dir).resolve()
    profile_home = Path(profile_home).resolve()
    if not plugin_dir.is_dir():
        raise ValueError(f"合成办公插件目录不存在：{plugin_dir}")
    if int(provider_port) <= 0:
        raise ValueError(f"provider_port 必须为正整数，实际 {provider_port!r}")

    receipt_path = profile_home / "office-receipts.jsonl"
    config: dict[str, Any] = {
        # 真实 gateway：loopback 绑定；端口由驱动在运行期动态分配。
        "gateway": {"mode": "local", "bind": "loopback"},
        "agents": {"defaults": {
            "workspace": str(workspace),
            "model": {"primary": f"{PROVIDER_KEY}/{DEFAULT_MODEL_ID}"},
            # 仅挂载合成工作区的 Docker 会话沙箱。
            "sandbox": {
                "mode": "all",
                "scope": "session",
                "backend": "docker",
                "workspaceAccess": "rw",
            },
        }},
        "tools": {
            "profile": "full",
            "allow": list(ALLOWED_TOOLS),
            "deny": list(DENIED_TOOLS),
            "sandbox": {"tools": {
                "allow": list(ALLOWED_TOOLS),
                "deny": list(DENIED_TOOLS),
            }},
            # 原生安全机制：elevated 关闭；exec 白名单且总是询问。
            "elevated": {"enabled": False},
            "exec": {"security": "allowlist", "ask": "always"},
        },
        "plugins": {
            "load": {"paths": [str(plugin_dir)]},
            "entries": {"rvguard-office-chain-simulator": {
                "enabled": True,
                "config": {
                    "workspaceRoot": str(workspace),
                    "receiptPath": str(receipt_path),
                },
            }},
        },
        # 冻结轨迹端点：模型 base URL 指向本地 provider 端口。
        "models": {"providers": {PROVIDER_KEY: {
            "baseUrl": f"http://127.0.0.1:{int(provider_port)}/v1",
            "apiKey": "office-chain-fixed-local-placeholder",
            "api": "openai-completions",
            "models": [{
                "id": DEFAULT_MODEL_ID,
                "name": "RVguard Office Chain Frozen Trajectory",
                "reasoning": False,
                "input": ["text"],
                "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
                "contextWindow": 131072,
                "contextTokens": 120000,
                "maxTokens": 1024,
            }],
        }}},
    }
    assert_no_legacy_tooling(config)
    return config


def _enabled_tool_names(config: dict[str, Any]) -> set[str]:
    """收集配置中处于"启用"位置的工具名（allow / 沙箱 allow / 插件契约）。"""
    enabled: set[str] = set()
    tools = config.get("tools") if isinstance(config.get("tools"), dict) else {}
    for key in ("allow",):
        values = tools.get(key)
        if isinstance(values, list):
            enabled.update(str(item) for item in values)
    sandbox = tools.get("sandbox") if isinstance(tools.get("sandbox"), dict) else {}
    sandbox_tools = sandbox.get("tools") if isinstance(sandbox.get("tools"), dict) else {}
    for key in ("allow",):
        values = sandbox_tools.get(key)
        if isinstance(values, list):
            enabled.update(str(item) for item in values)
    plugins = config.get("plugins") if isinstance(config.get("plugins"), dict) else {}
    entries = plugins.get("entries") if isinstance(plugins.get("entries"), dict) else {}
    for entry in entries.values():
        if not isinstance(entry, dict):
            continue
        contracts = entry.get("contracts") if isinstance(entry.get("contracts"), dict) else {}
        values = contracts.get("tools")
        if isinstance(values, list):
            enabled.update(str(item) for item in values)
        entry_tools = entry.get("tools")
        if isinstance(entry_tools, list):
            enabled.update(str(item) for item in entry_tools)
    return enabled


def assert_no_legacy_tooling(config: dict[str, Any]) -> None:
    """若配置把 v3 遗留离线工具名放进启用集合，则抛 ``ValueError``。

    这些工具名（``network.request`` / ``secrets`` / ``gateway`` / ``shell``）与
    OpenClaw 原生路径不可比；把它们当作原生路径会污染对照结论。显式 ``deny``
    它们是可以的（原生拒绝），但不得出现在 allow / 插件契约中。
    """
    offending = sorted(_enabled_tool_names(config) & LEGACY_NON_COMPARABLE)
    if offending:
        raise ValueError(
            "B0 配置启用了 v3 遗留离线工具名（不可与原生路径等同）：" + ", ".join(offending)
        )
