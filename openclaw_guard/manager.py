"""向后兼容模块 —— OpenclawGuardManager 子类化 GuardServices。

Phase 3 (v0.3.0): GuardServices 容器位于 openclaw_guard.services。
本模块保留为子类适配层，确保：
1. 所有现有导入路径（from openclaw_guard.manager import ...）无需变更
2. patch("openclaw_guard.manager.<adapter_fn>", ...) 可正常打补丁
   —— 测试依赖此行为来 mock OpenClaw gateway 调用

新代码请直接从 openclaw_guard.services 导入：
    from openclaw_guard.services import GuardServices, build_services

测试/打补丁场景：继续使用本模块的 OpenclawGuardManager 和 build_manager。
"""

from __future__ import annotations

from pathlib import Path

from openclaw_guard.config import AppContext, GuardSettings, apply_env_overrides, default_paths
from openclaw_guard.integrations.discovery import discover_openclaw
from openclaw_guard.integrations.openclaw_adapter import (
    get_chat_history,
    get_chat_status,
    get_guard_hook_status,
    inspect_guard_plugin,
    list_available_models,
    reset_chat_session,
    start_chat_message,
    wait_for_run,
)
from openclaw_guard.services import (
    GuardServices,
    _chat_history_impl,
    _chat_status_impl,
    _hook_status_impl,
    _new_chat_impl,
    _poll_chat_action_impl,
    _start_chat_action_impl,
)


class OpenclawGuardManager(GuardServices):
    """向后兼容子类 —— 从 manager.py 模块命名空间解析适配器函数。

    GuardServices 的方法委托给 _*_impl 辅助函数，并使用
    services.py 模块命名空间中的适配器函数。
    本子类覆盖这些方法，使用 **本模块** 中的适配器函数，
    使得 patch("openclaw_guard.manager.get_chat_status", ...) 能够生效。
    """

    def chat_status(self):
        return _chat_status_impl(
            self, get_chat_status_fn=get_chat_status, list_available_models_fn=list_available_models
        )

    def chat_history(self):
        return _chat_history_impl(self, get_chat_history_fn=get_chat_history)

    def new_chat(self):
        return _new_chat_impl(self, reset_chat_session_fn=reset_chat_session)

    def hook_status(self):
        return _hook_status_impl(
            self, inspect_guard_plugin_fn=inspect_guard_plugin, get_guard_hook_status_fn=get_guard_hook_status
        )

    def start_chat_action(self, action_id: str):
        return _start_chat_action_impl(
            self, action_id, get_chat_history_fn=get_chat_history, start_chat_message_fn=start_chat_message
        )

    def poll_chat_action(self, action_id: str, *, timeout_ms: int = 1_000):
        return _poll_chat_action_impl(
            self, action_id, timeout_ms=timeout_ms, wait_for_run_fn=wait_for_run, get_chat_history_fn=get_chat_history
        )


def build_manager(
    project_dir: Path,
    *,
    openclaw_root: Path | None = None,
    config_path: Path | None = None,
    profile: str | None = None,
    host: str = "127.0.0.1",
    port: int = 8780,
    ui_mode: str = "pro",
) -> OpenclawGuardManager:
    """构建 OpenclawGuardManager（向后兼容工厂，与旧签名完全一致）。"""
    from openclaw_guard.storage.db_store import reset_db_store

    reset_db_store()
    paths = default_paths(project_dir)
    target = discover_openclaw(openclaw_root=openclaw_root, config_path=config_path, profile=profile, cwd=project_dir)
    settings = apply_env_overrides(GuardSettings(host=host, port=port, ui_mode=ui_mode))
    context = AppContext(paths=paths, target=target, settings=settings)
    return OpenclawGuardManager(context)


__all__ = ["OpenclawGuardManager", "build_manager"]
