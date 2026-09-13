from pathlib import Path

import json

from openclaw_guard.config import AppContext, GuardSettings, OpenClawTarget, default_paths
from openclaw_guard.integrations.hook_runtime import (
    _ensure_plugin_config,
    ensure_runtime_hook_plugin,
    register_runtime_hook_in_config,
)


def test_ensure_plugin_config_removes_stale_tmp_guard_paths_and_deduplicates(tmp_path):
    plugin_dir = tmp_path / "runtime" / "openclaw-guard-plugin"
    config = {
        "plugins": {
            "load": {
                "paths": [
                    str(plugin_dir),
                    "/tmp/stale-guard/runtime/openclaw-guard-plugin",
                    str(plugin_dir),
                    "/opt/other-openclaw-plugin",
                ]
            }
        }
    }

    changed = _ensure_plugin_config(
        config,
        plugin_dir=plugin_dir,
        guard_url="http://127.0.0.1:8780",
        auth_token="token",
    )

    assert changed is True
    assert config["plugins"]["load"]["paths"] == [
        str(plugin_dir),
        "/opt/other-openclaw-plugin",
    ]


def test_transient_guard_project_does_not_mutate_ambient_openclaw_config(tmp_path):
    """Temporary test projects must not register their soon-to-be-deleted plugin globally."""
    project_dir = tmp_path / "temporary-guard"
    config_path = tmp_path / "ambient-openclaw" / "openclaw.json"
    config_path.parent.mkdir()
    original = {"plugins": {"load": {"paths": ["/opt/other-openclaw-plugin"]}}}
    config_path.write_text(json.dumps(original), encoding="utf-8")
    context = AppContext(
        paths=default_paths(project_dir),
        target=OpenClawTarget(config_path=config_path),
        settings=GuardSettings(host="127.0.0.1", port=8780),
    )

    result = ensure_runtime_hook_plugin(context)

    assert result["config_changed"] is False
    assert result["config_skipped"] is True
    assert json.loads(config_path.read_text(encoding="utf-8")) == original


def test_manual_hook_registration_also_skips_transient_external_config(tmp_path):
    """The explicit install endpoint must share the same isolation boundary."""
    plugin_dir = tmp_path / "temporary-guard" / "runtime" / "openclaw-guard-plugin"
    config_path = tmp_path / "ambient-openclaw" / "openclaw.json"
    config_path.parent.mkdir()
    original = {"plugins": {"load": {"paths": ["/opt/other-openclaw-plugin"]}}}
    config_path.write_text(json.dumps(original), encoding="utf-8")

    changed = register_runtime_hook_in_config(config_path, plugin_dir)

    assert changed is False
    assert json.loads(config_path.read_text(encoding="utf-8")) == original


def test_transient_guard_project_can_write_project_local_config(tmp_path):
    """Isolation must not disable an explicitly project-local OpenClaw config."""
    project_dir = tmp_path / "temporary-guard"
    config_path = project_dir / "openclaw.json"
    project_dir.mkdir()
    config_path.write_text("{}", encoding="utf-8")
    context = AppContext(
        paths=default_paths(project_dir),
        target=OpenClawTarget(config_path=config_path),
        settings=GuardSettings(host="127.0.0.1", port=8780),
    )

    result = ensure_runtime_hook_plugin(context)

    assert result["config_changed"] is True
    assert result["config_skipped"] is False
    data = json.loads(config_path.read_text(encoding="utf-8"))
    assert str(project_dir / "runtime" / "openclaw-guard-plugin") in data["plugins"]["load"]["paths"]
