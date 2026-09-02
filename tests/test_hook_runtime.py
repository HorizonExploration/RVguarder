from pathlib import Path

from openclaw_guard.integrations.hook_runtime import _ensure_plugin_config


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
