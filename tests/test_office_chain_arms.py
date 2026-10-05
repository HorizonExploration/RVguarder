"""测试五臂定义与配置等价性校验（Task 7.1）。"""

from __future__ import annotations

import copy

import pytest

from openclaw_guard.engine.experiment_components import COMPONENT_NAMES

from testlab.office_chain.arms import (
    ARM_NAMES,
    ARMS,
    GUARD_ARMS,
    arm_spec,
    arms_digest,
    arms_manifest,
    assert_arm_equivalence,
    component_matrix,
    native_projection_sha256,
    normalise_native_config,
)


def _base_config() -> dict:
    """构造一个最小但结构完整的 OpenClaw 配置（含 guard 与 office 插件）。"""

    return {
        "gateway": {"mode": "local", "bind": "loopback", "port": 19001},
        "agents": {
            "defaults": {
                "workspace": "/tmp/arm-workspace",
                "model": {"primary": "rvguard-office-chain-fixed-v1"},
                "sandbox": {
                    "mode": "all",
                    "scope": "session",
                    "backend": "docker",
                    "workspaceAccess": "rw",
                },
            }
        },
        "tools": {
            "profile": "full",
            "allow": ["read", "write", "office_message_send"],
            "deny": ["apply_patch", "edit", "browser", "gateway", "nodes"],
            "elevated": {"enabled": False},
            "exec": {"security": "allowlist", "ask": "always"},
        },
        "plugins": {
            "enabled": True,
            "load": {"paths": ["/repo/testlab/office_chain/native_office_plugin"]},
            "entries": {
                "rvguard-office-chain-simulator": {
                    "enabled": True,
                    "config": {
                        "workspaceRoot": "/tmp/arm-workspace",
                        "receiptPath": "/tmp/arm-profile/office-receipts.jsonl",
                    },
                }
            },
            "allow": [],
        },
    }


def _guard_config() -> dict:
    """在基线配置上叠加 guard 插件（模拟真实 guard 臂）。"""

    config = _base_config()
    config["plugins"]["load"]["paths"].append("/repo/runtime/openclaw-guard-plugin")
    config["plugins"]["entries"]["openclaw-guard-hook"] = {
        "enabled": True,
        "config": {"guardUrl": "http://127.0.0.1:8799"},
    }
    config["plugins"]["allow"].append("openclaw-guard-hook")
    return config


def test_arm_names_and_order() -> None:
    assert ARM_NAMES == ("B0", "P", "P+S", "P+C", "Full")
    assert [arm.name for arm in ARMS] == list(ARM_NAMES)
    assert GUARD_ARMS == ("P", "P+S", "P+C", "Full")


def test_b0_does_not_load_guard() -> None:
    assert arm_spec("B0").loads_guard is False
    assert arm_spec("Full").loads_guard is True


def test_disabled_component_sets() -> None:
    assert set(arm_spec("P").disabled_names()) == {"semantic_llm", "cross_step_rv"}
    assert set(arm_spec("P+S").disabled_names()) == {"cross_step_rv"}
    assert set(arm_spec("P+C").disabled_names()) == {"semantic_llm"}
    assert set(arm_spec("Full").disabled_names()) == set()


def test_full_enables_every_component() -> None:
    components = arm_spec("Full").components()
    for name in COMPONENT_NAMES:
        assert getattr(components, name) is True


def test_component_config_hashes_are_distinct() -> None:
    """四个 guard 臂的组件开关互异；B0 不加载 guard，其开关集等于 Full 属预期。"""

    guard_hashes = {arm.name: arm.config_hash() for arm in ARMS if arm.loads_guard}
    assert len(set(guard_hashes.values())) == len(guard_hashes) == 4
    assert arm_spec("B0").config_hash() == arm_spec("Full").config_hash()


def test_component_matrix_matches_arm_specs() -> None:
    matrix = component_matrix()
    for arm in ARMS:
        expected = arm.components()
        for name in COMPONENT_NAMES:
            assert matrix[arm.name][name] is getattr(expected, name)


def test_normalise_strips_environment_scoped_fields() -> None:
    config = _guard_config()
    normalised = normalise_native_config(config)
    assert "port" not in normalised["gateway"]
    assert "workspace" not in normalised["agents"]["defaults"]
    assert "/repo/runtime/openclaw-guard-plugin" not in normalised["plugins"]["load"]["paths"]
    assert "openclaw-guard-hook" not in normalised["plugins"]["entries"]
    assert "openclaw-guard-hook" not in normalised["plugins"]["allow"]
    assert "enabled" not in normalised["plugins"]
    office_config = normalised["plugins"]["entries"]["rvguard-office-chain-simulator"]["config"]
    assert "workspaceRoot" not in office_config
    assert "receiptPath" not in office_config


def test_native_projection_ignores_environment_differences() -> None:
    left = _guard_config()
    right = copy.deepcopy(left)
    right["gateway"]["port"] = 20123
    right["gateway"]["auth"] = {"mode": "token", "token": "deadbeef"}
    right["agents"]["defaults"]["workspace"] = "/tmp/other-workspace"
    right["plugins"]["load"]["paths"][-1] = "/tmp/other/openclaw-guard-plugin"
    right["plugins"]["entries"]["rvguard-office-chain-simulator"]["config"]["receiptPath"] = (
        "/tmp/other/receipts.jsonl"
    )
    assert native_projection_sha256(left) == native_projection_sha256(right)


def test_arm_equivalence_passes_for_equivalent_configs() -> None:
    configs = {name: _guard_config() for name in ARM_NAMES}
    projections = assert_arm_equivalence(configs)
    assert set(projections) == set(ARM_NAMES)
    assert len(set(projections.values())) == 1


def test_arm_equivalence_rejects_non_component_drift() -> None:
    configs = {name: _guard_config() for name in ARM_NAMES}
    configs["P+C"] = copy.deepcopy(configs["P+C"])
    configs["P+C"]["tools"]["exec"]["ask"] = "never"
    with pytest.raises(ValueError, match="不等价"):
        assert_arm_equivalence(configs)


def test_arm_equivalence_requires_all_arms() -> None:
    configs = {name: _base_config() for name in ("P", "P+S")}
    with pytest.raises(ValueError, match="缺少臂配置"):
        assert_arm_equivalence(configs)


def test_arm_equivalence_allows_guard_plugin_presence_on_guard_arms() -> None:
    """B0 不带 guard 插件，guard 臂带 —— 归一化后仍应等价。"""

    configs: dict[str, dict] = {"B0": _base_config()}
    for name in ("P", "P+S", "P+C", "Full"):
        configs[name] = _guard_config()
    projections = assert_arm_equivalence(configs)
    assert len(set(projections.values())) == 1


def test_arms_manifest_records_component_sets() -> None:
    manifest = arms_manifest()
    assert [entry["name"] for entry in manifest["arms"]] == list(ARM_NAMES)
    assert arms_digest() == arms_digest()
    full = next(entry for entry in manifest["arms"] if entry["name"] == "Full")
    assert full["disabled_components"] == []


def test_frozen_provider_ports_do_not_change_native_projection() -> None:
    """受控本地轨迹端口不影响策略哈希，归一化不能改写原配置。"""
    left = _base_config()
    left["models"] = {"providers": {"office-chain-fixed": {"baseUrl": "http://127.0.0.1:23001/v1"}}}
    right = copy.deepcopy(left)
    right["models"]["providers"]["office-chain-fixed"]["baseUrl"] = "http://127.0.0.1:23002/v1"
    assert native_projection_sha256(left) == native_projection_sha256(right)
    assert left["models"]["providers"]["office-chain-fixed"]["baseUrl"] == "http://127.0.0.1:23001/v1"


@pytest.mark.parametrize("changed_url", ["https://remote.example/v1", "http://127.0.0.2:23001/v1", "http://127.0.0.1:23001/other"])
def test_frozen_provider_endpoint_changes_remain_detectable(changed_url: str) -> None:
    """只豁免本地随机端口，真实 provider 地址或协议变化必须保留。"""
    left = _base_config()
    left["models"] = {"providers": {"office-chain-fixed": {"baseUrl": "http://127.0.0.1:23001/v1"}}}
    right = copy.deepcopy(left)
    right["models"]["providers"]["office-chain-fixed"]["baseUrl"] = changed_url
    assert native_projection_sha256(left) != native_projection_sha256(right)


def test_other_provider_ports_remain_detectable() -> None:
    """真实模型 provider 的端口不属于本实验随机绑定豁免。"""
    left = _base_config()
    left["models"] = {"providers": {"other-provider": {"baseUrl": "http://127.0.0.1:23001/v1"}}}
    right = copy.deepcopy(left)
    right["models"]["providers"]["other-provider"]["baseUrl"] = "http://127.0.0.1:23002/v1"
    assert native_projection_sha256(left) != native_projection_sha256(right)
