"""B0 配置构建、遗留工具守卫、合成插件与真实端到端冒烟测试。

真实冒烟测试需要 node（运行时准入合格）、openclaw CLI、Docker（含
``openclaw-sandbox:bookworm-slim`` 镜像）与可用的 Docker daemon；任一前置不满足时
以 ``pytest.skip`` 跳过并打印原因。冒烟使用冻结轨迹 provider 与真实 gateway 运行
**一个**最小 benign 场景，校验准入与 receipts 关联。
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from testlab.office_chain import office_driver
from testlab.office_chain.native_baseline import (
    LEGACY_NON_COMPARABLE,
    REQUIRED_TOOL_PATHS,
    assert_no_legacy_tooling,
    default_plugin_dir,
    resolve_b0_config,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIOS_PATH = REPO_ROOT / "testlab/office_chain/scenarios.json"
PLUGIN_DIR = default_plugin_dir()

#: 专门用于真实冒烟的最小 benign 场景（3 步：read、read、office_message_send，无 restart）。
SMOKE_SCENARIO_ID = "ECHOLEAK-CVE-2025-32711-CAL-B1"


def _config(workspace: Path, *, provider_port: int = 43210) -> dict:
    return resolve_b0_config(
        workspace, plugin_dir=PLUGIN_DIR, profile_home=workspace.parent / "profile", provider_port=provider_port,
    )


def _scenario(scenario_id: str) -> dict:
    payload = json.loads(SCENARIOS_PATH.read_text(encoding="utf-8"))
    for scenario in payload["scenarios"]:
        if scenario.get("scenario_id") == scenario_id:
            return scenario
    raise AssertionError(f"未找到场景 {scenario_id}")


# --------------------------------------------------------------------------- #
# 配置断言
# --------------------------------------------------------------------------- #

def test_resolve_b0_config_uses_native_safety_mechanisms(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    provider_port = 45123
    config = _config(workspace, provider_port=provider_port)

    defaults = config["agents"]["defaults"]
    assert defaults["workspace"] == str(workspace.resolve())
    assert defaults["sandbox"] == {
        "mode": "all", "scope": "session", "backend": "docker", "workspaceAccess": "rw",
    }
    tools = config["tools"]
    assert tools["profile"] == "full"
    assert set(REQUIRED_TOOL_PATHS).issubset(tools["allow"])
    assert set(tools["allow"]).issubset(set(tools["sandbox"]["tools"]["allow"]))
    assert "apply_patch" in tools["deny"]
    assert "browser" in tools["deny"]
    assert tools["exec"] == {"security": "allowlist", "ask": "always"}
    assert tools["elevated"]["enabled"] is False
    assert config["gateway"]["mode"] == "local"
    assert "port" not in config["gateway"]  # 端口由驱动在运行期动态分配


def test_resolve_b0_config_points_model_at_frozen_provider(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    provider_port = 45999
    config = _config(workspace, provider_port=provider_port)

    primary = config["agents"]["defaults"]["model"]["primary"]
    key, _, model_id = primary.partition("/")
    assert key and model_id
    provider = config["models"]["providers"][key]
    assert provider["baseUrl"] == f"http://127.0.0.1:{provider_port}/v1"
    assert provider["models"][0]["id"] == model_id
    assert config["plugins"]["load"]["paths"] == [str(PLUGIN_DIR.resolve())]


def test_resolve_b0_config_does_not_load_rvguarder(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = _config(workspace)
    blob = json.dumps(config, ensure_ascii=False).lower()
    # RVguarder 的运行时 Hook 插件绝不出现在 B0 配置中。
    assert "openclaw-guard" not in blob
    assert "openclaw-guard-hook" not in blob
    entries = config["plugins"]["entries"]
    assert list(entries) == ["rvguard-office-chain-simulator"]
    assert not any("guard-hook" in str(key) for key in entries)


def test_assert_no_legacy_tooling_rejects_legacy_names(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = _config(workspace)
    config["tools"]["allow"].append("network.request")
    with pytest.raises(ValueError) as excinfo:
        assert_no_legacy_tooling(config)
    assert "network.request" in str(excinfo.value)
    assert LEGACY_NON_COMPARABLE  # 守卫集合非空


def test_assert_no_legacy_tooling_allows_native_config(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    assert_no_legacy_tooling(_config(workspace))  # 不抛异常即通过


# --------------------------------------------------------------------------- #
# 合成办公插件
# --------------------------------------------------------------------------- #

def test_plugin_files_present_and_manifest_valid() -> None:
    assert (PLUGIN_DIR / "index.js").is_file()
    assert (PLUGIN_DIR / "index.test.mjs").is_file()
    manifest = json.loads((PLUGIN_DIR / "openclaw.plugin.json").read_text(encoding="utf-8"))
    assert manifest["id"] == "rvguard-office-chain-simulator"
    assert set(manifest["contracts"]["tools"]) == {
        "office_message_send", "office_network_post", "office_document_share",
    }
    assert manifest["configSchema"]["required"] == ["workspaceRoot", "receiptPath"]
    # 配置中的插件条目键必须与插件 id 一致，否则 OpenClaw 无法匹配配置。
    config = _config(Path("/tmp") / "office-chain-manifest-check")
    assert list(config["plugins"]["entries"]) == [manifest["id"]]
    # 插件源码绝不发起真实网络请求。
    source = (PLUGIN_DIR / "index.js").read_text(encoding="utf-8")
    for banned in ("node:http", "node:https", "node:net", "fetch(", "XMLHttpRequest"):
        assert banned not in source


def test_plugin_node_unit_tests_pass() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("环境无 node，跳过合成插件单测")
    result = subprocess.run(
        [node, "--test", str(PLUGIN_DIR / "index.test.mjs")],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


# --------------------------------------------------------------------------- #
# 纯逻辑单元（无需运行时）
# --------------------------------------------------------------------------- #

def test_segments_split_on_restart_before() -> None:
    scenario = _scenario("PRAISON-2026-55532-CAL-A1")
    segments = office_driver._segments(scenario)
    assert len(segments) == 2
    assert [event["event_id"] for event in segments[0]] == ["rule"]
    assert segments[1][0]["restart_before"] is True


def test_compose_task_message_carries_business_rules() -> None:
    scenario = _scenario(SMOKE_SCENARIO_ID)
    message = office_driver.compose_task_message(scenario)
    assert scenario["business_task"] in message
    assert scenario["work_rules"][0] in message
    assert scenario["user_authorization"] in message


def test_seed_workspace_creates_declared_files(tmp_path: Path) -> None:
    scenario = _scenario(SMOKE_SCENARIO_ID)
    workspace = tmp_path / "workspace"
    created = office_driver.seed_workspace(workspace, scenario)
    assert created
    for event in scenario["events"]:
        path = event["hook_payload"]["params"].get("path")
        if path:
            assert (workspace / path).is_file()


def test_benign_scenario_never_achieves_attack_goal(tmp_path: Path) -> None:
    scenario = _scenario(SMOKE_SCENARIO_ID)
    achieved = office_driver._adjudicate_attack_goal(
        scenario, attack_goal=scenario.get("attack_goal"), receipts=[],
        external_receipts=[], workspace=tmp_path, events=[],
    )
    assert achieved is False


def test_sensitive_file_deleted_oracle_reads_declared_effect_path(tmp_path: Path) -> None:
    """删除类目标的观测口径必须读场景声明的 ``effect["path"]``。

    矩阵里所有 ``kind == "delete"`` 的 effect 都声明 ``path``（从无 ``target``）。读错键会让
    ``targets`` 恒为空、判定恒为 ``False``——于是**每一个臂**（包括不加载任何防护的 ``B0``）
    都白拿一次"防护成功"，基线与实验组同时被抬高。
    """

    payload = json.loads(SCENARIOS_PATH.read_text(encoding="utf-8"))
    scenario = next(
        item for item in payload["scenarios"] if item.get("attack_goal") == "sensitive_file_deleted"
    )
    targets = [
        str(event["effect"]["path"])
        for event in scenario["events"]
        if isinstance(event.get("effect"), dict)
        and event["effect"].get("kind") == "delete"
        and event["effect"].get("path")
    ]
    assert targets, "该场景必须声明 delete 效果的目标路径，否则无从观测"

    workspace = tmp_path / "workspace"
    workspace.mkdir()

    # 目标文件不存在 → 目标已达成（攻击成功）。
    assert office_driver._adjudicate_attack_goal(
        scenario, attack_goal=scenario["attack_goal"], receipts=[], external_receipts=[],
        workspace=workspace, events=[],
    ) is True

    # 目标文件仍存在 → 未达成（防护成功）。
    for relative in targets:
        target = workspace / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("synthetic\n", encoding="utf-8")
    assert office_driver._adjudicate_attack_goal(
        scenario, attack_goal=scenario["attack_goal"], receipts=[], external_receipts=[],
        workspace=workspace, events=[],
    ) is False


# --------------------------------------------------------------------------- #
# 真实端到端冒烟
# --------------------------------------------------------------------------- #

def _require_runtime() -> dict:
    try:
        toolchain = office_driver.resolve_toolchain()
    except office_driver.RuntimeUnavailable as exc:
        pytest.skip(f"真实运行时不可用：{exc}")
    if not toolchain.get("node_admission_ok"):
        pytest.skip(f"node 不满足 OpenClaw 运行时准入：{toolchain.get('node_version')}")
    docker = toolchain.get("docker")
    info = subprocess.run([docker, "info"], capture_output=True, text=True, check=False)
    if info.returncode != 0:
        pytest.skip("Docker daemon 不可用，跳过真实冒烟")
    image = subprocess.run(
        [docker, "image", "inspect", "openclaw-sandbox:bookworm-slim"],
        capture_output=True, text=True, check=False,
    )
    if image.returncode != 0:
        pytest.skip("缺少 openclaw-sandbox:bookworm-slim 镜像，跳过真实冒烟")
    return toolchain


def test_b0_real_smoke_admits_and_correlates_receipts(tmp_path: Path) -> None:
    toolchain = _require_runtime()
    scenario = _scenario(SMOKE_SCENARIO_ID)
    result = office_driver.run_scenario_b0(
        scenario,
        workspace=tmp_path / "workspace",
        profile_home=tmp_path / "profile",
        toolchain=toolchain,
        timeout=240.0,
    )

    assert result["arm"] == "B0"
    assert set(result["admission_checks"]) == {
        "agent_run_observed", "hook_events_observed", "receipts_present", "automation_store_matchable",
    }
    assert result["admitted"] is True, result["notes"]
    assert result["admission_checks"]["hook_events_observed"] is True
    assert result["attack_goal_achieved"] is False  # benign 场景无攻击目标

    office_events = [row for row in result["events"] if row["tool_name"] in office_driver.OFFICE_TOOLS]
    assert office_events, result["events"]
    assert any(row["applied"] for row in office_events)

    office_receipts = [row for row in result["receipts"] if row.get("kind") == "message_send"]
    assert office_receipts, result["receipts"]
    for receipt in office_receipts:
        assert str(receipt.get("toolCallId"))
        assert int(receipt.get("sourceBytes", 0)) > 0
        assert len(str(receipt.get("sourceSha256", ""))) == 64
    assert result["external_effect_count"] >= 1
    assert result["guard_latency_ms"] == []
