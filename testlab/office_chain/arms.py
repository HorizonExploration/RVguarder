"""五臂对照定义与配置等价性校验（office-attack-chain-v1）。

臂语义（顺序固定）：

======  ==========================================  ==========================================
arm     含义                                        disabled 组件
======  ==========================================  ==========================================
``B0``  OpenClaw 原生安全机制（对照组）              不加载 RVguarder
``P``   仅 PMKB 单步                                ``semantic_llm``、``cross_step_rv``
``P+S`` PMKB + 冻结语义                             ``cross_step_rv``
``P+C`` PMKB + 跨步骤 RV                            ``semantic_llm``
``Full`` 全部启用（实验组）                          （空）
======  ==========================================  ==========================================

主对照结论来自 ``Full`` vs ``B0``；``P`` / ``P+S`` / ``P+C`` 只用于组件增量归因。
除被测组件开关外，五臂的 OpenClaw 配置、审批人格、工作区、轨迹与规则版本必须一致，
并通过 :func:`assert_arm_equivalence` 的 native 投影哈希校验。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from openclaw_guard.engine.experiment_components import (
    COMPONENT_NAMES,
    ExperimentComponents,
)

from testlab.office_chain.artifacts import canonical_json, digest_json

ARM_NAMES: tuple[str, ...] = ("B0", "P", "P+S", "P+C", "Full")

OFFICE_PLUGIN_ENTRY = "rvguard-office-chain-simulator"
GUARD_PLUGIN_ID = "openclaw-guard-hook"
GUARD_PLUGIN_PATH_SUFFIX = "/openclaw-guard-plugin"

OFFICE_PLUGIN_SCOPED_CONFIG_KEYS = ("workspaceRoot", "receiptPath")


@dataclass(frozen=True)
class ArmSpec:
    """单臂定义：是否加载 RVguarder，以及被消融的组件集合。"""

    name: str
    disabled_components: str = ""
    loads_guard: bool = True
    description: str = ""

    def components(self) -> ExperimentComponents:
        """返回该臂的组件开关集合。"""

        return ExperimentComponents.from_disabled(self.disabled_components)

    def config_hash(self) -> str:
        """组件开关集合的配置哈希。"""

        return self.components().config_hash()

    def disabled_names(self) -> tuple[str, ...]:
        return self.components().disabled()


ARMS: tuple[ArmSpec, ...] = (
    ArmSpec("B0", "", False, "OpenClaw 原生安全机制（对照组）"),
    ArmSpec("P", "semantic_llm,cross_step_rv", True, "仅 PMKB 单步"),
    ArmSpec("P+S", "cross_step_rv", True, "PMKB + 冻结语义"),
    ArmSpec("P+C", "semantic_llm", True, "PMKB + 跨步骤 RV"),
    ArmSpec("Full", "", True, "全部启用（实验组）"),
)

ARM_INDEX: dict[str, ArmSpec] = {arm.name: arm for arm in ARMS}

GUARD_ARMS: tuple[str, ...] = tuple(arm.name for arm in ARMS if arm.loads_guard)


def arm_spec(name: str) -> ArmSpec:
    """按名字取臂定义；未知名字抛 :class:`KeyError`。"""

    try:
        return ARM_INDEX[name]
    except KeyError as exc:  # pragma: no cover - 防御性分支
        raise KeyError(f"未知实验臂：{name}（可选：{', '.join(ARM_NAMES)}）") from exc


def normalise_native_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """归一化 OpenClaw 配置，使五臂在"非被测组件"维度上可直接比较。

    丢弃仅随运行环境变化的字段（端口、鉴权令牌、工作区绝对路径、插件绝对路径），
    以及 guard 插件的注册条目；保留全部原生安全机制与工具分组。
    """

    import copy

    normalised = copy.deepcopy(dict(config))

    gateway = normalised.get("gateway")
    if isinstance(gateway, dict):
        gateway.pop("port", None)
        gateway.pop("auth", None)

    agents = normalised.get("agents")
    if isinstance(agents, dict):
        defaults = agents.get("defaults")
        if isinstance(defaults, dict):
            defaults.pop("workspace", None)

    plugins = normalised.get("plugins")
    if isinstance(plugins, dict):
        load = plugins.get("load")
        if isinstance(load, dict):
            paths = load.get("paths")
            if isinstance(paths, list):
                load["paths"] = [
                    path
                    for path in paths
                    if not str(path).endswith(GUARD_PLUGIN_PATH_SUFFIX)
                ]
        entries = plugins.get("entries")
        if isinstance(entries, dict):
            entries.pop(GUARD_PLUGIN_ID, None)
            office_entry = entries.get(OFFICE_PLUGIN_ENTRY)
            if isinstance(office_entry, dict):
                office_config = office_entry.get("config")
                if isinstance(office_config, dict):
                    for key in OFFICE_PLUGIN_SCOPED_CONFIG_KEYS:
                        office_config.pop(key, None)
        allow = plugins.get("allow")
        if isinstance(allow, list):
            plugins["allow"] = [item for item in allow if item != GUARD_PLUGIN_ID]
        if plugins.get("enabled") is True:
            plugins.pop("enabled", None)

    return normalised


def native_projection_sha256(config: Mapping[str, Any]) -> str:
    """native 投影哈希：归一化配置的规范化 JSON sha256。"""

    return digest_json(normalise_native_config(config))


def assert_arm_equivalence(configs: Mapping[str, Mapping[str, Any]]) -> dict[str, str]:
    """校验五臂 OpenClaw 配置除被测组件外完全一致。

    返回 ``{arm: native_projection_sha256}``；若存在差异则抛
    :class:`ValueError` 并给出具体臂名与哈希。
    """

    missing = [name for name in ARM_NAMES if name not in configs]
    if missing:
        raise ValueError(f"缺少臂配置：{', '.join(missing)}")

    projections = {name: native_projection_sha256(configs[name]) for name in ARM_NAMES}
    distinct = set(projections.values())
    if len(distinct) != 1:
        detail = "，".join(f"{name}={value[:12]}" for name, value in projections.items())
        raise ValueError(f"五臂配置不等价（除被测组件外应完全一致）：{detail}")
    return projections


def component_matrix() -> dict[str, dict[str, bool]]:
    """返回 ``{arm: {component: enabled}}``，供 manifest 记录各臂开关集合。"""

    return {
        arm.name: {
            name: getattr(arm.components(), name) for name in COMPONENT_NAMES
        }
        for arm in ARMS
    }


def arms_manifest() -> dict[str, Any]:
    """各臂定义与组件哈希，供 bundle 的 ``arms.json`` 使用。"""

    return {
        "schema_version": 1,
        "arms": [
            {
                "name": arm.name,
                "description": arm.description,
                "loads_guard": arm.loads_guard,
                "disabled_components": list(arm.disabled_names()),
                "enabled_components": list(arm.components().enabled()),
                "component_config_hash": arm.config_hash(),
            }
            for arm in ARMS
        ],
        "component_matrix": component_matrix(),
    }


def arms_digest() -> str:
    """臂定义（含组件哈希）的稳定摘要。"""

    return digest_json(arms_manifest())


__all__ = [
    "ARM_NAMES",
    "ARMS",
    "ARM_INDEX",
    "GUARD_ARMS",
    "OFFICE_PLUGIN_ENTRY",
    "GUARD_PLUGIN_ID",
    "ArmSpec",
    "arm_spec",
    "normalise_native_config",
    "native_projection_sha256",
    "assert_arm_equivalence",
    "component_matrix",
    "arms_manifest",
    "arms_digest",
    "canonical_json",
]
