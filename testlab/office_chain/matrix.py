"""冻结的办公链式攻击场景矩阵与契约校验（schema_version=1）。

沿用 v3 ``testlab/office_value/runner.py`` 的校验风格：事件必须携带
``hook_payload`` / ``effect`` / ``oracle``，依赖只能引用更早出现的事件。
本模块额外固化 attack/benign 配对与"历史不可观测性"约束。
"""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any

from .artifacts import canonical_json, digest_json


SCHEMA_VERSION = 1
SUITE_ID = "office-attack-chain-v1"

FAMILIES = (
    "DSH-2026-853",
    "PRAISON-2026-55532",
    "MCP-SHELL-2026-55580",
    "ECHOLEAK-CVE-2025-32711",
    "SK-RCE-CVE-2026-26030",
    "SESSION-SMUGGLING-UNIT42",
)
EXPECTED_SCENARIOS_PER_FAMILY = 8
EXPECTED_SCENARIOS_PER_FAMILY_PER_SPLIT = 4  # 2 attack + 2 benign
EXPECTED_TOTAL_SCENARIOS = 48
EXPECTED_VARIANTS_PER_FAMILY_PER_SPLIT = {"attack": 2, "benign": 2}

SOURCE_KINDS = ("verified", "research_lead")
SPLITS = ("calibration", "holdout")
VARIANTS = ("attack", "benign")

_REQUIRED_INCIDENT_FIELDS = frozenset({
    "incident_id", "family", "title", "source_kind", "source_urls",
    "public_fact", "mapping_assumption", "office_migration",
    "precondition", "observable_chain",
})
_REQUIRED_SCENARIO_FIELDS = frozenset({
    "scenario_id", "family", "incident_id", "split", "variant", "paired_with",
    "workflow", "business_task", "work_rules", "user_authorization",
    "expected_user_goal", "attack_goal", "events", "oracle",
})
_REQUIRED_EVENT_FIELDS = frozenset({"hook_payload", "effect", "oracle"})
_REQUIRED_HOOK_FIELDS = frozenset({"toolName", "params", "sessionId", "agentId"})


def load_matrix(path: str | Path | None = None) -> dict[str, Any]:
    """Load and validate the frozen office-attack-chain matrix.

    Defaults to ``scenarios.json`` beside this module.  Raises ``ValueError``
    with a Chinese explanation when the file is missing, malformed or violates
    the frozen contract.
    """
    matrix_path = Path(path) if path is not None else Path(__file__).with_name("scenarios.json")
    try:
        payload = json.loads(matrix_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"无法加载办公链式攻击实验矩阵：{matrix_path}: {exc}") from exc
    validate_matrix(payload)
    return deepcopy(payload)


def validate_matrix(payload: dict[str, Any]) -> None:
    """Validate every frozen contract of the office-attack-chain matrix."""
    if not isinstance(payload, dict):
        raise ValueError("场景矩阵必须是 JSON 对象")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"场景矩阵 schema_version 必须为 {SCHEMA_VERSION}，实际 {payload.get('schema_version')!r}"
        )
    incidents = payload.get("incidents")
    scenarios = payload.get("scenarios")
    if not isinstance(incidents, list):
        raise ValueError("场景矩阵必须包含 incidents 数组")
    if not isinstance(scenarios, list):
        raise ValueError("场景矩阵必须包含 scenarios 数组")

    incident_families = _validate_incidents(incidents)
    index = _validate_scenarios(scenarios, incident_families)
    _validate_pairing(scenarios, index)
    _validate_history_equivalence(scenarios, index)
    _validate_scale(scenarios)


def scenario_index(matrix: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return a ``scenario_id -> scenario`` mapping."""
    scenarios = matrix.get("scenarios") if isinstance(matrix, dict) else None
    if not isinstance(scenarios, list):
        return {}
    return {
        str(scenario["scenario_id"]): scenario
        for scenario in scenarios
        if isinstance(scenario, dict) and scenario.get("scenario_id")
    }


def iter_pairs(matrix: dict[str, Any]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Return ``(attack, benign)`` pairs in matrix order."""
    index = scenario_index(matrix)
    scenarios = matrix.get("scenarios") if isinstance(matrix, dict) else None
    if not isinstance(scenarios, list):
        return []
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for scenario in scenarios:
        if not isinstance(scenario, dict) or scenario.get("variant") != "attack":
            continue
        partner = index.get(scenario.get("paired_with"))
        if partner is not None and partner.get("variant") == "benign":
            pairs.append((scenario, partner))
    return pairs


def matrix_digest(matrix: dict[str, Any]) -> str:
    """Return the sha256 hex of the canonical matrix JSON."""
    return digest_json(matrix)


def _validate_incidents(incidents: list[Any]) -> dict[str, str]:
    families_by_id: dict[str, str] = {}
    for index, incident in enumerate(incidents):
        if not isinstance(incident, dict) or _REQUIRED_INCIDENT_FIELDS - incident.keys():
            missing = sorted(_REQUIRED_INCIDENT_FIELDS - incident.keys()) if isinstance(incident, dict) else "全部"
            raise ValueError(f"incident[{index}] 字段不完整：{missing}")
        incident_id = str(incident["incident_id"])
        if not incident_id or incident_id in families_by_id:
            raise ValueError(f"incident ID 无效或重复：{incident_id!r}")
        family = incident["family"]
        if family not in FAMILIES:
            raise ValueError(f"incident {incident_id} 的 family 未知：{family!r}")
        if incident["source_kind"] not in SOURCE_KINDS:
            raise ValueError(f"incident {incident_id} 的 source_kind 无效：{incident['source_kind']!r}")
        if not incident["source_urls"] or not incident["public_fact"]:
            raise ValueError(f"incident {incident_id} 缺少来源事实")
        families_by_id[incident_id] = family
    return families_by_id


def _validate_scenarios(scenarios: list[Any], incident_families: dict[str, str]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for position, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict):
            raise ValueError(f"scenario[{position}] 必须是对象")
        missing = _REQUIRED_SCENARIO_FIELDS - scenario.keys()
        if missing:
            raise ValueError(f"scenario[{position}] 缺少字段：{sorted(missing)}")
        scenario_id = str(scenario["scenario_id"])
        if not scenario_id or scenario_id in index:
            raise ValueError(f"场景 ID 无效或重复：{scenario_id!r}")
        family = scenario["family"]
        if family not in FAMILIES:
            raise ValueError(f"场景 {scenario_id} 的 family 未知：{family!r}")
        incident_id = str(scenario["incident_id"])
        if incident_id not in incident_families:
            raise ValueError(f"场景 {scenario_id} 引用了未知 incident：{incident_id!r}")
        if incident_families[incident_id] != family:
            raise ValueError(f"场景 {scenario_id} 的 incident {incident_id} 与 family {family} 不一致")
        if scenario["split"] not in SPLITS:
            raise ValueError(f"场景 {scenario_id} 的 split 无效：{scenario['split']!r}")
        if scenario["variant"] not in VARIANTS:
            raise ValueError(f"场景 {scenario_id} 的 variant 无效：{scenario['variant']!r}")
        work_rules = scenario["work_rules"]
        if not isinstance(work_rules, list) or not work_rules:
            raise ValueError(f"场景 {scenario_id} 的 work_rules 必须是非空数组")
        _event_ids(scenario, scenario_id)
        _validate_goal_observations(scenario, scenario_id)
        index[scenario_id] = scenario
    return index


#: 每个 attack_goal 赖以观测的 effect 种类。声明了目标就必须声明对应观测：判定器在取不到
#: 观测目标时只能静默判为"未达成"，而那是**对防护有利**的方向——会让每个臂都白算一次
#: "防护成功"，把基线与实验组同时抬高。
_GOAL_OBSERVATION_KINDS: dict[str, str] = {
    "sensitive_file_deleted": "delete",
    "permission_expanded": "permission_change",
}


def _validate_goal_observations(scenario: dict[str, Any], scenario_id: str) -> None:
    """校验声明的 attack_goal 有可观测的 effect 支撑，避免判定器静默倒向防护。"""

    kind = _GOAL_OBSERVATION_KINDS.get(str(scenario.get("attack_goal")))
    if kind is None:
        return
    observed = [
        event
        for event in scenario.get("events") or []
        if isinstance(event.get("effect"), dict)
        and event["effect"].get("kind") == kind
        and event["effect"].get("path")
    ]
    if not observed:
        raise ValueError(
            f"场景 {scenario_id} 声明了 attack_goal={scenario['attack_goal']!r}，"
            f"但没有任何 effect.kind={kind!r} 且带 path 的事件可供观测"
        )


def _event_ids(scenario: dict[str, Any], scenario_id: str) -> list[str]:
    """Validate one scenario's events and return stable replay-local event IDs."""
    events = scenario.get("events")
    if not isinstance(events, list) or not events:
        raise ValueError(f"场景 {scenario_id} 必须至少有一个事件")
    identifiers: list[str] = []
    seen: set[str] = set()
    for event_index, event in enumerate(events, 1):
        if not isinstance(event, dict) or _REQUIRED_EVENT_FIELDS - event.keys():
            missing = sorted(_REQUIRED_EVENT_FIELDS - event.keys()) if isinstance(event, dict) else "全部"
            raise ValueError(f"场景 {scenario_id} 事件[{event_index}] 字段不完整：{missing}")
        hook = event["hook_payload"]
        if not isinstance(hook, dict) or _REQUIRED_HOOK_FIELDS - hook.keys():
            raise ValueError(f"场景 {scenario_id} 事件[{event_index}] hook_payload 不完整")
        if not isinstance(hook["params"], dict):
            raise ValueError(f"场景 {scenario_id} 事件[{event_index}] hook_payload.params 必须是对象")
        if not isinstance(event["effect"], dict) or not isinstance(event["oracle"], dict):
            raise ValueError(f"场景 {scenario_id} 事件[{event_index}] effect/oracle 类型无效")
        raw_id = event.get("event_id")
        event_id = f"step-{event_index}" if raw_id is None else raw_id
        if not isinstance(event_id, str) or not event_id.strip() or event_id in seen:
            raise ValueError(f"场景 {scenario_id} event_id 无效或重复：{event_id!r}")
        dependencies = event.get("depends_on", [])
        if not isinstance(dependencies, list) or any(
            not isinstance(item, str) or item not in seen for item in dependencies
        ):
            raise ValueError(f"场景 {scenario_id} depends_on 必须引用更早的事件：{dependencies!r}")
        identifiers.append(event_id)
        seen.add(event_id)
    return identifiers


def _validate_pairing(scenarios: list[Any], index: dict[str, dict[str, Any]]) -> None:
    for scenario in scenarios:
        scenario_id = str(scenario["scenario_id"])
        variant = scenario["variant"]
        partner_id = scenario.get("paired_with")
        if not isinstance(partner_id, str) or not partner_id.strip():
            raise ValueError(f"场景 {scenario_id} 的 paired_with 必须指向配对场景")
        partner = index.get(partner_id)
        if partner is None:
            raise ValueError(f"场景 {scenario_id} 的 paired_with 引用了不存在的场景：{partner_id!r}")
        expected_variant = "benign" if variant == "attack" else "attack"
        if partner.get("variant") != expected_variant:
            raise ValueError(f"场景 {scenario_id} 的配对 {partner_id} 必须为 {expected_variant} 场景")
        if partner.get("family") != scenario["family"]:
            raise ValueError(f"场景 {scenario_id} 与配对 {partner_id} 的事件族不一致")
        if partner.get("split") != scenario["split"]:
            raise ValueError(f"场景 {scenario_id} 与配对 {partner_id} 的 split 不一致")
        if partner.get("paired_with") != scenario_id:
            raise ValueError(f"配对 {partner_id} 未通过 paired_with 指回 {scenario_id}")


def _validate_history_equivalence(scenarios: list[Any], index: dict[str, dict[str, Any]]) -> None:
    """The last step of each pair must be indistinguishable in the Hook projection."""
    for scenario in scenarios:
        if scenario["variant"] != "attack":
            continue
        scenario_id = str(scenario["scenario_id"])
        partner = index[str(scenario["paired_with"])]
        attack_hook = _final_hook_projection(scenario)
        benign_hook = _final_hook_projection(partner)
        if attack_hook != benign_hook:
            raise ValueError(
                f"配对 {scenario_id}/{partner['scenario_id']} 的最后一步 Hook 投影不一致，"
                "历史不可观测性被破坏"
            )


def _final_hook_projection(scenario: dict[str, Any]) -> str:
    events = scenario.get("events")
    if not isinstance(events, list) or not events:
        raise ValueError(f"场景 {scenario.get('scenario_id')} 缺少可比较的最终事件")
    hook = events[-1].get("hook_payload")
    if not isinstance(hook, dict):
        raise ValueError(f"场景 {scenario.get('scenario_id')} 的最终事件缺少 hook_payload")
    return canonical_json({
        "toolName": hook.get("toolName"),
        "params": hook.get("params"),
        "sessionId": hook.get("sessionId"),
        "agentId": hook.get("agentId"),
    })


def _validate_scale(scenarios: list[Any]) -> None:
    total = len(scenarios)
    if total != EXPECTED_TOTAL_SCENARIOS:
        raise ValueError(f"场景总数必须为 {EXPECTED_TOTAL_SCENARIOS}，实际 {total}")
    counts: dict[str, int] = {family: 0 for family in FAMILIES}
    split_counts: dict[str, dict[str, int]] = {family: {split: 0 for split in SPLITS} for family in FAMILIES}
    variant_counts: dict[tuple[str, str, str], int] = {}
    for scenario in scenarios:
        family = scenario["family"]
        split = scenario["split"]
        counts[family] += 1
        split_counts[family][split] += 1
        variant_counts[(family, split, scenario["variant"])] = (
            variant_counts.get((family, split, scenario["variant"]), 0) + 1
        )
    for family in FAMILIES:
        if counts[family] != EXPECTED_SCENARIOS_PER_FAMILY:
            raise ValueError(f"事件族 {family} 场景数必须为 {EXPECTED_SCENARIOS_PER_FAMILY}，实际 {counts[family]}")
        for split in SPLITS:
            actual = split_counts[family][split]
            if actual != EXPECTED_SCENARIOS_PER_FAMILY_PER_SPLIT:
                raise ValueError(
                    f"事件族 {family} 在 {split} 的场景数必须为 "
                    f"{EXPECTED_SCENARIOS_PER_FAMILY_PER_SPLIT}，实际 {actual}"
                )
            for variant, expected in EXPECTED_VARIANTS_PER_FAMILY_PER_SPLIT.items():
                observed = variant_counts.get((family, split, variant), 0)
                if observed != expected:
                    raise ValueError(
                        f"事件族 {family} 在 {split} 的 {variant} 场景数必须为 {expected}，实际 {observed}"
                    )
