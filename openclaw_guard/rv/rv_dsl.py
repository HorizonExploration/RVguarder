from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field


Verdict = Literal["ok", "ask", "escalate", "block"]


class EntityMatcher(BaseModel):
    """实体值匹配器：指定 entity kind 与匹配模式。

    match_type 支持:
    - "value_in": 实体值列表中至少一个在 values 中
    - "domain_in": 取值域名部分，至少一个匹配
    - "domain_not_in": 取值域名部分，没有任何一个在 values 中
    """
    kind: str
    match_type: str  # "value_in" | "domain_in" | "domain_not_in"
    values: list[str] = Field(default_factory=list)


class CountGteRequirement(BaseModel):
    label: str
    threshold: int = Field(ge=0)
    window_size: int | None = Field(default=None, ge=1)


class WindowAnyOfRequirement(BaseModel):
    labels: list[str] = Field(default_factory=list)
    window_size: int | None = Field(default=None, ge=1)


class SequenceRequirement(BaseModel):
    steps: list["StepRequirement"] = Field(default_factory=list)
    window_size: int | None = Field(default=None, ge=1)


class StepRequirement(BaseModel):
    event: str | None = None
    all_of: list[str] = Field(default_factory=list)
    any_of: list[str] = Field(default_factory=list)
    none_of: list[str] = Field(default_factory=list)
    count_gte: CountGteRequirement | None = None
    window_any_of: WindowAnyOfRequirement | None = None
    sequence: SequenceRequirement | None = None
    window_age_gt_seconds: int | None = Field(default=None, ge=1)
    # ── 阶段 D：参数化原语 ──
    entity_all_of: list[EntityMatcher] = Field(default_factory=list)
    entity_any_of: list[EntityMatcher] = Field(default_factory=list)
    step_gap_within_seconds: int | None = Field(default=None, ge=0)
    step_gap_at_least_seconds: int | None = Field(default=None, ge=0)
    state_counter: dict[str, dict[str, int]] = Field(default_factory=dict)


class ChainRule(BaseModel):
    id: str
    from_state: str = Field(alias="from")
    to_state: str | None = Field(default=None, alias="to")
    when: StepRequirement = Field(default_factory=StepRequirement)
    verdict: Verdict | None = None
    # ── 阶段 E：来源标记 ──
    origin: str | None = None       # "nl2spec" | "handwritten"
    source_nl: str | None = None    # 原始自然语言描述


class MonitorSpec(BaseModel):
    name: str
    initial: str = "idle"
    rules: list[ChainRule] = Field(default_factory=list)
    # ── 阶段 D：参数化原语 ──
    quantifier: Literal["forall", "exists"] | None = None
    bind_vars: list[str] = Field(default_factory=list)


class Ruleset(BaseModel):
    version: int = 1
    monitors: list[MonitorSpec] = Field(default_factory=list)
    # ── 阶段 E：来源标记 ──
    source_nl: str | None = None  # 全局自然语言策略描述


StepRequirement.model_rebuild()
SequenceRequirement.model_rebuild()
ChainRule.model_rebuild()
MonitorSpec.model_rebuild()
Ruleset.model_rebuild()


def _default_rules_path() -> Path:
    return Path(__file__).with_name("rv_rules.json")


def load_ruleset(path: str | Path | None = None) -> Ruleset:
    p = Path(path) if path is not None else _default_rules_path()
    raw = json.loads(p.read_text(encoding="utf-8"))
    return Ruleset.model_validate(raw)


def _severity(verdict: Verdict) -> int:
    return {"block": 4, "escalate": 3, "ask": 2, "ok": 1}.get(verdict, 0)


def _entity_values_match(values: list[str], match_type: str, target_values: list[str]) -> bool:
    """实体值匹配辅助函数（与 runtime_verification._entity_matches 同逻辑）。"""
    if not values:
        return False

    def _domain(v: str) -> str:
        return v.rsplit("@", 1)[-1].lower() if "@" in v else v.lower()

    if match_type == "value_in":
        targets = {v.lower() for v in target_values}
        return any(v.lower() in targets for v in values)
    if match_type == "domain_in":
        domains = {d.lower() for d in target_values}
        return any(_domain(v) in domains for v in values)
    if match_type == "domain_not_in":
        domains = {d.lower() for d in target_values}
        return not any(_domain(v) in domains for v in values)
    return False


def _matches_requirement(
    req: StepRequirement,
    *,
    props: set[str],
    event: str,
    window: Any,
    current_state: str | None = None,
    prev_step: dict[str, Any] | None = None,
    current_step: dict[str, Any] | None = None,
    state_counts: dict[str, int] | None = None,
) -> bool:
    if req.event:
        if not (event == req.event or req.event in props):
            return False

    if req.all_of and not set(req.all_of).issubset(props):
        return False

    if req.any_of and not (set(req.any_of) & props):
        return False

    if req.none_of and (set(req.none_of) & props):
        return False

    if req.count_gte:
        if getattr(window, "cumulative_count")(req.count_gte.label, window_size=req.count_gte.window_size) < req.count_gte.threshold:
            return False

    if req.window_any_of:
        if not getattr(window, "contains_any")(set(req.window_any_of.labels), window_size=req.window_any_of.window_size):
            return False

    if req.sequence:
        if not _sequence_matches(req.sequence, window=window):
            return False

    if req.window_age_gt_seconds is not None:
        age = getattr(window, "age_of_oldest")()
        if age is None or age <= float(req.window_age_gt_seconds):
            return False

    # ── 阶段 D：实体守卫 ──
    if req.entity_all_of or req.entity_any_of:
        entities = (current_step or {}).get("entities") or []
        entity_values: dict[str, list[str]] = {}
        for e in entities:
            if isinstance(e, dict):
                kind = e.get("kind", "")
                entity_values.setdefault(kind, []).extend(
                    str(v) for v in e.get("values", []) if v is not None
                )

        for m in req.entity_all_of:
            vals = entity_values.get(m.kind, [])
            if not _entity_values_match(vals, m.match_type, m.values):
                return False

        for m in req.entity_any_of:
            vals = entity_values.get(m.kind, [])
            if _entity_values_match(vals, m.match_type, m.values):
                break
        else:
            if req.entity_any_of:
                return False

    # ── 阶段 D：时间间隔 ──
    if req.step_gap_within_seconds is not None:
        gap = getattr(window, "step_gap")(prev_step, current_step) if prev_step and current_step else None
        if gap is None or gap > float(req.step_gap_within_seconds):
            return False

    if req.step_gap_at_least_seconds is not None:
        gap = getattr(window, "step_gap")(prev_step, current_step) if prev_step and current_step else None
        if gap is not None and gap < float(req.step_gap_at_least_seconds):
            return False

    # ── 阶段 D：状态计数器 ──
    if req.state_counter:
        counts = state_counts or {}
        for state_name, op_dict in req.state_counter.items():
            actual = counts.get(state_name, 0)
            if "lt" in op_dict and actual >= op_dict["lt"]:
                return False
            if "lte" in op_dict and actual > op_dict["lte"]:
                return False
            if "gt" in op_dict and actual <= op_dict["gt"]:
                return False
            if "gte" in op_dict and actual < op_dict["gte"]:
                return False

    return True


def _sequence_matches(seq: SequenceRequirement, *, window: Any) -> bool:
    recent: list[dict[str, Any]] = getattr(window, "snapshot")()
    if seq.window_size and seq.window_size < len(recent):
        recent = recent[-seq.window_size :]

    idx = 0
    steps = seq.steps
    prev_step: dict[str, Any] | None = None
    for step in recent:
        if idx >= len(steps):
            break
        props = set(step.get("props", []))
        event = str(step.get("event", "") or "")
        if _matches_requirement(
            steps[idx], props=props, event=event, window=window,
            prev_step=prev_step, current_step=step,
        ):
            prev_step = step
            idx += 1
    return idx == len(steps)


class _SpecDrivenMonitor:
    def __init__(self, spec: MonitorSpec) -> None:
        self._spec = spec
        self._state = spec.initial
        self._props_snapshot: set[str] = set()
        self._state_counts: dict[str, int] = {}
        self._prev_step: dict[str, Any] | None = None

    @property
    def current_state(self) -> str:
        return self._state

    def reset(self) -> None:
        self._state = self._spec.initial
        self._props_snapshot = set()
        self._state_counts = {}

    def state_summary(self) -> dict[str, Any]:
        return {
            "state": self.current_state,
            "monitor": self._spec.name,
            "props_snapshot": sorted(self._props_snapshot),
            "state_counts": dict(self._state_counts),
        }

    def _state_matches(self, from_state: str) -> bool:
        return from_state == "*" or from_state == self._state

    def feed(self, step: dict[str, Any], window: Any) -> str | None:
        self._props_snapshot = set(step.get("props", []))
        event = str(step.get("event", "") or "")

        for rule in self._spec.rules:
            if rule.verdict is not None:
                continue
            if not self._state_matches(rule.from_state):
                continue
            if _matches_requirement(
                rule.when, props=self._props_snapshot, event=event, window=window,
                current_state=self._state, prev_step=self._prev_step,
                current_step=step, state_counts=self._state_counts,
            ):
                if rule.to_state is not None:
                    self._state = rule.to_state
                    # 更新状态计数器（仅限非终端状态）
                    if rule.to_state not in ("blocked", "escalated"):
                        self._state_counts[rule.to_state] = self._state_counts.get(rule.to_state, 0) + 1

        best: Verdict | None = None
        for rule in self._spec.rules:
            if rule.verdict is None:
                continue
            if not self._state_matches(rule.from_state):
                continue
            if _matches_requirement(
                rule.when, props=self._props_snapshot, event=event, window=window,
                current_state=self._state, prev_step=self._prev_step,
                current_step=step, state_counts=self._state_counts,
            ):
                if rule.to_state is not None:
                    self._state = rule.to_state
                    if rule.to_state not in ("blocked", "escalated"):
                        self._state_counts[rule.to_state] = self._state_counts.get(rule.to_state, 0) + 1
                if best is None or _severity(rule.verdict) > _severity(best):
                    best = rule.verdict

        self._prev_step = step
        return best


def compile_monitors(ruleset: Ruleset) -> list[Any]:
    monitors: list[Any] = []
    for spec in ruleset.monitors:
        if spec.bind_vars and spec.quantifier:
            # 参数化监视器：按 bind_vars 动态切片
            cls = type(spec.name, (_ParameterizedMonitor,), {})
            monitors.append(cls(spec))
        else:
            cls = type(spec.name, (_SpecDrivenMonitor,), {})
            monitors.append(cls(spec))
    return monitors


class _ParameterizedMonitor:
    """按 bind_vars 值切片的参数化监视器。

    在首次 feed 时从步骤实体中提取 bind_vars 值，创建独立的子监视器实例。
    后续每个步骤按实体值路由到对应子监视器。

    quantifier 控制判定语义：
    - "forall": 任一子监视器触发 → 整体触发（所有绑定都要安全）
    - "exists": 所有子监视器至少一个触发 → 整体才触发
    """

    def __init__(self, spec: MonitorSpec) -> None:
        self._spec = spec
        self._children: dict[tuple, _SpecDrivenMonitor] = {}
        self._initialized = False
        self._child_class = type(f"{spec.name}Child", (_SpecDrivenMonitor,), {})

    @property
    def current_state(self) -> str:
        if not self._children:
            return self._spec.initial
        return ",".join(m.current_state for m in self._children.values())

    def reset(self) -> None:
        for child in self._children.values():
            child.reset()

    def state_summary(self) -> dict[str, Any]:
        return {
            "state": self.current_state,
            "monitor": self._spec.name,
            "quantifier": self._spec.quantifier,
            "bind_vars": self._spec.bind_vars,
            "child_count": len(self._children),
        }

    def feed(self, step: dict[str, Any], window: Any) -> str | None:
        if not self._spec.bind_vars:
            return None

        # 提取绑定值
        bind_values = self._extract_bind_values(step)
        if not bind_values:
            return None

        # 首次遇到新绑定 → 创建子监视器
        bind_key = tuple(bind_values)
        if bind_key not in self._children:
            self._children[bind_key] = self._child_class(self._spec)
            self._initialized = True

        child = self._children[bind_key]
        child_verdict = child.feed(step, window)

        if self._spec.quantifier == "forall":
            # forall: 任一子监视器触发 → 整体触发
            # 仅当前子监视器的判定
            if child_verdict:
                return child_verdict
            return None
        else:
            # exists: 存在任一触发 → 触发
            return child_verdict

    def _extract_bind_values(self, step: dict[str, Any]) -> list[str]:
        """从步骤实体中提取 bind_vars 对应的值列表。"""
        entities = step.get("entities") or []
        values: list[str] = []
        for var in self._spec.bind_vars:
            found = False
            for e in entities:
                if isinstance(e, dict) and e.get("kind") == var:
                    vals = e.get("values", [])
                    if vals:
                        values.append(str(vals[0]))
                        found = True
                        break
            if not found:
                return []  # 缺失绑定变量，跳过
        return values
