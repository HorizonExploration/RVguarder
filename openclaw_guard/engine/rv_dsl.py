from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field


Verdict = Literal["ok", "ask", "escalate", "block"]


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


class ChainRule(BaseModel):
    id: str
    from_state: str = Field(alias="from")
    to_state: str | None = Field(default=None, alias="to")
    when: StepRequirement = Field(default_factory=StepRequirement)
    verdict: Verdict | None = None


class MonitorSpec(BaseModel):
    name: str
    initial: str = "idle"
    rules: list[ChainRule] = Field(default_factory=list)


class Ruleset(BaseModel):
    version: int = 1
    monitors: list[MonitorSpec] = Field(default_factory=list)


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


def _matches_requirement(
    req: StepRequirement,
    *,
    props: set[str],
    event: str,
    window: Any,
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

    return True


def _sequence_matches(seq: SequenceRequirement, *, window: Any) -> bool:
    recent: list[dict[str, Any]] = getattr(window, "snapshot")()
    if seq.window_size and seq.window_size < len(recent):
        recent = recent[-seq.window_size :]

    idx = 0
    steps = seq.steps
    for step in recent:
        if idx >= len(steps):
            break
        props = set(step.get("props", []))
        event = str(step.get("event", "") or "")
        if _matches_requirement(steps[idx], props=props, event=event, window=window):
            idx += 1
    return idx == len(steps)


class _SpecDrivenMonitor:
    def __init__(self, spec: MonitorSpec) -> None:
        self._spec = spec
        self._state = spec.initial
        self._props_snapshot: set[str] = set()

    @property
    def current_state(self) -> str:
        return self._state

    def reset(self) -> None:
        self._state = self._spec.initial
        self._props_snapshot = set()

    def state_summary(self) -> dict[str, Any]:
        return {
            "state": self.current_state,
            "monitor": self._spec.name,
            "props_snapshot": sorted(self._props_snapshot),
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
            if _matches_requirement(rule.when, props=self._props_snapshot, event=event, window=window):
                if rule.to_state is not None:
                    self._state = rule.to_state

        best: Verdict | None = None
        for rule in self._spec.rules:
            if rule.verdict is None:
                continue
            if not self._state_matches(rule.from_state):
                continue
            if _matches_requirement(rule.when, props=self._props_snapshot, event=event, window=window):
                if rule.to_state is not None:
                    self._state = rule.to_state
                if best is None or _severity(rule.verdict) > _severity(best):
                    best = rule.verdict
        return best


def compile_monitors(ruleset: Ruleset) -> list[Any]:
    monitors: list[Any] = []
    for spec in ruleset.monitors:
        cls = type(spec.name, (_SpecDrivenMonitor,), {})
        monitors.append(cls(spec))
    return monitors
