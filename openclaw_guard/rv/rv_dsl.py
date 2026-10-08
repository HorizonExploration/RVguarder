from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


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


class PolicyGuard(BaseModel):
    """Guard over normalized PMKB evidence attached to one RV step.

    The policy evaluator remains the authority for matching and permission
    closure.  This guard lets generated monitors consume its typed evidence
    without reimplementing the evaluator in the RV DSL.
    """

    rule_ids_any_of: list[str] = Field(default_factory=list)
    combo_violations_any_of: list[str] = Field(default_factory=list)
    effects_any_of: list[str] = Field(default_factory=list)
    match_statuses: list[str] = Field(default_factory=list)
    operation_families: list[str] = Field(default_factory=list)
    permission_families_any_of: list[str] = Field(default_factory=list)
    min_risk_score: int | None = Field(default=None, ge=0, le=100)


class ToolGuard(BaseModel):
    """约束真实调用的模型版本、操作族与有限效果。"""
    model_config = ConfigDict(extra="forbid")
    event_model: Literal["tool-call-v1"] = "tool-call-v1"
    names: list[str] = Field(default_factory=list)
    excluded_names: list[str] = Field(default_factory=list)
    operation_families: list[str] = Field(default_factory=list)
    effects_any_of: list[str] = Field(default_factory=list)
    execution_states: list[Literal["proposed", "succeeded", "legacy_replay"]] = Field(default_factory=list)


class StepRequirement(BaseModel):
    tool: ToolGuard | None = None
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
    policy: PolicyGuard | None = None


class ChainRule(BaseModel):
    id: str
    from_state: str = Field(alias="from")
    to_state: str | None = Field(default=None, alias="to")
    when: StepRequirement = Field(default_factory=StepRequirement)
    verdict: Verdict | None = None
    # ── 阶段 E：来源标记 ──
    origin: str | None = None       # "nl2spec" | "handwritten"
    source_nl: str | None = None    # 原始自然语言描述
    unless_authorized: "ExactAuthorizationGuard | None" = None
    verified_history: Literal["same_task_sensitive_bytes", "same_task_sensitive_access"] | None = None

    @model_validator(mode="after")
    def validate_authorization_exception(self) -> "ChainRule":
        """授权例外仅限定明确的终端egress block，不修改状态迁移或其他规则。"""
        if self.unless_authorized is not None and self.verdict != "block":
            raise ValueError("authorization exceptions require a block verdict rule")
        if self.unless_authorized is not None and self.to_state is not None:
            raise ValueError("authorization exceptions cannot rewrite monitor state")
        if self.verified_history is not None and (self.verdict != "block" or self.to_state is not None):
            raise ValueError("verified history guards require terminal block rules")
        return self


class ExactAuthorizationGuard(BaseModel):
    """限定逐规则授权例外的具体工具与操作族，不能以通配规则关闭RV。"""

    model_config = ConfigDict(extra="forbid", strict=True)
    tool_name: Literal["office_message_send", "office_network_post", "office_document_share"]
    operation_family: Literal["message.send", "network.egress"]

    @model_validator(mode="after")
    def validate_registered_contract(self) -> "ExactAuthorizationGuard":
        """具体工具必须符合已登记的有限操作族。"""
        from openclaw_guard.spec.execution_proposals import OFFICE_OPERATIONS
        if OFFICE_OPERATIONS[self.tool_name] != self.operation_family:
            raise ValueError("authorization guard operation mismatch")
        return self


class MonitorSpec(BaseModel):
    name: str
    initial: str = "idle"
    rules: list[ChainRule] = Field(default_factory=list)
    # ── 阶段 D：参数化原语 ──
    quantifier: Literal["forall", "exists"] | None = None
    bind_vars: list[str] = Field(default_factory=list)
    scope: Literal["session", "principal"] = "session"
    source: str = "handwritten"
    source_ids: list[str] = Field(default_factory=list)


class Ruleset(BaseModel):
    event_model: Literal["legacy", "tool-call-v1"] = "legacy"
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
    if path is None:
        from openclaw_guard.rv.native_contract_rules import native_request_monitor
        raw['monitors'].append(native_request_monitor())
    from openclaw_guard.rv.tool_events import migrate_rules_document
    return Ruleset.model_validate(migrate_rules_document(raw))


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
    if req.tool:
        step = current_step or {}
        if step.get("event_model") != req.tool.event_model:
            return False
        if req.tool.names and step.get("tool_name") not in req.tool.names:
            return False
        if step.get("tool_name") in req.tool.excluded_names:
            return False
        if req.tool.operation_families and step.get("operation_family") not in req.tool.operation_families:
            return False
        if req.tool.effects_any_of and not set(req.tool.effects_any_of).intersection(step.get("effects", [])):
            return False
        if req.tool.execution_states and step.get("execution_state") not in req.tool.execution_states:
            return False
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

    if req.policy and not _policy_matches(req.policy, current_step or {}):
        return False

    return True


def _policy_matches(guard: PolicyGuard, step: dict[str, Any]) -> bool:
    """Match a PMKB-generated synthetic step against authoritative evidence."""
    policy = step.get("policy")
    if not isinstance(policy, dict):
        return False

    def _overlaps(expected: list[str], actual: Any) -> bool:
        actual_values = {str(item) for item in actual} if isinstance(actual, list) else {str(actual)}
        return bool({str(item) for item in expected} & actual_values)

    if guard.rule_ids_any_of and not _overlaps(
        guard.rule_ids_any_of, policy.get("selected_rule_ids", []),
    ):
        return False
    if guard.combo_violations_any_of and not _overlaps(
        guard.combo_violations_any_of, policy.get("combo_violations", []),
    ):
        return False
    if guard.effects_any_of and str(policy.get("effect", "")) not in guard.effects_any_of:
        return False
    if guard.match_statuses and str(policy.get("match_status", "")) not in guard.match_statuses:
        return False
    if guard.operation_families and str(policy.get("operation_family", "")) not in guard.operation_families:
        return False
    if guard.permission_families_any_of and not _overlaps(
        guard.permission_families_any_of, policy.get("p_after_families", []),
    ):
        return False
    if guard.min_risk_score is not None and int(policy.get("risk_score", 0) or 0) < guard.min_risk_score:
        return False
    return True


class _WindowPrefixView:
    """读取轨迹某一步为止的窗口视图，供嵌套 DSL 查询避免前视。"""

    def __init__(self, steps: list[dict[str, Any]]) -> None:
        self._steps = steps

    def snapshot(self) -> list[dict[str, Any]]:
        return list(self._steps)

    def cumulative_count(self, label: str, window_size: int | None = None) -> int:
        steps = self._steps[-window_size:] if window_size else self._steps
        return sum(label in set(step.get("props", [])) for step in steps)

    def contains_any(self, labels: set[str], window_size: int | None = None) -> bool:
        steps = self._steps[-window_size:] if window_size else self._steps
        return any(labels & set(step.get("props", [])) for step in steps)

    def age_of_oldest(self) -> float | None:
        if not self._steps:
            return None
        oldest_epoch = self._steps[0].get("_ts_epoch")
        if oldest_epoch is None:
            return None
        return time.time() - float(oldest_epoch)

    @staticmethod
    def step_gap(older_step: dict[str, Any] | None, newer_step: dict[str, Any] | None) -> float | None:
        if older_step is None or newer_step is None:
            return None
        older_epoch = older_step.get("_ts_epoch")
        newer_epoch = newer_step.get("_ts_epoch")
        if older_epoch is None or newer_epoch is None:
            return None
        return abs(float(newer_epoch) - float(older_epoch))


def _sequence_matched_steps(seq: SequenceRequirement, *, window: Any) -> list[dict[str, Any]] | None:
    recent: list[dict[str, Any]] = getattr(window, "snapshot")()
    if seq.window_size and seq.window_size < len(recent):
        recent = recent[-seq.window_size :]

    matched: list[dict[str, Any]] = []
    for index, step in enumerate(recent):
        if len(matched) >= len(seq.steps):
            break
        prefix = _WindowPrefixView(recent[: index + 1])
        props = set(step.get("props", []))
        event = str(step.get("event", "") or "")
        previous = matched[-1] if matched else None
        if _matches_requirement(
            seq.steps[len(matched)], props=props, event=event, window=prefix,
            prev_step=previous, current_step=step,
        ):
            matched.append(step)
    if len(matched) != len(seq.steps):
        return None
    return matched


def _sequence_match_step_ids(seq: SequenceRequirement, *, window: Any) -> list[str]:
    matched = _sequence_matched_steps(seq, window=window)
    if matched is None:
        return []
    return [str(step["step_id"]) for step in matched if step.get("step_id")]


def _sequence_matches(seq: SequenceRequirement, *, window: Any) -> bool:
    return _sequence_matched_steps(seq, window=window) is not None


def _requirement_history_step_ids(
    requirement: StepRequirement,
    *,
    window: Any,
    previous_step: dict[str, Any] | None,
) -> list[str]:
    """收集当前 DSL 谓词实际依赖的历史步骤 ID。"""
    matched: list[str] = []
    steps = getattr(window, "snapshot")()
    if requirement.window_any_of:
        recent = steps
        if requirement.window_any_of.window_size and requirement.window_any_of.window_size < len(recent):
            recent = recent[-requirement.window_any_of.window_size :]
        labels = set(requirement.window_any_of.labels)
        matched.extend(
            str(step["step_id"]) for step in recent
            if labels & set(step.get("props", [])) and step.get("step_id")
        )
    if requirement.count_gte:
        recent = steps
        if requirement.count_gte.window_size and requirement.count_gte.window_size < len(recent):
            recent = recent[-requirement.count_gte.window_size :]
        candidates = [step for step in recent if requirement.count_gte.label in set(step.get("props", []))]
        candidates = candidates[-requirement.count_gte.threshold :] if requirement.count_gte.threshold else []
        matched.extend(str(step["step_id"]) for step in candidates if step.get("step_id"))
    if requirement.sequence:
        matched.extend(_sequence_match_step_ids(requirement.sequence, window=window))
    if (requirement.step_gap_within_seconds is not None or requirement.step_gap_at_least_seconds is not None) and previous_step:
        previous_id = previous_step.get("step_id")
        if previous_id:
            matched.append(str(previous_id))
    if requirement.window_age_gt_seconds is not None and steps and steps[0].get("step_id"):
        matched.append(str(steps[0]["step_id"]))
    return list(dict.fromkeys(matched))


def _merge_step_ids(*groups: list[str]) -> list[str]:
    """按出现次序合并步骤 ID 并去重。"""
    return list(dict.fromkeys(step_id for group in groups for step_id in group if step_id))


class _SpecDrivenMonitor:
    def __init__(self, spec: MonitorSpec, authorization_checker: Callable | None = None, history_checker: Callable | None = None) -> None:
        self._spec = spec
        self._authorization_checker = authorization_checker
        self._history_checker = history_checker
        self._state = spec.initial
        self._props_snapshot: set[str] = set()
        self._state_counts: dict[str, int] = {}
        self._prev_step: dict[str, Any] | None = None
        self._state_step_ids: dict[str, list[str]] = {spec.initial: []}
        self.last_match: dict[str, Any] | None = None
        self.last_authorized_rules: list[str] = []
        self.last_authorized_matches: list[dict[str, str]] = []

    @property
    def current_state(self) -> str:
        return self._state

    def reset(self) -> None:
        self._state = self._spec.initial
        self._props_snapshot = set()
        self._state_counts = {}
        self._prev_step = None
        self._state_step_ids = {self._spec.initial: []}
        self.last_match = None
        self.last_authorized_rules = []
        self.last_authorized_matches = []

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
        self.last_match = None
        self.last_authorized_rules = []
        self.last_authorized_matches = []
        self._props_snapshot = set(step.get("props", []))
        event = str(step.get("event", "") or "")
        current_step_id = str(step.get("step_id") or "")

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
                    source_state = self._state
                    source_ids = self._state_step_ids.get(source_state, [])
                    requirement_ids = _requirement_history_step_ids(
                        rule.when, window=window, previous_step=self._prev_step,
                    )
                    transition_ids = _merge_step_ids(
                        source_ids, requirement_ids, [current_step_id],
                    )
                    self._state = rule.to_state
                    self._state_step_ids[rule.to_state] = transition_ids
                    # 更新状态计数器（仅限非终端状态）
                    if rule.to_state not in ("blocked", "escalated"):
                        self._state_counts[rule.to_state] = self._state_counts.get(rule.to_state, 0) + 1

        best: Verdict | None = None
        best_match: dict[str, Any] | None = None
        for rule in self._spec.rules:
            if rule.verdict is None:
                continue
            if not self._state_matches(rule.from_state):
                continue
            host_history = self._verified_history(rule, step)
            if rule.verified_history is not None and host_history is None:
                continue
            if _matches_requirement(
                rule.when, props=self._props_snapshot, event=event, window=window,
                current_state=self._state, prev_step=self._prev_step,
                current_step=step, state_counts=self._state_counts,
            ):
                if self._is_exactly_authorized(rule, step):
                    self.last_authorized_rules.append(rule.id)
                    continue
                state_ids = self._state_step_ids.get(self._state, [])
                requirement_ids = _requirement_history_step_ids(
                    rule.when, window=window, previous_step=self._prev_step,
                )
                history_ids = [step_id for step_id in _merge_step_ids(state_ids, requirement_ids,
                               list(host_history.history_step_ids) if host_history else [])
                               if step_id != current_step_id]
                if rule.to_state is not None:
                    self._state = rule.to_state
                    self._state_step_ids[rule.to_state] = _merge_step_ids(
                        history_ids, [current_step_id],
                    )
                    if rule.to_state not in ("blocked", "escalated"):
                        self._state_counts[rule.to_state] = self._state_counts.get(rule.to_state, 0) + 1
                if best is None or _severity(rule.verdict) > _severity(best):
                    candidate = {
                        "rule_id": rule.id,
                        "trigger_step_id": current_step_id or None,
                        "matched_history_step_ids": history_ids,
                        **({"verified_cross_session_receipt_ids": list(host_history.receipt_ids),
                            "verified_cross_session_link_ids": list(host_history.link_ids)} if host_history else {}),
                    }
                    if host_history is not None:
                        from openclaw_guard.engine.experiment_components import commit_if_current
                        accepted, committed = host_history.lease.commit_if_active(lambda: commit_if_current(
                            host_history.component_generation, "cross_session_rv", lambda: (rule.verdict, candidate)))
                        if not accepted or not committed[0]:
                            continue
                        best, best_match = committed[1]
                    else:
                        best, best_match = rule.verdict, candidate

        self._prev_step = step
        self.last_match = best_match
        return best

    def _verified_history(self, rule: ChainRule, step: dict[str, Any]) -> Any:
        """纯内存类型核验；缺证据只跳过此条规则，其他RV规则照常生效。"""
        if rule.verified_history is None or self._history_checker is None:
            return None
        from openclaw_guard.spec.history_facts import VerifiedCrossSessionHistory
        from openclaw_guard.spec.task_history import HostHistoryLease
        from openclaw_guard.engine.experiment_components import snapshot, commit_if_current
        import hashlib
        import time
        from openclaw_guard.spec.content_receipts import _canonical
        components, generation = snapshot()
        if not components.cross_session_rv:
            return None
        try:
            fact = self._history_checker(step, rule.id)
            if not isinstance(fact, VerifiedCrossSessionHistory) or fact.component_generation != generation or fact.expires_at_ms <= int(time.time() * 1000):
                return None
            if not isinstance(fact.lease, HostHistoryLease) or not fact.lease.is_active():
                return None
            if rule.verified_history == "same_task_sensitive_bytes" and fact.relationship != "exact_consumed_byte_identity":
                return None
            context, provenance = step.get("context") or {}, step.get("provenance") or {}
            expected = {"step_id": step.get("step_id"), "tool_name": step.get("tool_name"),
                        "operation_family": step.get("operation_family"), "principal_id": (context.get("principal") or {}).get("id"),
                        "agent_id": context.get("agent_id"), "session_id": context.get("session_id"), "run_id": provenance.get("run_id")}
            if not fact.history_step_ids or fact.step_id in fact.history_step_ids or any(getattr(fact, key) != value for key, value in expected.items()):
                return None
            if step.get("event_model") != "tool-call-v1" or step.get("effects") != ["egress"] or hashlib.sha256(_canonical(step.get("arguments") or {})).hexdigest() != fact.arguments_sha256:
                return None
            accepted, result = commit_if_current(generation, "cross_session_rv", lambda: fact)
            return result if accepted else None
        except Exception:
            return None

    def _is_exactly_authorized(self, rule: ChainRule, step: dict[str, Any]) -> bool:
        """无可信checker或范围不完整时保持原block，不读模型/参数中的授权声明。"""
        guard = rule.unless_authorized
        if guard is None or self._authorization_checker is None:
            return False
        from openclaw_guard.engine.experiment_components import snapshot, commit_if_current
        from openclaw_guard.spec.authorization_facts import VerifiedCallAuthorization
        from openclaw_guard.spec.content_receipts import _canonical, _freeze_bounded_json
        import hashlib
        components, generation = snapshot()
        if not components.authorization:
            return False
        if (step.get("event_model") != "tool-call-v1" or step.get("execution_state") not in {"proposed", "succeeded"}
                or step.get("effects") != ["egress"]
                or step.get("tool_name") != guard.tool_name or step.get("operation_family") != guard.operation_family):
            return False
        try:
            # checker只读有界副本，不能改写实际步骤影响其他监视器。
            captured = _freeze_bounded_json(step, 65536)
            fact = self._authorization_checker(captured, rule.id)
            if not isinstance(fact, VerifiedCallAuthorization) or fact.decision_eligible is not True:
                return False
            if fact.component_generation != generation:
                return False
            context, provenance = step.get("context") or {}, step.get("provenance") or {}
            expected = {"step_id": step.get("step_id"), "agent_id": context.get("agent_id"),
                "session_id": context.get("session_id") or "", "run_id": provenance.get("run_id"),
                "tool_call_id": provenance.get("tool_call_id"), "tool_name": step.get("tool_name"),
                "operation_family": step.get("operation_family"),
                "principal_id": (context.get("principal") or {}).get("id")}
            if any(getattr(fact, key) != value for key, value in expected.items()):
                return False
            now = int(time.time() * 1000)
            if (not fact.source.full_resource or not fact.valid_from_ms <= now < fact.expires_at_ms
                    or not 0 < fact.expires_at_ms - fact.valid_from_ms <= 300000):
                return False
            arguments = _freeze_bounded_json(step.get("arguments"), 65536)
            if not isinstance(arguments, dict):
                return False
            destination = arguments.get("url" if guard.tool_name == "office_network_post" else "recipient")
            if not isinstance(destination, str) or fact.recipient != destination.strip():
                return False
            reference = arguments.get("sourcePath")
            if reference is None and guard.tool_name == "office_document_share":
                reference = arguments.get("document")
            # 非规范引用不会扩大授权；实际规范化需由受控执行器提供。
            if reference is not None and fact.source.resource_id != f"{fact.source.namespace}:{reference}":
                return False
            matches = hashlib.sha256(_canonical(arguments)).hexdigest() == fact.arguments_sha256
            accepted, _ = commit_if_current(generation, "authorization", lambda: None)
            if matches and accepted:
                self.last_authorized_matches.append({"rule_id": rule.id, "step_id": fact.step_id,
                    "grant_id": fact.grant_id, "snapshot_id": fact.snapshot_id, "task_id": fact.task_id})
                return True
            return False
        except Exception:
            return False


def compile_monitors(ruleset: Ruleset, *, authorization_checker: Callable | None = None, history_checker: Callable | None = None) -> list[Any]:
    monitors: list[Any] = []
    for spec in ruleset.monitors:
        if spec.bind_vars and spec.quantifier:
            # 参数化监视器：按 bind_vars 动态切片
            cls = type(spec.name, (_ParameterizedMonitor,), {})
            monitors.append(cls(spec, authorization_checker=authorization_checker, history_checker=history_checker))
        else:
            cls = type(spec.name, (_SpecDrivenMonitor,), {})
            monitors.append(cls(spec, authorization_checker=authorization_checker, history_checker=history_checker))
    return monitors


class _ParameterizedMonitor:
    """按 bind_vars 值切片的参数化监视器。

    在首次 feed 时从步骤实体中提取 bind_vars 值，创建独立的子监视器实例。
    后续每个步骤按实体值路由到对应子监视器。

    quantifier 控制判定语义：
    - "forall": 任一子监视器触发 → 整体触发（所有绑定都要安全）
    - "exists": 所有子监视器至少一个触发 → 整体才触发
    """

    def __init__(self, spec: MonitorSpec, authorization_checker: Callable | None = None, history_checker: Callable | None = None) -> None:
        self._spec = spec
        self._authorization_checker = authorization_checker
        self._history_checker = history_checker
        self._children: dict[tuple, _SpecDrivenMonitor] = {}
        self._initialized = False
        self._child_class = type(f"{spec.name}Child", (_SpecDrivenMonitor,), {})
        self.last_match: dict[str, Any] | None = None
        self.last_authorized_matches: list[dict[str, str]] = []

    @property
    def current_state(self) -> str:
        if not self._children:
            return self._spec.initial
        return ",".join(m.current_state for m in self._children.values())

    def reset(self) -> None:
        for child in self._children.values():
            child.reset()
        self.last_match = None
        self.last_authorized_matches = []

    def state_summary(self) -> dict[str, Any]:
        return {
            "state": self.current_state,
            "monitor": self._spec.name,
            "quantifier": self._spec.quantifier,
            "bind_vars": self._spec.bind_vars,
            "child_count": len(self._children),
        }

    def feed(self, step: dict[str, Any], window: Any) -> str | None:
        self.last_match = None
        self.last_authorized_matches = []
        if not self._spec.bind_vars:
            return None

        # 提取绑定值
        bind_values = self._extract_bind_values(step)
        if not bind_values:
            return None

        # 首次遇到新绑定 → 创建子监视器
        bind_key = tuple(bind_values)
        if bind_key not in self._children:
            self._children[bind_key] = self._child_class(self._spec, authorization_checker=self._authorization_checker, history_checker=self._history_checker)
            self._initialized = True

        child = self._children[bind_key]
        binding_history = [
            historical_step for historical_step in getattr(window, "snapshot")()
            if tuple(self._extract_bind_values(historical_step)) == bind_key
        ]
        child_window = _WindowPrefixView(binding_history)
        child_verdict = child.feed(step, child_window)
        self.last_authorized_matches = list(child.last_authorized_matches)
        if child_verdict:
            self.last_match = child.last_match

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
