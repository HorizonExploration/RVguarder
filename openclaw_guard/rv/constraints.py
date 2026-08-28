"""
约束推理引擎 —— 阶段 B。

基于 IR 结构化中间表示（ToolCallIR）的规则匹配引擎，替代纯标签布尔交集。
支持动作/标签/实体/敏感度/时序五类约束，加权评分并支持语义置信度门控。

设计原则：
- 消费阶段 A 产出的 ToolCallIR，利用 entities/constraints/confidence 结构化字段
- 与现有标签系统并行：TagConstraint 兼容原有 props 匹配，EntityConstraint 启用实体级规则
- 渐进迁移：已迁移规则行为与旧 lambda 规则一致；未迁移规则继续走原检测路径
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from openclaw_guard.rv.ir import ToolCallIR


# =============================================================================
# 约束类型
# =============================================================================


class ActionConstraint(BaseModel):
    """动作类型约束：步骤的 event 字段必须在允许列表中。

    Example:
        ActionConstraint(action_types=["command_exec", "network_egress"])
    """

    action_types: list[str]


class TagConstraint(BaseModel):
    """标签约束：检查步骤 props 中的语义标签。

    支持两种模式：
    - require_all: 标签必须全部存在（AND）
    - require_any: 至少一个标签存在（OR）

    Example:
        TagConstraint(require_all=["network_egress"], require_any=["network_http", "network_public_ip"])
    """

    require_all: list[str] = Field(default_factory=list)
    require_any: list[str] = Field(default_factory=list)


class EntityConstraint(BaseModel):
    """实体级约束：检查步骤 entities 中指定 kind 的值是否满足匹配条件。

    支持三种 match_type：
    - "value_in": 实体值中至少有一个在 values 列表中
    - "domain_in": 取值的域名部分，至少一个在列表中
    - "domain_not_in": 取值的域名部分，没有任何一个在列表中

    Example:
        EntityConstraint(kind="recipients", match_type="domain_not_in",
                        values=["internal.com"])
    """

    kind: str
    match_type: str  # "value_in" | "domain_in" | "domain_not_in"
    values: list[str] = Field(default_factory=list)

    def _extract_domain(self, value: str) -> str:
        return value.rsplit("@", 1)[-1].lower() if "@" in value else value.lower()

    def matches(self, entity_values: list[str]) -> bool:
        if not entity_values:
            return False
        if self.match_type == "value_in":
            targets = {v.lower() for v in self.values}
            return any(v.lower() in targets for v in entity_values)
        if self.match_type == "domain_in":
            domains = {d.lower() for d in self.values}
            return any(self._extract_domain(v) in domains for v in entity_values)
        if self.match_type == "domain_not_in":
            domains = {d.lower() for d in self.values}
            return not any(self._extract_domain(v) in domains for v in entity_values)
        return False


class SensitivityConstraint(BaseModel):
    """敏感度约束：步骤 sensitivity 字段必须在/不在给定级别中。

    敏感度级别由语义层提取（如 high / critical），用于表达「涉及机密/凭据」
    这类不与具体实体绑定的风险条件。

    Example:
        SensitivityConstraint(levels=["high", "critical"])
        SensitivityConstraint(levels=["none"], match_type="not_in")
    """

    levels: list[str] = Field(default_factory=list)
    match_type: str = "in"  # "in" | "not_in"

    def matches(self, sensitivity: str | None) -> bool:
        if not sensitivity or not self.levels:
            return False
        value = sensitivity.lower()
        targets = {level.lower() for level in self.levels}
        if self.match_type == "not_in":
            return value not in targets
        return value in targets


class TemporalConstraint(BaseModel):
    """时序约束：步骤 constraints 中 kind="time_range" 的值匹配。

    时序约束来自语义层提取的时间范围（today / yesterday / this_week），
    用于表达「仅限今日」「仅限本周」这类时间边界。

    Example:
        TemporalConstraint(values=["today", "this_week"])
    """

    values: list[str] = Field(default_factory=list)

    def matches(self, step_constraints: list[Any]) -> bool:
        if not self.values:
            return False
        targets = {v.lower() for v in self.values}
        for item in step_constraints:
            kind = item.get("kind") if isinstance(item, dict) else getattr(item, "kind", None)
            value = item.get("value") if isinstance(item, dict) else getattr(item, "value", None)
            if kind == "time_range" and isinstance(value, str) and value.lower() in targets:
                return True
        return False


# =============================================================================
# 约束规则
# =============================================================================


class ConstraintRule(BaseModel):
    """由约束条件组成的规则，替代旧的 lambda 谓词。

    一条规则可组合 action/tags/entity/sensitivity/temporal 五类约束，
    全部匹配时得分为各约束加权和。

    confidence_threshold: 当步骤语义置信度低于此值时，规则不参与最终判定
    """

    rule_id: str
    title: str
    description: str
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    risk_level: str  # "blocked" | "dangerous" | "caution" | "safe"
    decision: str  # "block" | "escalate" | "ask"
    action: ActionConstraint | None = None
    tags: TagConstraint | None = None
    entity: EntityConstraint | None = None
    sensitivity: SensitivityConstraint | None = None
    temporal: TemporalConstraint | None = None
    # 语义置信度门控阈值（spec B4）：步骤 confidence < 阈值时不参与判定。
    # 默认 0.5，对应「<0.5 保守回退」；旧数据无 confidence 按中性 0.5 处理。
    confidence_threshold: float = 0.5


# =============================================================================
# 约束推理引擎
# =============================================================================

# 约束类型权重（总分最大 1.0）
_WEIGHTS: dict[str, float] = {
    "action": 0.25,
    "tags": 0.40,
    "entity": 0.35,
    "sensitivity": 0.25,
    "temporal": 0.25,
}


class ConstraintEngine:
    """基于约束的规则匹配引擎。

    evaluate() 接收 ToolCallIR 步骤列表，为每条规则计算加权评分，
    返回命中规则及得分（按得分降序）。
    """

    def __init__(self, rules: list[ConstraintRule] | None = None) -> None:
        self._rules = list(rules or [])

    @property
    def rules(self) -> list[ConstraintRule]:
        return self._rules

    def add_rule(self, rule: ConstraintRule) -> None:
        self._rules.append(rule)

    def evaluate(
        self,
        ir_steps: list[ToolCallIR],
    ) -> list[tuple[ConstraintRule, float]]:
        """评估所有规则对当前 IR 步骤的匹配情况。

        对每条规则调用 _match_score，最高分跨步骤取 max，
        按得分降序排列，过滤掉低于 confidence_threshold 的规则。

        Returns:
            list of (rule, score), sorted by score descending
        """
        if not ir_steps:
            return []
        results: list[tuple[ConstraintRule, float]] = []
        for rule in self._rules:
            best_score = 0.0
            best_confidence = 0.0
            for step in ir_steps:
                score = self._match_score(rule, step)
                if score > best_score:
                    best_score = score
                    confidence = step.confidence
                    # 旧数据无 confidence 时按中性 0.5 处理，保持向后兼容
                    best_confidence = 0.5 if confidence is None else float(confidence)
            # 语义置信度门控（spec B4）：confidence < 阈值 → 保守回退，不参与判定
            if best_score > 0.0 and best_confidence >= rule.confidence_threshold:
                results.append((rule, best_score))
        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def evaluate_steps(
        self,
        rv_trace: list[dict[str, Any]],
    ) -> list[tuple[ConstraintRule, float]]:
        """评估语义层产出的 dict 格式 rv_trace（自动转换为 ToolCallIR）。

        这是约束引擎在生产流水线中的入口：把 rv_trace 步骤（dict）
        转换为阶段 A 的 ToolCallIR 结构化模型后再评估。
        """
        ir_steps: list[ToolCallIR] = []
        for step in rv_trace:
            if isinstance(step, ToolCallIR):
                ir_steps.append(step)
                continue
            if not isinstance(step, dict):
                continue
            try:
                ir_steps.append(ToolCallIR.model_validate(step))
            except Exception:
                continue  # 跳过无法结构化的步骤，保持向后兼容
        return self.evaluate(ir_steps)

    def _match_score(self, rule: ConstraintRule, step: ToolCallIR) -> float:
        """计算单条规则对单个 IR 步骤的加权匹配分数。

        所有在规则上声明的约束必须全部满足（AND 语义）。
        若有约束未满足，返回 0.0（不匹配）。

        Returns:
            0.0 ~ 1.0，0.0 表示完全不匹配
        """
        # 动作约束：若声明则必须命中
        if rule.action is not None:
            if step.event not in rule.action.action_types:
                return 0.0

        # 标签约束：若声明则必须命中
        if rule.tags is not None:
            if not self._tags_match(rule.tags, step.props):
                return 0.0

        # 实体约束：若声明则必须命中
        if rule.entity is not None:
            entity_values = self._get_entity_values(step.entities, rule.entity.kind)
            if not rule.entity.matches(entity_values):
                return 0.0

        # 敏感度约束：若声明则必须命中
        if rule.sensitivity is not None:
            if not rule.sensitivity.matches(step.sensitivity):
                return 0.0

        # 时序约束：若声明则必须命中
        if rule.temporal is not None:
            if not rule.temporal.matches(step.constraints):
                return 0.0

        # 所有已声明约束全部命中 → 计算加权得分
        score = 0.0
        total_weight = 0.0
        if rule.action is not None:
            total_weight += _WEIGHTS["action"]
            score += _WEIGHTS["action"]
        if rule.tags is not None:
            total_weight += _WEIGHTS["tags"]
            score += _WEIGHTS["tags"]
        if rule.entity is not None:
            total_weight += _WEIGHTS["entity"]
            score += _WEIGHTS["entity"]
        if rule.sensitivity is not None:
            total_weight += _WEIGHTS["sensitivity"]
            score += _WEIGHTS["sensitivity"]
        if rule.temporal is not None:
            total_weight += _WEIGHTS["temporal"]
            score += _WEIGHTS["temporal"]

        if total_weight == 0:
            return 0.0
        return score / total_weight

    @staticmethod
    def _tags_match(tags: TagConstraint, props: list[str]) -> bool:
        props_set = set(props)
        if tags.require_all and not all(t in props_set for t in tags.require_all):
            return False
        if tags.require_any and not any(t in props_set for t in tags.require_any):
            return False
        return True

    @staticmethod
    def _get_entity_values(
        entities: list[Any], kind: str
    ) -> list[str]:
        """从实体列表中提取指定 kind 的 values。"""
        for entity in entities:
            if isinstance(entity, dict):
                if entity.get("kind") == kind:
                    return [str(v) for v in entity.get("values", []) if v is not None]
            elif hasattr(entity, "kind") and entity.kind == kind:
                return [str(v) for v in getattr(entity, "values", []) if v is not None]
        return []


# =============================================================================
# 已迁移规则（47 条 legacy DetectionEngine 规则）
# =============================================================================


def migrated_constraint_rules() -> list[ConstraintRule]:
    """Compile all 47 legacy detection records into structured constraints.

    During the compatibility phase the DetectionRule record is the source for
    title/action/label facts, eliminating the former hand-maintained list of
    only ten mirrors.  PMKB migration metadata records the same legacy IDs.
    """
    from openclaw_guard.engine.detection import builtin_rules

    return [
        ConstraintRule(
            rule_id=rule.rule_id,
            title=rule.title,
            description=rule.description,
            severity=rule.severity,
            risk_level=rule.risk_level,
            decision=rule.decision,
            action=ActionConstraint(action_types=rule.action_types),
            tags=TagConstraint(require_all=rule.match_labels),
        )
        for rule in builtin_rules()
    ]
