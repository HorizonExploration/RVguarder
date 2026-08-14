"""
IR 结构化中间表示 —— 阶段 A 数据模型。

定义 ToolCallIR / Entity / Constraint 三个 Pydantic 模型，
用于语义层到 RV 引擎的结构化数据传递。

设计原则：
- 字段类型受 Pydantic 约束，避免运行时类型错误
- entities / constraints / confidence 均为可选，向后兼容不含这些字段的旧 rv_trace
- props 保留原样，下游所有基于 props 的监视器零修改
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class Entity(BaseModel):
    """语义分析提取的结构化实体。

    kind: 实体类别（recipients / paths / urls / tool_name）
    values: 实体值列表
    """
    kind: str
    values: list[str] = Field(default_factory=list)


class Constraint(BaseModel):
    """语义分析提取的约束条件。

    kind: 约束类别（exclude / time_range / scope / human_review）
    value: 约束值（字符串或布尔）
    """
    kind: str
    value: str | bool


class ToolCallIR(BaseModel):
    """单条 rv_trace 步骤的结构化中间表示。

    对应语义层产出的一条 RV trace 步骤，在原有 step_id/event/props
    基础上新增 entities/constraints/confidence 结构化字段。

    阶段 A1 语义模型字段（tool_name/arguments/permission_level/side_effect/
    sensitivity/irreversibility/intent）均为可选，确保与旧 rv_trace 完全向后兼容。
    """
    step_id: str
    event: str
    props: list[str] = Field(default_factory=list)
    entities: list[Entity] = Field(default_factory=list)
    constraints: list[Constraint] = Field(default_factory=list)
    confidence: float | None = None
    tool_name: str | None = None
    arguments: dict[str, Any] | None = None
    permission_level: str | None = None
    side_effect: str | None = None
    sensitivity: str | None = None
    irreversibility: str | None = None
    intent: str | None = None
