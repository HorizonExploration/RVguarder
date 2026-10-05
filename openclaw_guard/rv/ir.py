"""工具调用中间表示：真实调用的有限效果、上下文和语义补充事实。

生产 RV 使用 tool-call-v1，一次调用对应一个步骤。旧语义步骤保留可读兼容，
不能作为实际调用次数或可信违规证据。
"""

from __future__ import annotations

from typing import Any, Literal

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
    """承载真实工具调用；legacy 默认值仅兼容旧语义模型输出。"""
    event_model: Literal["legacy", "tool-call-v1"] = "legacy"
    operation_family: str | None = None
    effects: list[Literal["read", "write", "delete", "execute", "egress", "configure",
                          "grant", "schedule", "spawn", "interact", "transform", "query", "unknown"]] = Field(default_factory=list)
    execution_state: Literal["proposed", "succeeded", "legacy_replay"] = "proposed"
    context: dict[str, Any] = Field(default_factory=dict)
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
    # Optional authorization evidence, retained when a hook supplies it.
    negated: bool = False
    excluded_entities: list[str] = Field(default_factory=list)
    quantity: int = 0
    provenance: dict[str, Any] = Field(default_factory=dict)
