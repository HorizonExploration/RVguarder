"""供宿主核验器返回的类型化单调用授权范围；字典/语义标签不构成事实。

仅可信宿主checker可向监视器返回该类型。该模型不接受HTTP反序列化
接入，不签发授权，不替代执行器、撤销及部署隔离验收。
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from openclaw_guard.spec.content_receipts import ContentVersion


class VerifiedCallAuthorization(BaseModel):
    """绑定单个具体调用的核验结果；仅用于明确配置的逐规则守卫。"""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    decision_eligible: Literal[True]
    component_generation: int = Field(ge=0)
    step_id: str = Field(min_length=1)
    grant_id: str = Field(min_length=1)
    snapshot_id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    principal_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    session_id: str
    run_id: str = Field(min_length=1)
    tool_call_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    operation_family: Literal["message.send", "network.egress"]
    arguments_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    recipient: str = Field(min_length=1)
    source: ContentVersion
    valid_from_ms: int = Field(ge=0)
    expires_at_ms: int = Field(ge=0)
