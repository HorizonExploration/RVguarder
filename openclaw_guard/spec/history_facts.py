"""宿主核验的单调用跨会话历史事实，不接受工具或语义字典自报。"""
from __future__ import annotations

from typing import Literal
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class VerifiedCrossSessionHistory(BaseModel):
    """同任务确切字节历史，只提供当前真实调用的有限DSL guard。"""
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, arbitrary_types_allowed=True)
    lease: Any = Field(exclude=True)
    relationship: Literal["exact_consumed_byte_identity", "same_task_sensitive_read_capability"]
    component_generation: int = Field(ge=0)
    step_id: str
    principal_id: str
    agent_id: str
    session_id: str
    run_id: str
    tool_name: str
    operation_family: Literal["message.send", "network.egress"]
    arguments_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    task_id: str
    history_step_ids: tuple[str, ...]
    receipt_ids: tuple[str, ...]
    link_ids: tuple[str, ...]
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expires_at_ms: int = Field(ge=0)
