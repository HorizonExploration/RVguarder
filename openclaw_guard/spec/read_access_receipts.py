"""原生read访问证据与字节收据分型；前后版本观察不证明原始字节消费。"""
from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from openclaw_guard.spec.content_receipts import ContentReceipt, ContentVersion


class NativeReadAccessReceipt(ContentReceipt):
    """只证明认证read成功和前后观察一致；不能建立复制/授权/字节血缘。"""
    kind: Literal['read_access']
    observation: Literal['observed_before_after']
    accessed_resource: ContentVersion
    details_content_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    details_content_size_bytes: int = Field(ge=0, le=262144)

    @model_validator(mode='after')
    def check_access_only(self) -> NativeReadAccessReceipt:
        """访问证据不给inputs/outputs添加实际消费或产生的字节。"""
        if self.tool_name != 'read' or self.operation_family != 'file.read' or self.inputs or self.outputs:
            raise ValueError('read access evidence cannot contain byte lineage or another tool')
        if not self.accessed_resource.full_resource or self.accessed_resource.size_bytes > 262144:
            raise ValueError('read access requires a bounded complete observed resource')
        return self
