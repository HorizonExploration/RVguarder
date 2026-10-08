"""受控执行器的执行前快照证明，仅供后台核验，不产生授权放行。

证明与成功收据采用不同purpose/schema，不能互换。可信度依赖实际
执行器强制消费同一私有快照；签名本身不能证明部署或SDK身份可信。
"""
from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from openclaw_guard.engine.experiment_components import current
from openclaw_guard.spec.content_receipts import (
    ContentReceiptError, ContentVersion, HostContentReceiptAuthority,
    _canonical, _freeze_bounded_json,
)


OFFICE_OPERATIONS = {
    "office_message_send": "message.send",
    "office_network_post": "network.egress",
    "office_document_share": "network.egress",
}


class ExecutionProposal(BaseModel):
    """绑定一个未来有限egress调用的不可变字节快照，不宣称调用成功。"""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    format_version: Literal[1]
    purpose: Literal["proposed_content_use"]
    enforcement: Literal["snapshot-v1", "snapshot-grant-v1"]
    snapshot_id: str = Field(min_length=1, max_length=64)
    issuer: str = Field(min_length=1, max_length=128)
    task_id: str = Field(min_length=1, max_length=256)
    principal_id: str = Field(min_length=1, max_length=256)
    agent_id: str = Field(min_length=1, max_length=256)
    session_id: str = Field(max_length=256)
    run_id: str = Field(min_length=1, max_length=256)
    tool_call_id: str = Field(min_length=1, max_length=256)
    tool_name: str = Field(min_length=1, max_length=128)
    operation_family: Literal["message.send", "network.egress"]
    arguments_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    recipient: str = Field(min_length=1, max_length=4096)
    source: ContentVersion
    issued_at_ms: int = Field(ge=0)
    expires_at_ms: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_contract(self) -> ExecutionProposal:
        """仅支持已登记工具和完整快照，禁止将部分读取当作完整资源。"""
        if OFFICE_OPERATIONS.get(self.tool_name) != self.operation_family:
            raise ValueError("unsupported concrete execution contract")
        if not self.source.full_resource or self.source.size_bytes > 1024 * 1024:
            raise ValueError("proposal requires a bounded full snapshot")
        if self.recipient != self.recipient.strip() or "\x00" in self.recipient:
            raise ValueError("recipient must be exact")
        if not 0 < self.expires_at_ms - self.issued_at_ms <= 300000:
            raise ValueError("proposal lifetime must be at most five minutes")
        return self


class HostExecutionProposalVerifier:
    """核验签名和当前宿主授权，结果只作为诊断，不提交监视器事实。"""

    def __init__(self, authority: HostContentReceiptAuthority) -> None:
        """复用显式登记执行器的私有密钥；不提供HTTP或Agent签发接口。"""
        self.authority = authority

    def verify(self, envelope: dict, *, event: Any, step: dict, active_grants: list[dict] | None = None) -> ExecutionProposal:
        """有界复制后核验，宿主数据库查询不得在before Hook同步调用。"""
        frozen = _freeze_bounded_json(envelope, 16384)
        if not isinstance(frozen, dict) or set(frozen) != {"payload", "signature"}:
            raise ContentReceiptError("invalid proposal envelope")
        payload, signature = frozen["payload"], frozen["signature"]
        if not isinstance(payload, dict) or not isinstance(signature, str) or len(signature) != 64:
            raise ContentReceiptError("invalid proposal types")
        expected_signature = hmac.new(self.authority._key, _canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            raise ContentReceiptError("invalid proposal signature")
        proposal = ExecutionProposal.model_validate(payload)
        meta = event.metadata
        if (meta.get("hook_auth_verified") is not True or not meta.get("hook_auth_binding")
                or step.get("event_model") != "tool-call-v1" or step.get("execution_state") != "proposed"
                or step.get("effects") != ["egress"]):
            raise ContentReceiptError("untrusted or non-proposed finite call")
        expected = {"principal_id": f"hook:{meta['hook_auth_binding']}", "agent_id": meta.get("agent_id"),
                    "session_id": meta.get("session_id") or "", "run_id": meta.get("run_id"),
                    "tool_call_id": meta.get("tool_call_id"), "tool_name": step.get("tool_name"),
                    "operation_family": step.get("operation_family")}
        if (proposal.issuer != self.authority.issuer
                or self.authority.tool_operations.get(proposal.tool_name) != proposal.operation_family
                or any(getattr(proposal, key) != value for key, value in expected.items())):
            raise ContentReceiptError("proposal call identity mismatch")
        arguments = _freeze_bounded_json(event.raw_payload.get("params"), 65536)
        if not isinstance(arguments, dict) or hashlib.sha256(_canonical(arguments)).hexdigest() != proposal.arguments_sha256:
            raise ContentReceiptError("proposal arguments mismatch")
        now = int(time.time() * 1000)
        if not proposal.issued_at_ms <= now < proposal.expires_at_ms:
            raise ContentReceiptError("proposal expired or not yet valid")
        if active_grants is None:
            task = self.authority.task_resolver(principal_id=proposal.principal_id,
                agent_id=proposal.agent_id, session_id=proposal.session_id, run_id=proposal.run_id)
            valid_task = task is not None and task.task_id == proposal.task_id
        else:
            tasks = {grant["binding"]["task_id"] for grant in active_grants
                if all(grant["binding"][key] == getattr(proposal, key) for key in ("principal_id", "agent_id"))
                and all(not grant["binding"][key] or grant["binding"][key] == getattr(proposal, key)
                        for key in ("session_id", "run_id"))}
            valid_task = tasks == {proposal.task_id}
        if not valid_task:
            raise ContentReceiptError("proposal task is not uniquely host-registered")
        return proposal

    def inspect_authorization(self, envelope: dict, *, event: Any, step: dict) -> dict:
        """后台诊断精确消费版本与当前授权；无授权不表示可放行或应阻断。"""
        if not current().authorization:
            return {"status": "disabled", "decision_eligible": False}
        proposal = self.verify(envelope, event=event, step=step)
        grant_id = None
        grants = self.authority._store.query()
        # 任务及授权匹配必须基于同一次当前读取，避免两次查询间新增歧义任务。
        tasks = {grant["binding"]["task_id"] for grant in grants
            if not grant["revoked"] and not grant["expired"]
            and all(grant["binding"][key] == getattr(proposal, key) for key in ("principal_id", "agent_id"))
            and all(not grant["binding"][key] or grant["binding"][key] == getattr(proposal, key)
                    for key in ("session_id", "run_id"))}
        if tasks != {proposal.task_id}:
            raise ContentReceiptError("proposal task changed or became ambiguous during inspection")
        for grant in grants:
            binding, resource = grant["binding"], grant["resource"]
            if grant["revoked"] or grant["expired"]:
                continue
            if any(binding[key] != getattr(proposal, key) for key in ("task_id", "principal_id", "agent_id")):
                continue
            if any(binding[key] and binding[key] != getattr(proposal, key) for key in ("session_id", "run_id")):
                continue
            if grant["operation"] != proposal.operation_family or grant["recipient"] != proposal.recipient:
                continue
            if (resource["namespace"] != proposal.source.namespace or resource["resource_id"] != proposal.source.resource_id
                    or resource["content_version"] != f"sha256:{proposal.source.sha256}" or resource["size_bytes"] != proposal.source.size_bytes):
                continue
            grant_id = grant["id"]
            break
        return {"status": "proposal_verified", "snapshot_id": proposal.snapshot_id,
                "snapshot_grant_match": grant_id is not None, "grant_id": grant_id,
                "task_id": proposal.task_id, "source": proposal.source.model_dump(mode="json"),
                "decision_eligible": False, "execution_state": "proposed",
                "scope_limit": "native_executor_identity_isolation_and_revocation_boundary_not_accepted"}
