"""后台核验当前授权并签发单次执行permit；监视器只消费类型事实。

仅接受带撤销消费契约的已登记宿主执行器。默认生产未接入；prepare
不能直接在监视器热路径运行，须有界后台准备并在实际执行时重验撤销。
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import time
from typing import Any

from openclaw_guard.engine.experiment_components import commit_if_current, snapshot
from openclaw_guard.spec.authorization_facts import VerifiedCallAuthorization
from openclaw_guard.spec.content_receipts import _canonical
from openclaw_guard.spec.execution_proposals import HostExecutionProposalVerifier


@dataclass(frozen=True)
class PreparedCallAuthorization:
    """一条当前授权事实及同快照执行许可；不能恢复为长期授权。"""

    fact: VerifiedCallAuthorization
    permit: dict


class HostCallAuthorizer:
    """以同次宿主授权快照核验任务和具体资源，避免跨读取歧义。"""

    def __init__(self, verifier: HostExecutionProposalVerifier) -> None:
        """执行器须私有配置snapshot-grant-v1；无契约不签许可。"""
        self.verifier = verifier

    def prepare(self, envelope: dict, *, event: Any, step: dict) -> PreparedCallAuthorization | None:
        """后台准备，异常由调用者保持原裁决；不抑制其他RV/PMKB规则。"""
        components, generation = snapshot()
        if not components.authorization:
            return None
        grants = self.verifier.authority._store.query_for_decision()
        proposal = self.verifier.verify(envelope, event=event, step=step, active_grants=grants)
        if proposal.enforcement != "snapshot-grant-v1":
            return None
        for grant in grants:
            binding, resource = grant["binding"], grant["resource"]
            if any(binding[key] != getattr(proposal, key) for key in ("task_id", "principal_id", "agent_id")):
                continue
            if any(binding[key] and binding[key] != getattr(proposal, key) for key in ("session_id", "run_id")):
                continue
            if grant["operation"] != proposal.operation_family or grant["recipient"] != proposal.recipient:
                continue
            if (resource["namespace"] != proposal.source.namespace or resource["resource_id"] != proposal.source.resource_id
                    or resource["content_version"] != f"sha256:{proposal.source.sha256}" or resource["size_bytes"] != proposal.source.size_bytes):
                continue
            now = int(time.time() * 1000)
            expires = min(proposal.expires_at_ms, int(grant["expires_at"] * 1000), now + 300000)
            if expires <= now:
                return None
            fact = VerifiedCallAuthorization(decision_eligible=True, component_generation=generation,
                step_id=step["step_id"], grant_id=grant["id"], snapshot_id=proposal.snapshot_id,
                task_id=proposal.task_id, principal_id=proposal.principal_id, agent_id=proposal.agent_id,
                session_id=proposal.session_id, run_id=proposal.run_id, tool_call_id=proposal.tool_call_id,
                tool_name=proposal.tool_name, operation_family=proposal.operation_family,
                arguments_sha256=proposal.arguments_sha256, recipient=proposal.recipient, source=proposal.source,
                valid_from_ms=now, expires_at_ms=expires)
            payload = {"format_version": 1, "purpose": "authorized_snapshot_use", "proposal": proposal.model_dump(mode="json"),
                       "grant_id": grant["id"], "issued_at_ms": now, "expires_at_ms": expires}
            permit = {"payload": payload, "signature": hmac.new(self.verifier.authority._key, _canonical(payload), hashlib.sha256).hexdigest()}
            accepted, result = commit_if_current(generation, "authorization", lambda: PreparedCallAuthorization(fact, permit))
            return result if accepted else None
        return None
