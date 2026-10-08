"""按有限已执行调用查询内容来源图，不预置攻击链或生成虚构工具事件。

仅消费宿主签名收据表；派生关系不是机密外泄、公开分类或授权证明。
查询含宿主任务校验，只能用于后台分析，不进入同步Hook决策路径。
"""
from __future__ import annotations

from collections import deque
import time

from openclaw_guard.spec.content_receipts import ContentReceiptError, ContentVersion, ExecutedContentLedger
from openclaw_guard.spec.host_authorization import TaskBinding


def _version_key(version: dict) -> tuple:
    return tuple(version[key] for key in ("namespace", "resource_id", "sha256", "size_bytes", "full_resource", "offset"))


class VerifiedContentFlow:
    """在相同宿主任务/Agent/session/run中连接已核验复制与变换关系。"""

    def __init__(self, ledger: ExecutedContentLedger) -> None:
        """只接受受控执行收据表，不接受Agent自报图、文件名或Oracle血缘。"""
        self._ledger = ledger

    def ancestors(self, target: ContentVersion, *, binding: TaskBinding) -> dict:
        """有界查询来源版本及实际调用见证；撤销/歧义任务不复用。"""
        binding.validate()
        if not binding.run_id:
            raise ContentReceiptError("content flow requires one exact host run")
        trusted = self._ledger.authority._store.resolve_task_binding(
            principal_id=binding.principal_id, agent_id=binding.agent_id,
            session_id=binding.session_id, run_id=binding.run_id,
        )
        if trusted is None or trusted.task_id != binding.task_id:
            return {"status": "untrusted_task", "ancestors": [], "witnesses": [], "classification_evidence": "not_provided"}
        records = self._ledger.snapshot()
        now = int(time.time() * 1000)
        reverse: dict[tuple, list[dict]] = {}
        for record in records:
            if any(record[key] != value for key, value in binding.__dict__.items()):
                continue
            if not record["issued_at_ms"] <= now < record["expires_at_ms"] or record["kind"] not in {"copy", "transform"}:
                continue
            output = record["outputs"][0]
            reverse.setdefault(_version_key(output), []).append(record)
        pending = deque([target.model_dump(mode="json")])
        visited = {_version_key(pending[0])}
        found, witnesses, witnessed = [], [], set()
        while pending:
            output = pending.popleft()
            for record in reverse.get(_version_key(output), []):
                call_key = (record["run_id"], record["tool_call_id"])
                if call_key not in witnessed:
                    witnesses.append({"receipt_id": record["receipt_id"], "run_id": record["run_id"],
                                      "tool_call_id": record["tool_call_id"], "tool_name": record["tool_name"],
                                      "operation_family": record["operation_family"], "kind": record["kind"]})
                    witnessed.add(call_key)
                for source in record["inputs"]:
                    key = _version_key(source)
                    if key in visited:
                        continue
                    visited.add(key)
                    found.append(dict(source))
                    pending.append(source)
        return {"status": "verified_relations" if witnesses else "no_verified_relation", "ancestors": found,
                "witnesses": witnesses, "classification_evidence": "not_provided",
                "relationship": "received_as_transformation_input; not proof of sensitive output bytes"}
