"""将认证Hook与宿主授权关联，证据仅补充有限工具调用上下文。

当前只验证参数引用的宿主资源版本，不证明工具最终读取/外发的字节。
不得将reference_grant_match当作完整授权或绕过PMKB/RV的依据。
"""
from __future__ import annotations

import json
from collections import OrderedDict
import copy
from queue import Empty, Full, Queue
import threading
from types import SimpleNamespace
import os
from pathlib import Path
import stat
from typing import Any

from openclaw_guard.engine.experiment_components import commit_if_current, current, snapshot
from openclaw_guard.spec.host_authorization import HostAuthorizationError, HostAuthorizationStore
from openclaw_guard.spec.resource_evidence import HostResourceObserver, ResourceEvidenceError

# 登记具体原生契约；未登记工具不按猜测字段读取资源。
RESOURCE_FIELDS = {
    "read": ("path",),
    "office_message_send": ("sourcePath",),
    "office_network_post": ("sourcePath",),
    "office_document_share": ("sourcePath", "document"),
}

RESOURCE_OPERATIONS = {
    "read": "file.read", "office_message_send": "message.send",
    "office_network_post": "network.egress", "office_document_share": "network.egress",
}


class HostAuthorizationBridge:
    """关联认证上下文、受控命名空间及宿主授权，不改变安全裁决。"""

    def __init__(
        self, store: HostAuthorizationStore, observer: HostResourceObserver, *,
        tool_namespaces: dict[str, str],
    ) -> None:
        """使用宿主提供的具体工具映射，不从工具参数学习命名空间。"""
        if any(tool not in RESOURCE_FIELDS for tool in tool_namespaces):
            raise HostAuthorizationError("unsupported host resource contract")
        if any(namespace not in observer.namespace_names for namespace in tool_namespaces.values()):
            raise HostAuthorizationError("unknown host resource namespace")
        self.content_evidence_ledger = None
        self.execution_proposal_verifier = None
        self.decision_preparation = None
        self.history_preparation = None
        self.history_recorder = None
        self.store = store
        self.observer = observer
        self.tool_namespaces = dict(tool_namespaces)
        self._queue: Queue = Queue(maxsize=16)
        self._closed = threading.Event()
        self._results_lock = threading.Lock()
        self._results: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._result_generations: dict[str, int] = {}
        # 仅显式配置时启动一个后台观察器，绝不在before Hook等待磁盘/数据库。
        self._worker = threading.Thread(target=self._observe_pending, daemon=True, name="rv-host-reference")
        self._worker.start()

    @classmethod
    def from_config(cls, config_path: Path) -> HostAuthorizationBridge:
        """加载宿主私有配置；配置与存储均不得置于Agent可写工作区。"""
        path = Path(config_path).absolute()
        for ancestor in (path, *path.parents):
            if ancestor.is_symlink():
                raise HostAuthorizationError("host config path must not contain symlinks")
        parent = path.parent.stat()
        if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077:
            raise HostAuthorizationError("host config directory must be private")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
                raise HostAuthorizationError("host config must be a private regular file")
            config = json.load(stream)
        workspaces = [Path(p) for p in config["agent_workspaces"]]
        if any(path.resolve().is_relative_to(p.resolve()) for p in workspaces):
            raise HostAuthorizationError("host config must be outside agent workspaces")
        store = HostAuthorizationStore(Path(config["state_dir"]), agent_workspaces=workspaces)
        observer = HostResourceObserver({name: Path(root) for name, root in config["namespaces"].items()})
        bridge = cls(store, observer, tool_namespaces=config["tool_namespaces"])
        try:
            if config.get("content_receipts"):
                from openclaw_guard.spec.content_receipts import ExecutedContentLedger, HostContentReceiptAuthority
                receipt_config = config["content_receipts"]
                authority = HostContentReceiptAuthority(store, issuer=receipt_config["issuer"],
                                                       tool_operations=receipt_config["tool_operations"])
                bridge.content_evidence_ledger = ExecutedContentLedger(authority, background=True)
                from openclaw_guard.spec.execution_proposals import HostExecutionProposalVerifier
                bridge.execution_proposal_verifier = HostExecutionProposalVerifier(authority)
                if config.get("cross_session_history") is True:
                    from openclaw_guard.spec.task_history import HostTaskHistory
                    from openclaw_guard.spec.cross_history import HostCrossHistoryAuthorizer, BoundedHistoryRecorder
                    from openclaw_guard.spec.authorization_preparation import BoundedAuthorizationPreparation
                    history = HostTaskHistory(store, authority)
                    authority.task_resolver = history.resolve_task_binding
                    bridge.history_recorder = BoundedHistoryRecorder(authority, history)
                    bridge.history_preparation = BoundedAuthorizationPreparation(
                        HostCrossHistoryAuthorizer(bridge.execution_proposal_verifier, history), component="cross_session_rv")
                if config.get("decision_authorization") is True:
                    from openclaw_guard.spec.call_authorizer import HostCallAuthorizer
                    from openclaw_guard.spec.authorization_preparation import BoundedAuthorizationPreparation
                    bridge.decision_preparation = BoundedAuthorizationPreparation(HostCallAuthorizer(bridge.execution_proposal_verifier))
            elif config.get("decision_authorization") is True or config.get("cross_session_history") is True:
                raise HostAuthorizationError("decision authorization requires controlled content receipts")
            return bridge
        except Exception:
            bridge.close()
            raise

    def submit(self, event: Any, step: dict[str, Any]) -> dict[str, Any]:
        """非阻塞提交参考观察，队列满或停用时不影响PMKB/RV判定。"""
        pending = {"status": "pending_reference_observation", "reference_grant_match": False,
                   "content_lineage_verified": False}
        components, generation = snapshot()
        if self._closed.is_set() or not components.authorization:
            return {**pending, "status": "disabled"}
        metadata = event.metadata
        # 只保留少量不可变上下文和已登记字符串参数，不复制大body/语义载荷。
        captured_metadata = {key: metadata.get(key) for key in (
            "hook_bridge", "hook_auth_verified", "hook_auth_binding", "agent_id", "session_id", "run_id", "tool_call_id",
        )}
        captured_metadata["trusted_identity"] = dict(metadata.get("trusted_identity") or {})
        params = event.raw_payload.get("params") or {}
        if not isinstance(params, dict):
            return {**pending, "status": "invalid_parameters"}
        keys = (*RESOURCE_FIELDS.get(step.get("tool_name"), ()), "recipient", "url")
        captured_params = {key: params[key] for key in keys if key in params and isinstance(params[key], str)}
        captured_raw = {"params": captured_params}
        proposal = event.raw_payload.get("executionProposal")
        if self.execution_proposal_verifier is not None and proposal is not None:
            from openclaw_guard.spec.content_receipts import _freeze_bounded_json
            try:
                captured_raw = {"params": _freeze_bounded_json(params, 65536),
                                "executionProposal": _freeze_bounded_json(proposal, 16384)}
            except (TypeError, ValueError, RecursionError):
                pass # 无效可选证明不影响既有参考观察/裁决。
        captured_event = SimpleNamespace(metadata=captured_metadata, raw_payload=captured_raw)
        captured_step = {key: step.get(key) for key in ("event_model", "tool_name", "operation_family", "execution_state")}
        captured_step["effects"] = list(step.get("effects") or [])
        try:
            self._queue.put_nowait((str(event.event_id), captured_event, captured_step, generation))
        except Full:
            return {**pending, "status": "reference_queue_full"}
        return pending

    def reference_evidence(self, event_id: str) -> dict[str, Any] | None:
        """读取有界后台结果用于诊断；结果不能充当执行前放行证明。"""
        _, generation = snapshot()
        def read_result():
            with self._results_lock:
                if self._result_generations.get(event_id) != generation:
                    return None
                result = self._results.get(event_id)
                return copy.deepcopy(result) if result is not None else None
        accepted, result = commit_if_current(generation, "authorization", read_result)
        return result if accepted else None

    def close(self) -> None:
        """停止接收新任务，不等待慢磁盘或数据库，观察线程为daemon。"""
        with self._results_lock:
            self._closed.set()
        if self.content_evidence_ledger is not None:
            self.content_evidence_ledger.close()
        if self.decision_preparation is not None:
            self.decision_preparation.close()
        if self.history_preparation is not None:
            self.history_preparation.close()
        if self.history_recorder is not None:
            self.history_recorder.close()

    def _observe_pending(self) -> None:
        while not self._closed.is_set():
            try:
                event_id, event, step, generation = self._queue.get(timeout=0.1)
            except Empty:
                continue
            try:
                components, active_generation = snapshot()
                result = self.project(event, step) if components.authorization and active_generation == generation else {"status": "disabled"}
                if (self.execution_proposal_verifier is not None and event.raw_payload.get("executionProposal") is not None
                        and result.get("status") != "disabled"):
                    try:
                        diagnostic = self.execution_proposal_verifier.inspect_authorization(
                            event.raw_payload["executionProposal"], event=event, step=step)
                    except Exception:
                        diagnostic = {"status": "unverified", "decision_eligible": False}
                    result = {**result, "execution_proposal": diagnostic}
            except Exception:
                result = {"status": "inconclusive", "reference_grant_match": False, "content_lineage_verified": False}
            def cache_result() -> None:
                with self._results_lock:
                    if not self._closed.is_set():
                        self._results[event_id] = result
                        self._result_generations[event_id] = generation
                        self._results.move_to_end(event_id)
                        while len(self._results) > 64:
                            removed, _ = self._results.popitem(last=False)
                            self._result_generations.pop(removed, None)
            commit_if_current(generation, "authorization", cache_result)
            self._queue.task_done()

    def project(self, event: Any, step: dict[str, Any]) -> dict[str, Any]:
        """从真实有限调用生成引用证据，不采纳参数自报身份或授权文字。"""
        if not current().authorization:
            return {"status": "disabled"}
        metadata = event.metadata
        identity = metadata.get("trusted_identity") or {}
        hook_binding = metadata.get("hook_auth_binding")
        agent_id = metadata.get("agent_id")
        if not (
            metadata.get("hook_bridge") is True
            and metadata.get("hook_auth_verified") is True
            and hook_binding and agent_id
            and identity.get("binding") == "hook_token"
            and identity.get("principal_id") == f"hook:{hook_binding}"
            and identity.get("agent_id") == agent_id
            and step.get("event_model") == "tool-call-v1"
        ):
            return {"status": "untrusted_context"}
        tool = step.get("tool_name")
        namespace = self.tool_namespaces.get(tool)
        if not namespace:
            return {"status": "unsupported_resource_contract"}
        if step.get("operation_family") != RESOURCE_OPERATIONS[tool]:
            return {"status": "operation_contract_mismatch"}
        params = event.raw_payload.get("params") or {}
        if not isinstance(params, dict):
            return {"status": "invalid_parameters"}
        reference = next((params[key] for key in RESOURCE_FIELDS[tool] if key in params), None)
        # 不把缺失sourcePath的document/body自动映射为同名宿主资源。
        if not isinstance(reference, str) or not reference:
            return {"status": "no_resource_reference"}
        try:
            resource = self.observer.observe(namespace, reference)
            result: dict[str, Any] = {
                "status": "reference_observed", "resource_reference": resource.to_dict(),
                "content_relationship": "parameter_reference_only", "content_lineage_verified": False,
                "reference_grant_match": False,
            }
            binding = self.store.resolve_task_binding(
                principal_id=identity["principal_id"], agent_id=agent_id,
                session_id=str(metadata.get("session_id") or ""), run_id=str(metadata.get("run_id") or ""),
            )
            if binding is None:
                result["task_status"] = "unresolved_or_ambiguous"
                return result
            result["task_status"] = "host_bound"
            result["task_id"] = binding.task_id
            # 子动作不同的多功能工具不可复用操作族级授权。当前仅匹配
            # 三个已登记办公egress契约，read观察不签发或提交权限。
            if tool not in {"office_message_send", "office_network_post", "office_document_share"} or step.get("effects") != ["egress"]:
                return result
            recipient = params.get("url" if tool == "office_network_post" else "recipient")
            if not isinstance(recipient, str) or not recipient:
                return result
            grant = self.store.match(self.observer, namespace, reference, binding=binding,
                                     operation=step["operation_family"], recipient=recipient)
            if grant and grant["resource"]["content_version"] == resource.content_version:
                result["reference_grant_match"] = True
                result["grant_id"] = grant["id"]
            return result
        except (ResourceEvidenceError, HostAuthorizationError, OSError):
            # 补充证据失败不创建授权，也不替换原有PMKB/RV路径。
            return {"status": "inconclusive", "reference_grant_match": False, "content_lineage_verified": False}
