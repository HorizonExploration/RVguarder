"""Deterministic compilation of hook behavior into authorization evidence."""
from __future__ import annotations

from collections.abc import Mapping
import shlex
from typing import Any
from uuid import uuid4

from openclaw_guard.models import BehaviorEvent
from openclaw_guard.engine.command_safety import analyze_command
from openclaw_guard.engine.semantic_models import SemanticMatchIR, local_semantic_match
from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.policy.models import (
    AuthorizationTrace, ContextRef, CoverageResult, DataRef,
    PrincipalRef, ProvenanceRef, ResourceRef, SecurityFactEvidence,
)


_ACTION_TO_TOOL = {
    "network_egress": "network.request", "channel_send": "feishu.im.send",
    "command_exec": "process.execute", "file_write": "file.write",
}
_CLASSIFICATION = ("public", "internal", "sensitive", "secret")


class TraceCompiler:
    def __init__(self, bundle: PolicyBundle):
        self.bundle = bundle

    def compile(self, event: BehaviorEvent, *, semantic: dict[str, Any],
                rv_trace: list[dict[str, Any]], semantic_match: dict[str, Any] | None = None,
                source_message: str = "") -> AuthorizationTrace:
        semantic = semantic or {}
        steps = [item.model_dump() if hasattr(item, "model_dump") else dict(item)
                 for item in (rv_trace or []) if isinstance(item, Mapping) or hasattr(item, "model_dump")]
        tool_id = str(event.metadata.get("tool_name") or event.api_name or _ACTION_TO_TOOL.get(event.action_type, event.action_type))
        params = dict(event.raw_payload.get("params", {})) if isinstance(event.raw_payload.get("params", {}), dict) else {}
        params["action_type"] = event.action_type
        # 派生安全证据不能由工具参数或调用者提供的标签覆盖。
        command_safety = analyze_command(event.command).to_dict() if event.command else None
        params.pop("command_safety", None)
        if isinstance(command_safety, dict):
            params["command_safety"] = command_safety["classification"]
        if event.command:
            params["command"] = event.command
            try:
                params["argv"] = shlex.split(event.command)
            except ValueError:
                params["argv"] = []
        operation = self.bundle.operation_for_tool(tool_id, params)
        if operation.family == "unknown_tool" and event.action_type in _ACTION_TO_TOOL:
            operation = self.bundle.operation_for_tool(_ACTION_TO_TOOL[event.action_type], params)

        labels = {str(x) for x in semantic.get("labels", [])}
        for step in steps:
            labels.update(str(x) for x in step.get("props", []) if isinstance(x, str))
        recipients = _entities(semantic, steps, "recipients")
        # 已登记执行器消费recipient字符串；模型实体不能替换实际接收方。
        # 网络分享仍是原有限operation，不新增消息调用或授权事实。
        office_recipient_contract = tool_id in {"office_message_send", "office_document_share"}
        suggested_recipients = list(recipients)
        if office_recipient_contract:
            actual_recipient = params.get("recipient")
            recipients = [actual_recipient.strip()] if isinstance(actual_recipient, str) and actual_recipient.strip() else []
        native_recipient_contract = tool_id == "message" and event.metadata.get("tool_action") in {"send", "broadcast"}
        if native_recipient_contract:
            explicit_target = next((params[key] for key in ("target", "to", "channelId")
                                    if isinstance(params.get(key), str) and params[key].strip()), None)
            targets = params.get("targets", []) if event.metadata.get("tool_action") == "broadcast" else [explicit_target]
            recipients = [value.strip() for value in targets if isinstance(value, str) and value.strip()] if isinstance(targets, list) else []
        paths = _entities(semantic, steps, "paths") or list(event.target_paths)
        if operation.family == "process.execute" and not paths and isinstance(command_safety, dict):
            hints = command_safety.get("path_hints")
            if isinstance(hints, list):
                paths = [str(item) for item in hints if item]
        urls = _entities(semantic, steps, "urls") or list(event.network_targets)
        if operation.family == "process.execute" and not (recipients or paths or urls) and (event.command or tool_id == "process.execute"):
            paths = [event.command or tool_id]
        resource_ids = recipients or paths or urls
        if office_recipient_contract or native_recipient_contract:
            resource_ids = recipients
        native_low = (
            event.metadata.get("tool_origin") == "openclaw_native"
            and event.metadata.get("risk_class") == "low"
        )
        native_control_plane = native_low and event.metadata.get("tool_group") in {
            "session", "memory", "agents", "planning", "human_input", "ui"
        }
        if native_control_plane and not resource_ids:
            resource_ids = [f"openclaw:{tool_id}"]
        resource_type = "recipient" if recipients else ("path" if paths else ("url" if urls else "unknown"))
        if office_recipient_contract or native_recipient_contract:
            resource_type = "recipient"
        if native_control_plane:
            resource_type = "control_plane"
        if operation.family == "process.execute":
            resource_type = "command"
        outside = bool(event.metadata.get("outside_workspace"))
        scope = str(event.metadata.get("scope_class") or "")
        if scope == "unknown" or scope not in {"workspace", "managed_project", "outside", "external"}:
            if recipients:
                # Recipient scope is distinct from filesystem paths.  Internal
                # recipients stay within the managed boundary so the calibrated
                # low-risk message rule can apply without treating an address
                # as a workspace path.
                scope = "external" if any(_external(x) for x in recipients) else "workspace"
            else:
                scope = "outside" if outside else ("workspace" if paths else "unknown")
        if urls and not paths:
            scope = "external"
        if office_recipient_contract:
            # 未绑定执行器internalDomains时，绝不以默认域名授予内部低风险。
            # 外部标记只能增加风险；false不是内部证明。
            office_external = bool(recipients) and (
                params.get("external") is True or str(params.get("access") or "").lower() == "external"
            )
            scope = "external" if recipients else "unknown"
        if native_control_plane and scope == "unknown":
            scope = "workspace"

        classification = _classification(semantic, labels, steps)
        quantity = _quantity(semantic, steps, len(resource_ids))
        if native_recipient_contract:
            quantity = len(recipients)  # 接收方数量来自原生参数，不能由模型缩小。
        recipient_zone = "external" if recipients and any(_external(x) for x in recipients) else ("internal" if recipients else "unknown")
        if office_recipient_contract:
            recipient_zone = "external" if office_external else "unknown"
        elif native_recipient_contract and (not recipients or any('@' not in value for value in recipients)):
            # 渠道ID/别名没有已验证内部域；不能由模型称其为内部收件人。
            recipient_zone = "unknown"
            scope = "unknown"
        purpose = str(semantic.get("purpose") or semantic.get("intent", {}).get("goal", "") if isinstance(semantic.get("intent"), dict) else semantic.get("purpose", ""))
        missing = []
        resource_gap = _resource_gap(operation.family, resource_ids)
        if resource_gap:
            missing.append(resource_gap)
        if operation.family == "unknown_tool":
            missing.append("operation.mapping")
        gaps = list(operation.gaps)
        if resource_gap:
            gaps.append(resource_gap)
        security_facts, fact_conflicts = _security_facts(event, semantic_match)
        if office_recipient_contract or native_recipient_contract:
            # 弱模型矛盾只记录诊断，不污染coverage而压低确定硬约束。
            event.metadata["resource_projection"] = {
                "source": "registered_office_recipient_contract" if office_recipient_contract else "native_message_recipient_contract", "recipient_ids": list(recipients),
                "executor_internal_domains_verified": False,
                "conflicts": ["resource.recipient_conflict"] if suggested_recipients and suggested_recipients != recipients else [],
            }
        coverage_status = "conflict" if fact_conflicts else ("complete" if not missing else "partial")
        coverage = CoverageResult(
            status=coverage_status,
            missing_features=missing,
            gaps=list(dict.fromkeys(gaps)),
            conflicts=fact_conflicts,
        )
        trusted_identity = event.metadata.get("trusted_identity")
        if not isinstance(trusted_identity, dict) or trusted_identity.get("trust") != "verified":
            trusted_identity = {}
        semantic_principal = semantic.get("principal") if isinstance(semantic.get("principal"), dict) else {}
        principal_id = str(
            trusted_identity.get("principal_id")
            or (semantic_principal.get("id") if not event.metadata.get("hook_bridge") else "")
            or "unknown"
        )
        principal_type = str(
            trusted_identity.get("principal_type")
            or (semantic_principal.get("type") if not event.metadata.get("hook_bridge") else "")
            or "agent"
        )
        if principal_type not in {"human", "agent", "skill", "service"}: principal_type = "agent"
        agent_id = str(trusted_identity.get("agent_id") or "") or None
        raw_lineage = trusted_identity.get("capability_lineage")
        capability_lineage = (
            [str(item) for item in raw_lineage if isinstance(item, str) and item]
            if isinstance(raw_lineage, list)
            else []
        )
        confidence = {
            "operation": 1.0 if operation.family != "unknown_tool" else 0.2,
            "resource": 0.9 if resource_ids else 0.0,
            "scope": 0.95 if scope == "external" else (0.8 if scope in {"workspace", "managed_project", "outside"} else 0.0),
            "overall": _bounded_confidence(semantic.get("confidence", 0.0)),
        }
        return AuthorizationTrace(
            trace_id=str(event.event_id or uuid4()), principal=PrincipalRef(id=principal_id, type=principal_type,
                trust="verified" if trusted_identity else "unknown"), operation=operation,
            resource=ResourceRef(type=resource_type, ids=resource_ids, scope=scope),
            coverage=coverage, agent_id=agent_id, session_id=str(event.metadata.get("session_id") or "") or None,
            capability_lineage=capability_lineage,
            data=DataRef(classification=classification, quantity=quantity),
            context=ContextRef(recipient_zone=recipient_zone, purpose=purpose),
            provenance=ProvenanceRef(source=str(semantic.get("origin") or event.source or "unknown"),
                trust=str(event.metadata.get("provenance_trust") or "unknown")),
            confidence=confidence, security_facts=security_facts, rv_steps=steps,
        )


def _security_facts(
    event: BehaviorEvent,
    semantic_match: dict[str, Any] | None,
) -> tuple[dict[str, SecurityFactEvidence], list[str]]:
    suggested: dict[str, SecurityFactEvidence] = {}
    if isinstance(semantic_match, dict):
        try:
            parsed = SemanticMatchIR.model_validate(semantic_match)
        except ValueError:
            parsed = None
        if parsed is not None:
            suggested = {
                name: SecurityFactEvidence.model_validate(fact.model_dump())
                for name, fact in parsed.facts.items()
            }

    deterministic = local_semantic_match(event).facts
    conflicts: list[str] = []
    for name, fact in deterministic.items():
        existing = suggested.get(name)
        if existing is not None and existing.value != fact.value:
            conflicts.append(f"fact_conflict:{name}")
        suggested[name] = SecurityFactEvidence.model_validate(fact.model_dump())
    return suggested, conflicts


def _entities(semantic, steps, kind):
    raw = semantic.get("entities", {}).get(kind, []) if isinstance(semantic.get("entities"), dict) else []
    found = list(raw) if isinstance(raw, list) else []
    for step in steps:
        for entity in step.get("entities", []) or []:
            if isinstance(entity, dict) and entity.get("kind") == kind:
                found.extend(entity.get("values", []) or [])
    return list(dict.fromkeys(str(x) for x in found if x))


def _external(value):
    value = str(value).lower()
    return "@" in value and not value.endswith(("@openclaw.ai", "@company.local", "@internal.local"))


def _classification(semantic, labels, steps):
    candidates = []
    explicit = semantic.get("data_classification") or semantic.get("classification")
    if explicit in _CLASSIFICATION: candidates.append(explicit)
    step_classes = [step.get("sensitivity") or step.get("classification") for step in steps]
    candidates.extend(item for item in step_classes if item in _CLASSIFICATION)
    for level in reversed(_CLASSIFICATION):
        if level == "secret" and ({"contains_secret", "network_secret_payload"} & labels): candidates.append(level)
        if level == "sensitive" and ("sensitive_data" in labels or "path_sensitive_creds" in labels): candidates.append(level)
        if level == "internal" and ({"internal_source", "source_internal"} & labels): candidates.append(level)
    return max(candidates, key=_CLASSIFICATION.index) if candidates else "internal"


def _resource_gap(family, resource_ids):
    if resource_ids:
        return ""
    if family in {"message.send", "network.egress"}:
        return "resource.recipient"
    if family in {"file.write", "secret.read", "credential.read"}:
        return "resource.path"
    if family in {"document.read", "document.write", "table.read", "data.export"}:
        return "resource.target"
    if family == "process.execute":
        return "resource.command"
    if family == "config.modify":
        return "resource.config"
    return ""


def _quantity(semantic, steps, fallback):
    value = semantic.get("quantity")
    for step in steps:
        if isinstance(step.get("quantity"), int): value = step["quantity"]
    return int(value) if isinstance(value, (int, float)) else fallback


def _bounded_confidence(value):
    try:
        return max(0.0, min(1.0, float(value or 0.0)))
    except (TypeError, ValueError):
        return 0.0
