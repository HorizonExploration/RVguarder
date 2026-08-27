"""Deterministic compilation of hook behavior into authorization evidence."""
from __future__ import annotations

from collections.abc import Mapping
import shlex
from typing import Any
from uuid import uuid4

from openclaw_guard.models import BehaviorEvent
from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.policy.models import (
    AuthorizationTrace, ContextRef, CoverageResult, DataRef, OperationRef,
    PrincipalRef, ProvenanceRef, ResourceRef,
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
                rv_trace: list[dict[str, Any]], source_message: str = "") -> AuthorizationTrace:
        semantic = semantic or {}
        steps = [item.model_dump() if hasattr(item, "model_dump") else dict(item)
                 for item in (rv_trace or []) if isinstance(item, Mapping) or hasattr(item, "model_dump")]
        tool_id = str(event.metadata.get("tool_name") or event.api_name or _ACTION_TO_TOOL.get(event.action_type, event.action_type))
        params = dict(event.raw_payload.get("params", {})) if isinstance(event.raw_payload.get("params", {}), dict) else {}
        if event.command:
            params.setdefault("command", event.command)
            try:
                params.setdefault("argv", shlex.split(event.command))
            except ValueError:
                params.setdefault("argv", [])
        operation = self.bundle.operation_for_tool(tool_id, params)
        if operation.family == "unknown_tool" and event.action_type in _ACTION_TO_TOOL:
            operation = self.bundle.operation_for_tool(_ACTION_TO_TOOL[event.action_type], params)

        labels = {str(x) for x in semantic.get("labels", [])}
        for step in steps:
            labels.update(str(x) for x in step.get("props", []) if isinstance(x, str))
        recipients = _entities(semantic, steps, "recipients")
        paths = _entities(semantic, steps, "paths") or list(event.target_paths)
        urls = _entities(semantic, steps, "urls") or list(event.network_targets)
        resource_ids = recipients or paths or urls
        resource_type = "recipient" if recipients else ("path" if paths else ("url" if urls else "unknown"))
        outside = bool(event.metadata.get("outside_workspace"))
        scope = "external" if recipients and any(_external(x) for x in recipients) else ("outside" if outside else ("workspace" if paths else "unknown"))
        if urls and not paths:
            scope = "external"

        classification = _classification(semantic, labels, steps)
        quantity = _quantity(semantic, steps, len(resource_ids))
        recipient_zone = "external" if recipients and any(_external(x) for x in recipients) else ("internal" if recipients else "unknown")
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
        coverage = CoverageResult(status="complete" if not missing else "partial", missing_features=missing,
                                  gaps=list(dict.fromkeys(gaps)))
        principal = semantic.get("principal") if isinstance(semantic.get("principal"), dict) else {}
        principal_id = str(principal.get("id") or event.metadata.get("principal_id") or event.user or event.process_name or "unknown")
        principal_type = str(principal.get("type") or event.metadata.get("principal_type") or "agent")
        if principal_type not in {"human", "agent", "skill", "service"}: principal_type = "agent"
        confidence = {
            "operation": 1.0 if operation.family != "unknown_tool" else 0.2,
            "resource": 0.9 if resource_ids else 0.0,
            "scope": 0.95 if scope == "external" else (0.8 if scope in {"workspace", "outside"} else 0.0),
            "overall": _bounded_confidence(semantic.get("confidence", 0.0)),
        }
        return AuthorizationTrace(
            trace_id=str(event.event_id or uuid4()), principal=PrincipalRef(id=principal_id, type=principal_type,
                trust="verified" if event.user else "unknown"), operation=operation,
            resource=ResourceRef(type=resource_type, ids=resource_ids, scope=scope),
            coverage=coverage, agent_id=event.process_name, session_id=str(event.metadata.get("session_id") or "") or None,
            data=DataRef(classification=classification, quantity=quantity),
            context=ContextRef(recipient_zone=recipient_zone, purpose=purpose),
            provenance=ProvenanceRef(source=str(semantic.get("origin") or event.source or "unknown"),
                trust=str(event.metadata.get("provenance_trust") or "unknown")),
            confidence=confidence, legacy_steps=steps,
        )


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
