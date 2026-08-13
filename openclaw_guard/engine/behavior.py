from __future__ import annotations

from typing import Any
from uuid import uuid4

from openclaw_guard.collectors.ebpf_adapter import EBPFCollector
from openclaw_guard.collectors.hook_bridge import HookBridge
from openclaw_guard.collectors.ptrace_adapter import PtraceCollector
from openclaw_guard.models import BehaviorEvent, CapabilityStatus
from openclaw_guard.utils import utc_now_iso


class BehaviorCollectorManager:
    def __init__(self) -> None:
        self.ptrace = PtraceCollector()
        self.ebpf = EBPFCollector()
        self.hook_bridge = HookBridge()

    def capabilities(self) -> list[CapabilityStatus]:
        return [self.ptrace.capability(), self.ebpf.capability(), self.hook_bridge.capability()]

    def ingest(self, payload: dict[str, Any]) -> BehaviorEvent:
        target_paths = [str(item) for item in payload.get("target_paths", []) if str(item)]
        network_targets = [str(item) for item in payload.get("network_targets", []) if str(item)]
        if path := payload.get("path"):
            target_paths.append(str(path))
        if url := payload.get("url"):
            network_targets.append(str(url))
        return BehaviorEvent(
            event_id=payload.get("event_id") or uuid4().hex[:16],
            timestamp=payload.get("timestamp") or utc_now_iso(),
            action_type=str(payload.get("action_type") or payload.get("type") or "command_exec"),
            process_name=str(payload.get("process_name") or "openclaw"),
            pid=int(payload["pid"]) if payload.get("pid") is not None else None,
            user=str(payload.get("user") or ""),
            command=str(payload.get("command")) if payload.get("command") is not None else None,
            target_paths=target_paths,
            network_targets=network_targets,
            api_name=str(payload.get("api_name")) if payload.get("api_name") is not None else None,
            skill_name=str(payload.get("skill_name")) if payload.get("skill_name") is not None else None,
            channel_name=str(payload.get("channel_name")) if payload.get("channel_name") is not None else None,
            raw_payload=payload,
            source=str(payload.get("source") or "hook-bridge"),
            working_directory=str(payload.get("working_directory")) if payload.get("working_directory") is not None else None,
            metadata=dict(payload.get("metadata") or {}),
        )

