from __future__ import annotations

from openclaw_guard.models import CapabilityStatus


class HookBridge:
    def capability(self) -> CapabilityStatus:
        return CapabilityStatus(name="hook-bridge", available=True, mode="local-api", detail="Local non-intrusive hook bridge is available.")

