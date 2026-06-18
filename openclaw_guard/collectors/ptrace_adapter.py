from __future__ import annotations

import os
import sys

from openclaw_guard.models import CapabilityStatus


class PtraceCollector:
    def capability(self) -> CapabilityStatus:
        available = sys.platform.startswith("linux") and hasattr(os, "getpid")
        mode = "native" if available else "capability-only"
        detail = "ptrace collector ready for attach mode." if available else "ptrace requires Linux runtime support."
        return CapabilityStatus(name="ptrace", available=available, mode=mode, detail=detail)

