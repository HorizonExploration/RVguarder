from __future__ import annotations

from pathlib import Path
import sys

from openclaw_guard.models import CapabilityStatus


class EBPFCollector:
    def capability(self) -> CapabilityStatus:
        bpf_fs = Path("/sys/fs/bpf")
        available = sys.platform.startswith("linux") and bpf_fs.exists()
        mode = "native" if available else "capability-only"
        detail = "eBPF program loading prerequisites detected." if available else "eBPF requires Linux with /sys/fs/bpf."
        return CapabilityStatus(name="ebpf", available=available, mode=mode, detail=detail)

