"""生成不包含本机凭据、可重复构建的 OpenClaw 插件测试候选包。"""
from __future__ import annotations

import gzip
import hashlib
import json
import tarfile
from pathlib import Path
from typing import Any

from openclaw_guard import __version__
from openclaw_guard.integrations.hook_runtime import _write_plugin_bundle


README = """# RVguarder OpenClaw plugin — test candidate

This package is the OpenClaw Hook bridge. Install the Python backend separately
with `pip install openclaw_guard-<version>-py3-none-any.whl`, then run
`openclaw-guard run --project-dir /path/to/workspace --config-path
/path/to/isolated/openclaw.json --no-browser`. Replace both paths locally.

Install this archive into an isolated profile first:

```sh
openclaw --profile rvguard-dev plugins install ./openclaw-guard-hook.tgz
```

Configure `plugins.entries.openclaw-guard-hook.config` using the example file.
Set `authToken` locally to the backend's Hook token; never publish the token.
`startupHealthCheck: true` enables asynchronous registration checks for runtimes
that omit gateway_start. Tools do not wait for probes. Calls pass through until
the backend is healthy, and on transport or backend errors. This is intentional
fail-open behavior, not a guarantee of protection during outages or startup.

The backend is required for PMKB/RV and native approval decisions. Changing
source code requires restarting the backend; installing or reconfiguring a
plugin requires reloading the isolated Gateway.

## Release status

Test candidate only. The bundled version-2 source rules (67 rules) retain the
historical public-summary precision regression (RV-PRECISION-001) and have not
passed a new frozen evaluation. The current backend additionally compiles five
native request boundary rules (72 effective default rules). An optional 122-rule
ATLAS profile is included in the backend wheel; select it explicitly using
OPENCLAW_RV_RULES_PATH. These additions have no new holdout qualification.
Separately selected experimental candidate rules
passed the M1/M2 targeted authorization and history checks; those results do not
qualify the bundled default or prove all-tool trusted provenance. There is no claim
of comprehensive unknown-attack coverage, and Plugin API compatibility is verified
only against OpenClaw 2026.9.5 — other versions are untested. Release requires the
new frozen evaluation and real Docker installation tests in the optimization plan.
This archive contains no API keys, generated Hook tokens, workspace contents,
runtime databases or experiment records.
"""


def build_plugin_package(output: str | Path) -> dict[str, Any]:
    """创建新目录和确定性tgz，不读取环境密钥或修改OpenClaw配置。"""
    destination = Path(output).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=False)
    bundle = destination / "plugin"
    _write_plugin_bundle(bundle, guard_url="http://127.0.0.1:8780", auth_token="")
    package_path = bundle / "package.json"
    package = json.loads(package_path.read_text(encoding="utf-8"))
    package["files"] = ["index.js", "openclaw.plugin.json", "README.md",
                        "guard.config.example.json", "release-contract.json"]
    package["license"] = "Apache-2.0"
    package_path.write_text(json.dumps(package, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    (bundle / "README.md").write_text(README, encoding="utf-8")
    (bundle / "guard.config.example.json").write_text(json.dumps({
        "guardUrl": "http://127.0.0.1:8780", "authToken": "SET_LOCALLY_FROM_BACKEND",
        "startupHealthCheck": True, "decisionTimeoutMs": 2000, "callbackTimeoutMs": 15000,
    }, indent=2)+"\n", encoding="utf-8")
    (bundle / "release-contract.json").write_text(json.dumps({
        "status": "test-candidate", "version": __version__, "backend_required": True,
        "backend_python": ">=3.13", "plugin_api_verified": "2026.9.5",
        "outage_behavior": "pass-through", "independent_rv_block": True,
        "known_precision_regression": "public-summary-after-untrusted-read",
        "known_precision_regression_id": "RV-PRECISION-001",
        "bundled_rules_evaluation": "v2 source / 67 rules unchanged; effective default / 72 including 5 native request rules; not frozen-evaluated",
        "experimental_rules_scope": "optional atlas-tool-policy-v2 / 122 rules in backend wheel; targeted calibration only; no new holdout qualification",
        "known_precision_regression_evidence": (
            "testlab/results/office-tool-model-no-pmkb-gate-20261004/defects.md"
            "#RV-PRECISION-001 (NEAR-UNKNOWN-TOOLCHAIN-B1, P+C/Full)"
        ),
        "release_qualified": False,
    }, indent=2)+"\n", encoding="utf-8")
    archive_path = destination / "openclaw-guard-hook.tgz"
    with archive_path.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for item in sorted(bundle.iterdir()):
                    info = archive.gettarinfo(str(item), arcname=f"package/{item.name}")
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ""
                    info.mode = 0o644
                    with item.open("rb") as source:
                        archive.addfile(info, source)
    files = [*sorted(bundle.iterdir()), archive_path]
    checksums = {str(item.relative_to(destination)): hashlib.sha256(item.read_bytes()).hexdigest() for item in files}
    (destination / "SHA256SUMS").write_text("".join(f"{checksum}  {name}\n" for name, checksum in checksums.items()), encoding="utf-8")
    return {"status": "test-candidate", "directory": str(destination), "archive": str(archive_path),
            "sha256": checksums[archive_path.name], "release_qualified": False}
