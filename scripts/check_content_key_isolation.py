"""最小Docker密钥挂载边界检查；不是OpenClaw安全效果实验。"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

def main() -> None:
    """只用本地镜像运行自动删除容器，保留脱敏边界报告。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="openclaw-sandbox:bookworm-slim")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    image = subprocess.run(["docker", "image", "inspect", args.image, "--format", "{{.Id}}"],
                           text=True, capture_output=True, check=True, timeout=15).stdout.strip()
    with tempfile.TemporaryDirectory(prefix="rv-content-isolation-") as directory:
        root = Path(directory)
        workspace = root / "workspace"
        workspace.mkdir()
        fixture_dir = root / "host"
        fixture_dir.mkdir(mode=0o700)
        key = fixture_dir / "public-fixture.bin"
        # 已公开的固定字节，绝不生成或挂载真实/临时签名密钥。
        key.write_bytes(bytes(32))
        key.chmod(0o600)
        before = hashlib.sha256(key.read_bytes()).hexdigest()
        profile = ["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
                   "--security-opt=no-new-privileges", "--user", f"{os.getuid()}:{os.getgid()}",
                   "--mount", f"type=bind,source={workspace},target=/workspace"]
        probes = [
            ("agent_workspace_writable", [], "touch /workspace/probe"),
            ("agent_private_fixture_unmounted", [], "test ! -e /host/public-fixture.bin"),
            ("agent_docker_socket_absent", [], "test ! -e /var/run/docker.sock"),
            ("agent_host_path_absent", [], f"test ! -e {key}"),
            ("trusted_executor_private_fixture_readable", ["--mount", f"type=bind,source={fixture_dir},target=/host,readonly"],
             "test $(wc -c < /host/public-fixture.bin) -eq 32"),
            ("trusted_executor_cannot_overwrite_fixture", ["--mount", f"type=bind,source={fixture_dir},target=/host,readonly"],
             "if (printf forbidden > /host/public-fixture.bin) 2>/dev/null; then exit 1; else exit 0; fi"),
        ]
        results = []
        for name, mounts, command in probes:
            result = subprocess.run([*profile, *mounts, "--entrypoint=/bin/sh", args.image, "-c", command],
                                    text=True, capture_output=True, timeout=30, check=False)
            results.append({"probe": name, "passed": result.returncode == 0, "exit_code": result.returncode})
        results.append({"probe": "host_fixture_unchanged", "passed": before == hashlib.sha256(key.read_bytes()).hexdigest()})
    report = {"schema_version": 1, "recorded_at": datetime.now(timezone.utc).isoformat(), "image": args.image,
              "image_id": image, "scope": "minimal Docker mount boundary; not OpenClaw integration or attack efficacy",
              "fixture": "public constant 32 zero bytes; no signing key generated or exposed",
              "agent_profile": {"network": "none", "rootfs": "read-only", "capabilities": "drop ALL",
                                "no_new_privileges": True, "host_socket_mounted": False, "host_key_mounted": False},
              "results": results, "passed": all(row["passed"] for row in results),
              "limits": ["Production OpenClaw executor placement and tool transport remain unverified",
                         "Mounting the key or Docker socket into an Agent invalidates this isolation profile"]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "probes": len(results), "output": str(args.output)}))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
