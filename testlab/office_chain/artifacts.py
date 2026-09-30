"""办公链式攻击价值实验的冻结摘要与不可覆盖产物工具。

与 v3 ``testlab/office_value/report.py`` 保持同一测量纪律：规范化 JSON 摘要、
一次性写出的产物目录不可覆盖。
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence


MANIFEST_SCHEMA_VERSION = 1


def canonical_json(value: Any) -> str:
    """Return the canonical JSON encoding used for every frozen digest."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_json(value: Any) -> str:
    """Return the sha256 hex of the canonical JSON encoding of ``value``."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def write_immutable_bundle(output_dir: str | Path, files: dict[str, str | bytes]) -> dict[str, str]:
    """Write one immutable bundle to a fresh directory.

    ``dict`` / ``list`` values are serialized as indented JSON.  An existing
    destination directory is never overwritten.
    """
    destination = Path(output_dir)
    if destination.exists():
        raise FileExistsError(f"拒绝写入既有目录：{destination}")
    destination.mkdir(parents=True, exist_ok=False)
    written: dict[str, str] = {}
    for name, content in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        elif isinstance(content, str):
            target.write_text(content, encoding="utf-8")
        elif isinstance(content, (dict, list)):
            target.write_text(json.dumps(content, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        else:
            raise TypeError(f"不支持的文件内容类型：{type(content).__name__}（{name}）")
        written[str(name)] = str(target)
    return written


def source_revision(repo_root: str | Path, paths: Sequence[str]) -> dict[str, Any]:
    """记录代码修订与相关文件的工作树状态。

    bundle 必须能回答"这份报告由哪一版代码产生"；只记场景/配置哈希不足以复核策略代码本身。
    取不到 git 时如实写 ``unavailable``，绝不留空或伪造。
    """

    root = Path(repo_root)

    def _git(*args: str) -> str | None:
        try:
            result = subprocess.run(
                ["git", *args], cwd=root, check=True, capture_output=True, text=True, timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return result.stdout

    commit = (_git("rev-parse", "HEAD") or "").strip()
    status = _git("status", "--porcelain", "--", *paths) or ""
    dirty_paths = [line[3:] for line in status.splitlines() if line.strip()]
    return {
        "commit": commit or "unavailable",
        "dirty": bool(dirty_paths),
        "dirty_paths": dirty_paths,
        "scope": list(paths),
    }


def build_manifest(
    *,
    suite_id: str,
    scenario_digest: str,
    run_spec: Any,
    component_sets: Any,
    artifact_files: Any,
    openclaw_version: str,
    docker_version: str,
    image: str,
    claims: Any,
    source_revision: Any = None,
) -> dict[str, Any]:
    """Assemble the frozen manifest for one immutable run bundle.

    The manifest records the input digest, rule/config hashes, OpenClaw and
    Docker versions, the component on/off sets, the artifact file list and the
    caller-supplied claims (including the "no real external side effects"
    declaration).  ``source_revision`` records which code revision produced the
    bundle.
    """
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "suite_id": suite_id,
        "scenario_digest": scenario_digest,
        "run_spec": run_spec,
        "run_spec_digest": digest_json(run_spec),
        "component_sets": component_sets,
        "component_digest": digest_json(component_sets),
        "config_digest": digest_json({"run_spec": run_spec, "component_sets": component_sets}),
        "artifact_files": list(artifact_files),
        "openclaw_version": openclaw_version,
        "docker_version": docker_version,
        "image": image,
        "source_revision": dict(source_revision) if isinstance(source_revision, Mapping) else None,
        "claims": claims,
    }
