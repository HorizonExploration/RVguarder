from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import Any

from openclaw_guard.config import OpenClawTarget
from openclaw_guard.models import AssetRecord
from openclaw_guard.utils import collect_env_snapshot, first_lines


COMMON_PORTS = (19001, 18789)
SOURCE_SEARCH_DEPTH = 3
COMMON_CONFIG_PATTERNS = (
    "~/.openclaw-dev/openclaw.json",
    "~/.openclaw/openclaw.json",
)


def discover_openclaw(
    *,
    openclaw_root: Path | None = None,
    config_path: Path | None = None,
    profile: str | None = None,
    cwd: Path | None = None,
    home: Path | None = None,
) -> OpenClawTarget:
    resolved_home = home or Path.home()
    resolved_cwd = (cwd or Path.cwd()).resolve()
    explicit_root = openclaw_root.expanduser().resolve() if openclaw_root else None
    explicit_config = config_path.expanduser().resolve() if config_path else None

    source_root = _detect_source_root(explicit_root, resolved_cwd)
    found_config = explicit_config or _discover_config(profile=profile, cwd=resolved_cwd, home=resolved_home, source_root=source_root)
    config_data = _load_config_data(found_config)
    gateway_info = _extract_gateway_info(config_data)
    gateway_urls = _derive_gateway_urls(gateway_info)
    http_urls = _derive_http_urls(gateway_info)
    reachability = _probe_gateway(gateway_info["port"])

    root = explicit_root or (found_config.parent if found_config else source_root)
    workspace = _choose_existing_path(
        [
            (root / "workspace") if root else None,
            (resolved_home / ".openclaw-dev" / "workspace"),
            (resolved_home / ".openclaw" / "workspace"),
        ]
    )
    logs = _choose_existing_path(
        [
            (root / "logs") if root else None,
            Path("/tmp/openclaw"),
            Path("/tmp") / "openclaw",
        ]
    )
    return OpenClawTarget(
        root=root,
        config_path=found_config,
        workspace_path=workspace,
        logs_path=logs,
        profile=profile or _infer_profile(found_config),
        source_root=source_root,
        gateway_port=gateway_info["port"],
        gateway_bind=gateway_info["bind"],
        gateway_host=gateway_info["host"],
        gateway_urls=gateway_urls,
        web_urls=http_urls,
        auth_mode=gateway_info["auth_mode"],
        reachability_state=reachability["state"],
        reachable_ports=reachability["ports"],
        current_model=_extract_current_model(config_data),
        current_agent=_extract_current_agent(config_data),
        available_models=_extract_available_models(config_data),
    )


def collect_assets(target: OpenClawTarget) -> list[AssetRecord]:
    env = collect_env_snapshot()
    assets = [
        AssetRecord(category="system", name="platform", value=str(env["platform"]), source="runtime"),
        AssetRecord(category="system", name="python", value=str(env["python"]), source="runtime"),
        AssetRecord(category="system", name="hostname", value=str(env["hostname"]), source="runtime"),
        AssetRecord(category="system", name="user", value=str(env["user"]), source="runtime"),
    ]
    if target.root:
        assets.append(AssetRecord(category="openclaw", name="root", value=str(target.root), source="discovery"))
    if target.config_path:
        assets.append(AssetRecord(category="openclaw", name="config", value=str(target.config_path), source="discovery"))
    if target.workspace_path:
        assets.append(AssetRecord(category="openclaw", name="workspace", value=str(target.workspace_path), source="discovery"))
    if target.logs_path:
        assets.append(AssetRecord(category="openclaw", name="logs", value=str(target.logs_path), source="discovery"))
    for port in target.reachable_ports:
        assets.append(AssetRecord(category="network", name="open_port", value=str(port), source="socket_probe"))
    if target.current_model:
        assets.append(AssetRecord(category="openclaw", name="current_model", value=target.current_model, source="config"))
    if target.current_agent:
        assets.append(AssetRecord(category="openclaw", name="current_agent", value=target.current_agent, source="config"))
    if target.logs_path and target.logs_path.exists():
        for log in sorted(target.logs_path.glob("*.log"))[:5]:
            try:
                preview = " | ".join(first_lines(log.read_text(encoding="utf-8", errors="replace"), 2))
            except OSError:
                preview = ""
            assets.append(AssetRecord(category="log", name=log.name, value=str(log), detail=preview, source="logs"))
    return assets


def _discover_config(*, profile: str | None, cwd: Path, home: Path, source_root: Path | None = None) -> Path | None:
    candidates: list[Path] = []
    if profile:
        normalized = "dev" if profile == "dev" else profile
        candidates.extend(
            [
                home / f".openclaw-{normalized}" / "openclaw.json",
                home / f".openclaw-{normalized}.json",
            ]
        )
    for pattern in COMMON_CONFIG_PATTERNS:
        candidates.append(Path(os.path.expanduser(pattern)))
    candidates.extend(sorted(home.glob(".openclaw-*/openclaw.json")))
    search_roots = [cwd, *list(cwd.parents)[:4]]
    if source_root:
        search_roots.append(source_root)
    seen: set[Path] = set()
    for root in search_roots:
        resolved_root = root.expanduser()
        if resolved_root in seen:
            continue
        seen.add(resolved_root)
        candidates.append(resolved_root / "openclaw.json")
        candidates.extend(_bounded_find_named_file(resolved_root, "openclaw.json", max_depth=2))
    seen_paths: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.expanduser()
        if resolved in seen_paths:
            continue
        seen_paths.add(resolved)
        if resolved.exists():
            return resolved.resolve()
    return None


def _detect_source_root(explicit_root: Path | None, cwd: Path) -> Path | None:
    candidates: list[Path] = []
    if explicit_root is not None:
        candidates.append(explicit_root.resolve())
    candidates.append(cwd)
    candidates.extend(list(cwd.parents)[:4])
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if _looks_like_source_root(resolved):
            return resolved
        nested = _find_source_root_below(resolved)
        if nested is not None:
            return nested
    return None


def _find_source_root_below(base: Path) -> Path | None:
    if not base.exists() or not base.is_dir():
        return None
    queue: list[tuple[Path, int]] = [(base, 0)]
    seen: set[Path] = set()
    while queue:
        current, depth = queue.pop(0)
        resolved = current.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if depth > 0 and _looks_like_source_root(resolved):
            return resolved
        if depth >= SOURCE_SEARCH_DEPTH:
            continue
        try:
            children = sorted((child for child in resolved.iterdir() if child.is_dir()), key=lambda child: child.name.lower())
        except OSError:
            continue
        for child in children[:40]:
            if child.name.startswith(".git") or child.name in {"node_modules", ".venv", "venv", "dist", "build"}:
                continue
            queue.append((child, depth + 1))
    return None


def _looks_like_source_root(path: Path) -> bool:
    if not path.exists() or not path.is_dir():
        return False
    package_json = path / "package.json"
    dist_index = path / "dist" / "index.js"
    run_node = path / "scripts" / "run-node.mjs"
    try:
        return package_json.exists() and (dist_index.exists() or run_node.exists())
    except OSError:
        return False


def _bounded_find_named_file(root: Path, filename: str, max_depth: int = 2) -> list[Path]:
    matches: list[Path] = []
    for candidate in _bounded_directories(root, max_depth=max_depth):
        path = candidate / filename
        if path.exists():
            matches.append(path)
    return matches


def _bounded_directories(root: Path, *, max_depth: int = 2) -> list[Path]:
    try:
        iterator = os.walk(root)
    except OSError:
        return []
    base_depth = len(root.parts)
    results: list[Path] = []
    skipped = {".git", "node_modules", ".venv", "venv", "dist", "build", "runtime", "output", "ui"}
    for current, dirs, _files in iterator:
        current_path = Path(current)
        depth = len(current_path.parts) - base_depth
        if depth > max_depth:
            dirs[:] = []
            continue
        dirs[:] = [item for item in dirs if item not in skipped]
        results.append(current_path)
    return results


def _load_config_data(config_path: Path | None) -> dict[str, Any] | None:
    if config_path is None or not config_path.exists():
        return None
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _extract_gateway_info(config_data: dict[str, Any] | None) -> dict[str, Any]:
    gateway = config_data.get("gateway") if isinstance(config_data, dict) else None
    if not isinstance(gateway, dict):
        return {"bind": None, "host": "127.0.0.1", "port": COMMON_PORTS[0], "auth_mode": None}
    bind = _as_string(gateway.get("bind"))
    host = _as_string(gateway.get("host"))
    port = gateway.get("port")
    auth = gateway.get("auth")
    auth_mode = None
    if isinstance(auth, dict):
        auth_mode = _as_string(auth.get("mode"))
    normalized_host = host or ("0.0.0.0" if bind == "lan" else "127.0.0.1")
    return {
        "bind": bind,
        "host": normalized_host,
        "port": int(port) if isinstance(port, int) else COMMON_PORTS[0],
        "auth_mode": auth_mode,
    }


def _derive_gateway_urls(gateway_info: dict[str, Any]) -> list[str]:
    port = int(gateway_info["port"])
    host = str(gateway_info["host"] or "127.0.0.1")
    bind = str(gateway_info["bind"] or "").lower()
    urls: list[str] = []
    if bind in {"lan", "0.0.0.0"} or host in {"0.0.0.0", "::"}:
        urls.extend([f"ws://127.0.0.1:{port}", f"ws://localhost:{port}"])
    elif host:
        urls.extend(
            [
                f"ws://{host}:{port}",
                f"ws://127.0.0.1:{port}" if host not in {"127.0.0.1", "localhost"} else "",
                f"ws://localhost:{port}" if host != "localhost" else "",
            ]
        )
    urls.extend(f"ws://127.0.0.1:{candidate}" for candidate in COMMON_PORTS if candidate != port)
    unique: list[str] = []
    seen: set[str] = set()
    for url in urls:
        if not url or url in seen:
            continue
        seen.add(url)
        unique.append(url)
    return unique


def _derive_http_urls(gateway_info: dict[str, Any]) -> list[str]:
    """从 gateway 信息推导 HTTP 访问地址（用于浏览器跳转）。"""
    port = int(gateway_info["port"])
    host = str(gateway_info["host"] or "127.0.0.1")
    bind = str(gateway_info["bind"] or "").lower()
    urls: list[str] = []
    if bind in {"lan", "0.0.0.0"} or host in {"0.0.0.0", "::"}:
        urls.extend([f"http://127.0.0.1:{port}", f"http://localhost:{port}"])
    elif host:
        urls.extend(
            [
                f"http://{host}:{port}",
                f"http://127.0.0.1:{port}" if host not in {"127.0.0.1", "localhost"} else "",
                f"http://localhost:{port}" if host != "localhost" else "",
            ]
        )
    unique: list[str] = []
    seen: set[str] = set()
    for url in urls:
        if not url or url in seen:
            continue
        seen.add(url)
        unique.append(url)
    return unique


def _probe_gateway(port: int | None) -> dict[str, Any]:
    ports = [int(port)] if isinstance(port, int) else []
    ports.extend(common for common in COMMON_PORTS if common not in ports)
    reachable_ports: list[int] = []
    state = "unreachable"
    
    # Try socket probe first (fast)
    for candidate in ports:
        if _port_probe("127.0.0.1", candidate) == "reachable" or _port_probe("localhost", candidate) == "reachable":
            reachable_ports.append(candidate)
            state = "reachable"
            
    # If socket probe fails, it might be due to OS-level restrictions or IPv6 issues.
    # We don't do API call here because discovery should be side-effect free and not depend on adapter.
    return {"state": state, "ports": reachable_ports}


def _port_probe(host: str, port: int) -> str:
    try:
        # Increase timeout to be more resilient
        with socket.create_connection((host, port), timeout=1.5):
            return "reachable"
    except (PermissionError, ConnectionRefusedError, socket.timeout, OSError):
        return "unreachable"


def _choose_existing_path(candidates: list[Path | None]) -> Path | None:
    for candidate in candidates:
        if candidate is not None and candidate.exists():
            return candidate
    for candidate in candidates:
        if candidate is not None:
            return candidate
    return None


def _extract_current_model(config_data: dict[str, Any] | None) -> str | None:
    if not isinstance(config_data, dict):
        return None
    agents = config_data.get("agents")
    if isinstance(agents, dict):
        defaults = agents.get("defaults")
        if isinstance(defaults, dict):
            model = defaults.get("model")
            if isinstance(model, dict):
                primary = model.get("primary")
                if isinstance(primary, str) and primary:
                    return primary
    models = config_data.get("models")
    if isinstance(models, dict):
        providers = models.get("providers")
        if isinstance(providers, dict):
            for provider_name, provider in providers.items():
                if not isinstance(provider, dict):
                    continue
                model_list = provider.get("models")
                if isinstance(model_list, list) and model_list:
                    first = model_list[0]
                    if isinstance(first, str):
                        return f"{provider_name}/{first}"
                    if isinstance(first, dict):
                        ref = first.get("ref") or first.get("key") or first.get("id") or first.get("model") or first.get("name")
                        if isinstance(ref, str) and ref:
                            return f"{provider_name}/{ref}"
    return None


def _extract_current_agent(config_data: dict[str, Any] | None) -> str | None:
    if not isinstance(config_data, dict):
        return None
    agents = config_data.get("agents")
    if isinstance(agents, dict):
        defaults = agents.get("defaults")
        if isinstance(defaults, dict):
            name = defaults.get("name")
            if isinstance(name, str) and name:
                return name
    return "default"


def _extract_available_models(config_data: dict[str, Any] | None) -> list[str]:
    if not isinstance(config_data, dict):
        return []
    output: list[str] = []
    models = config_data.get("models")
    providers = models.get("providers") if isinstance(models, dict) else None
    if not isinstance(providers, dict):
        return []
    for provider_name, provider in providers.items():
        if not isinstance(provider, dict):
            continue
        model_list = provider.get("models")
        if not isinstance(model_list, list):
            continue
        for item in model_list:
            if isinstance(item, str):
                output.append(f"{provider_name}/{item}")
            elif isinstance(item, dict):
                ref = item.get("ref") or item.get("key") or item.get("id") or item.get("model") or item.get("name")
                if isinstance(ref, str) and ref:
                    output.append(f"{provider_name}/{ref}")
    unique: list[str] = []
    seen: set[str] = set()
    for item in output:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def _infer_profile(config_path: Path | None) -> str | None:
    if config_path is None:
        return None
    parent_name = config_path.expanduser().resolve().parent.name
    if parent_name == ".openclaw":
        return "default"
    if parent_name.startswith(".openclaw-"):
        return parent_name.removeprefix(".openclaw-")
    return None


def _as_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None
