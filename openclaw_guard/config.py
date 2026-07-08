from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from openclaw_guard import PRODUCT_NAME, PRODUCT_NAME_ZH, __version__


@dataclass
class AppPaths:
    project_dir: Path
    output_dir: Path
    runtime_dir: Path
    export_dir: Path
    policy_dir: Path
    report_dir: Path
    audit_dir: Path
    fix_dir: Path

    def ensure(self) -> None:
        for path in (
            self.project_dir,
            self.output_dir,
            self.runtime_dir,
            self.export_dir,
            self.policy_dir,
            self.report_dir,
            self.audit_dir,
            self.fix_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def to_dict(self) -> dict[str, str]:
        return {key: str(value) for key, value in asdict(self).items()}


@dataclass
class OpenClawTarget:
    root: Path | None = None
    config_path: Path | None = None
    workspace_path: Path | None = None
    logs_path: Path | None = None
    profile: str | None = None
    source_root: Path | None = None
    gateway_port: int | None = None
    gateway_bind: str | None = None
    gateway_host: str | None = None
    gateway_urls: list[str] = field(default_factory=list)
    auth_mode: str | None = None
    reachability_state: str = "unreachable"
    reachable_ports: list[int] = field(default_factory=list)
    current_model: str | None = None
    current_agent: str | None = None
    available_models: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root) if self.root else None,
            "config_path": str(self.config_path) if self.config_path else None,
            "workspace_path": str(self.workspace_path) if self.workspace_path else None,
            "logs_path": str(self.logs_path) if self.logs_path else None,
            "profile": self.profile,
            "source_root": str(self.source_root) if self.source_root else None,
            "gateway_port": self.gateway_port,
            "gateway_bind": self.gateway_bind,
            "gateway_host": self.gateway_host,
            "gateway_urls": list(self.gateway_urls),
            "auth_mode": self.auth_mode,
            "reachability_state": self.reachability_state,
            "reachable_ports": list(self.reachable_ports),
            "current_model": self.current_model,
            "current_agent": self.current_agent,
            "available_models": list(self.available_models),
        }


@dataclass
class GuardSettings:
    host: str = "127.0.0.1"
    port: int = 8780
    policy_template: str = "police-default"
    read_only: bool = False
    ui_mode: str = "pro"
    sqlite_path: Path | None = None
    json_backup_path: Path | None = None
    # Database configuration (PostgreSQL or SQLite)
    database_url: str | None = None  # e.g., "postgresql://user:pass@host:5432/db" or "sqlite:///path/to/db"
    # PostgreSQL specific
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "openclaw_guard"
    db_username: str = ""
    db_password: str = ""
    # Redis cache specific
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str | None = None
    redis_enabled: bool = False
    # Feature flags
    enable_ptrace: bool = True
    enable_ebpf: bool = True
    enable_hook_bridge: bool = True
    output_formats: tuple[str, ...] = ("json", "html", "pdf")
    performance_budget_cpu_avg: float = 3.0
    performance_budget_cpu_peak: float = 5.0
    performance_budget_memory_base_mb: int = 120
    performance_budget_memory_peak_mb: int = 200
    performance_budget_latency_ms: int = 200
    log_archive_days: int = 7

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        for key in ("sqlite_path", "json_backup_path"):
            value = payload.get(key)
            if isinstance(value, Path):
                payload[key] = str(value)
        # Don't expose password in to_dict
        payload.pop("db_password", None)
        if payload.get("redis_password"):
            payload["redis_password"] = "***"
        return payload

    def get_database_url(self) -> str | None:
        """Get the database connection URL"""
        if self.database_url:
            return self.database_url
        if self.db_username and self.db_name:
            return f"postgresql://{self.db_username}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"
        return None


@dataclass
class AppContext:
    paths: AppPaths
    target: OpenClawTarget
    settings: GuardSettings = field(default_factory=GuardSettings)

    def describe(self) -> dict[str, Any]:
        return {
            "product": {
                "name": PRODUCT_NAME,
                "name_zh": PRODUCT_NAME_ZH,
                "version": __version__,
            },
            "paths": self.paths.to_dict(),
            "target": self.target.to_dict(),
            "settings": self.settings.to_dict(),
        }


def default_paths(project_dir: Path) -> AppPaths:
    return AppPaths(
        project_dir=project_dir,
        output_dir=project_dir / "output",
        runtime_dir=project_dir / "runtime",
        export_dir=project_dir / "exports",
        policy_dir=project_dir / "policies",
        report_dir=project_dir / "output" / "reports",
        audit_dir=project_dir / "output" / "audit",
        fix_dir=project_dir / "output" / "fixes",
    )
