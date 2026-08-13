from __future__ import annotations

import os
import shlex
import stat
import time
from pathlib import Path

from openclaw_guard.config import AppContext
from openclaw_guard.integrations.discovery import collect_assets
from openclaw_guard.models import AssetRecord, BaselineCheck, BaselineFinding, ComplianceReport
from openclaw_guard.utils import build_simple_pdf, utc_now_iso, write_json


class BaselineScanner:
    def __init__(self, context: AppContext) -> None:
        self.context = context

    def run(self) -> ComplianceReport:
        start = time.perf_counter()
        assets = collect_assets(self.context.target)
        checks: list[BaselineCheck] = []
        checks.extend(self._scan_config_permissions())
        checks.extend(self._scan_gateway_auth())
        checks.extend(self._scan_plugin_trust_policy())
        checks.extend(self._scan_workspace_and_logs())
        checks.extend(self._scan_runtime_user())
        checks.extend(self._scan_open_ports(assets))
        checks.extend(self._scan_gateway_health())
        checks.extend(self._scan_hook_runtime())
        checks.extend(self._scan_model_resolution())
        checks.extend(self._scan_dependencies())
        checks.extend(self._scan_os_security())
        findings = [_finding_from_check(item) for item in checks if item.status != "ok"]
        findings = sorted(findings, key=lambda item: (_severity_rank(item.severity), item.finding_id))
        checks = sorted(checks, key=lambda item: (_check_status_rank(item.status), _severity_rank(item.severity), item.check_id))
        average = round(time.perf_counter() - start, 4)
        report = ComplianceReport(
            generated_at=utc_now_iso(),
            target_root=str(self.context.target.root) if self.context.target.root else None,
            config_path=str(self.context.target.config_path) if self.context.target.config_path else None,
            findings=findings,
            checks=checks,
            assets=assets,
            average_seconds=average,
        )
        outputs = self.write_outputs(report)
        report.outputs = outputs
        return report

    def write_outputs(self, report: ComplianceReport) -> dict[str, str]:
        self.context.paths.report_dir.mkdir(parents=True, exist_ok=True)
        json_path = self.context.paths.report_dir / "compliance-report.json"
        html_path = self.context.paths.report_dir / "compliance-report.html"
        pdf_path = self.context.paths.report_dir / "compliance-report.pdf"
        fix_path = self.context.paths.fix_dir / "baseline-remediation.sh"
        write_json(json_path, report.to_dict())
        html_path.write_text(_render_html(report), encoding="utf-8")
        build_simple_pdf(
            pdf_path,
            "Openclaw Guard Compliance Report",
            [f"{item.severity.upper()} {item.title} - {item.recommendation}" for item in report.findings],
        )
        fix_path.parent.mkdir(parents=True, exist_ok=True)
        fix_path.write_text(_render_fix_script(report), encoding="utf-8")
        fix_path.chmod(0o755)
        return {
            "json": str(json_path),
            "html": str(html_path),
            "pdf": str(pdf_path),
            "fix_script": str(fix_path),
        }

    def _scan_config_permissions(self) -> list[BaselineCheck]:
        path = self.context.target.config_path
        if not path or not path.exists():
            return [
                BaselineCheck(
                    check_id="BASE-001",
                    category="config",
                    title="未找到 OpenClaw 配置文件",
                    status="risk",
                    severity="high",
                    description="无法定位 openclaw.json，无法完成高可信合规检查。",
                    evidence={"config_path": str(path) if path else None},
                    recommendation="显式指定 --config-path，或先完成 OpenClaw 初始化。",
                )
            ]
        mode = stat.S_IMODE(path.stat().st_mode)
        checks: list[BaselineCheck] = [
            BaselineCheck(
                check_id="BASE-001A",
                category="config",
                title="已定位 OpenClaw 配置文件",
                status="ok",
                severity="info",
                description="OpenClaw 主配置文件可正常读取。",
                evidence={"path": str(path)},
                recommendation="保持配置路径稳定，并纳入变更管理。",
            )
        ]
        if mode & 0o077:
            checks.append(
                BaselineCheck(
                    check_id="BASE-002",
                    category="config",
                    title="OpenClaw 配置权限过宽",
                    status="risk",
                    severity="high",
                    description="openclaw.json 对组或其他用户可读写，不符合高安全场景最小权限原则。",
                    evidence={"path": str(path), "mode": oct(mode)},
                    recommendation="调整为 600 或 640，并确认仅管理账户可访问。",
                )
            )
        else:
            checks.append(
                BaselineCheck(
                    check_id="BASE-002A",
                    category="config",
                    title="OpenClaw 配置权限符合最小权限原则",
                    status="ok",
                    severity="info",
                    description="配置文件权限未向组和其他用户暴露。",
                    evidence={"path": str(path), "mode": oct(mode)},
                    recommendation="继续保持最小权限配置。",
                )
            )
        return checks

    def _scan_gateway_auth(self) -> list[BaselineCheck]:
        path = self.context.target.config_path
        if not path or not path.exists():
            return []
        try:
            import json

            config = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return [
                BaselineCheck(
                    check_id="BASE-002B",
                    category="config",
                    title="无法解析 gateway 鉴权配置",
                    status="warn",
                    severity="medium",
                    description="配置文件存在，但未能可靠解析 gateway 鉴权设置。",
                    evidence={"path": str(path)},
                    recommendation="检查 openclaw.json 的 JSON 格式是否完整，并确认 gateway.auth 字段正确。",
                )
            ]
        gateway = config.get("gateway") if isinstance(config, dict) else None
        auth = gateway.get("auth") if isinstance(gateway, dict) else None
        bind = gateway.get("bind") if isinstance(gateway, dict) else None
        checks: list[BaselineCheck] = []
        if isinstance(auth, dict) and auth.get("mode") in {"password", "token"}:
            checks.append(
                BaselineCheck(
                    check_id="BASE-002C",
                    category="config",
                    title="Gateway 鉴权已启用",
                    status="ok",
                    severity="info",
                    description="OpenClaw gateway 已配置鉴权模式。",
                    evidence={"auth_mode": auth.get("mode")},
                    recommendation="继续妥善保管 gateway 凭据，并避免在脚本中明文暴露。",
                )
            )
        else:
            checks.append(
                BaselineCheck(
                    check_id="BASE-002D",
                    category="config",
                    title="Gateway 鉴权未明确启用",
                    status="risk",
                    severity="high",
                    description="未检测到明确的 gateway.auth.mode，高安全场景下不建议开放无鉴权入口。",
                    evidence={"auth": auth if isinstance(auth, dict) else auth},
                    recommendation="至少启用 password 或 token 模式，并将凭据纳入安全分发流程。",
                )
            )
        if str(bind or "").lower() in {"lan", "0.0.0.0"}:
            checks.append(
                BaselineCheck(
                    check_id="BASE-002E",
                    category="network",
                    title="Gateway 当前对局域网暴露",
                    status="warn",
                    severity="medium",
                    description="检测到 gateway 以局域网绑定模式运行，需结合内网边界控制与鉴权策略评估暴露面。",
                    evidence={"bind": bind, "port": self.context.target.gateway_port},
                    recommendation="若无跨设备接入需求，优先改为仅监听本机回环地址；如必须开放，请确保鉴权与边界访问控制到位。",
                )
            )
        else:
            checks.append(
                BaselineCheck(
                    check_id="BASE-002F",
                    category="network",
                    title="Gateway 仅监听本机地址",
                    status="ok",
                    severity="info",
                    description="gateway 未对局域网额外暴露。",
                    evidence={"bind": bind, "port": self.context.target.gateway_port},
                    recommendation="继续保持本机监听模式，减少不必要暴露面。",
                )
            )
        return checks

    def _scan_runtime_user(self) -> list[BaselineCheck]:
        user = os.environ.get("USER") or os.environ.get("USERNAME") or ""
        if user.lower() in {"root", "administrator"}:
            return [
                BaselineCheck(
                    check_id="BASE-003",
                    category="runtime",
                    title="OpenClaw 可能以高权限账户运行",
                    status="risk",
                    severity="high",
                    description="检测到当前账户接近系统管理员权限，存在权限越界风险。",
                    evidence={"user": user},
                    recommendation="建议为 OpenClaw 与 Openclaw Guard 分配专用低权限服务账户。",
                )
            ]
        return [
            BaselineCheck(
                check_id="BASE-003A",
                category="runtime",
                title="运行账户权限级别正常",
                status="ok",
                severity="info",
                description="当前账户不是系统级管理员账户。",
                evidence={"user": user},
                recommendation="继续使用专用低权限账户运行。",
            )
        ]

    def _scan_workspace_and_logs(self) -> list[BaselineCheck]:
        checks: list[BaselineCheck] = []
        workspace = self.context.target.workspace_path
        logs = self.context.target.logs_path
        if workspace and workspace.exists():
            checks.append(
                BaselineCheck(
                    check_id="BASE-010A",
                    category="runtime",
                    title="工作区目录可访问",
                    status="ok",
                    severity="info",
                    description="已找到 OpenClaw 工作区目录。",
                    evidence={"workspace": str(workspace)},
                    recommendation="保持工作区路径稳定，并纳入备份策略。",
                )
            )
        else:
            checks.append(
                BaselineCheck(
                    check_id="BASE-010",
                    category="runtime",
                    title="工作区目录缺失",
                    status="warn",
                    severity="medium",
                    description="未定位到 OpenClaw 工作区，可能影响上下文、文件工具和取证。",
                    evidence={"workspace": str(workspace) if workspace else None},
                    recommendation="确认 OpenClaw 工作区目录已初始化并可访问。",
                )
            )
        if logs and logs.exists():
            checks.append(
                BaselineCheck(
                    check_id="BASE-011A",
                    category="audit",
                    title="日志目录可访问",
                    status="ok",
                    severity="info",
                    description="已找到 OpenClaw 日志目录。",
                    evidence={"logs": str(logs)},
                    recommendation="继续保留日志目录，并定期归档。",
                )
            )
        else:
            checks.append(
                BaselineCheck(
                    check_id="BASE-011",
                    category="audit",
                    title="日志目录缺失",
                    status="warn",
                    severity="medium",
                    description="未发现日志目录，可能影响审计取证与运行问题定位。",
                    evidence={"logs": str(logs) if logs else None},
                    recommendation="确认 OpenClaw 日志目录存在并对当前账户可读。",
                )
            )
        return checks

    def _scan_open_ports(self, assets: list[AssetRecord]) -> list[BaselineCheck]:
        checks: list[BaselineCheck] = []
        seen_ports: set[int] = set()
        expected_ports = {8780, 19001}
        if self.context.target.gateway_port:
            expected_ports.add(int(self.context.target.gateway_port))
        for item in assets:
            if item.category != "network":
                continue
            try:
                port = int(item.value)
            except (TypeError, ValueError):
                continue
            if port in seen_ports or port in expected_ports:
                continue
            seen_ports.add(port)
            if port not in expected_ports:
                checks.append(
                    BaselineCheck(
                        check_id=f"BASE-004-{port}",
                        category="network",
                        title="发现额外开放端口",
                        status="warn",
                        severity="medium",
                        description="运行环境检测到额外监听端口，可能扩大攻击面。",
                        evidence={"port": str(port)},
                        recommendation="核实监听服务必要性，关闭与 OpenClaw 无关的暴露端口。",
                    )
                )
        if not checks:
            checks.append(
                BaselineCheck(
                    check_id="BASE-004A",
                    category="network",
                    title="未发现异常开放端口",
                    status="ok",
                    severity="info",
                    description="除了 Guard 与 OpenClaw 预期端口外，未发现异常监听端口。",
                    evidence={},
                    recommendation="保持端口最小暴露。",
                )
            )
        return checks

    def _scan_gateway_health(self) -> list[BaselineCheck]:
        # Prioritize reachability_state which might have been overridden by manager using real API status
        is_reachable = self.context.target.reachability_state == "reachable"
        
        evidence = {
            "gateway_port": self.context.target.gateway_port,
            "gateway_bind": self.context.target.gateway_bind,
            "gateway_urls": list(self.context.target.gateway_urls),
            "reachability_state": self.context.target.reachability_state,
        }

        if is_reachable:
            return [
                BaselineCheck(
                    check_id="BASE-012A",
                    category="runtime",
                    title="OpenClaw gateway 端口可达",
                    status="ok",
                    severity="info",
                    description="已检测到 gateway 监听端口可达或 API 通信正常。",
                    evidence=evidence,
                    recommendation="保持 gateway 在内网可控范围内运行。",
                )
            ]
        return [
            BaselineCheck(
                check_id="BASE-012",
                category="runtime",
                title="OpenClaw gateway 当前不可达",
                status="risk",
                severity="high",
                description="当前没有从 Guard 侧确认到 gateway 可达，实时拦截与对话能力可能失效。",
                evidence=evidence,
                recommendation="确认 OpenClaw gateway 已启动，并检查本机回环地址与鉴权配置。",
            )
        ]

    def _scan_hook_runtime(self) -> list[BaselineCheck]:
        runtime_hook = self.context.target.config_path
        plugin_dir = self.context.paths.runtime_dir / "openclaw-guard-plugin"
        if plugin_dir.exists():
            return [
                BaselineCheck(
                    check_id="BASE-013A",
                    category="audit",
                    title="Guard Hook 插件目录已生成",
                    status="ok",
                    severity="info",
                    description="本地运行时 Hook 插件已生成，可供 OpenClaw 加载。",
                    evidence={"plugin_dir": str(plugin_dir), "config_path": str(runtime_hook) if runtime_hook else None},
                    recommendation="如首次写入配置，请重启 OpenClaw gateway 使 Hook 生效。",
                )
            ]
        return [
            BaselineCheck(
                check_id="BASE-013",
                category="audit",
                title="Guard Hook 插件未生成",
                status="risk",
                severity="high",
                description="未发现 Guard Hook 插件目录，OpenClaw 工具执行前拦截链无法建立。",
                evidence={"plugin_dir": str(plugin_dir)},
                recommendation="重新启动 Openclaw Guard，确保运行时 Hook 插件成功生成。",
            )
        ]

    def _scan_plugin_trust_policy(self) -> list[BaselineCheck]:
        path = self.context.target.config_path
        if not path or not path.exists():
            return []
        try:
            import json

            config = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        plugins = config.get("plugins") if isinstance(config, dict) else None
        allow = plugins.get("allow") if isinstance(plugins, dict) else None
        if isinstance(allow, list) and allow:
            return [
                BaselineCheck(
                    check_id="BASE-013B",
                    category="audit",
                    title="插件信任列表已显式配置",
                    status="ok",
                    severity="info",
                    description="plugins.allow 已显式列出受信插件，插件加载边界更清晰。",
                    evidence={"allow": allow},
                    recommendation="继续保持最小信任清单，仅保留必要插件。",
                )
            ]
        return [
            BaselineCheck(
                check_id="BASE-013C",
                category="audit",
                title="插件信任列表未显式配置",
                status="warn",
                severity="medium",
                description="当前 plugins.allow 为空，非内置插件可能按发现结果自动加载，存在供应链与配置漂移风险。",
                evidence={"allow": allow if isinstance(allow, list) else None},
                recommendation="在 plugins.allow 中明确列出受信插件 ID，例如 openclaw-guard-hook，避免无意加载未知插件。",
            )
        ]

    def _scan_model_resolution(self) -> list[BaselineCheck]:
        if self.context.target.current_model:
            return [
                BaselineCheck(
                    check_id="BASE-014A",
                    category="runtime",
                    title="当前模型已识别",
                    status="ok",
                    severity="info",
                    description="已从 OpenClaw 配置中识别出当前模型。",
                    evidence={"model": self.context.target.current_model, "agent": self.context.target.current_agent},
                    recommendation="继续保持模型配置可解析，便于风险联动与前端切换。",
                )
            ]
        return [
            BaselineCheck(
                check_id="BASE-014",
                category="runtime",
                title="当前模型未识别",
                status="warn",
                severity="medium",
                description="Guard 尚未从配置中识别出当前模型，可能影响前端展示与调试。",
                evidence={"agent": self.context.target.current_agent},
                recommendation="检查 OpenClaw 配置中的默认模型和 provider 是否完整。",
            )
        ]

    def _scan_dependencies(self) -> list[BaselineCheck]:
        source_root = self.context.target.source_root
        if source_root and (source_root / "package.json").exists():
            return [
                BaselineCheck(
                    check_id="BASE-005A",
                    category="dependency",
                    title="已发现 OpenClaw 源码依赖描述",
                    status="ok",
                    severity="info",
                    description="已定位 package.json，可继续进行依赖合规分析。",
                    evidence={"source_root": str(source_root)},
                    recommendation="保留依赖描述文件，便于持续审计。",
                )
            ]
        return [
            BaselineCheck(
                check_id="BASE-005",
                category="dependency",
                title="未发现 OpenClaw 源码依赖描述",
                status="warn",
                severity="low",
                description="未定位到 package.json，依赖合规信息可能不完整。",
                evidence={"source_root": str(source_root) if source_root else None},
                recommendation="若使用源码部署，建议保留 package.json 以便进行依赖审计。",
            )
        ]

    def _scan_os_security(self) -> list[BaselineCheck]:
        checks: list[BaselineCheck] = []
        if Path("/etc").exists() and not Path("/etc/hosts").exists():
            checks.append(
                BaselineCheck(
                    check_id="BASE-006",
                    category="os",
                    title="系统基础安全配置异常",
                    status="warn",
                    severity="medium",
                    description="系统基础网络配置缺失，可能影响运行时解析与审计。",
                    evidence={"path": "/etc/hosts"},
                    recommendation="恢复系统基础配置，并记录变更来源。",
                )
            )
        else:
            checks.append(
                BaselineCheck(
                    check_id="BASE-006A",
                    category="os",
                    title="系统基础网络配置正常",
                    status="ok",
                    severity="info",
                    description="系统基础网络配置存在，可支持运行时解析与审计。",
                    evidence={"path": "/etc/hosts"},
                    recommendation="保持系统基础配置完整。",
                )
            )
        return checks


def _finding_from_check(check: BaselineCheck) -> BaselineFinding:
    return BaselineFinding(
        finding_id=check.check_id,
        severity=check.severity,
        category=check.category,
        title=check.title,
        description=check.description,
        evidence=check.evidence,
        recommendation=check.recommendation,
        compliant=check.status == "ok",
    )


def _render_html(report: ComplianceReport) -> str:
    checks = "\n".join(
        f"<tr><td>{item.status}</td><td>{item.category}</td><td>{item.title}</td><td>{item.description}</td><td>{item.recommendation}</td></tr>"
        for item in report.checks
    )
    findings = "\n".join(
        f"<tr><td>{item.severity}</td><td>{item.category}</td><td>{item.title}</td><td>{item.recommendation}</td></tr>"
        for item in report.findings
    )
    assets = "\n".join(
        f"<tr><td>{item.category}</td><td>{item.name}</td><td>{item.value}</td><td>{item.detail}</td></tr>"
        for item in report.assets
    )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>Openclaw Guard 合规报告</title>
  <style>
    body {{ font-family: "PingFang SC", "Segoe UI", sans-serif; margin: 32px; color: #1f2937; background: #f7f8fb; }}
    .card {{ background: white; border-radius: 18px; padding: 24px; margin-bottom: 20px; box-shadow: 0 16px 40px rgba(15, 23, 42, 0.08); }}
    h1, h2 {{ margin-top: 0; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 12px; border-bottom: 1px solid #e5e7eb; text-align: left; vertical-align: top; }}
    .pill {{ display: inline-block; border-radius: 999px; padding: 4px 10px; background: #eef2ff; color: #312e81; margin-right: 8px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Openclaw Guard（龙虾卫士）基线合规报告</h1>
    <p>生成时间：{report.generated_at}</p>
    <p>目标根目录：{report.target_root or "未识别"}</p>
    <p>配置路径：{report.config_path or "未识别"}</p>
    <p><span class="pill">耗时 {report.average_seconds:.4f}s</span><span class="pill">发现项 {len(report.findings)}</span></p>
  </div>
  <div class="card">
    <h2>完整检查项</h2>
    <table>
      <thead><tr><th>状态</th><th>类别</th><th>检查项</th><th>说明</th><th>整改建议</th></tr></thead>
      <tbody>{checks or "<tr><td colspan='5'>暂无检查结果</td></tr>"}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>不合规项</h2>
    <table>
      <thead><tr><th>等级</th><th>类别</th><th>问题</th><th>整改建议</th></tr></thead>
      <tbody>{findings or "<tr><td colspan='4'>未发现问题</td></tr>"}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>资产概览</h2>
    <table>
      <thead><tr><th>类别</th><th>名称</th><th>值</th><th>说明</th></tr></thead>
      <tbody>{assets}</tbody>
    </table>
  </div>
</body>
</html>
"""


def _render_fix_script(report: ComplianceReport) -> str:
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "# Openclaw Guard generated remediation helper",
    ]
    for finding in report.findings:
        if finding.finding_id == "BASE-002":
            path = finding.evidence.get("path")
            if path:
                lines.append(f"chmod 600 {shlex.quote(str(path))}")
    if len(lines) == 3:
        lines.append('echo "No one-click remediation actions were generated."')
    return "\n".join(lines) + "\n"


def _severity_rank(value: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(value, 99)


def _check_status_rank(value: str) -> int:
    order = {"risk": 0, "warn": 1, "ok": 2}
    return order.get(value, 99)
