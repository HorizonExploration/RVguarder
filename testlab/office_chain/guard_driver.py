"""guard 臂真实运行驱动（office-attack-chain-v1）。

本模块在**真实 OpenClaw 2026.9.5** 上执行 office-chain 场景，但额外在**同进程**
内启动 RVguarder（``build_manager`` + ``launch_web``），并把 OpenClaw 的
``before_tool_call`` Hook 通过运行期插件回连到 guard 的 ``/api/hook/before-tool-call``。

与 B0（:mod:`testlab.office_chain.office_driver`）的唯一区别是"是否加载 RVguarder 并
启用哪些组件"：原生 gateway、Docker 沙箱、工具 allow/deny、冻结轨迹 provider、原生审批、
合成 receipts 与准入纪律完全一致，因此两臂的 Hook payload 逐位可比。

关键设计：

- **同进程组件门**：整段真实运行包在 ``experiment_components.using(arm.components())``
  内。该组件门是进程级全局且不读环境变量，因此 guard 必须与驱动同进程。
- **冻结语义回放**：通过 ``openclaw_guard.services.semantic_enhancer_factory`` 这个
  模块级可选钩子（默认 ``None``，生产行为不变）把 ``SemanticEnhancer`` 的
  ``llm_transport`` 绑定到 ``ReplayLLMTransport``，实验期**绝不**发起真实模型 HTTP。
- **guard 生命周期**：先选 guard 端口 → 写基础 OpenClaw 配置 → ``build_manager``
  （其内部会急切注册 Hook 插件，因此配置必须已存在）→ ``launch_web`` → 等
  ``/api/health`` 通过 → ``install_hook`` → 才启动真实 gateway；结束/异常按相反顺序清理。
- **延迟口径**：包装 ``manager.handle_before_tool_call`` 测量 **in-process guard 决策
  延迟**（不含 gateway→guard 的 loopback HTTP 传输），按 ``(sessionKey, toolCallId)`` 归类。

本模块不伪造任何结果：准入、攻击目标裁定与事件判定全部复用 B0 口径。
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Iterator

import openclaw_guard.integrations.hook_runtime as hook_runtime
import openclaw_guard.services as guard_services
from openclaw_guard.engine import experiment_components
from openclaw_guard.engine.semantic_enhancer import SemanticEnhancer

from .arms import GUARD_ARMS, arm_spec, native_projection_sha256
from .native_baseline import default_plugin_dir, resolve_b0_config
from .office_driver import (
    EGRESS_EFFECT_KINDS,
    OFFICE_TOOLS,
    _Gateway,
    _adjudicate_attack_goal,
    _build_events,
    _child_env,
    _docker_ps_ids,
    _free_port,
    _json_rows,
    _list_automations,
    _run_agent_with_approvals,
    _segments,
    _successful_tool_names,
    compose_task_message,
    resolve_toolchain,
    seed_workspace,
)
from .semantic_recording import apply_recording, load_recording


#: OpenClaw Docker 会话沙箱镜像（B0 与 guard 臂一致）。
SANDBOX_IMAGE = "openclaw-sandbox:bookworm-slim"

_GUARD_HEALTH_TIMEOUT_SECONDS = 60.0
_LATENCY_NOTE = (
    "延迟口径：in-process guard 决策延迟（包装 manager.handle_before_tool_call），"
    "不含 gateway→guard 的 loopback HTTP 传输。"
)

#: guard 插件源码中"注册完成"的锚点行，用于实验期注入即时健康检查。
_EAGER_HEALTH_ANCHOR = (
    "api.logger.info(`[${PLUGIN_ID}] registered all hooks (5) via api.on()`);"
)
#: 实验期修正片段：OpenClaw 2026.9.5 在同一进程内把插件加载进两个注册表，
#: ``gateway_start`` 只在其中一个注册表触发健康检查，而派发 ``before_tool_call``
#: 的另一个注册表仍是 ``silent``，会静默放行所有工具。这里在 ``register()``
#: 结束时立即做一次健康检查，使每个插件实例都能进入 active。
#: 只修改**本实验生成的插件源码**，生产代码与默认行为完全不变。
_EAGER_HEALTH_SNIPPET = (
    "\n    // EXPERIMENT-ONLY: 立即健康检查，避免 before_tool_call 静默放行。"
    "\n    void doHealthCheck();"
)


@contextlib.contextmanager
def _eager_guard_health_check() -> Iterator[None]:
    """实验期：让生成的 guard 插件在注册时立即做一次健康检查。

    ``openclaw_guard.integrations.hook_runtime._plugin_source`` 是插件源码的唯一
    生成入口；本上下文只在实验进程内临时替换它，退出时严格还原，因此不改变
    生产代码与其默认行为。
    """

    original = hook_runtime._plugin_source

    def patched(*, guard_url: str, auth_token: str) -> str:
        source = original(guard_url=guard_url, auth_token=auth_token)
        if _EAGER_HEALTH_ANCHOR not in source:  # 生产源码变动时显式失败，绝不静默跳过
            raise RuntimeError("guard 插件源码缺少已知锚点，无法注入实验期健康检查")
        return source.replace(_EAGER_HEALTH_ANCHOR, _EAGER_HEALTH_ANCHOR + _EAGER_HEALTH_SNIPPET, 1)

    hook_runtime._plugin_source = patched  # type: ignore[assignment]
    try:
        yield
    finally:
        hook_runtime._plugin_source = original  # type: ignore[assignment]


class _GuardLatencyRecorder:
    """按 ``(sessionKey, toolCallId)`` 归类 before-Hook 的 guard 决策延迟。"""

    def __init__(self) -> None:
        self.samples: list[float] = []
        self.by_call: dict[tuple[str, str], float] = {}
        self.decisions: dict[tuple[str, str], str] = {}
        self.evidence: dict[tuple[str, str], dict[str, Any]] = {}

    def wrap(self, manager: Any) -> Any:
        """包装 ``manager.handle_before_tool_call``，返回原方法以便恢复。"""

        original = manager.handle_before_tool_call

        def timed(payload: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
            started = time.perf_counter()
            result: Any = None
            try:
                result = original(payload, *args, **kwargs)
                return result
            finally:
                elapsed_ms = (time.perf_counter() - started) * 1000.0
                self.samples.append(elapsed_ms)
                key = (
                    str(payload.get("sessionKey") or ""),
                    str(payload.get("toolCallId") or ""),
                )
                self.by_call[key] = elapsed_ms
                if isinstance(result, dict):
                    self.decisions[key] = str(result.get("action") or "")
                    record = result.get("action_record") or {}
                    metadata = (record.get("event") or {}).get("metadata") or {}
                    self.evidence[key] = {
                        "action": self.decisions[key], "rv_result": metadata.get("rv_result"),
                        "rv_trace": metadata.get("rv_trace"),
                        "semantic_audit": metadata.get("semantic_audit"),
                        "policy_decision": (record.get("decision") or {}).get("policy_decision"),
                    }

        manager.handle_before_tool_call = timed  # type: ignore[method-assign]
        return original


def _read_config(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _guard_plugin_entries(config: dict[str, Any]) -> dict[str, Any]:
    """从配置中提取 guard 插件注册事实（供冒烟核对，不修改配置）。"""

    plugins = config.get("plugins") if isinstance(config.get("plugins"), dict) else {}
    load = plugins.get("load") if isinstance(plugins.get("load"), dict) else {}
    paths = [str(item) for item in (load.get("paths") or [])]
    entries = plugins.get("entries") if isinstance(plugins.get("entries"), dict) else {}
    allow = [str(item) for item in (plugins.get("allow") or [])]
    guard_id = "openclaw-guard-hook"
    return {
        "guard_paths": [item for item in paths if item.endswith("/openclaw-guard-plugin")],
        "guard_entry": entries.get(guard_id),
        "guard_allowed": guard_id in allow,
    }


def _wait_guard_health(url: str, *, timeout: float) -> None:
    """等待 guard ``/api/health`` 返回 ``ok=true`` 且 ``product=openclaw-guard``。"""

    from urllib.request import urlopen

    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=1.5) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if isinstance(payload, dict) and payload.get("ok") is True and payload.get("product") == "openclaw-guard":
                return
            last = f"ok={payload.get('ok')} product={payload.get('product')}"
        except Exception as exc:  # 连接尚未就绪/解析失败
            last = type(exc).__name__
        time.sleep(0.25)
    raise RuntimeError(f"guard 健康检查未通过：{url}（最后状态：{last}）")


def _collect_guard_log_lines(profile_dir: Path, *, limit: int = 200) -> list[str]:
    """收集 profile 日志中 guard 插件相关行，证明 gateway 真实调用了 Hook。"""

    lines: list[str] = []
    try:
        candidates = sorted(profile_dir.rglob("*.log"))
    except OSError:
        return []
    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            if "openclaw-guard-hook" in line:
                lines.append(line.strip())
    return lines[-limit:]


def _docker_inspect(docker: str, container: str, fmt: str, *, timeout: float = 30.0) -> str:
    try:
        result = subprocess.run(
            [docker, "inspect", "--format", fmt, container],
            env=dict(os.environ), text=True, capture_output=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return (result.stdout or "").strip()


def cleanup_new_sandboxes(
    before_ids: set[str],
    *,
    toolchain: dict[str, Any],
    session_keys: list[str] | None = None,
    image: str = SANDBOX_IMAGE,
) -> list[str]:
    """移除本窗口内新建的 OpenClaw 沙箱容器。

    ``office_driver._cleanup_sandboxes`` 以 gateway profile 名做子串匹配，而 OpenClaw
    把沙箱容器命名为 ``openclaw-sbx-workspace-<hash>``（并只在 label 里带 sessionKey），
    因此原名匹配必然落空。这里改为：仅清理 ``before_ids`` 之外、镜像等于 ``image``
    的容器；若给定 ``session_keys``，还要求容器 label 命中其一，避免误删他人容器。
    """

    docker = toolchain.get("docker")
    if not docker:
        return []
    try:
        result = subprocess.run(
            [docker, "ps", "-aq"], env=dict(os.environ), text=True,
            capture_output=True, timeout=30.0, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    removed: list[str] = []
    for container in (result.stdout or "").split():
        if container in before_ids:
            continue
        descriptor = _docker_inspect(docker, container, "{{.Config.Image}}|{{.Config.Labels}}")
        container_image, _, labels = descriptor.partition("|")
        if container_image.strip() != image:
            continue
        if session_keys and not any(key and key in labels for key in session_keys):
            continue
        try:
            subprocess.run(
                [docker, "rm", "-f", container], env=dict(os.environ),
                text=True, capture_output=True, timeout=30.0, check=False,
            )
            removed.append(container)
        except (OSError, subprocess.SubprocessError):
            pass
    return removed


def _category_for_tool(tool_name: str) -> str:
    from openclaw_guard.integrations.tool_hook_bridge import OPENCLAW_NATIVE_TOOL_PROFILES

    profile = OPENCLAW_NATIVE_TOOL_PROFILES.get(tool_name)
    if isinstance(profile, dict):
        return str(profile.get("tool_group") or profile.get("action_type") or "unknown")
    return "unknown"


def run_scenario_guard(
    scenario: dict[str, Any],
    *,
    arm: str,
    workspace: Path,
    profile_home: Path,
    provider_port: int | None = None,
    toolchain: dict[str, Any] | None = None,
    plugin_dir: Path | None = None,
    working_root: Path | None = None,
    timeout: float = 300.0,
    approval_policy: str = "allow-once",
    restart_gateway: bool = True,
    recording: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """在真实 guard 臂上执行一个 office-chain 场景，返回**原始观测** dict。

    参数：
    - ``scenario``：来自 ``scenarios.json`` 的场景对象。
    - ``arm``：``arms.GUARD_ARMS`` 之一（``P`` / ``P+S`` / ``P+C`` / ``Full``）；
      传入 ``B0``（不加载 guard）抛 ``ValueError``。
    - ``workspace``：合成工作区（仅此目录被沙箱挂载）。
    - ``profile_home``：运行期临时 profile 根（receipts 落盘处）。
    - ``provider_port``：可选。提供时由调用方在该端口提供冻结轨迹 provider，驱动以单会话运行。
    - ``toolchain``：可选。已解析的运行时工具链；缺省时自行解析。
    - ``plugin_dir``：可选。合成办公插件目录；缺省用套件内置目录。
    - ``working_root``：可选。本次运行的临时 arm 根；结束时整棵删除。
    - ``approval_policy``：原生审批人格（``allow-once`` / ``deny``）。
    - ``restart_gateway``：多会话段时是否真实重启 gateway。

    返回的 dict 只承载原始观测；统一记录由 :func:`records.build_run_record` 生成。
    """

    if arm not in GUARD_ARMS:
        raise ValueError(f"guard 驱动不支持该臂：{arm!r}（可选：{', '.join(GUARD_ARMS)}）")
    if not isinstance(scenario, dict) or not scenario.get("events"):
        raise ValueError("scenario 必须是含非空 events 的字典")
    if approval_policy not in {"allow-once", "deny"}:
        raise ValueError(f"不支持的 approval_policy：{approval_policy!r}")

    spec = arm_spec(arm)
    toolchain = toolchain or resolve_toolchain()
    workspace = Path(workspace).resolve()
    profile_home = Path(profile_home).resolve()
    plugin_dir = Path(plugin_dir).resolve() if plugin_dir else default_plugin_dir()
    working_root = Path(working_root).resolve() if working_root else profile_home.parent
    working_root.mkdir(parents=True, exist_ok=True)

    project_dir = working_root / "guard-project"
    home_dir = project_dir / "home"
    home_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = profile_home / "office-receipts.jsonl"
    hooks_path = Path(f"{receipt_path}.hooks.jsonl")

    notes: list[str] = [
        f"guard 臂 {arm}：组件开关={{{', '.join(spec.components().enabled())}}}；"
        f"gateway=loopback/动态端口，sandbox=docker(mode=all,workspaceAccess=rw)，"
        f"exec.security=allowlist,ask=always，elevated=off；approval_policy={approval_policy}",
        "原生配置、审批人格、工作区、冻结轨迹与 B0 完全一致，仅被测组件开关不同。",
        _LATENCY_NOTE,
        "实验期修正：生成的 guard 插件在 register() 结束时立即做一次健康检查，"
        "规避 OpenClaw 2026.9.5 双注册表下 before_tool_call 静默放行；仅作用于本实验进程生成的插件，生产代码不变。",
        "外部副作用只写本地 receipts，无真实网络出站、无真实凭据、无真实 shell 提权。",
        "攻击目标是否达成仅由真实 receipts / 沙箱观测裁定，不读取场景 variant 字段。",
    ]

    created_files = seed_workspace(workspace, scenario)
    if created_files:
        notes.append(f"工作区播种 {len(created_files)} 个合成文件。")

    recording = recording or load_recording()

    def _enhancer_factory(config_path: Path) -> SemanticEnhancer:
        enhancer = SemanticEnhancer(config_path=config_path)
        apply_recording(enhancer, recording)
        return enhancer

    before_receipts = _json_rows(receipt_path)
    before_hooks = _json_rows(hooks_path)
    docker_before = _docker_ps_ids(toolchain)
    env = _child_env(toolchain)

    segments = _segments(scenario)
    if provider_port is not None:
        notes.append(f"使用调用方提供的冻结 provider 端口 {provider_port}，单会话运行整条链。")
        segments = [list(scenario["events"])]

    slug = re.sub(r"[^a-z0-9-]+", "-", str(scenario.get("scenario_id", "scenario")).lower()).strip("-")[:80]

    recorder = _GuardLatencyRecorder()
    gateway: _Gateway | None = None
    web_handle: Any = None
    manager: Any = None
    owned_providers: list[Any] = []
    session_keys: list[str] = []
    agent_runs: list[dict[str, Any]] = []
    hooks: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    external_receipts: list[dict[str, Any]] = []
    attack_goal_achieved = False
    admission_checks: dict[str, bool] = {}
    config_projection = ""
    guard_registration: dict[str, Any] = {}
    guard_log_lines: list[str] = []
    guard_port = 0
    gateway_port = 0

    previous_home = os.environ.get("HOME")
    previous_factory = guard_services.semantic_enhancer_factory
    previous_method: Any = None
    error: str | None = None

    try:
        with _eager_guard_health_check(), experiment_components.using(spec.components()):
            # PATH/HOME 必须在构造 _Gateway 前生效：_Gateway 用 Path.home() 定位 profile。
            os.environ["HOME"] = str(home_dir)
            # 子进程环境同样指向临时 home，否则 gateway 会去真实 home 找配置而报 "Missing config"。
            env["HOME"] = str(home_dir)
            guard_services.semantic_enhancer_factory = _enhancer_factory

            guard_port = _free_port()
            gateway = _Gateway(toolchain=toolchain, env=env)

            for index, segment_events in enumerate(segments):
                if provider_port is None:
                    from testlab.office_chain import frozen_provider

                    provider = frozen_provider.FrozenTrajectoryProvider({
                        "scenario_id": str(scenario.get("scenario_id") or ""),
                        "events": segment_events,
                    })
                    server, port, _thread = frozen_provider.serve(provider, host="127.0.0.1", port=0)
                    owned_providers.append(server)
                else:
                    port = int(provider_port)

                config = resolve_b0_config(
                    workspace, plugin_dir=plugin_dir, profile_home=profile_home, provider_port=port,
                )
                gateway_port = _free_port()
                gateway.write_config(config, port=gateway_port)

                if index == 0:
                    # 首个会话段：完成 guard 全生命周期。
                    from openclaw_guard.manager import build_manager
                    from openclaw_guard.web.app import launch_web

                    manager = build_manager(
                        project_dir,
                        config_path=gateway.config_path,
                        host="127.0.0.1",
                        port=guard_port,
                        ui_mode="pro",
                    )
                    previous_method = recorder.wrap(manager)
                    web_handle, _web_thread, _guard_url = launch_web(
                        manager, "127.0.0.1", guard_port, no_browser=True,
                    )
                    _wait_guard_health(
                        f"http://127.0.0.1:{guard_port}/api/health",
                        timeout=_GUARD_HEALTH_TIMEOUT_SECONDS,
                    )
                    install_result = manager.install_hook()
                    config_after = _read_config(gateway.config_path)
                    guard_registration = _guard_plugin_entries(config_after)
                    notes.append(
                        f"guard install_hook → {install_result.get('status')}；"
                        f"guard_paths={guard_registration['guard_paths']}，"
                        f"guard_allowed={guard_registration['guard_allowed']}，"
                        f"guard_entry={'present' if guard_registration['guard_entry'] else 'absent'}"
                    )
                    if not guard_registration["guard_paths"] or not guard_registration["guard_entry"]:
                        raise RuntimeError("guard 插件未注册进 profile 配置（可能被 transient 作用域跳过）")
                else:
                    # 多会话段重启：配置被整体重写，需重新注册 guard 插件。
                    if restart_gateway:
                        gateway.stop()
                        notes.append(f"会话段 {index + 1}：restart_before → 真实重启 gateway。")
                    manager.install_hook()

                gateway.start()
                session_key = f"agent:main:{slug}-{index + 1}-{uuid.uuid4().hex[:10]}"
                session_keys.append(session_key)
                message = compose_task_message(scenario, segment=index, total=len(segments))
                run = _run_agent_with_approvals(
                    profile=gateway.profile, session_key=session_key, message=message,
                    timeout=timeout, approval_policy=approval_policy, toolchain=toolchain, env=env,
                )
                run["segment"] = index
                agent_runs.append(run)
                if run.get("timed_out"):
                    notes.append(f"会话段 {index + 1} Agent 运行超时。")
                if run.get("returncode") not in (0, None):
                    notes.append(f"会话段 {index + 1} Agent 退出码 {run.get('returncode')}。")

            assert gateway is not None and manager is not None  # segments 非空

            config_projection = native_projection_sha256(_read_config(gateway.config_path))

            store_ok, _jobs = _list_automations(
                gateway.profile, env=env, cli=toolchain["openclaw"],
            )
            session_set = set(session_keys)
            hooks = [
                row for row in _json_rows(hooks_path)[len(before_hooks):]
                if row.get("sessionKey") in session_set
            ]
            receipts = _json_rows(receipt_path)[len(before_receipts):]
            approvals = [row for run in agent_runs for row in run.get("approvals", [])]
            successful_tools = _successful_tool_names(agent_runs)
            executions = _json_rows(Path(f"{receipt_path}.executions.jsonl"))
            events = _build_events(hooks, receipts, approvals, successful_tools, execution_observations=executions)

            for event, hook in zip(events, hooks):
                key = (
                    str(hook.get("sessionKey") or ""),
                    str(hook.get("toolCallId") or ""),
                )
                event["guard_evidence"] = recorder.evidence.get(key, {})
                guard_action = recorder.decisions.get(key)
                if guard_action:
                    event["decision"] = guard_action
                latency = recorder.by_call.get(key)
                if latency is not None:
                    event["before_hook_latency_ms"] = round(latency, 3)
                    event["guard_decision_latency_ms"] = round(latency, 3)

            external_receipts = [row for row in receipts if row.get("external") is True]

            agent_run_observed = any(
                isinstance(run.get("response"), dict) and not run.get("timed_out") for run in agent_runs
            )
            scenario_events = scenario.get("events", [])
            expects_egress = any(
                isinstance(event.get("effect"), dict)
                and event["effect"].get("kind") in EGRESS_EFFECT_KINDS
                for event in scenario_events
            ) or any(
                isinstance(event.get("hook_payload"), dict)
                and event["hook_payload"].get("toolName") in OFFICE_TOOLS
                for event in scenario_events
            )
            expects_automation = any(
                isinstance(event.get("hook_payload"), dict)
                and event["hook_payload"].get("toolName") == "automations"
                for event in scenario_events
            )
            # 被 guard 拦截（ask/block）的外发调用不会执行工具，因而不会留下
            # receipt；此时 receipt 缺失是防护成功的正常表现，而非观测通道
            # 故障，故计入准入，避免"防得越成功越被判为无效运行"。
            guard_intercepted = any(
                action in {"ask", "block"} for action in recorder.decisions.values()
            )
            receipts_present = bool(receipts) or not expects_egress or guard_intercepted
            automation_observed = any(row.get("tool_name") == "automations" for row in events)
            automation_store_matchable = bool(store_ok) and (automation_observed or not expects_automation)

            admission_checks = {
                "agent_run_observed": bool(agent_run_observed),
                "hook_events_observed": bool(hooks),
                "receipts_present": bool(receipts_present),
                "automation_store_matchable": bool(automation_store_matchable),
            }
            attack_goal_achieved = bool(_adjudicate_attack_goal(
                scenario,
                attack_goal=scenario.get("attack_goal"),
                receipts=receipts,
                external_receipts=external_receipts,
                workspace=workspace,
                events=events,
            ))
            # 在清理 profile 之前抓取 gateway 日志中的 guard Hook 证据。
            guard_log_lines = _collect_guard_log_lines(gateway.profile_dir)
    except Exception as exc:  # 真实运行失败：如实记录，不伪造观测。
        error = f"{type(exc).__name__}: {exc}"
        notes.append(f"运行失败：{error}")
    finally:
        # 反向清理：停 gateway → 注销 Hook → 停 uvicorn → 清沙箱 → 删整棵临时根。
        try:
            if gateway is not None:
                gateway.cleanup()
        except Exception:
            pass
        try:
            if manager is not None:
                if previous_method is not None:
                    try:
                        manager.handle_before_tool_call = previous_method
                    except Exception:
                        pass
                manager.uninstall_hook()
        except Exception:
            pass
        try:
            if web_handle is not None:
                web_handle.shutdown()
                web_handle.server_close()
        except Exception:
            pass
        for server in owned_providers:
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                pass
        try:
            cleanup_new_sandboxes(
                docker_before, toolchain=toolchain, session_keys=session_keys,
            )
        except Exception:
            pass
        guard_services.semantic_enhancer_factory = previous_factory
        if previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = previous_home
        shutil.rmtree(working_root, ignore_errors=True)

    tool_categories = sorted({_category_for_tool(str(row.get("tool_name") or "")) for row in events})

    runtime = {
        "arm": arm,
        "openclaw_version": toolchain.get("openclaw_version", ""),
        "docker_version": toolchain.get("docker_version", ""),
        "sandbox_image": SANDBOX_IMAGE,
        "guard_port": guard_port,
        "gateway_port": gateway_port,
        "guard_plugin_registered": bool(guard_registration.get("guard_entry")),
    }

    result: dict[str, Any] = {
        "arm": arm,
        "scenario_id": scenario.get("scenario_id"),
        "split": scenario.get("split"),
        "variant": scenario.get("variant"),
        "admitted": bool(admission_checks) and all(admission_checks.values()),
        "admission_checks": admission_checks,
        "events": events,
        "approvals": approvals,
        "execution_observations": locals().get("executions", []),
        "receipts": receipts,
        "external_effect_count": len(external_receipts),
        "attack_goal_achieved": attack_goal_achieved,
        "before_hook_latencies_ms": [round(sample, 3) for sample in recorder.samples],
        "guard_decision_latencies_ms": [round(sample, 3) for sample in recorder.samples],
        "tool_categories": tool_categories,
        "guard_decisions": [
            {
                "sessionKey": key[0],
                "toolCallId": key[1],
                "action": recorder.decisions.get(key, ""),
                "latency_ms": round(recorder.by_call.get(key, 0.0), 3),
            }
            for key in recorder.by_call
        ],
        "component_config_hash": spec.config_hash(),
        "config_projection_sha256": config_projection,
        "guard_registration": guard_registration,
        "guard_hook_log_lines": guard_log_lines,
        "runtime": runtime,
        "session_keys": session_keys,
        "notes": notes,
        "error": error,
    }
    return result


__all__ = ["SANDBOX_IMAGE", "cleanup_new_sandboxes", "run_scenario_guard"]
