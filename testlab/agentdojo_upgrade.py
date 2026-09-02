"""AgentDojo 评测适配层。

本模块只承载 testlab 的边界契约，不改变 Guard 生产运行时。AgentDojo 是
可选实验依赖，因此模块导入时不加载 AgentDojo；真实运行通过
``load_agentdojo`` 延迟导入。
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class ApprovalMode(str, Enum):
    """实验中如何处理 Guard 的审批要求。"""

    DENY = "deny"
    ALLOW_ONCE = "allow-once"


@dataclass(frozen=True)
class GuardOutcome:
    """一次 Guard 决策及其是否实际执行的结果。"""

    decision: str
    execute: bool
    response: Mapping[str, Any] = field(default_factory=dict, compare=False)


@dataclass(frozen=True)
class ToolExecutionRecord:
    """一条工具调用的 Guard 决策、执行状态和错误摘要。"""

    function: str
    tool_call_id: str | None
    decision: str
    executed: bool
    output: Any = None
    error: str | None = None
    response: Mapping[str, Any] = field(default_factory=dict, compare=False)


class GuardClient(Protocol):
    """向 Guard 提交 before_tool_call 载荷的最小接口。"""

    def check(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        """返回 Guard JSON 响应。"""


class GuardRequestError(RuntimeError):
    """Guard 请求失败且工具不应继续执行。"""


class AgentDojoDependencyError(RuntimeError):
    """AgentDojo 环境不可用。"""


def normalize_openai_message_roles(messages: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """将 AgentDojo 的 ``developer`` 系统消息映射为兼容的 ``system``。

    AgentDojo 0.1.35 遵循新版 OpenAI 角色约定，把系统消息编码为
    ``developer``。部分 OpenAI-compatible 服务（包括 DeepSeek Chat）仍只
    接受 ``system``，因此评测边界需要做一次不改变内容的角色归一化。
    """
    normalized: list[Mapping[str, Any]] = []
    for message in messages:
        if isinstance(message, Mapping) and message.get("role") == "developer":
            item = dict(message)
            item["role"] = "system"
            normalized.append(item)
        else:
            normalized.append(message)
    return normalized


class _OpenAIChatCompletionsRoleAdapter:
    """只包装 chat.completions.create，避免修改 AgentDojo 或 OpenAI SDK。"""

    def __init__(self, delegate: Any) -> None:
        self._delegate = delegate

    def create(self, *args: Any, **kwargs: Any) -> Any:
        if "messages" in kwargs:
            kwargs["messages"] = normalize_openai_message_roles(kwargs["messages"])
        return self._delegate.create(*args, **kwargs)


class _OpenAIChatRoleAdapter:
    def __init__(self, delegate: Any) -> None:
        self.completions = _OpenAIChatCompletionsRoleAdapter(delegate.completions)


class OpenAICompatibleRoleAdapter:
    """为 OpenAI-compatible 评测端点适配 AgentDojo 的系统消息角色。"""

    def __init__(self, client: Any) -> None:
        self._client = client
        self.chat = _OpenAIChatRoleAdapter(client.chat)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def adapt_openai_client_for_compatible_roles(client: Any) -> OpenAICompatibleRoleAdapter:
    """返回一个不修改原客户端的兼容角色代理。"""
    return OpenAICompatibleRoleAdapter(client)


def _get_value(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


_AGENTDOJO_TOOL_MAP = {
    # AgentDojo's read-only synthetic tools are represented as the existing
    # low-risk OpenClaw memory capability. The original function name remains
    # in ``agentdojoToolName`` for audit and task-runtime correlation.
    "get_current_day": "memory_search",
    "search_calendar_events": "memory_search",
    "get_day_calendar_events": "memory_search",
    "get_unread_emails": "memory_search",
    "get_sent_emails": "memory_search",
    "get_received_emails": "memory_search",
    "get_draft_emails": "memory_search",
    "search_emails": "memory_search",
    "search_contacts_by_name": "memory_search",
    "search_contacts_by_email": "memory_search",
    "list_files": "memory_search",
    "search_files": "memory_search",
    "search_files_by_filename": "memory_search",
    "get_file_by_id": "memory_search",
    # Mutating/external synthetic tools use existing high-risk capability IDs.
    "send_email": "feishu.im.send",
    "share_file": "feishu.im.send",
    "create_file": "feishu.docs.write",
    "append_to_file": "feishu.docs.write",
    "create_calendar_event": "feishu.calendar.modify",
    "cancel_calendar_event": "feishu.calendar.modify",
    "reschedule_calendar_event": "feishu.calendar.modify",
    "add_calendar_event_participants": "feishu.calendar.modify",
}


def _agentdojo_tool_name(tool_name: str) -> str:
    return _AGENTDOJO_TOOL_MAP.get(tool_name.lower(), tool_name)


def build_tool_call_payload(
    tool_call: Any,
    *,
    session_id: str | None = None,
    agent_id: str | None = None,
    goal_id: str | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """把 AgentDojo FunctionCall 转成 OpenClaw before_tool_call 载荷。"""
    tool_name = str(_get_value(tool_call, "function", "") or "")
    raw_args = _get_value(tool_call, "args", {})
    if isinstance(raw_args, str):
        try:
            raw_args = json.loads(raw_args)
        except json.JSONDecodeError:
            raw_args = {}
    params = copy.deepcopy(raw_args) if isinstance(raw_args, Mapping) else {}
    payload: dict[str, Any] = {
        "toolName": _agentdojo_tool_name(tool_name),
        "agentdojoToolName": tool_name,
        "evaluationMode": "agentdojo",
        "params": dict(params),
    }
    optional = {
        "toolCallId": _get_value(tool_call, "id"),
        "sessionId": session_id,
        "agentId": agent_id,
        "goalId": goal_id,
        "runId": run_id,
    }
    payload.update({key: value for key, value in optional.items() if value not in (None, "")})
    return payload


def classify_guard_response(
    response: Mapping[str, Any], mode: ApprovalMode = ApprovalMode.DENY
) -> GuardOutcome:
    """将 Guard 响应映射为决策和实际执行行为。

    ``ask`` 永远保留为决策值；只有显式的 ``allow-once`` 实验模式才会执行
    该工具，从而避免把“发起审批”误报为“安全阻止”。
    """
    action = str(response.get("action") or response.get("decision") or "").strip().lower()
    action = action.replace("-", "_")
    if action == "allow":
        return GuardOutcome("allow", True, response)
    if action in {"block", "deny", "blocked"}:
        return GuardOutcome("block", False, response)
    if action in {
        "require_approval",
        "requireapproval",
        "approval",
        "ask",
        "openclaw_approval",
        "escalate",
    }:
        return GuardOutcome("ask", mode == ApprovalMode.ALLOW_ONCE, response)
    if action in {"clarify", "clarify_then_retry", "revise"}:
        return GuardOutcome("clarify", False, response)
    return GuardOutcome("unknown", False, response)


def redact_secrets(value: Any) -> Any:
    """递归遮罩实验结果中的凭据字段。"""
    sensitive = re.compile(r"(?:api[_-]?key|token|password|secret|credential|authorization)", re.I)
    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]" if sensitive.search(str(key)) else redact_secrets(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return [redact_secrets(item) for item in value]
    return value


def principal_key(principal_id: str | None, agent_id: str | None, capability_lineage: Sequence[str] | None) -> str:
    """生成跨 session 状态键；能力链缺失时显式标记未知。"""
    principal = str(principal_id or "unknown")
    agent = str(agent_id or "unknown")
    lineage = "->".join(str(item) for item in capability_lineage or ()) or "unknown-lineage"
    return f"{principal}|{agent}|{lineage}"


def pipeline_name_for_attack(model: str, arm: str, model_alias: str = "gpt-4o-2024-05-13") -> str:
    """生成兼容 AgentDojo attack registry 的 pipeline name。

    AgentDojo 的 ``important_instructions`` 和 ``tool_knowledge`` 会从
    ``pipeline.name`` 识别一组固定模型名；DeepSeek 等 OpenAI-compatible
    模型不在该 registry 中，因此保留真实模型名并附带一个仅用于攻击模板
    选择的官方 alias。三组 Arm 使用同一 alias，避免对照偏差。
    """
    return f"{model_alias}::{model}::{arm}"


def run_manifest(
    *,
    suites: Sequence[str],
    attacks: Sequence[str],
    model: str,
    config: Mapping[str, Any],
    benchmark_version: str = "v1.2.2",
) -> dict[str, Any]:
    """生成可复现实验清单，配置先脱敏再计算哈希。"""
    safe_config = redact_secrets(dict(config))
    encoded = json.dumps(safe_config, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "benchmark_version": benchmark_version,
        "suites": list(suites),
        "attacks": list(attacks),
        "model": model,
        "config": safe_config,
        "config_hash": hashlib.sha256(encoded).hexdigest(),
    }


def _version_tuple(value: str) -> tuple[int, ...]:
    numbers = re.findall(r"\d+", str(value))
    return tuple(int(item) for item in numbers[:4]) or (0,)


def dependency_report(
    agentdojo_version: str, pydantic_version: str, python_version: str | None = None
) -> dict[str, Any]:
    """检查实验环境的最小版本契约。"""
    errors: list[str] = []
    if _version_tuple(agentdojo_version) < (0, 1, 35):
        errors.append("agentdojo>=0.1.35")
    if _version_tuple(pydantic_version) < (2, 7, 1):
        errors.append("pydantic>=2.7.1")
    return {
        "python": python_version or sys.version.split()[0],
        "agentdojo": agentdojo_version,
        "pydantic": pydantic_version,
        "ready": not errors,
        "errors": errors,
    }


def run_dependency_probe(python_executable: str | None = None) -> dict[str, Any]:
    """在指定 Python 环境中读取版本并返回可序列化报告。"""
    executable = python_executable or sys.executable
    code = (
        "import importlib.metadata as m, sys; "
        "print(sys.version.split()[0]); print(m.version('agentdojo')); print(m.version('pydantic'))"
    )
    try:
        completed = subprocess.run(
            [executable, "-c", code], capture_output=True, text=True, timeout=10, check=True
        )
        lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
        if len(lines) < 3:
            raise RuntimeError("version probe returned incomplete output")
        return dependency_report(lines[1], lines[2], lines[0])
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        return {
            "python_executable": executable,
            "ready": False,
            "errors": [f"dependency_probe_failed:{exc}"],
        }


def load_agentdojo() -> dict[str, Any]:
    """延迟加载 AgentDojo 官方运行组件，失败时给出可操作提示。"""
    try:
        from agentdojo.agent_pipeline import AgentPipeline, ToolsExecutionLoop, ToolsExecutor
        from agentdojo.agent_pipeline.agent_pipeline import InitQuery, OpenAILLM, SystemMessage, load_system_message
        from agentdojo.attacks.attack_registry import load_attack
        from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
        from agentdojo.task_suite.load_suites import get_suite
    except Exception as exc:  # pragma: no cover - 依赖环境专属分支
        raise AgentDojoDependencyError(
            "AgentDojo 环境不可用，请在独立环境安装 agentdojo>=0.1.35 和 pydantic>=2.7.1；"
            f"当前导入错误：{exc}"
        ) from exc
    return {
        "AgentPipeline": AgentPipeline,
        "ToolsExecutionLoop": ToolsExecutionLoop,
        "ToolsExecutor": ToolsExecutor,
        "InitQuery": InitQuery,
        "OpenAILLM": OpenAILLM,
        "SystemMessage": SystemMessage,
        "load_system_message": load_system_message,
        "load_attack": load_attack,
        "benchmark_suite_with_injections": benchmark_suite_with_injections,
        "benchmark_suite_without_injections": benchmark_suite_without_injections,
        "get_suite": get_suite,
    }


class HTTPGuardClient:
    """使用标准库调用 Guard Hook API，便于在 AgentDojo 环境运行。"""

    def __init__(self, base_url: str = "http://127.0.0.1:8780", token: str | None = None, timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def check(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        """发送 before-tool-call 请求并返回 JSON。"""
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["x-openclaw-guard-token"] = self.token
        request = Request(
            f"{self.base_url}/api/hook/before-tool-call", data=body, headers=headers, method="POST"
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
                try:
                    decoded = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise GuardRequestError(f"Guard response invalid JSON: {raw[:200]}") from exc
                if not isinstance(decoded, Mapping):
                    raise GuardRequestError("Guard response must be a JSON object")
                return decoded
        except HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise GuardRequestError(f"Guard HTTP {exc.code}: {raw[:200]}") from exc
        except (URLError, TimeoutError) as exc:
            raise GuardRequestError(f"Guard request failed: {exc}") from exc


def evaluate_tool_call(
    guard: GuardClient,
    tool_call: Any,
    *,
    mode: ApprovalMode = ApprovalMode.DENY,
    session_id: str | None = None,
    agent_id: str | None = None,
    goal_id: str | None = None,
    run_id: str | None = None,
    recorder: Callable[[dict[str, Any]], None] | None = None,
) -> GuardOutcome:
    """执行一次 Guard 检查并记录不含凭据的决策证据。"""
    payload = build_tool_call_payload(
        tool_call,
        session_id=session_id,
        agent_id=agent_id,
        goal_id=goal_id,
        run_id=run_id,
    )
    started = time.perf_counter()
    try:
        response = guard.check(payload)
    except GuardRequestError as exc:
        response = {"ok": False, "error": str(exc)}
    outcome = classify_guard_response(response, mode)
    if recorder is not None:
        action_record = response.get("action_record")
        action_record = action_record if isinstance(action_record, Mapping) else {}
        nested_decision = action_record.get("decision")
        nested_decision = nested_decision if isinstance(nested_decision, Mapping) else {}
        evidence = {
            "risk_level": (
                response.get("risk_level")
                or response.get("riskLevel")
                or nested_decision.get("risk_level")
                or nested_decision.get("riskLevel")
            ),
            "rule_ids": (
                response.get("rule_ids")
                or response.get("ruleIds")
                or nested_decision.get("rule_ids")
                or nested_decision.get("ruleIds")
                or []
            ),
            "policy_version": (
                response.get("policy_version")
                or response.get("policyVersion")
                or action_record.get("policy_version")
                or nested_decision.get("policy_version")
                or nested_decision.get("policyVersion")
            ),
        }
        recorder(
            redact_secrets(
                {
                    "payload": payload,
                    "response": dict(response),
                    "decision": outcome.decision,
                    "executed": outcome.execute,
                    **evidence,
                    "latency_ms": round((time.perf_counter() - started) * 1000, 3),
                }
            )
        )
    return outcome


def execute_guarded_calls(
    tool_calls: Sequence[Any],
    runtime: Any,
    guard: GuardClient,
    *,
    env: Any = None,
    mode: ApprovalMode = ApprovalMode.DENY,
    session_id: str | None = None,
    agent_id: str | None = None,
    goal_id: str | None = None,
    run_id: str | None = None,
    recorder: Callable[[dict[str, Any]], None] | None = None,
) -> list[ToolExecutionRecord]:
    """在 AgentDojo runtime 上执行一批经过 Guard 检查的工具调用。

    该函数不依赖 AgentDojo 类型，既可被离线测试使用，也可由
    ``GuardedToolsExecutor`` 包装为 AgentDojo pipeline element。
    """
    registered = getattr(runtime, "functions", {})
    records: list[ToolExecutionRecord] = []
    for tool_call in tool_calls:
        function = str(_get_value(tool_call, "function", "") or "")
        call_id = _get_value(tool_call, "id")
        if not function or function not in registered:
            records.append(
                ToolExecutionRecord(function, call_id, "unknown", False, error="invalid_tool")
            )
            continue
        outcome = evaluate_tool_call(
            guard,
            tool_call,
            mode=mode,
            session_id=session_id,
            agent_id=agent_id,
            goal_id=goal_id,
            run_id=run_id,
            recorder=recorder,
        )
        if not outcome.execute:
            error = {
                "block": "blocked_by_guard",
                "ask": "approval_required",
                "clarify": "clarification_required",
                "unknown": "guard_decision_unknown",
            }.get(outcome.decision, "guard_rejected")
            records.append(
                ToolExecutionRecord(function, call_id, outcome.decision, False, error=error, response=outcome.response)
            )
            continue
        args = _get_value(tool_call, "args", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        args = dict(args) if isinstance(args, Mapping) else {}
        try:
            output, error = runtime.run_function(env, function, args)
        except Exception as exc:  # pragma: no cover - runtime 专属异常
            output, error = None, str(exc)
        records.append(
            ToolExecutionRecord(
                function,
                call_id,
                outcome.decision,
                True,
                output=output,
                error=str(error) if error else None,
                response=outcome.response,
            )
        )
    return records


def build_guarded_tools_executor(
    guard: GuardClient,
    *,
    mode: ApprovalMode = ApprovalMode.DENY,
    context: Mapping[str, Any] | None = None,
    recorder: Callable[[dict[str, Any]], None] | None = None,
) -> Any:
    """构造实现 AgentDojo ``ToolsExecutor`` 接口的 Guard 包装器。

    AgentDojo 仅在函数调用时被动态导入，因此项目自身的测试和生产依赖不
    会被污染。返回对象的 ``query`` 签名与官方 ``ToolsExecutor`` 一致。
    """
    dojo = load_agentdojo()
    tools_executor = dojo["ToolsExecutor"]
    try:
        from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
        from agentdojo.types import ChatToolResultMessage, text_content_block_from_string
    except Exception as exc:  # pragma: no cover - 依赖环境专属分支
        raise AgentDojoDependencyError(f"AgentDojo message types unavailable: {exc}") from exc

    fixed_context = dict(context or {})

    class GuardedToolsExecutor(tools_executor):
        """在官方工具执行器前插入 Guard 检查。"""

        def query(self, query, runtime, env=None, messages=(), extra_args=None):
            extra_args = dict(extra_args or {})
            if not messages or messages[-1]["role"] != "assistant":
                return query, runtime, env, messages, extra_args
            tool_calls = messages[-1].get("tool_calls")
            if not tool_calls:
                return query, runtime, env, messages, extra_args

            current = {**fixed_context, **extra_args}
            results = execute_guarded_calls(
                list(tool_calls),
                runtime,
                guard,
                env=env,
                mode=mode,
                session_id=current.get("session_id") or current.get("sessionId"),
                agent_id=current.get("agent_id") or current.get("agentId"),
                goal_id=current.get("goal_id") or current.get("goalId"),
                run_id=current.get("run_id") or current.get("runId"),
                recorder=recorder,
            )
            messages_out = list(messages)
            tool_messages = []
            for tool_call, result in zip(tool_calls, results):
                if result.function == EMPTY_FUNCTION_NAME:
                    error = "empty_tool_name"
                elif result.error:
                    error = result.error
                else:
                    error = None
                formatted = "" if error else self.output_formatter(result.output)
                tool_messages.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string(formatted)],
                        tool_call_id=result.tool_call_id,
                        tool_call=tool_call,
                        error=error,
                    )
                )
            messages_out.extend(tool_messages)
            return query, runtime, env, messages_out, extra_args

    return GuardedToolsExecutor()


def compare_replay(
    legacy: Sequence[Mapping[str, Any]], candidate: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """对齐同一工具轨迹的新旧决策，输出可序列化差异。"""
    rows: list[dict[str, Any]] = []
    for index, (old, new) in enumerate(zip(legacy, candidate)):
        old_decision = str(old.get("decision") or "unknown")
        new_decision = str(new.get("decision") or "unknown")
        rows.append(
            {
                "index": index,
                "legacy_decision": old_decision,
                "candidate_decision": new_decision,
                "changed": old_decision != new_decision,
                "legacy_executed": bool(old.get("executed", False)),
                "candidate_executed": bool(new.get("executed", False)),
            }
        )
    return {
        "legacy_count": len(legacy),
        "candidate_count": len(candidate),
        "aligned_count": len(rows),
        "length_mismatch": len(legacy) != len(candidate),
        "changed_count": sum(1 for row in rows if row["changed"]),
        "rows": rows,
    }


def summarize_guard_records(records: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    """统计 Guard 专属指标，不把审批需求等同于安全阻止。"""
    approval_demand = 0
    prevented = 0
    executed = 0
    high_risk_total = 0
    for record in records:
        decision = str(record.get("decision") or "unknown")
        did_execute = bool(record.get("executed", False))
        risk = str(record.get("risk") or record.get("risk_level") or "").lower()
        approval_demand += decision == "ask"
        executed += did_execute
        prevented += decision == "block" or (decision == "ask" and not did_execute)
        high_risk_total += risk in {"high", "critical", "dangerous", "blocked"}
    return {
        "total": len(records),
        "approval_demand": approval_demand,
        "prevented": prevented,
        "executed": executed,
        "high_risk_total": high_risk_total,
    }


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """返回二项比例的 Wilson 95% 置信区间。"""
    if total <= 0:
        return 0.0, 0.0
    successes = max(0, min(successes, total))
    proportion = successes / total
    denominator = 1 + z * z / total
    centre = (proportion + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((proportion * (1 - proportion) + z * z / (4 * total)) / total) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)
