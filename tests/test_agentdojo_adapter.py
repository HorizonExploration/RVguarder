"""AgentDojo 评测适配层的离线契约测试。"""

from __future__ import annotations

from dataclasses import dataclass, field
from io import BytesIO
from urllib.error import HTTPError

import pytest

from testlab.agentdojo_upgrade import (
    ApprovalMode,
    GuardOutcome,
    GuardRequestError,
    HTTPGuardClient,
    adapt_openai_client_for_compatible_roles,
    build_tool_call_payload,
    classify_guard_response,
    compare_replay,
    dependency_report,
    execute_guarded_calls,
    principal_key,
    pipeline_name_for_attack,
    run_manifest,
    summarize_guard_records,
    wilson_interval,
    redact_secrets,
    normalize_openai_message_roles,
)
from testlab.脚本工具.agentdojo_upgrade_eval import parse_args
from testlab.脚本工具.agentdojo_upgrade_eval import profile_task_selection
from testlab.脚本工具.agentdojo_upgrade_eval import summarize_arm


def test_demo_profile_uses_curated_risk_representatives() -> None:
    assert profile_task_selection("workspace", "demo") == (
        ["user_task_0", "user_task_12", "user_task_16", "user_task_19"],
        ["injection_task_0", "injection_task_4", "injection_task_10"],
    )
    assert profile_task_selection("banking", "demo") == (
        ["user_task_0", "user_task_1", "user_task_6", "user_task_13"],
        ["injection_task_4", "injection_task_5", "injection_task_7"],
    )


def test_full_profile_reduces_original_matrix_by_about_sixty_percent() -> None:
    workspace_users = [f"user_task_{i}" for i in range(40)]
    workspace_injections = [f"injection_task_{i}" for i in range(14)]
    banking_users = [f"user_task_{i}" for i in range(16)]
    banking_injections = [f"injection_task_{i}" for i in range(9)]

    selected_workspace = profile_task_selection("workspace", "full", workspace_users, workspace_injections)
    selected_banking = profile_task_selection("banking", "full", banking_users, banking_injections)

    workspace_episodes = len(selected_workspace[0]) * len(selected_workspace[1]) * 4 + len(selected_workspace[0])
    banking_episodes = len(selected_banking[0]) * len(selected_banking[1]) * 4 + len(selected_banking[0])
    assert (len(selected_workspace[0]), len(selected_workspace[1])) == (24, 8)
    assert (len(selected_banking[0]), len(selected_banking[1])) == (11, 8)
    assert workspace_episodes + banking_episodes == 1155


def test_eval_defaults_to_report_sized_demo_profile() -> None:
    args = parse_args([])

    assert args.profile == "demo"
    assert args.max_tool_iters is None


def test_summary_excludes_error_episodes_from_effect_denominators() -> None:
    summary = summarize_arm(
        [
            {"attack_success": False, "attack_prevented": True, "utility": True, "tool_traces": []},
            {
                "attack_success": False,
                "attack_prevented": True,
                "utility": False,
                "tool_traces": [],
                "error": "RateLimitError: 429",
            },
            {"attack_success": None, "utility": True, "tool_traces": []},
        ]
    )

    assert summary["episodes"] == 3
    assert summary["valid_episodes"] == 2
    assert summary["errors"] == 1
    assert summary["utility"] == {"successes": 2, "total": 2, "rate": 1.0, "ci95": [0.342372, 1.0]}
    assert summary["attack_success"]["total"] == 1
    assert summary["attack_prevention"]["total"] == 1


def test_eval_pipeline_can_reuse_an_existing_llm_instance(monkeypatch: pytest.MonkeyPatch) -> None:
    import testlab.脚本工具.agentdojo_upgrade_eval as eval_script

    class FakePipeline:
        def __init__(self, elements):
            self.elements = elements
            self.name = ""

    class FakeExecutor:
        pass

    class FakeLoop:
        def __init__(self, elements, max_iters):
            self.elements = elements
            self.max_iters = max_iters

    dojo = {
        "SystemMessage": lambda value: ("system", value),
        "InitQuery": lambda: ("init",),
        "load_system_message": lambda _value: "system prompt",
        "AgentPipeline": FakePipeline,
        "ToolsExecutionLoop": FakeLoop,
    }
    args = type("Args", (), {"model": "deepseek-chat", "approval_mode": "deny", "max_tool_iters": 2})()
    shared_llm = object()

    monkeypatch.setattr(eval_script, "build_guarded_tools_executor", lambda *a, **k: FakeExecutor())
    monkeypatch.setattr(eval_script, "pipeline_name_for_attack", lambda model, arm: f"{model}:{arm}")
    monkeypatch.setattr(eval_script, "_build_llm", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("rebuild")))

    pipeline = eval_script._build_pipeline(
        dojo,
        args,
        guard=object(),
        context={"arm": "candidate"},
        recorder=lambda _item: None,
        llm=shared_llm,
    )

    assert shared_llm in pipeline.elements


@dataclass
class FakeToolCall:
    function: str
    args: dict[str, object] = field(default_factory=dict)
    id: str = "call-1"


class FakeFunction:
    def __init__(self, name: str) -> None:
        self.name = name


class FakeRuntime:
    def __init__(self) -> None:
        self.functions = {"safe_tool": FakeFunction("safe_tool"), "dangerous_tool": FakeFunction("dangerous_tool")}
        self.calls: list[tuple[str, dict[str, object]]] = []

    def run_function(self, env: object, name: str, args: dict[str, object]) -> tuple[str, None]:
        self.calls.append((name, args))
        return f"ran:{name}", None


class FakeGuard:
    def __init__(self, responses: dict[str, dict[str, object]]) -> None:
        self.responses = responses

    def check(self, payload: dict[str, object]) -> dict[str, object]:
        return self.responses[str(payload["toolName"])]


def test_build_tool_call_payload_preserves_identity_and_arguments() -> None:
    payload = build_tool_call_payload(
        FakeToolCall("search_emails", {"query": "weekly report"}),
        session_id="session-1",
        agent_id="agent-1",
        goal_id="goal-1",
    )

    assert payload == {
        "toolName": "memory_search",
        "agentdojoToolName": "search_emails",
        "evaluationMode": "agentdojo",
        "params": {"query": "weekly report"},
        "toolCallId": "call-1",
        "sessionId": "session-1",
        "agentId": "agent-1",
        "goalId": "goal-1",
    }


def test_agentdojo_read_tool_maps_to_safe_openclaw_capability() -> None:
    payload = build_tool_call_payload(FakeToolCall("search_calendar_events", {"query": "meeting"}))

    assert payload["toolName"] == "memory_search"
    assert payload["agentdojoToolName"] == "search_calendar_events"
    assert payload["evaluationMode"] == "agentdojo"


def test_agentdojo_external_tool_keeps_high_risk_openclaw_capability() -> None:
    payload = build_tool_call_payload(FakeToolCall("send_email", {"to": "outside@example.com"}))

    assert payload["toolName"] == "feishu.im.send"
    assert payload["agentdojoToolName"] == "send_email"
    assert payload["evaluationMode"] == "agentdojo"


def test_normalize_openai_message_roles_maps_developer_without_mutating_input() -> None:
    messages = [{"role": "developer", "content": "rules"}, {"role": "user", "content": "task"}]

    normalized = normalize_openai_message_roles(messages)

    assert normalized == [{"role": "system", "content": "rules"}, messages[1]]
    assert messages[0]["role"] == "developer"


def test_openai_compatible_role_adapter_only_normalizes_chat_messages() -> None:
    class Completions:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def create(self, **kwargs: object) -> str:
            self.calls.append(kwargs)
            return "ok"

    class Client:
        def __init__(self) -> None:
            self.completions = Completions()
            self.other = "preserved"

    raw = Client()
    adapted = adapt_openai_client_for_compatible_roles(type("Client", (), {"chat": raw, "other": "preserved"})())
    result = adapted.chat.completions.create(
        model="deepseek-chat",
        messages=[{"role": "developer", "content": "rules"}],
    )

    assert result == "ok"
    assert raw.completions.calls[0]["messages"] == [{"role": "system", "content": "rules"}]
    assert adapted.other == "preserved"


@pytest.mark.parametrize(
    ("response", "mode", "expected"),
    [
        ({"action": "allow"}, ApprovalMode.DENY, GuardOutcome("allow", True)),
        ({"action": "block"}, ApprovalMode.DENY, GuardOutcome("block", False)),
        ({"action": "require_approval"}, ApprovalMode.DENY, GuardOutcome("ask", False)),
        ({"action": "requireApproval"}, ApprovalMode.DENY, GuardOutcome("ask", False)),
        ({"action": "require_approval"}, ApprovalMode.ALLOW_ONCE, GuardOutcome("ask", True)),
        ({"action": "clarify"}, ApprovalMode.DENY, GuardOutcome("clarify", False)),
        ({"ok": False, "error": "guard unavailable"}, ApprovalMode.DENY, GuardOutcome("unknown", False)),
    ],
)
def test_classify_guard_response_separates_decision_from_execution(
    response: dict[str, object], mode: ApprovalMode, expected: GuardOutcome
) -> None:
    assert classify_guard_response(response, mode) == expected


def test_redact_secrets_removes_sensitive_keys_and_values() -> None:
    redacted = redact_secrets(
        {
            "api_key": "sk-test-secret",
            "nested": {"token": "token-value", "message": "safe"},
        }
    )

    assert redacted == {
        "api_key": "[REDACTED]",
        "nested": {"token": "[REDACTED]", "message": "safe"},
    }


def test_dependency_report_marks_current_agentdojo_environment_invalid() -> None:
    report = dependency_report("0.1.35", "1.10.26")

    assert report["agentdojo"] == "0.1.35"
    assert report["pydantic"] == "1.10.26"
    assert report["ready"] is False
    assert any(item.startswith("pydantic") for item in report["errors"])


def test_execute_guarded_calls_does_not_run_blocked_tool() -> None:
    runtime = FakeRuntime()
    records = execute_guarded_calls(
        [FakeToolCall("safe_tool"), FakeToolCall("dangerous_tool", id="call-2")],
        runtime,
        FakeGuard({"safe_tool": {"action": "allow"}, "dangerous_tool": {"action": "block"}}),
    )

    assert [record.decision for record in records] == ["allow", "block"]
    assert [record.executed for record in records] == [True, False]
    assert runtime.calls == [("safe_tool", {})]


def test_execute_guarded_calls_allow_once_executes_but_keeps_ask_decision() -> None:
    runtime = FakeRuntime()
    records = execute_guarded_calls(
        [FakeToolCall("dangerous_tool")],
        runtime,
        FakeGuard({"dangerous_tool": {"action": "require_approval"}}),
        mode=ApprovalMode.ALLOW_ONCE,
    )

    assert records[0].decision == "ask"
    assert records[0].executed is True
    assert runtime.calls == [("dangerous_tool", {})]


def test_execute_guarded_calls_records_risk_and_rule_evidence() -> None:
    runtime = FakeRuntime()
    evidence: list[dict[str, object]] = []
    execute_guarded_calls(
        [FakeToolCall("dangerous_tool")],
        runtime,
        FakeGuard(
            {
                "dangerous_tool": {
                    "action": "block",
                    "risk_level": "critical",
                    "rule_ids": ["CMD-001"],
                    "policy_version": "1.1.0",
                }
            }
        ),
        recorder=evidence.append,
    )

    assert evidence[0]["risk_level"] == "critical"
    assert evidence[0]["rule_ids"] == ["CMD-001"]
    assert evidence[0]["policy_version"] == "1.1.0"


def test_execute_guarded_calls_extracts_nested_action_record_evidence() -> None:
    runtime = FakeRuntime()
    evidence: list[dict[str, object]] = []
    execute_guarded_calls(
        [FakeToolCall("dangerous_tool")],
        runtime,
        FakeGuard(
            {
                "dangerous_tool": {
                    "action": "require_approval",
                    "action_record": {
                        "decision": {"risk_level": "dangerous", "rule_ids": ["PMKB-001"]},
                        "policy_version": "1.1.0",
                    },
                }
            }
        ),
        recorder=evidence.append,
    )

    assert evidence[0]["risk_level"] == "dangerous"
    assert evidence[0]["rule_ids"] == ["PMKB-001"]


def test_execute_guarded_calls_rejects_unknown_tool_without_runtime_call() -> None:
    runtime = FakeRuntime()
    records = execute_guarded_calls(
        [FakeToolCall("not_registered")],
        runtime,
        FakeGuard({"not_registered": {"action": "allow"}}),
    )

    assert records[0].decision == "unknown"
    assert records[0].executed is False
    assert records[0].error == "invalid_tool"
    assert runtime.calls == []


def test_summarize_guard_records_separates_approval_demand_and_prevention() -> None:
    summary = summarize_guard_records(
        [
            {"decision": "allow", "executed": True, "risk": "low"},
            {"decision": "ask", "executed": False, "risk": "high"},
            {"decision": "ask", "executed": True, "risk": "high"},
            {"decision": "block", "executed": False, "risk": "critical"},
        ]
    )

    assert summary["approval_demand"] == 2
    assert summary["prevented"] == 2
    assert summary["executed"] == 2
    assert summary["high_risk_total"] == 3


def test_wilson_interval_is_bounded_and_contains_point_estimate() -> None:
    low, high = wilson_interval(8, 10)

    assert 0 <= low <= 0.8 <= high <= 1


def test_compare_replay_reports_alignment_and_changed_decisions() -> None:
    comparison = compare_replay(
        [{"decision": "allow", "executed": True}, {"decision": "ask", "executed": False}],
        [{"decision": "ask", "executed": False}, {"decision": "ask", "executed": False}],
    )

    assert comparison["aligned_count"] == 2
    assert comparison["length_mismatch"] is False
    assert comparison["changed_count"] == 1
    assert comparison["rows"][0]["candidate_decision"] == "ask"


def test_principal_key_requires_agent_and_capability_lineage() -> None:
    assert principal_key("user-1", "agent-1", ["grant-1"]) == "user-1|agent-1|grant-1"
    assert principal_key("user-1", "agent-1", []) == "user-1|agent-1|unknown-lineage"


def test_pipeline_name_contains_agentdojo_model_alias_for_attack_templates() -> None:
    assert pipeline_name_for_attack("deepseek-chat", "candidate") == (
        "gpt-4o-2024-05-13::deepseek-chat::candidate"
    )


def test_run_manifest_contains_config_hash_without_secret_values() -> None:
    manifest = run_manifest(
        suites=["workspace"],
        attacks=["direct"],
        model="deepseek-chat",
        config={"api_key": "sk-secret", "temperature": 0},
    )

    assert manifest["suites"] == ["workspace"]
    assert manifest["attacks"] == ["direct"]
    assert manifest["config"]["temperature"] == 0
    assert manifest["config"]["api_key"] == "[REDACTED]"
    assert len(manifest["config_hash"]) == 64


def test_http_guard_rejects_malformed_success_response(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self) -> bytes:
            return b"not-json"

    monkeypatch.setattr("testlab.agentdojo_upgrade.urlopen", lambda *_args, **_kwargs: Response())

    with pytest.raises(GuardRequestError, match="invalid JSON"):
        HTTPGuardClient().check({"toolName": "safe_tool", "params": {}})


def test_http_guard_fails_closed_on_http_error_even_if_body_says_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    error = HTTPError(
        "http://guard.test/api/hook/before-tool-call",
        503,
        "unavailable",
        hdrs=None,
        fp=BytesIO(b'{"action":"allow"}'),
    )
    monkeypatch.setattr("testlab.agentdojo_upgrade.urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(error))

    with pytest.raises(GuardRequestError, match="Guard HTTP 503"):
        HTTPGuardClient("http://guard.test").check({"toolName": "safe_tool", "params": {}})
