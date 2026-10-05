"""验证 RV 规约统一建立在真实工具调用和有限操作效果上。"""
from copy import deepcopy

import pytest

from openclaw_guard.integrations.tool_hook_bridge import build_hook_event
from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.policy.trace import TraceCompiler
from openclaw_guard.rv.runtime_verification import RuntimeVerificationEngine
from openclaw_guard.rv.rv_dsl import load_ruleset
from openclaw_guard.rv.tool_events import (
    LEGACY_EFFECTS, OPERATION_EFFECTS, build_tool_call_step, migrate_rules_document,
)
from openclaw_guard.services import build_services
from openclaw_guard.spec.nl2spec_generator import generate_ruleset


def project(tool, params, labels=(), steps=(), call_id="call"):
    event = build_hook_event({"toolName": tool, "params": params,
                              "runId": "run", "toolCallId": call_id})
    event.metadata.update(semantic={"labels": list(labels)}, semantic_rv_trace=list(steps))
    trace = TraceCompiler(PolicyBundle.load()).compile(event, semantic={}, rv_trace=[])
    return build_tool_call_step(event, trace)


def test_catalog_has_explicit_effects_for_every_registered_operation():
    assert {item.family for item in PolicyBundle.load().operations} == set(OPERATION_EFFECTS)


def test_semantic_model_cannot_invent_extra_calls_or_effects():
    step = project("read", {"path": "/workspace/report.txt"},
                   labels=["effect:egress", "network_egress"],
                   steps=[{"event": "file_delete", "props": ["file_delete"]},
                          {"event": "network_egress", "props": ["effect:egress"]}])
    assert step["step_id"] == "run:call"
    assert step["event"] == "tool_call"
    assert step["operation_family"] == "file.read"
    assert step["effects"] == ["read"]
    assert "effect:delete" not in step["props"]
    assert "effect:egress" not in step["props"]


@pytest.mark.parametrize("tool,params", [
    ("network.request", {"url": "https://outside.example/upload"}),
    ("office_network_post", {"url": "https://outside.example/upload"}),
    ("office_document_share", {"document": "report", "access": "external"}),
    ("message", {"action": "send", "target": "outside@example.com", "message": "report"}),
])
def test_same_sensitive_read_constraint_covers_different_egress_tools(tool, params):
    engine = RuntimeVerificationEngine(window_ttl_seconds=None)
    read = project("read", {"path": "/workspace/secret.txt"}, labels=["contains_secret"])
    engine.evaluate([read], session_key="task")
    send = project(tool, params, labels=["external_recipient"], call_id="send")
    assert "egress" in send["effects"]
    result = engine.preview([send], session_key="task")
    assert result["verdict"] == "block"
    assert result["proposed_verdict"] == "block"
    assert result["hard_block_evidence"] == "rv_rule_match"
    assert result["downgrade_reason"] is None
    assert read["step_id"] in result["matched_history_step_ids"]


def test_unexecuted_read_does_not_arm_monitor():
    engine = RuntimeVerificationEngine(window_ttl_seconds=None)
    engine.preview([project("read", {"path": "/workspace/secret.txt"}, labels=["contains_secret"])])
    result = engine.preview([project("message", {"target": "outside@example.com"}, labels=["external_recipient"])])
    assert result["verdict"] == "ask"
    assert engine.window.snapshot() == []


def test_unknown_tool_is_explicit_and_requests_native_approval(tmp_path):
    step = project("unknown_extension", {"effect": "read_only"}, labels=["file_read"])
    assert step["effects"] == ["unknown"]
    config = tmp_path / "openclaw.json"
    config.write_text("{}", encoding="utf-8")
    result = build_services(tmp_path, config_path=config).handle_before_tool_call({
        "toolName": "unknown_extension", "params": {"effect": "read_only"}})
    assert result["action"] == "require_approval"


def test_all_default_requirements_are_migrated_and_migration_is_idempotent():
    rules = load_ruleset()
    raw = rules.model_dump(by_alias=True, exclude_none=True)
    assert migrate_rules_document(raw) == raw
    def check(req):
        assert req.tool is not None
        assert req.event is None
        assert not set(req.all_of + req.any_of + req.none_of).intersection(LEGACY_EFFECTS)
        if req.sequence:
            for child in req.sequence.steps:
                check(child)
    for monitor in rules.monitors:
        for rule in monitor.rules:
            check(rule.when)


def test_generated_specs_use_tool_call_model():
    rules = generate_ruleset("当发送外部邮件时需要确认")
    assert rules.event_model == "tool-call-v1"
    assert all(rule.when.tool is not None for monitor in rules.monitors for rule in monitor.rules)


@pytest.mark.parametrize("failed", [False, True])
def test_real_hook_commits_exactly_one_call_only_after_success(tmp_path, failed):
    config = tmp_path / "openclaw.json"
    config.write_text("{}", encoding="utf-8")
    target = tmp_path / "README.md"
    target.write_text("public summary", encoding="utf-8")
    services = build_services(tmp_path, config_path=config)
    payload = {"toolName": "read", "params": {"path": str(target)},
               "sessionId": "task", "runId": "run", "toolCallId": "call"}
    before = services.handle_before_tool_call(payload)
    assert before["action"] == "allow"
    event = before["action_record"]["event"]
    trace = event["metadata"]["rv_trace"]
    assert len(trace) == 1
    assert trace[0]["event_model"] == "tool-call-v1"
    assert services.rv_engine._get_session_window("session_task").snapshot() == []
    result = services.handle_after_tool_call({**payload, "result": "public summary", "error": "failed" if failed else ""})
    assert result["ok"]
    history = services.rv_engine._get_session_window("session_task").snapshot()
    assert len(history) == (0 if failed else 1)
    if history:
        assert history[0]["execution_state"] == "succeeded"
        assert history[0]["step_id"] == "run:call"
        assert history[0]["provenance"]["source"] == "hook_projection"


def test_restored_old_history_keeps_timestamp_and_marks_unverified_replay():
    engine = RuntimeVerificationEngine(window_ttl_seconds=None)
    engine.window.push({"step_id": "old", "event": "file_read", "props": ["contains_secret"]})
    state = deepcopy(engine.serialize_state())
    restored = RuntimeVerificationEngine(window_ttl_seconds=None)
    restored.deserialize_state(state)
    step = restored.window.snapshot()[0]
    assert step["_ts_epoch"] == state["default_window"]["buffer"][0]["_ts_epoch"]
    assert step["provenance"]["source"] == "legacy_replay"


def test_confirmed_pmkb_block_is_not_downgraded():
    engine = RuntimeVerificationEngine(window_ttl_seconds=None)
    engine.evaluate([project("read", {"path": "/workspace/secret.txt"}, labels=["contains_secret"])])
    result = engine.preview([project("network.request", {"url": "https://outside.example"},
                                    labels=["external_recipient"], call_id="send")],
                            policy_decision={"effect": "block"})
    assert result["verdict"] == "block"
    assert result["hard_block_evidence"] == "pmkb_confirmed"


@pytest.mark.parametrize("tool,params,effects", [
    ("exec", {"command": "cat report.txt"}, {"execute", "read"}),
    ("exec", {"command": "curl https://outside.example"}, {"execute", "egress"}),
    ("exec", {"command": "rm -rf folder"}, {"execute", "delete"}),
    ("exec", {"command": "python3 helper.py"}, {"execute", "unknown"}),
    ("cron", {"action": "list"}, {"read"}),
    ("cron", {"action": "add"}, {"configure", "schedule"}),
    ("message", {"action": "read"}, {"read"}),
    ("message", {"action": "unregistered"}, {"unknown"}),
    ("web_fetch", {"url": "https://outside.example"}, {"read"}),
])
def test_compound_tools_use_actual_subactions_and_command_effects(tool, params, effects):
    assert set(project(tool, params)["effects"]) == effects


def test_untrusted_content_loaded_by_fetch_then_send_blocks_independently():
    engine = RuntimeVerificationEngine(window_ttl_seconds=None)
    engine.evaluate([project("web_fetch", {"url": "https://outside.example"}, labels=["external_source"])])
    result = engine.preview([project("message", {"target": "outside@example.com"},
                                    labels=["external_recipient"], call_id="send")])
    assert result["verdict"] == "block"
    assert result["proposed_verdict"] == "block"
    assert result["hard_block_evidence"] == "rv_rule_match"


def test_public_send_after_sensitive_read_exposes_existing_rule_false_positive():
    engine = RuntimeVerificationEngine(window_ttl_seconds=None)
    engine.evaluate([project("read", {"path": "/workspace/secret.txt"}, labels=["contains_secret"])])
    result = engine.preview([project("message", {"target": "outside@example.com", "message": "public summary"},
                                    labels=["external_recipient"], call_id="send")])
    assert result["verdict"] == "block"
    assert result["hard_block_evidence"] == "rv_rule_match"



def test_unregistered_subaction_of_known_tool_cannot_use_low_risk_message_allow():
    step = project("message", {"action": "unregistered", "target": "teammate@company.local"})
    result = RuntimeVerificationEngine().preview([step])
    assert result["verdict"] == "ask"
    assert result["triggered_rule_id"] == "tool_unmodeled_effect_ask"



def test_public_hook_trace_scrubs_new_arguments_and_entities():
    from openclaw_guard.engine.pipeline import _scrub_public_trace
    value = {"arguments": {"body": "private-token"},
             "entities": [{"kind": "paths", "values": ["/private/secret.txt"]}],
             "resource": {"type": "path", "ids": ["/private/secret.txt"]}}
    _scrub_public_trace(value)
    assert value["arguments"] == {}
    assert value["entities"][0]["values"] == ["[REDACTED]"]
    assert value["resource"]["ids"] == ["[REDACTED]"]


NORMAL_CALLS = [
    ("read", {"path": "README.md"}),
    ("exec", {"command": "ls -la"}),
    ("exec", {"command": "git status --short"}),
    ("exec", {"command": "git log --oneline"}),
    ("exec", {"command": "rg TODO src"}),
    ("exec", {"command": "sed -n '1,20p' README.md"}),
    ("write", {"path": "summary.md", "content": "public summary"}),
    ("message", {"action": "send", "target": "teammate@company.local", "message": "meeting reminder"}),
    ("message", {"action": "send", "target": "partner@example.com", "message": "public summary"}),
    ("cron", {"action": "add", "job": {"name": "daily summary"}}),
    ("cron", {"action": "list"}),
    ("gateway", {"action": "config.get"}),
    ("sessions_list", {}),
    ("memory_search", {"query": "meeting notes"}),
    ("web_fetch", {"url": "https://public.example/help"}),
]


@pytest.mark.parametrize("tool,params", NORMAL_CALLS)
def test_normal_call_pair_has_no_added_hard_block_or_approval_request(tmp_path, tool, params):
    actions = []
    for enabled in (False, True):
        project_dir = tmp_path / str(enabled)
        project_dir.mkdir()
        config = project_dir / "openclaw.json"
        config.write_text("{}", encoding="utf-8")
        (project_dir / "README.md").write_text("public summary", encoding="utf-8")
        services = build_services(project_dir, config_path=config)
        services.rv_toggle({"enabled": enabled})
        call_params = dict(params)
        if "path" in call_params:
            call_params["path"] = str(project_dir / call_params["path"])
        if tool == "exec":
            call_params["cwd"] = str(project_dir)
        result = services.handle_before_tool_call({"toolName": tool, "params": call_params,
            "sessionId": "normal", "runId": "run", "toolCallId": "call"})
        actions.append(result["action"])
    assert "block" not in actions
    assert actions[0] == actions[1]



def test_non_hook_telemetry_does_not_claim_hook_provenance():
    from openclaw_guard.models import BehaviorEvent
    event = BehaviorEvent(event_id="observed", timestamp="2026-10-04T00:00:00Z",
                          action_type="network_egress", process_name="openclaw", pid=None, user="tester",
                          metadata={"tool_name": "network.request"})
    trace = TraceCompiler(PolicyBundle.load()).compile(event, semantic={}, rv_trace=[])
    assert build_tool_call_step(event, trace)["provenance"]["source"] == "behavior_projection"
