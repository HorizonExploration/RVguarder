"""逐规则授权守卫的范围与独立阻断回归；宿主checker为受控测试夹具。"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import time
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from openclaw_guard.engine import experiment_components as ec
from openclaw_guard.engine.pipeline import _apply_rv_if_available
from openclaw_guard.rv.rv_dsl import Ruleset, compile_monitors
from openclaw_guard.rv.runtime_verification import RuntimeVerificationEngine, WindowManager
from openclaw_guard.spec.authorization_facts import VerifiedCallAuthorization
from openclaw_guard.spec.content_receipts import _canonical, content_version


@pytest.fixture
def scoped():
    """固定有限sink及逐调用身份；不代表原生部署已验证。"""
    params = {"recipient": "partner@example.test", "sourcePath": "summary.txt"}
    step = {"step_id": "run:call", "event": "tool_call", "event_model": "tool-call-v1",
        "execution_state": "proposed", "tool_name": "office_message_send", "operation_family": "message.send",
        "effects": ["egress"], "props": ["effect:egress"], "arguments": params,
        "context": {"agent_id": "agent", "session_id": "session", "principal": {"id": "hook:binding"}},
        "provenance": {"run_id": "run", "tool_call_id": "call"}}
    now = int(time.time() * 1000)
    fact = VerifiedCallAuthorization(decision_eligible=True, component_generation=ec.snapshot()[1], step_id="run:call", grant_id="grant", snapshot_id="snapshot",
        task_id="task", principal_id="hook:binding", agent_id="agent", session_id="session", run_id="run",
        tool_call_id="call", tool_name="office_message_send", operation_family="message.send",
        arguments_sha256=hashlib.sha256(_canonical(params)).hexdigest(), recipient=params["recipient"],
        source=content_version("office", "summary.txt", b"public summary"), valid_from_ms=now, expires_at_ms=now+300000)
    guarded = {"id": "external_content", "from": "*", "verdict": "block", "when": {"all_of": ["effect:egress"]},
        "unless_authorized": {"tool_name": "office_message_send", "operation_family": "message.send"}}
    rules = Ruleset.model_validate({"event_model": "tool-call-v1", "version": 3,
        "monitors": [{"name": "Scoped", "rules": [guarded]}]})
    return step, fact, rules


def feed(rules, step, checker=None):
    """仅调用实际DSL生成监视器，不改默认规则文件。"""
    monitor = compile_monitors(rules, authorization_checker=checker)[0]
    return monitor, monitor.feed(step, WindowManager())


def test_exact_host_fact_affects_only_explicit_rule(scoped):
    step, fact, rules = scoped
    assert feed(rules, step)[1] == "block"
    monitor, verdict = feed(rules, step, lambda *_: fact)
    assert verdict is None
    assert monitor.last_authorized_rules == ["external_content"]
    rules.monitors[0].rules.append(rules.monitors[0].rules[0].model_copy(update={"id": "other_hard_block", "unless_authorized": None}))
    monitor, verdict = feed(rules, step, lambda *_: fact)
    assert verdict == "block"
    assert monitor.last_match["rule_id"] == "other_hard_block"


@pytest.mark.parametrize("result", [True, {"decision_eligible": True}, {"snapshot_grant_match": True}, None])
def test_bool_dictionary_or_missing_diagnostic_cannot_authorize(scoped, result):
    step, _, rules = scoped
    step["context"]["host_authorization"] = {"decision_eligible": True, "snapshot_grant_match": True}
    step["props"].append("authorized")
    assert feed(rules, step, lambda *_: result)[1] == "block"


@pytest.mark.parametrize("field", ["step_id", "agent_id", "session_id", "run_id", "tool_call_id", "principal_id", "arguments_sha256"])
def test_wrong_call_scope_cannot_suppress_block(scoped, field):
    step, fact, rules = scoped
    wrong = fact.model_copy(update={field: "0" * 64 if field == "arguments_sha256" else "wrong"})
    assert feed(rules, step, lambda *_: wrong)[1] == "block"


def test_receiver_change_expiry_partial_and_unknown_effect_keep_block(scoped):
    step, fact, rules = scoped
    altered = deepcopy(step)
    altered["arguments"]["recipient"] = "attacker@example.test"
    assert feed(rules, altered, lambda *_: fact)[1] == "block"
    expired = fact.model_copy(update={"expires_at_ms": 1})
    assert feed(rules, step, lambda *_: expired)[1] == "block"
    partial = fact.model_copy(update={"source": fact.source.model_copy(update={"full_resource": False})})
    assert feed(rules, step, lambda *_: partial)[1] == "block"
    altered["effects"].append("unknown")
    assert feed(rules, altered, lambda *_: fact)[1] == "block"


def test_disabled_or_switching_authorization_does_not_suppress_block(scoped):
    step, fact, rules = scoped
    def should_not_run(*_):
        raise AssertionError("disabled checker called")
    with ec.using(ec.ExperimentComponents(authorization=False)):
        assert feed(rules, step, should_not_run)[1] == "block"
    def switching(*_):
        ec.configure(ec.ExperimentComponents(authorization=False))
        ec.reset()
        return fact
    try:
        assert feed(rules, step, switching)[1] == "block"
    finally:
        ec.reset()


def test_parameterized_monitor_keeps_host_checker(scoped):
    step, fact, rules = scoped
    rules.monitors[0].quantifier = "forall"
    rules.monitors[0].bind_vars = ["recipients"]
    step["entities"] = [{"kind": "recipients", "values": ["partner@example.test"]}]
    assert feed(rules, step, lambda *_: fact)[1] is None


def test_rule_scope_is_validated_and_nonverdict_exceptions_rejected(scoped):
    _, _, rules = scoped
    raw = rules.model_dump(by_alias=True)
    rule = raw["monitors"][0]["rules"][0]
    rule["verdict"] = None
    with pytest.raises(ValidationError): Ruleset.model_validate(raw)
    rule["verdict"] = "block"
    rule["to"] = "blocked"
    with pytest.raises(ValidationError): Ruleset.model_validate(raw)
    rule["to"] = None
    rule["unless_authorized"]["operation_family"] = "network.egress"
    with pytest.raises(ValidationError): Ruleset.model_validate(raw)


@pytest.mark.parametrize("policy_action", ["allow", "ask", "block"])
def test_real_pipeline_preserves_other_rv_block_and_pmkb_hard_block(scoped, policy_action):
    step, fact, rules = scoped
    rules.monitors[0].rules.append(rules.monitors[0].rules[0].model_copy(update={"id": "other_hard_block", "unless_authorized": None}))
    engine = RuntimeVerificationEngine(authorization_checker=lambda *_: fact)
    engine._spec_ruleset = rules
    event = SimpleNamespace(metadata={"rv_trace": [step], "session_id": "session"}, raw_payload={})
    decision = SimpleNamespace(action=policy_action, reason="PMKB", rule_ids=[], policy_decision={"effect": policy_action})
    result = _apply_rv_if_available(SimpleNamespace(rv_enabled=lambda: True, rv_engine=engine), event, decision)
    assert result.action == "block"
    if policy_action != "block": assert result.reason.startswith("[RV]")


@pytest.mark.parametrize("parameterized", [False, True])
def test_authorization_exception_audit_is_visible_and_not_restored_as_authority(scoped, parameterized):
    """preview/evaluate记录指定豁免；持久历史不包含可恢复授权，撤销不改旧状态。"""
    step, fact, rules = scoped
    if parameterized:
        rules.monitors[0].quantifier = "forall"
        rules.monitors[0].bind_vars = ["recipients"]
        step["entities"] = [{"kind": "recipients", "values": ["partner@example.test"]}]
    engine = RuntimeVerificationEngine(authorization_checker=lambda *_: fact)
    engine._spec_ruleset = rules
    preview = engine.preview([step])
    assert preview["authorization_exceptions"] == [{"rule_id": "external_content", "step_id": "run:call",
        "grant_id": "grant", "snapshot_id": "snapshot", "task_id": "task"}]
    executed = deepcopy(step)
    executed["execution_state"] = "succeeded"
    assert engine.evaluate([executed])["authorization_exceptions"] == preview["authorization_exceptions"]
    state = engine.serialize_state()
    restored = RuntimeVerificationEngine()
    restored._spec_ruleset = rules
    restored.deserialize_state(state)
    assert "authorization_exceptions" not in str(state)
    assert "grant_id" not in str(state)
    harmless = deepcopy(step)
    harmless.update(step_id="run:read", tool_name="read", operation_family="file.read", effects=["read"], props=["effect:read"])
    # 没有checker重放旧历史不会通过guard改变状态而污染新的无关读取。
    assert restored.preview([harmless])["verdict"] == "ok"
    assert restored.preview([harmless])["authorization_exceptions"] == []


def test_noneligible_typed_fact_does_not_authorize(scoped):
    step, fact, rules = scoped
    fact = fact.model_copy(update={"decision_eligible": False})
    assert feed(rules, step, lambda *_: fact)[1] == "block"


def test_checker_cannot_mutate_step_to_disable_other_block(scoped):
    step, fact, rules = scoped
    rules.monitors[0].rules.append(rules.monitors[0].rules[0].model_copy(update={"id": "other_hard_block", "unless_authorized": None}))
    def mutating(captured, rule_id):
        captured["props"].clear()
        captured["arguments"]["recipient"] = "attacker@example.test"
        return fact
    assert feed(rules, step, mutating)[1] == "block"
    assert step["props"] == ["effect:egress"]
    assert step["arguments"]["recipient"] == "partner@example.test"


@pytest.mark.parametrize("mutation", ["recipient", "source", "lifetime"])
def test_inconsistent_typed_resource_scope_cannot_authorize(scoped, mutation):
    step, fact, rules = scoped
    if mutation == "recipient":
        fact = fact.model_copy(update={"recipient": "attacker@example.test"})
    elif mutation == "source":
        fact = fact.model_copy(update={"source": content_version("office", "other.txt", b"public summary")})
    else:
        fact = fact.model_copy(update={"expires_at_ms": fact.valid_from_ms + 300001})
    assert feed(rules, step, lambda *_: fact)[1] == "block"


def test_cached_old_generation_fact_cannot_be_reused_in_new_arm(scoped):
    step, fact, rules = scoped
    assert feed(rules, step, lambda *_: fact)[1] is None
    try:
        ec.configure(ec.ExperimentComponents(authorization=False))
        ec.reset()
        assert feed(rules, step, lambda *_: fact)[1] == "block"
        new_fact = fact.model_copy(update={"component_generation": ec.snapshot()[1]})
        assert feed(rules, step, lambda *_: new_fact)[1] is None
    finally:
        ec.reset()
