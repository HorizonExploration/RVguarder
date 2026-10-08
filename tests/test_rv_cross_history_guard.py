"""跨会话DSL只接受当前单调用类型事实，不信任props或旧代际。"""
from __future__ import annotations

import hashlib
import time

from openclaw_guard.engine import experiment_components as ec
from openclaw_guard.rv.runtime_verification import RuntimeVerificationEngine
from openclaw_guard.rv.rv_dsl import Ruleset
from openclaw_guard.spec.content_receipts import _canonical
from openclaw_guard.spec.history_facts import VerifiedCrossSessionHistory


def fixture(checker_factory, tmp_path, request):
    """构造最小单调用guard，不声称真实原生防护结果。"""
    step = {"event_model": "tool-call-v1", "event": "tool_call", "step_id": "run:send", "tool_name": "office_network_post",
        "operation_family": "network.egress", "effects": ["egress"], "props": [], "arguments": {"url": "https://outside.test"},
        "context": {"principal": {"id": "principal"}, "agent_id": "agent", "session_id": "session"}, "provenance": {"run_id": "run"}}
    from openclaw_guard.spec.host_authorization import HostAuthorizationStore, TaskBinding
    from openclaw_guard.spec.task_history import HostTaskHistory, HostHistoryLease
    from openclaw_guard.spec.content_receipts import content_version
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = HostAuthorizationStore(tmp_path / "private", agent_workspaces=[workspace])
    history = HostTaskHistory(store, None)
    link = history.register([TaskBinding("task", "principal", "agent", "prior-session"), TaskBinding("task", "principal", "agent", "session")],
                            sensitive_versions=[content_version("office", "note.txt", b"fixture").model_dump(mode="json")])
    lease = HostHistoryLease(history, [link["id"]], expires_at_ms=int(time.time() * 1000) + 1000)
    request.addfinalizer(lease.release)
    fact = VerifiedCrossSessionHistory(lease=lease,relationship="exact_consumed_byte_identity", component_generation=ec.snapshot()[1],
        step_id="run:send", tool_name="office_network_post", operation_family="network.egress", principal_id="principal",
        agent_id="agent", session_id="session", run_id="run", task_id="task", history_step_ids=("prior:read",),
        receipt_ids=("receipt",), link_ids=("link",), source_sha256="a" * 64,
        arguments_sha256=hashlib.sha256(_canonical(step["arguments"])).hexdigest(), expires_at_ms=int(time.time() * 1000) + 10000)
    engine = RuntimeVerificationEngine(history_checker=checker_factory(fact))
    engine._spec_ruleset = Ruleset.model_validate({"version": 2, "event_model": "tool-call-v1", "monitors": [{
        "name": "Cross", "rules": [{"id": "cross_sensitive", "from": "idle", "verdict": "block",
        "verified_history": "same_task_sensitive_bytes", "when": {"tool": {"effects_any_of": ["egress"]}}}]}]})
    return engine, step


def test_exact_fact_independently_blocks_and_references_successful_receipt(tmp_path, request):
    engine, step = fixture(lambda fact: lambda *_: fact, tmp_path, request)
    result = engine.preview([step])
    assert result["verdict"] == "block" and result["hard_block_evidence"] == "rv_rule_match"
    assert result["matched_history_step_ids"] == ["prior:read"]
    assert result["verified_cross_session_receipt_ids"] == ["receipt"]


def test_dictionary_or_semantic_claim_is_not_a_trusted_history_fact(tmp_path, request):
    engine, step = fixture(lambda fact: lambda *_: fact.model_dump(), tmp_path, request)
    step["props"] = ["same_task_sensitive_bytes"]
    assert engine.preview([step])["verdict"] != "block"


def test_changed_arguments_do_not_reuse_fact(tmp_path, request):
    engine, step = fixture(lambda fact: lambda *_: fact, tmp_path, request)
    step["arguments"]["url"] = "https://substitute.test"
    assert engine.preview([step])["verdict"] != "block"


def test_checker_cannot_restore_old_fact_after_component_aba(tmp_path, request):
    def checker_factory(fact):
        def checker(*_):
            ec.configure(ec.ExperimentComponents.from_disabled("cross_session"))
            ec.reset()
            return fact
        return checker
    engine, step = fixture(checker_factory, tmp_path, request)
    try:
        assert engine.preview([step])["verdict"] != "block"
    finally:
        ec.reset()


def test_revocation_between_fact_lookup_and_rule_match_cannot_commit_block(tmp_path, request, monkeypatch):
    """检查后停用再匹配，最终内存提交仍必须拒绝旧事实。"""
    captured = []
    def checker_factory(fact):
        captured.append(fact)
        return lambda *_: fact
    engine, step = fixture(checker_factory, tmp_path, request)
    from openclaw_guard.rv import rv_dsl
    original = rv_dsl._matches_requirement
    def match(*args, **kwargs):
        captured[0].lease.release()
        return original(*args, **kwargs)
    monkeypatch.setattr(rv_dsl, '_matches_requirement', match)
    assert engine.preview([step])['verdict'] != 'block'
