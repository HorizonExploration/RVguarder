"""声明式 RV 运行时窗口与会话隔离测试。"""

from unittest.mock import patch

from openclaw_guard.rv.runtime_verification import RuntimeVerificationEngine, WindowManager
from openclaw_guard.rv.rv_dsl import ChainRule, MonitorSpec, Ruleset, StepRequirement


def test_window_manager_preserves_order_and_bound():
    window = WindowManager(max_size=2, ttl_seconds=None)
    window.push({"event": "read", "props": ["file_read"]})
    window.push({"event": "write", "props": ["file_write"]})
    window.push({"event": "delete", "props": ["file_delete"]})

    assert [step["event"] for step in window.snapshot()] == ["write", "delete"]
    assert window.latest()["event"] == "delete"


def test_window_manager_matches_ordered_sequence_and_counts():
    window = WindowManager(max_size=5, ttl_seconds=None)
    window.push({"event": "search", "props": ["file_search"]})
    window.push({"event": "delete", "props": ["file_delete"]})

    assert window.sequence_matches([{"file_search"}, {"file_delete"}])
    assert window.cumulative_count("file_delete") == 1


def test_window_manager_ttl_expiry_and_serialization():
    window = WindowManager(max_size=5, ttl_seconds=1)
    with patch("openclaw_guard.rv.runtime_verification._time.time") as clock:
        clock.return_value = 1000.0
        window.push({"event": "old", "props": ["old"]})
        clock.return_value = 1005.0
        window.push({"event": "new", "props": ["new"]})
        assert [step["event"] for step in window.snapshot()] == ["new"]
        restored = WindowManager.from_dict(window.to_dict())
        assert restored.latest()["event"] == "new"


def test_engine_uses_generated_dsl_for_legacy_mode_alias():
    engine = RuntimeVerificationEngine(rule_mode="fsm", window_ttl_seconds=None)
    assert engine.rule_mode() == "dsl"
    result = engine.evaluate([{
        "step_id": "s1",
        "event": "mail_send",
        "props": ["mail_send", "external_recipient", "contains_secret"],
    }])
    assert result["verdict"] == "block"
    assert result["rule_mode"] == "dsl"


def test_engine_keeps_sessions_isolated():
    engine = RuntimeVerificationEngine(window_size=10, window_ttl_seconds=None)
    engine.evaluate([{
        "step_id": "s1",
        "event": "file_read",
        "props": ["file_read", "contains_secret"],
    }], session_key="session-a")
    result = engine.evaluate([{
        "step_id": "s1",
        "event": "mail_send",
        "props": ["mail_send", "external_recipient"],
    }], session_key="session-b")
    assert result["verdict"] != "block"


def test_engine_replays_same_session_chain_and_can_release_it():
    engine = RuntimeVerificationEngine(window_size=10, window_ttl_seconds=None)
    engine.evaluate([{
        "step_id": "s1",
        "event": "file_read",
        "props": ["attachment_open", "channel_external"],
    }], session_key="chain")
    engine.evaluate([{
        "step_id": "s2",
        "event": "file_read",
        "props": ["contains_secret"],
    }], session_key="chain")
    result = engine.evaluate([{
        "step_id": "s3",
        "event": "mail_send",
        "props": ["mail_send", "external_recipient"],
    }], session_key="chain")

    assert result["verdict"] == "block"
    assert engine.session_count() == 1
    engine.release_session("chain")
    assert engine.session_count() == 0


def test_engine_reset_clears_window_and_summary():
    engine = RuntimeVerificationEngine(window_size=10, window_ttl_seconds=None)
    engine.evaluate([{"step_id": "s1", "event": "chat_message", "props": ["chat_message"]}])
    assert engine.result_summary()["window_size"] == 1
    engine.reset()
    assert engine.result_summary()["window_size"] == 0


def _packet_rule_engine() -> RuntimeVerificationEngine:
    engine = RuntimeVerificationEngine(window_ttl_seconds=None)
    engine._spec_ruleset = Ruleset(monitors=[MonitorSpec(name="PacketMonitor", rules=[
        ChainRule(id="read_arms", **{"from": "idle", "to": "armed"},
                  when=StepRequirement(any_of=["file_read"])),
        ChainRule(id="package_arms", **{"from": "armed", "to": "packed"},
                  when=StepRequirement(any_of=["file_package"])),
        ChainRule(id="pack_egress", **{"from": "packed", "to": "blocked"}, verdict="block",
                  when=StepRequirement(any_of=["network_egress"])),
    ])])
    return engine


def test_preview_reports_causal_transition_and_history_step_ids():
    engine = _packet_rule_engine()
    engine.evaluate([{"step_id": "read-1", "event": "read", "props": ["file_read"]}])
    engine.evaluate([{"step_id": "pack-1", "event": "write", "props": ["file_package"]}])

    preview = engine.preview([{"step_id": "send-1", "event": "send", "props": ["network_egress"]}])

    assert preview["verdict"] == "block"
    assert preview["triggered_rule_id"] == "pack_egress"
    assert preview["trigger_step_id"] == "send-1"
    assert preview["matched_history_step_ids"] == ["read-1", "pack-1"]

    committed = _packet_rule_engine()
    committed.evaluate([{"step_id": "read-1", "event": "read", "props": ["file_read"]}])
    committed.evaluate([{"step_id": "pack-1", "event": "write", "props": ["file_package"]}])
    evaluated = committed.evaluate([{"step_id": "send-1", "event": "send", "props": ["network_egress"]}])
    assert evaluated["triggered_rule_id"] == preview["triggered_rule_id"]
    assert evaluated["matched_history_step_ids"] == preview["matched_history_step_ids"]


def test_sequence_rule_reports_exact_prior_steps():
    engine = RuntimeVerificationEngine(window_ttl_seconds=None)
    engine._spec_ruleset = Ruleset(monitors=[MonitorSpec(name="SequenceMonitor", rules=[
        ChainRule(id="read_package_egress", **{"from": "idle", "to": "blocked"}, verdict="block",
                  when=StepRequirement(sequence={"steps": [
                      {"any_of": ["file_read"]},
                      {"any_of": ["file_package"]},
                      {"any_of": ["network_egress"]},
                  ]})),
    ])])
    engine.evaluate([{"step_id": "read-1", "event": "read", "props": ["file_read"]}])
    engine.evaluate([{"step_id": "pack-1", "event": "write", "props": ["file_package"]}])

    result = engine.preview([{"step_id": "send-1", "event": "send", "props": ["network_egress"]}])

    assert result["triggered_rule_id"] == "read_package_egress"
    assert result["trigger_step_id"] == "send-1"
    assert result["matched_history_step_ids"] == ["read-1", "pack-1"]


def test_rv_prefix_replay_cannot_use_future_window_event():
    engine = RuntimeVerificationEngine(window_ttl_seconds=None)
    engine._spec_ruleset = Ruleset(monitors=[MonitorSpec(name="NoLookahead", rules=[
        ChainRule(id="future_egress_arms", **{"from": "idle", "to": "armed"},
                  when=StepRequirement(all_of=["file_read"], window_any_of={"labels": ["network_egress"]})),
        ChainRule(id="armed_egress_blocks", **{"from": "armed", "to": "blocked"}, verdict="block",
                  when=StepRequirement(all_of=["network_egress"])),
    ])])

    result = engine.evaluate([
        {"step_id": "read-1", "event": "read", "props": ["file_read"]},
        {"step_id": "send-1", "event": "send", "props": ["network_egress"]},
    ])

    assert result["verdict"] == "ok"
    assert result["triggered_rule_id"] is None


def test_parameterized_monitor_does_not_cross_bind_history():
    from openclaw_guard.rv.rv_dsl import compile_monitors

    ruleset = Ruleset(monitors=[MonitorSpec(
        name="PerPathMonitor", bind_vars=["paths"], quantifier="forall", rules=[
            ChainRule(id="read_egress_blocks", **{"from": "idle", "to": "blocked"}, verdict="block",
                      when=StepRequirement(sequence={"steps": [
                          {"any_of": ["file_read"]},
                          {"any_of": ["network_egress"]},
                      ]})),
        ]
    )])
    monitor = compile_monitors(ruleset)[0]
    window = WindowManager(max_size=10, ttl_seconds=None)
    steps = [
        {"step_id": "path-a-read", "event": "read", "props": ["file_read"],
         "entities": [{"kind": "paths", "values": ["artifact-a"]}]},
        {"step_id": "path-b-send", "event": "send", "props": ["network_egress"],
         "entities": [{"kind": "paths", "values": ["artifact-b"]}]},
    ]
    verdicts = []
    for step in steps:
        window.push(step)
        verdicts.append(monitor.feed(step, window))

    assert verdicts == [None, None]
    assert monitor.last_match is None


def test_preview_does_not_commit_candidate_chain_step():
    engine = _packet_rule_engine()
    engine.evaluate([{"step_id": "read-1", "event": "read", "props": ["file_read"]}])

    preview = engine.preview([{"step_id": "pack-preview", "event": "write", "props": ["file_package"]}])
    later = engine.evaluate([{"step_id": "send-1", "event": "send", "props": ["network_egress"]}])

    assert preview["verdict"] == "ok"
    assert later["verdict"] == "ok"
