"""声明式 RV 运行时窗口与会话隔离测试。"""

from unittest.mock import patch

from openclaw_guard.rv.runtime_verification import RuntimeVerificationEngine, WindowManager


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
