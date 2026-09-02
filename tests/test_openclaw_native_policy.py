from openclaw_guard.integrations.tool_hook_bridge import build_hook_event
from openclaw_guard.policy.engine import AuthorizationPolicyEngine


def test_openclaw_native_read_tools_are_auto_allowed_by_pmkb():
    engine = AuthorizationPolicyEngine()

    for tool_name in (
        "sessions_history",
        "sessions_list",
        "session_status",
        "memory_search",
        "memory_get",
        "get_goal",
        "agents_list",
    ):
        event = build_hook_event(
            {
                "toolName": tool_name,
                "params": {"query": "daily"},
                "runId": f"run-{tool_name}",
                "toolCallId": f"call-{tool_name}",
                "sessionId": "native-policy-test",
            }
        )
        decision = engine.evaluate(event)
        assert decision.effect == "auto_allow_audit"
        assert decision.match_status == "matched"
