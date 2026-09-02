from __future__ import annotations

from openclaw_guard.integrations.tool_hook_bridge import build_hook_event, build_hook_source_message


def test_openclaw_native_tools_have_explicit_semantic_mapping():
    cases = [
        ("sessions_history", "file_read", "session", "session.read", "low", "会话历史"),
        ("sessions_list", "file_read", "session", "session.read", "low", "列出会话"),
        ("memory_search", "file_read", "memory", "memory.read", "low", "搜索记忆"),
        ("memory_get", "file_read", "memory", "memory.read", "low", "读取记忆"),
        ("session_status", "file_read", "session", "session.read", "low", "读取会话状态"),
        ("agents_list", "file_read", "agents", "agents.read", "low", "列出代理"),
        ("get_goal", "file_read", "planning", "goal.read", "low", "读取目标"),
        ("update_plan", "file_write", "planning", "plan.write", "medium", "更新计划"),
        ("create_goal", "file_write", "planning", "goal.write", "medium", "创建目标"),
        ("update_goal", "file_write", "planning", "goal.write", "medium", "更新目标"),
    ]

    for tool_name, action_type, tool_group, permission_family, risk_class, summary in cases:
        event = build_hook_event(
            {
                "toolName": tool_name,
                "params": {"id": "fixture"},
                "runId": f"run-{tool_name}",
                "toolCallId": f"call-{tool_name}",
            }
        )

        assert event.action_type == action_type
        assert event.metadata["tool_origin"] == "openclaw_native"
        assert event.metadata["tool_group"] == tool_group
        assert event.metadata["permission_family"] == permission_family
        assert event.metadata["risk_class"] == risk_class
        assert summary in build_hook_source_message(event)


def test_agentdojo_evaluation_marker_is_propagated_for_mapped_tool():
    event = build_hook_event(
        {
            "toolName": "memory_search",
            "agentdojoToolName": "search_calendar_events",
            "evaluationMode": "agentdojo",
            "params": {"query": "meeting"},
        }
    )

    assert event.metadata["evaluation_mode"] == "agentdojo"


def test_dangerous_session_control_tools_do_not_inherit_read_only_native_mapping():
    for tool_name in ("sessions_send", "sessions_spawn"):
        event = build_hook_event(
            {
                "toolName": tool_name,
                "params": {"id": "fixture"},
                "runId": f"run-{tool_name}",
                "toolCallId": f"call-{tool_name}",
            }
        )

        assert event.action_type != "file_read"
        assert event.metadata["tool_origin"] != "openclaw_native"
        assert event.metadata["risk_class"] != "low"


def test_native_read_mapping_requires_safe_parameters_and_same_session_scope():
    unsafe_cases = [
        {
            "toolName": "memory_search",
            "params": {"query": "read /etc/shadow"},
        },
        {
            "toolName": "memory_get",
            "params": {"url": "https://example.test/export"},
        },
        {
            "toolName": "sessions_history",
            "params": {"sessionKey": "agent:other:main"},
            "sessionKey": "agent:main:main",
        },
    ]

    for index, payload in enumerate(unsafe_cases):
        event = build_hook_event(
            {
                **payload,
                "runId": f"unsafe-native-run-{index}",
                "toolCallId": f"unsafe-native-call-{index}",
                "sessionId": "agent:main:main",
            }
        )

        assert event.metadata["tool_origin"] != "openclaw_native"
        assert event.metadata["risk_class"] != "low"
