from __future__ import annotations

from openclaw_guard.integrations.tool_hook_bridge import build_hook_event, build_hook_source_message
from openclaw_guard.engine.semantic_enhancer import SemanticEnhancer
from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.policy.trace import TraceCompiler


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


def test_openclaw_read_profiles_are_auto_allowed_by_pmkb():
    from openclaw_guard.policy.engine import AuthorizationPolicyEngine

    engine = AuthorizationPolicyEngine()
    for tool_name in (
        "sessions_history", "sessions_list", "session_status", "memory_search",
        "memory_get", "get_goal", "agents_list",
    ):
        event = build_hook_event({
            "toolName": tool_name,
            "params": {"query": "daily"},
            "runId": f"run-{tool_name}",
            "toolCallId": f"call-{tool_name}",
            "sessionId": "native-policy-test",
        })
        decision = engine.evaluate(event)
        assert decision.effect == "auto_allow_audit"
        assert decision.match_status == "matched"


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


def test_message_recipients_are_not_misclassified_as_paths():
    recipients = [f"person-{index}@external.example" for index in range(11)]
    event = build_hook_event({
        "toolName": "message",
        "params": {"to": recipients, "content": "status update"},
        "runId": "recipient-run",
        "toolCallId": "recipient-call",
    })

    assert event.target_paths == []


def test_message_trace_preserves_all_recipients_and_quantity():
    recipients = [f"person-{index}@external.example" for index in range(11)]
    event = build_hook_event({
        "toolName": "message",
        "params": {"to": recipients, "content": "status update"},
        "runId": "recipient-trace-run",
        "toolCallId": "recipient-trace-call",
    })
    semantic = SemanticEnhancer(api_key="").evaluate(
        event,
        {"source_message": "发送状态更新", "origin": "hook"},
    )
    event.metadata.update(semantic)
    trace = TraceCompiler(PolicyBundle.load()).compile(
        event,
        semantic=semantic["semantic"],
        rv_trace=semantic["rv_trace"],
        source_message="发送状态更新",
    )

    assert trace.resource.type == "recipient"
    assert len(trace.resource.ids) == 11
    assert trace.data.quantity == 11
    assert trace.context.recipient_zone == "external"
