from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

from testlab.office_chain.frozen_provider import (
    DEFAULT_MODEL_ID,
    FixedTrajectoryError,
    FrozenTrajectoryProvider,
    completion_for,
    scenario_tool_calls,
    serve,
)
from testlab.office_chain.matrix import (
    EXPECTED_TOTAL_SCENARIOS,
    load_matrix,
    scenario_index,
)


def _matrix() -> dict:
    return load_matrix()


def _messages_with(calls: list[dict], *, task: str = "执行固定办公任务") -> list[dict]:
    messages: list[dict] = [{"role": "user", "content": task}]
    for index, call in enumerate(calls):
        messages.append({
            "role": "assistant",
            "tool_calls": [{
                "id": f"call-{index}",
                "type": "function",
                "function": {
                    "name": call["toolName"],
                    "arguments": json.dumps(call["params"], ensure_ascii=False),
                },
            }],
        })
        messages.append({"role": "tool", "tool_call_id": f"call-{index}", "content": "ok"})
    return messages


def _post(port: int, path: str, payload) -> tuple[int, dict]:
    body = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_scenario_tool_calls_covers_every_scenario_in_stable_order():
    matrix = _matrix()
    scenarios = matrix["scenarios"]
    assert len(scenarios) == EXPECTED_TOTAL_SCENARIOS

    for scenario in scenarios:
        calls = scenario_tool_calls(scenario)
        assert calls, f"{scenario['scenario_id']} 的工具调用序列不得为空"
        expected_names = [event["hook_payload"]["toolName"] for event in scenario["events"]]
        assert [call["toolName"] for call in calls] == expected_names
        for call in calls:
            assert isinstance(call["toolName"], str) and call["toolName"]
            assert isinstance(call["params"], dict)
        # 顺序稳定且为独立副本。
        assert scenario_tool_calls(scenario) == calls
        assert calls[0] is not scenario_tool_calls(scenario)[0]


def test_scenario_tool_calls_maps_office_semantics():
    index = scenario_index(_matrix())
    scenario = index["DSH-2026-853-CAL-A1"]
    calls = scenario_tool_calls(scenario)

    assert calls[0]["toolName"] == "write"
    assert set(calls[0]["params"]) == {"path", "content"}
    read_call = next(call for call in calls if call["toolName"] == "read")
    assert set(read_call["params"]) == {"path"}

    message_scenario = next(
        item for item in _matrix()["scenarios"]
        if any(event["hook_payload"]["toolName"] == "office_message_send" for event in item["events"])
    )
    message_call = next(
        call for call in scenario_tool_calls(message_scenario)
        if call["toolName"] == "office_message_send"
    )
    assert "recipient" in message_call["params"]
    assert "body" in message_call["params"]
    assert "recipients" not in message_call["params"]
    assert "text" not in message_call["params"]


def test_provider_advances_through_the_frozen_sequence_then_finishes():
    scenario = scenario_index(_matrix())["DSH-2026-853-CAL-A1"]
    provider = FrozenTrajectoryProvider(scenario)
    expected = provider.expected_prefix
    assert provider.model_id == DEFAULT_MODEL_ID
    assert len(expected) >= 2

    for position, call in enumerate(expected):
        response = provider.chat_completion({"messages": _messages_with(expected[:position])})
        choice = response["choices"][0]
        assert choice["finish_reason"] == "tool_calls"
        emitted = choice["message"]["tool_calls"][0]
        assert emitted["function"]["name"] == call["toolName"]
        assert json.loads(emitted["function"]["arguments"]) == call["params"]
        assert response["model"] == DEFAULT_MODEL_ID

    final = provider.chat_completion({"messages": _messages_with(expected)})
    assert final["choices"][0]["finish_reason"] == "stop"
    assert final["choices"][0]["message"]["tool_calls"] == []


def test_provider_rejects_trajectory_drift():
    scenario = scenario_index(_matrix())["DSH-2026-853-CAL-A1"]
    provider = FrozenTrajectoryProvider(scenario)
    forged = [{"role": "user", "content": "执行固定办公任务"}, {
        "role": "assistant",
        "tool_calls": [{"function": {"name": "office_message_send", "arguments": "{}"}}],
    }]
    with pytest.raises(FixedTrajectoryError, match="drift"):
        provider.chat_completion({"messages": forged})
    with pytest.raises(FixedTrajectoryError):
        provider.chat_completion({"messages": "not-a-list"})


def test_expected_prefix_is_deterministic_across_constructions():
    scenario = scenario_index(_matrix())["SK-RCE-CVE-2026-26030-HOL-A1"]
    first = FrozenTrajectoryProvider(scenario)
    second = FrozenTrajectoryProvider(scenario)
    assert first.expected_prefix == second.expected_prefix
    assert first.expected_prefix == scenario_tool_calls(scenario)

    messages = _messages_with([])
    assert completion_for(scenario, messages) == completion_for(scenario, messages)


def test_http_endpoint_serves_frozen_calls_and_rejects_drift_and_unknown_routes():
    scenario = scenario_index(_matrix())["DSH-2026-853-CAL-A1"]
    provider = FrozenTrajectoryProvider(scenario)
    server, port, thread = serve(provider)
    try:
        assert port > 0
        expected = provider.expected_prefix

        valid_messages = [{"role": "user", "content": "执行固定办公任务"}]
        status, payload = _post(port, "/v1/chat/completions", {"model": provider.model_id, "messages": valid_messages})
        assert status == 200
        choice = payload["choices"][0]
        assert choice["finish_reason"] == "tool_calls"
        emitted = choice["message"]["tool_calls"][0]
        assert emitted["function"]["name"] == expected[0]["toolName"]
        assert json.loads(emitted["function"]["arguments"]) == expected[0]["params"]

        drift_messages = _messages_with([], task="执行固定办公任务") + [{
            "role": "assistant",
            "tool_calls": [{"function": {"name": "read", "arguments": "{}"}}],
        }]
        status, payload = _post(port, "/v1/chat/completions", {"messages": drift_messages})
        assert status == 409
        assert payload["error"]["type"] == "trajectory_drift"

        status, payload = _post(port, "/v1/chat/completions", b"{not json")
        assert status == 400
        assert payload["error"]["type"] == "invalid_request"

        status, payload = _post(port, "/v1/unknown", {"messages": []})
        assert status == 404
        assert payload["error"]["type"] == "not_found"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
