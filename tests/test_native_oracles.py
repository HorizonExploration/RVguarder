"""实际效果Oracle的失败准入和复用污染反例。"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
import hashlib
import json

import pytest

from openclaw_guard.engine.experiment_components import ExperimentComponents
from testlab.office_chain.native_oracles import (
    evaluate_native_oracles, validate_observation_inputs, verify_causal_native_block,
    verify_cross_session_native_block,
)


def observations():
    """公开固定字节的最小观测，不伪称真实实验。"""
    scenario = {"scenario_id": "fixture", "events": [{"hook_payload": {"toolName": "read", "params": {"path": "note.txt"}}}],
        "attack_oracle": {"recipient": "outside@example.test", "source_sha256": "a" * 64}}
    observation = {"arm": "Full", "components": asdict(ExperimentComponents()), "passed": True,
        "cleanup_passed": True, "agent_timed_out": False, "agent_returncodes": [0],
        "scenario_sha256": hashlib.sha256(json.dumps(scenario, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
        "hooks": [{"toolName": "read", "paramSha256": hashlib.sha256(b'{"path":"note.txt"}').hexdigest()}],
        "host_grants": [], "native_config": {"plugins": {"entries": {"openclaw-guard-hook": {}}}}}
    return scenario, observation


@pytest.mark.parametrize("codes", [[1], [None], [], [False], [0, 1]])
def test_cli_failure_or_missing_completion_is_not_admitted(codes):
    scenario, observation = observations()
    observation["agent_returncodes"] = codes
    assert evaluate_native_oracles(scenario, observation)["admitted"] is False


@pytest.mark.parametrize("field,value", [("arm", "B0"), ("scenario_sha256", "wrong"), ("components", {}),
                                          ("hooks", []), ("host_grants", [{"forged": True}])])
def test_other_arm_or_changed_input_cannot_be_pooled(field, value):
    scenario, observation = observations()
    observation[field] = value
    with pytest.raises(ValueError):
        validate_observation_inputs(scenario, observation, arm="Full")


def test_missing_legacy_hash_requires_explicit_oracle_only_compatibility():
    scenario, observation = observations()
    observation.pop("scenario_sha256")
    with pytest.raises(ValueError):
        validate_observation_inputs(scenario, observation, arm="Full")
    assert validate_observation_inputs(scenario, observation, arm="Full", allow_legacy_oracle_only=True)["legacy_oracle_only_reuse"]
    changed = deepcopy(scenario)
    changed["events"][0]["hook_payload"]["params"]["path"] = "other.txt"
    with pytest.raises(ValueError):
        validate_observation_inputs(changed, observation, arm="Full", allow_legacy_oracle_only=True)


def causal_fixture():
    """有原生先后顺序与认证完成证据的最小归因记录。"""
    identity = {"runId": "run", "sessionId": "session", "sessionKey": "key", "agentId": "agent"}
    metadata = {"trusted_identity": {"principal_id": "principal"}}
    return {"hooks": [{**identity, "toolName": "read", "toolCallId": "read", "ts": "2026-10-07T00:00:00Z"},
                      {**identity, "toolName": "office_network_post", "toolCallId": "send", "ts": "2026-10-07T00:00:02Z"}],
            "executions": [{"toolName": "read", "toolCallId": "read", "sessionKey": "key", "success": True,
                            "ts": "2026-10-07T00:00:01Z"}],
            "actions": [{"event": {"event_id": "run:send", "metadata": {**deepcopy(metadata), "rv_result": {
                "verdict": "block", "hard_block_evidence": "rv_rule_match", "triggered_rule_id": "rule",
                "trigger_step_id": "run:send", "matched_history_step_ids": ["run:read"]}}}, "decision": {"action": "block"}},
                        {"event": {"event_id": "run:read", "metadata": {**deepcopy(metadata), "rv_trace": [{
                            "step_id": "run:read", "execution_state": "succeeded", "provenance": {
                                "completion_evidence": {"source": "authenticated_after_tool_call"}}}]}}}]}


def test_native_history_attribution_accepts_reverse_action_storage_order():
    assert verify_causal_native_block(causal_fixture(), terminal_tool="office_network_post", rule_ids={"rule"})["passed"]


def test_first_dangerous_boundary_does_not_accept_later_sink_block():
    observation = causal_fixture()
    observation["hooks"].insert(1, {**observation["hooks"][0], "toolName": "exec", "toolCallId": "danger",
                                    "ts": "2026-10-07T00:00:01.5Z"})
    assert not verify_causal_native_block(observation, terminal_tool="exec", target_index=1, rule_ids={"rule"})["passed"]
    assert verify_causal_native_block(observation, terminal_tool="office_network_post", rule_ids={"rule"})["passed"]


def cross_fixture():
    """构造两真实身份结构的校验夹具，不作为实验结果计数。"""
    observation = causal_fixture()
    observation["hooks"][0].update(runId="prior-run", sessionId="prior-session", sessionKey="prior-key")
    source = {"namespace": "office", "resource_id": "office:secret.txt", "sha256": "a" * 64,
              "size_bytes": 12, "full_resource": True, "offset": 0}
    target = observation["actions"][0]["event"]["metadata"]["rv_result"]
    target.update(matched_history_step_ids=["prior-run:read"], verified_cross_session_receipt_ids=["receipt"],
                  verified_cross_session_link_ids=["link"])
    observation["actions"][1]["event"]["event_id"] = "prior-run:read"
    observation["actions"][1]["event"]["metadata"]["rv_trace"][0]["step_id"] = "prior-run:read"
    observation["hooks"][0]["paramSha256"] = "b" * 64
    observation["executions"][0].update(sessionKey="prior-key", executionReceipt={"signature": "c" * 64, "payload": {
        "receipt_id": "receipt", "kind": "read", "success": True, "tool_name": "read", "arguments_sha256": "b" * 64,
        "run_id": "prior-run", "tool_call_id": "read", "session_id": "prior-session", "agent_id": "agent",
        "principal_id": "principal", "task_id": "task", "issued_at_ms": 1791331201000,
        "expires_at_ms": 1791331501000, "inputs": [source]}})
    observation["host_task_link"] = {"id": "link", "issued_at": 1791331200, "expires_at": 1791331500,
        "classification_source": "controlled_host_registration", "sensitive_versions": [source],
        "bindings": [{"task_id": "task", "principal_id": "principal", "agent_id": "agent", "run_id": "",
                      "session_id": session} for session in ["prior-session", "session"]]}
    return observation


def test_cross_session_identity_and_prior_receipt_linkage():
    assert verify_cross_session_native_block(cross_fixture(), rule_ids={"rule"})["passed"]


@pytest.mark.parametrize("tamper", ["session", "agent", "principal", "task", "version", "expiry", "revocation",
                                   "receipt_id", "params", "late_completion", "failed_read", "classification"])
def test_cross_session_block_rejects_misassociated_or_stale_native_evidence(tamper):
    observation = cross_fixture()
    receipt = observation["executions"][0]["executionReceipt"]["payload"]
    if tamper == "session":
        observation["host_task_link"]["bindings"][0]["session_id"] = "other"
    elif tamper == "agent":
        receipt["agent_id"] = "other"
    elif tamper == "principal":
        receipt["principal_id"] = "other"
    elif tamper == "task":
        receipt["task_id"] = "other"
    elif tamper == "version":
        observation["host_task_link"]["sensitive_versions"] = []
    elif tamper == "expiry":
        receipt["expires_at_ms"] = 1791331200000
    elif tamper == "revocation":
        observation["host_task_link_revocations"] = [{"success": True}]
    elif tamper == "receipt_id":
        receipt["receipt_id"] = "other"
    elif tamper == "params":
        receipt["arguments_sha256"] = "d" * 64
    elif tamper == "late_completion":
        observation["executions"][0]["ts"] = "2026-10-07T00:00:03Z"
    elif tamper == "failed_read":
        observation["executions"][0]["success"] = False
    else:
        observation["host_task_link"]["classification_source"] = "agent_attachment"
    assert not verify_cross_session_native_block(observation, rule_ids={"rule"})["passed"]


@pytest.mark.parametrize("attack", ["later_completion", "other_session", "other_principal", "wrong_rule", "pmkb_block", "self_reference", "failed_read"])
def test_native_history_attribution_rejects_noncausal_evidence(attack):
    observation = causal_fixture()
    if attack == "later_completion":
        observation["executions"][0]["ts"] = "2026-10-07T00:00:03Z"
    elif attack == "other_session":
        observation["hooks"][0]["sessionId"] = "unrelated"
    elif attack == "other_principal":
        observation["actions"][1]["event"]["metadata"]["trusted_identity"]["principal_id"] = "other"
    elif attack == "wrong_rule":
        observation["actions"][0]["event"]["metadata"]["rv_result"]["triggered_rule_id"] = "unrelated"
    elif attack == "pmkb_block":
        observation["actions"][0]["event"]["metadata"]["rv_result"]["hard_block_evidence"] = "pmkb_hard_block"
    elif attack == "self_reference":
        observation["actions"][0]["event"]["metadata"]["rv_result"]["matched_history_step_ids"] = ["run:send"]
    else:
        observation["executions"][0]["success"] = False
    assert not verify_causal_native_block(observation, terminal_tool="office_network_post", rule_ids={"rule"})["passed"]
