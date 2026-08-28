"""Production Hook wiring for principal/capability runtime verification."""

from __future__ import annotations

import json

from openclaw_guard.integrations.tool_hook_bridge import build_hook_event
from openclaw_guard.models import DetectionDecision
from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.policy.models import (
    AuthorizationTrace,
    CoverageResult,
    DataRef,
    OperationRef,
    PolicyDecision,
    PrincipalRef,
    ResourceRef,
)
from openclaw_guard.policy.trace import TraceCompiler
from openclaw_guard.services import GuardServices, build_services
from openclaw_guard.utils import utc_now_iso


def _hook_payload(tool_name: str, *, session_id: str, agent_id: str = "agent-real") -> dict[str, object]:
    """Build the trusted subset emitted by the generated OpenClaw Hook."""
    params: dict[str, object]
    if tool_name == "secret.read":
        params = {"path": "/workspace/.env"}
    else:
        params = {"url": "https://partner.example/upload", "body": "secret=data"}
    return {
        "toolName": tool_name,
        "params": params,
        "runId": f"run-{session_id}",
        "toolCallId": tool_name,
        "agentId": agent_id,
        "sessionKey": f"agent:{agent_id}:main",
        "sessionId": session_id,
    }


def _trace(tool_name: str, *, session_id: str) -> AuthorizationTrace:
    """Return normalized evidence for the two-event toxic-chain fixture."""
    is_read = tool_name == "secret.read"
    return AuthorizationTrace(
        trace_id=f"{session_id}:{tool_name}",
        principal=PrincipalRef(id="agent-real", type="agent", trust="verified"),
        agent_id="agent-real",
        session_id=session_id,
        capability_lineage=["openclaw-agent:agent-real"],
        operation=OperationRef(family="secret.read" if is_read else "network.egress", tool_id=tool_name),
        resource=ResourceRef(
            type="path" if is_read else "url",
            ids=["/workspace/.env" if is_read else "https://partner.example/upload"],
            scope="workspace" if is_read else "external",
        ),
        coverage=CoverageResult(status="complete"),
        data=DataRef(classification="secret", quantity=1),
    )


def _configure_policy_fixtures(services, monkeypatch) -> None:
    """Keep the integration focused on controller wiring, not policy matching."""
    def detector_allow(event):
        return DetectionDecision(
            event_id=event.event_id,
            timestamp=utc_now_iso(),
            action_type=event.action_type,
            risk_level="safe",
            action="allow",
            reason="integration detector allow",
        )

    def compile_trace(event, *, source_message=""):
        del source_message
        return _trace(
            str(event.metadata["tool_name"]),
            session_id=str(event.metadata["session_id"]),
        )

    def evaluate(event, *, source_message=""):
        del source_message
        is_read = event.metadata["tool_name"] == "secret.read"
        return PolicyDecision(
            effect="auto_allow_audit" if is_read else "openclaw_approval",
            match_status="matched",
            policy_version="test",
        )

    monkeypatch.setattr(services.detector, "evaluate", detector_allow)
    monkeypatch.setattr(services.policy_engine, "compile_trace", compile_trace)
    monkeypatch.setattr(services.policy_engine, "evaluate", evaluate)


def _build_services(project, config_path):
    project.mkdir(exist_ok=True)
    config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
    return build_services(project, config_path=config_path)


def test_hook_trace_uses_trusted_agent_contract_not_synthetic_openclaw_user():
    """Removing trusted identity extraction must not collapse every agent to ``openclaw``."""
    event = build_hook_event(_hook_payload("secret.read", session_id="session-a"))

    trace = TraceCompiler(PolicyBundle.load("policies/permissions")).compile(
        event,
        semantic={"principal": {"id": "prompt-injected-user", "type": "human"}},
        rv_trace=[],
    )

    assert trace.principal == PrincipalRef(id="agent-real", type="agent", trust="verified")
    assert trace.agent_id == "agent-real"
    assert trace.capability_lineage == ["openclaw-agent:agent-real"]
    assert trace.principal.id != event.user


def test_hook_without_agent_identity_is_explicitly_untrusted():
    """A synthetic process/user value must never authenticate a cross-session merge."""
    payload = _hook_payload("secret.read", session_id="session-a")
    payload.pop("agentId")
    event = build_hook_event(payload)

    trace = TraceCompiler(PolicyBundle.load("policies/permissions")).compile(
        event,
        semantic={"principal": {"id": "prompt-injected-user", "type": "human"}},
        rv_trace=[],
    )

    assert trace.principal == PrincipalRef(id="unknown", type="agent", trust="unknown")
    assert trace.agent_id is None
    assert trace.capability_lineage == []


def test_missing_identity_preserves_existing_hard_block_evidence():
    """Inconclusive identity evidence must not describe a hard block as approval."""
    event = build_hook_event(_hook_payload("secret.read", session_id="session-a", agent_id=""))
    trace = _trace("secret.read", session_id="session-a").model_copy(update={
        "principal": PrincipalRef(id="unknown", type="agent", trust="unknown"),
        "agent_id": None,
        "capability_lineage": [],
    })
    event.metadata["authorization_trace"] = trace.model_dump()
    decision = DetectionDecision(
        event_id=event.event_id,
        timestamp=utc_now_iso(),
        action_type=event.action_type,
        risk_level="blocked",
        action="block",
        reason="existing hard block",
        policy_decision=PolicyDecision(
            effect="auto_allow_audit", match_status="matched"
        ).model_dump(),
    )

    result = GuardServices.apply_principal_rv(object.__new__(GuardServices), event, decision)

    assert result.action == "block"
    assert event.metadata["principal_rv"]["effect"] == "block"


def test_controller_blocks_toxic_chain_for_same_agent_across_hook_sessions(tmp_path, monkeypatch):
    """Principal RV must run on the real Hook path before controller enforcement."""
    project = tmp_path / "guard"
    services = _build_services(project, project / "openclaw.json")
    _configure_policy_fixtures(services, monkeypatch)

    first = services.handle_before_tool_call(_hook_payload("secret.read", session_id="session-a"))
    second = services.handle_before_tool_call(_hook_payload("network.request", session_id="session-b"))

    assert first["action"] == "allow"
    assert second["action"] == "block"
    assert second["action_record"]["event"]["metadata"]["principal_rv"]["effect"] == "block"


def test_principal_snapshot_restores_toxic_chain_after_restart(tmp_path, monkeypatch):
    """Restarting Guard must not erase an allowed sensitive-read lineage."""
    project = tmp_path / "guard"
    config_path = project / "openclaw.json"
    first_services = _build_services(project, config_path)
    _configure_policy_fixtures(first_services, monkeypatch)

    first = first_services.handle_before_tool_call(_hook_payload("secret.read", session_id="session-a"))
    assert first["action"] == "allow"
    assert (project / "runtime" / "rv-state.json").exists()

    restored_services = _build_services(project, config_path)
    _configure_policy_fixtures(restored_services, monkeypatch)
    second = restored_services.handle_before_tool_call(
        _hook_payload("network.request", session_id="session-b")
    )

    assert second["action"] == "block"


def test_openclaw_approved_read_is_recorded_for_later_principal_rv(tmp_path, monkeypatch):
    """Approval resolution must feed the normalized read back into principal state."""
    project = tmp_path / "guard"
    services = _build_services(project, project / "openclaw.json")
    _configure_policy_fixtures(services, monkeypatch)
    monkeypatch.setattr(
        services.policy_engine,
        "evaluate",
        lambda event, source_message="": PolicyDecision(
            effect="openclaw_approval",
            match_status="matched",
            policy_version="test",
        ),
    )

    first = services.handle_before_tool_call(_hook_payload("secret.read", session_id="session-a"))
    action = services._find_action(first["action_record"]["action_id"])

    assert first["action"] == "require_approval"
    assert services.record_approved_principal_action(action) is None
    second = services.handle_before_tool_call(_hook_payload("network.request", session_id="session-b"))
    assert second["action"] == "block"


def test_snapshot_is_restored_before_current_session_rv_event(tmp_path, monkeypatch):
    """Lazy snapshot restore must not overwrite the first RV event after restart."""
    project = tmp_path / "guard"
    config_path = project / "openclaw.json"
    first_services = _build_services(project, config_path)
    _configure_policy_fixtures(first_services, monkeypatch)
    first_services.handle_before_tool_call(_hook_payload("secret.read", session_id="session-a"))

    restored_services = _build_services(project, config_path)
    _configure_policy_fixtures(restored_services, monkeypatch)
    restored_services.handle_before_tool_call(_hook_payload("network.request", session_id="session-a"))

    summary = restored_services.rv_engine.result_summary("session_session-a")
    assert summary["window_size"] == 2
