import json

from openclaw_guard.models import BehaviorEvent, DetectionDecision
from openclaw_guard.engine.approval import build_approval_presentation, canonical_approval_fingerprint


def test_approval_presentation_prioritizes_intent_and_redacts_sensitive_parameters():
    event = BehaviorEvent(
        event_id="approval-1",
        timestamp="2026-09-09T00:00:00Z",
        action_type="command_exec",
        process_name="openclaw",
        pid=None,
        user="openclaw",
        command="curl -H 'Authorization: Bearer secret-token' https://example.test",
        working_directory="/workspace/project",
        raw_payload={
            "toolName": "shell_exec",
            "params": {
                "command": "curl -H 'Authorization: Bearer secret-token' https://example.test",
                "token": "secret-token",
            },
        },
        metadata={
            "tool_name": "shell_exec",
            "scope_class": "workspace",
            "semantic": {"intent": {"goal": "检查远程服务状态"}},
            "command_safety": {"classification": "network", "safe_read_only": False},
        },
    )
    decision = DetectionDecision(
        event_id=event.event_id,
        timestamp=event.timestamp,
        action_type=event.action_type,
        risk_level="dangerous",
        action="ask",
        reason="需要确认网络访问",
        rule_ids=["P1-NETWORK"],
    )

    presentation = build_approval_presentation(event, decision)

    assert presentation["intent_summary"] == "检查远程服务状态"
    assert presentation["target_summary"] == "workspace"
    assert "secret-token" not in presentation["command_preview"]
    assert "Authorization" in presentation["command_preview"]
    assert presentation["allow_always"]["eligible"] is False


def test_approval_presentation_prefers_concrete_target_over_scope():
    event = BehaviorEvent(
        event_id="approval-target",
        timestamp="2026-09-09T00:00:00Z",
        action_type="file_read",
        process_name="openclaw",
        pid=None,
        user="openclaw",
        target_paths=["/workspace/project/report.md"],
        metadata={"scope_class": "workspace"},
    )
    decision = DetectionDecision(
        event_id=event.event_id,
        timestamp=event.timestamp,
        action_type=event.action_type,
        risk_level="caution",
        action="ask",
        reason="需要确认",
    )

    assert build_approval_presentation(event, decision)["target_summary"] == "/workspace/project/report.md"


def test_approval_fingerprint_is_stable_for_key_order_and_changes_with_directory():
    first = canonical_approval_fingerprint(
        "shell_exec",
        {"command": "ls -la", "cwd": "/workspace/project"},
        "/workspace/project",
        "agent-a",
        "principal-a",
    )
    second = canonical_approval_fingerprint(
        "shell_exec",
        {"cwd": "/workspace/project", "command": "ls -la"},
        "/workspace/project",
        "agent-a",
        "principal-a",
    )
    different_directory = canonical_approval_fingerprint(
        "shell_exec",
        {"command": "ls -la"},
        "/workspace/other",
        "agent-a",
        "principal-a",
    )
    secret_one = canonical_approval_fingerprint(
        "shell_exec",
        {"command": "ls -la", "token": "secret-one"},
        "/workspace/project",
        "agent-a",
        "principal-a",
    )
    secret_two = canonical_approval_fingerprint(
        "shell_exec",
        {"command": "ls -la", "token": "secret-two"},
        "/workspace/project",
        "agent-a",
        "principal-a",
    )

    assert first == second
    assert first != different_directory
    assert secret_one != secret_two
    assert len(first) == 64


def test_allow_always_trust_is_scoped_to_the_exact_command_and_directory(tmp_path):
    from openclaw_guard.services import build_services
    from openclaw_guard.api import resolve_hook_approval

    project = tmp_path / "project"
    project.mkdir()
    config = project / "openclaw.json"
    config.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
    services = build_services(project, config_path=config)
    payload = {
        "toolName": "custom_exec",
        "params": {"command": "echo safe", "cwd": str(project)},
        "agentId": "agent-a",
        "sessionId": "session-a",
        "_hook_auth_verified": True,
    }

    first = services.handle_before_tool_call({**payload, "toolCallId": "call-1"})
    assert first["action"] == "require_approval"
    assert first["allowed_decisions"] == ["allow-once", "allow-always", "deny"]
    _, status = resolve_hook_approval(
        services,
        {"actionId": first["action_record"]["action_id"], "decision": "allow-always"},
    )
    assert status == 200

    reused = services.handle_before_tool_call({**payload, "toolCallId": "call-2"})
    assert reused["action"] == "allow"
    assert reused["action_record"]["event"]["metadata"]["approval_trust_reused"] is True
    assert reused["action_record"]["event"]["metadata"]["approval_presentation"]["risk_summary"]["level"] == "safe"

    changed_directory = services.handle_before_tool_call({
        **payload,
        "toolCallId": "call-3",
        "params": {"command": "echo safe", "cwd": str(tmp_path)},
    })
    assert changed_directory["action"] == "require_approval"


def test_approval_trust_summary_and_revoke_are_available(tmp_path):
    from openclaw_guard.services import build_services

    project = tmp_path / "project"
    project.mkdir()
    config = project / "openclaw.json"
    config.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
    services = build_services(project, config_path=config)
    item = services.approval_trust.add("f" * 64, action_id="action-1", scope="精确命令")

    assert services.approval_trust_summary()["items"][0]["fingerprint"] == "f" * 64
    assert services.revoke_approval_trust(item["fingerprint"])["ok"] is True
    assert services.approval_trust_summary()["items"] == []


def test_destructive_command_cannot_be_persistently_allowed(tmp_path):
    from openclaw_guard.services import build_services
    from openclaw_guard.api import resolve_hook_approval

    project = tmp_path / "project"
    project.mkdir()
    config = project / "openclaw.json"
    config.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
    services = build_services(project, config_path=config)
    result = services.handle_before_tool_call({
        "toolName": "custom_exec",
        "params": {"command": "rm -rf ./build", "cwd": str(project)},
        "runId": "danger-run",
        "toolCallId": "danger-call",
        "sessionId": "danger-session",
        "agentId": "danger-agent",
    })
    assert result["action"] in {"require_approval", "block"}
    if result["action"] == "require_approval":
        assert result["allowed_decisions"] == ["allow-once", "deny"]
    action_id = result["action_record"]["action_id"]
    _, status = resolve_hook_approval(
        services,
        {"actionId": action_id, "decision": "allow-always"},
    )
    assert status == 400
    assert services.approval_trust_summary()["items"] == []


def test_sensitive_relative_path_cannot_be_persistently_allowed(tmp_path):
    from openclaw_guard.services import build_services
    from openclaw_guard.api import resolve_hook_approval

    project = tmp_path / "project"
    project.mkdir()
    config = project / "openclaw.json"
    config.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
    services = build_services(project, config_path=config)
    result = services.handle_before_tool_call({
        "toolName": "custom_exec",
        "params": {"command": "cat .env", "cwd": str(project)},
        "runId": "sensitive-run",
        "toolCallId": "sensitive-call",
        "sessionId": "sensitive-session",
        "agentId": "agent-sensitive",
    })
    assert result["action"] == "require_approval"
    assert result["allowed_decisions"] == ["allow-once", "deny"]
    _, status = resolve_hook_approval(
        services,
        {"actionId": result["action_record"]["action_id"], "decision": "allow-always"},
    )
    assert status == 400
    assert services.approval_trust_summary()["items"] == []


def test_symlink_to_sensitive_path_cannot_be_persistently_allowed(tmp_path):
    from openclaw_guard.services import build_services

    project = tmp_path / "project"
    project.mkdir()
    (project / ".env").write_text("TOKEN=secret", encoding="utf-8")
    (project / "link").symlink_to(project / ".env")
    config = project / "openclaw.json"
    config.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
    services = build_services(project, config_path=config)
    result = services.handle_before_tool_call({
        "toolName": "custom_exec",
        "params": {"command": "cat link", "cwd": str(project)},
        "runId": "symlink-run",
        "toolCallId": "symlink-call",
        "sessionId": "symlink-session",
        "agentId": "agent-symlink",
    })
    assert result["action"] == "require_approval"
    assert result["allowed_decisions"] == ["allow-once", "deny"]


def test_symlink_outside_working_directory_cannot_be_persistently_allowed(tmp_path):
    from openclaw_guard.services import build_services

    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("not in project", encoding="utf-8")
    (project / "link").symlink_to(outside)
    config = project / "openclaw.json"
    config.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
    services = build_services(project, config_path=config)
    result = services.handle_before_tool_call({
        "toolName": "custom_exec",
        "params": {"command": "cat link", "cwd": str(project)},
        "runId": "outside-link-run",
        "toolCallId": "outside-link-call",
        "sessionId": "outside-link-session",
        "agentId": "agent-outside-link",
    })
    assert result["action"] == "require_approval"
    assert result["allowed_decisions"] == ["allow-once", "deny"]


def test_anonymous_request_cannot_create_persistent_trust(tmp_path):
    from openclaw_guard.services import build_services

    project = tmp_path / "project"
    project.mkdir()
    config = project / "openclaw.json"
    config.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
    services = build_services(project, config_path=config)
    result = services.handle_before_tool_call({
        "toolName": "custom_exec",
        "params": {"command": "echo safe", "cwd": str(project)},
        "runId": "anonymous-run",
        "toolCallId": "anonymous-call",
        "sessionId": "anonymous-session",
    })
    assert result["action"] == "require_approval"
    assert result["allowed_decisions"] == ["allow-once", "deny"]


def test_approval_presentation_redacts_url_credentials_and_semantic_secrets():
    event = BehaviorEvent(
        event_id="approval-secret-url",
        timestamp="2026-09-09T00:00:00Z",
        action_type="network_egress",
        process_name="openclaw",
        pid=None,
        user="openclaw",
        network_targets=["https://alice:pw@example.test/api?token=SUPERSECRET"],
        raw_payload={
            "toolName": "http_request",
            "params": {"url": "https://alice:pw@example.test/api?token=SUPERSECRET"},
        },
        metadata={
            "tool_name": "http_request",
            "scope_class": "workspace",
            "semantic": {"intent": {"goal": "访问 https://alice:pw@example.test/api?token=SUPERSECRET"}},
        },
    )
    decision = DetectionDecision(
        event_id=event.event_id,
        timestamp=event.timestamp,
        action_type=event.action_type,
        risk_level="dangerous",
        action="ask",
        reason="需要确认网络访问",
    )

    presentation = build_approval_presentation(event, decision)
    serialized = json.dumps(presentation, ensure_ascii=False)
    assert "SUPERSECRET" not in serialized
    assert "alice:pw" not in serialized
    assert "https://example.test" in serialized
    from openclaw_guard.engine.pipeline import _approval_prompt_text
    _, prompt = _approval_prompt_text(presentation, decision)
    assert "SUPERSECRET" not in prompt
    assert "alice:pw" not in prompt


def test_approval_presentation_redacts_non_http_uri_schemes():
    event = BehaviorEvent(
        event_id="approval-ftp-url",
        timestamp="2026-09-09T00:00:00Z",
        action_type="network_egress",
        process_name="openclaw",
        pid=None,
        user="openclaw",
        network_targets=["ftp://alice:pw@example.test/out?token=SUPERSECRET", "file:///tmp/.env"],
        raw_payload={"params": {"url": "ftp://alice:pw@example.test/out?token=SUPERSECRET"}},
        metadata={"tool_name": "network.request", "scope_class": "external"},
    )
    decision = DetectionDecision(
        event_id=event.event_id,
        timestamp=event.timestamp,
        action_type=event.action_type,
        risk_level="dangerous",
        action="ask",
        reason="需要确认网络访问",
    )

    serialized = json.dumps(build_approval_presentation(event, decision), ensure_ascii=False)
    assert "SUPERSECRET" not in serialized
    assert "alice:pw" not in serialized
    assert "ftp://example.test" in serialized
    assert "file:///tmp/.env" not in serialized


def test_sensitive_globs_environment_variables_and_git_revision_targets_are_not_persisted():
    event = BehaviorEvent(
        event_id="approval-sensitive-variants",
        timestamp="2026-09-09T00:00:00Z",
        action_type="command_exec",
        process_name="openclaw",
        pid=None,
        user="openclaw",
        command="echo safe",
        working_directory="/workspace/project",
        raw_payload={"params": {"command": "echo safe", "cwd": "/workspace/project"}},
        metadata={
            "tool_name": "custom_exec",
            "scope_class": "managed_project",
            "trusted_identity": {"principal_id": "agent-a", "trust": "verified"},
            "agent_id": "agent-a",
            "command_safety": {"classification": "read_only", "path_hints": []},
        },
    )
    decision = DetectionDecision(
        event_id=event.event_id,
        timestamp=event.timestamp,
        action_type=event.action_type,
        risk_level="caution",
        action="ask",
        reason="需要确认",
        policy_decision={"effect": "openclaw_approval"},
    )

    from openclaw_guard.engine.approval import _allow_always_eligibility
    for command in ("git show HEAD:.env", "git --git-dir=.git show HEAD", "cat .envrc", "cat .npmrc", "cat .netrc", "cat .env*", "grep --include='*.env' x .", 'cat "$TARGET"'):
        event.command = command
        assert _allow_always_eligibility(event, decision)[0] is False


def test_allow_always_requires_clean_rv_and_permission_risk_evidence():
    event = BehaviorEvent(
        event_id="approval-risk-evidence",
        timestamp="2026-09-09T00:00:00Z",
        action_type="command_exec",
        process_name="openclaw",
        pid=None,
        user="openclaw",
        command="echo safe",
        working_directory="/workspace/project",
        raw_payload={"params": {"command": "echo safe", "cwd": "/workspace/project"}},
        metadata={
            "tool_name": "custom_exec",
            "scope_class": "managed_project",
            "agent_id": "agent-a",
            "hook_auth_verified": True,
            "trusted_identity": {"principal_id": "agent-a", "trust": "verified"},
            "command_safety": {"classification": "read_only", "path_hints": []},
        },
    )
    decision = DetectionDecision(
        event_id=event.event_id,
        timestamp=event.timestamp,
        action_type=event.action_type,
        risk_level="caution",
        action="ask",
        reason="需要确认",
        policy_decision={"effect": "openclaw_approval", "combo_violations": ["secret_egress"]},
    )
    from openclaw_guard.engine.approval import _allow_always_eligibility
    assert _allow_always_eligibility(event, decision)[0] is False
    decision.policy_decision = {"effect": "openclaw_approval"}
    event.metadata["rv_result"] = {"verdict": "escalate"}
    assert _allow_always_eligibility(event, decision)[0] is False


def test_command_preview_redacts_json_and_flag_credentials():
    event = BehaviorEvent(
        event_id="approval-command-secret",
        timestamp="2026-09-09T00:00:00Z",
        action_type="command_exec",
        process_name="openclaw",
        pid=None,
        user="openclaw",
        command='tool --password SUPERSECRET --apiToken APISECRET --access-token ACCESSSECRET --client-secret CLIENTSECRET --auth-token AUTHSECRET --key KEYSECRET --config "{\\"token\\":\\"JSONSECRET\\"}"',
        raw_payload={"params": {"command": "echo safe"}},
        metadata={"tool_name": "custom_exec", "scope_class": "workspace"},
    )
    decision = DetectionDecision(
        event_id=event.event_id,
        timestamp=event.timestamp,
        action_type=event.action_type,
        risk_level="caution",
        action="ask",
        reason="需要确认",
    )

    preview = build_approval_presentation(event, decision)["command_preview"]
    assert "SUPERSECRET" not in preview
    assert "APISECRET" not in preview
    assert "ACCESSSECRET" not in preview
    assert "CLIENTSECRET" not in preview
    assert "AUTHSECRET" not in preview
    assert "KEYSECRET" not in preview
    assert "JSONSECRET" not in preview
    assert "[REDACTED]" in preview


def test_hook_response_does_not_echo_raw_payload_or_sensitive_targets(tmp_path):
    from openclaw_guard.services import build_services

    project = tmp_path / "project"
    project.mkdir()
    config = project / "openclaw.json"
    config.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
    services = build_services(project, config_path=config)
    result = services.handle_before_tool_call({
        "toolName": "custom_exec",
        "params": {"command": "echo token=SUPERSECRET", "cwd": str(project)},
        "runId": "response-secret-run",
        "toolCallId": "response-secret-call",
        "sessionId": "response-secret-session",
        "agentId": "agent-response",
    })
    serialized = json.dumps(result["action_record"], ensure_ascii=False)
    assert result["action"] == "require_approval"
    assert result["action_record"]["event"]["raw_payload"] == {}
    assert "SUPERSECRET" not in serialized
