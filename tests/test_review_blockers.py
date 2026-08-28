from pathlib import Path
import json

import pytest

from openclaw_guard.models import BehaviorEvent
from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.policy.engine import AuthorizationPolicyEngine
from openclaw_guard.policy.models import PermissionRef
from openclaw_guard.integrations.hook_runtime import _plugin_source
from openclaw_guard import api


@pytest.fixture
def services(tmp_path):
    project = tmp_path / "OpenclawGuard"
    project.mkdir()
    config_path = project / "openclaw.json"
    config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
    from openclaw_guard.services import build_services
    return build_services(project, config_path=config_path)


def test_permission_ref_carries_all_least_privilege_dimensions_and_is_hashable():
    permission = PermissionRef(
        family="document.read",
        resource_type="document",
        resource_ids=["doc-1"],
        scope="workspace",
        classification="sensitive",
        field_scope=["title"],
        purpose="meeting_summary",
        ttl_seconds=300,
    )
    assert permission.resource_ids == ("doc-1",)
    assert permission.field_scope == ("title",)
    assert hash(permission)


def test_policy_engine_uses_distinct_requested_and_required_trace(tmp_path):
    root = Path("policies/permissions")
    engine = AuthorizationPolicyEngine(root)
    event = BehaviorEvent(
        event_id="h3",
        timestamp="2026-01-01T00:00:00Z",
        action_type="file_write",
        process_name="openclaw",
        pid=None,
        user="u1",
        target_paths=["/tmp/report.txt"],
        metadata={
            "requested_permissions": [{"family": "file.write", "resource_type": "file", "scope": "external"}],
            "required_trace": [{"family": "file.write", "resource_type": "file", "scope": "workspace"}],
        },
    )
    decision = engine.evaluate(event)
    assert decision.excessive_permissions
    assert decision.p_after


def test_default_policy_bundle_is_independent_of_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    engine = AuthorizationPolicyEngine()
    assert engine.bundle.version == "1.0.0"


def test_generated_openclaw_approval_contract_is_single_owner_and_once_only():
    source = _plugin_source(guard_url="http://127.0.0.1:8780", auth_token="token")
    assert 'allowedDecisions: ["allow-once", "deny"]' in source
    assert "timeoutBehavior" not in source
    assert 'registrationId: "openclaw_guard_before_tool_call"' in source


def test_persistent_allow_always_resolution_is_rejected(services):
    result = services.handle_before_tool_call({
        "toolName": "shell_exec",
        "params": {"command": "echo safe"},
        "runId": "h6-run",
        "toolCallId": "h6-tool",
        "sessionId": "h6-session",
        "agentId": "agent-h6",
    })
    action_id = result["action_record"]["action_id"]
    payload, status = api.resolve_hook_approval(
        services, {"actionId": action_id, "decision": "allow-always"}
    )
    assert status == 400
    assert payload["error_code"] == "unsupported_resolution"
