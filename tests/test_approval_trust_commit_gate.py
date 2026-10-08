"""原生审批解析仍批准本次操作，禁用/切臂不能留下持久信任。"""
import json

import pytest

from openclaw_guard import api
from openclaw_guard.engine import experiment_components as ec
from openclaw_guard.services import build_services


@pytest.fixture(autouse=True)
def reset_components():
    ec.reset()
    yield
    ec.reset()


@pytest.mark.parametrize('mode,expected_items', [('enabled', 1), ('disabled', 0), ('changed_generation', 0)])
def test_resolution_approves_this_call_without_disabled_persistent_trust(tmp_path, monkeypatch, mode, expected_items):
    config = tmp_path / 'openclaw.json'
    config.write_text(json.dumps({'models': {'providers': {}}}))
    services = build_services(tmp_path, config_path=config)
    request = services.handle_before_tool_call({'toolName': 'shell_exec',
        'params': {'command': 'rm -f /tmp/guard-sync-owned-fixture'}, 'runId': 'fixture-run',
        'toolCallId': 'fixture-call', 'sessionId': 'fixture-session'})
    assert request['action'] == 'require_approval'
    # Isolate resolution of an already offered eligible native approval; command
    # eligibility itself is covered by the real readonly native probe and its tests.
    import openclaw_guard.api._handlers as handlers
    monkeypatch.setattr(handlers, 'build_approval_presentation', lambda *_: {
        'allow_always': {'eligible': True, 'fingerprint': 'fixture-fingerprint', 'scope': 'workspace'}})
    if mode == 'disabled':
        ec.configure(ec.ExperimentComponents(approval_trust=False))
    if mode == 'changed_generation':
        approve = services.action_service.approve
        def switch_during_resolution(*args, **kwargs):
            result = approve(*args, **kwargs)
            ec.configure(ec.ExperimentComponents(approval_trust=False))
            ec.configure(ec.ExperimentComponents())
            return result
        monkeypatch.setattr(services.action_service, 'approve', switch_during_resolution)
    result, status = api.resolve_hook_approval(services, {'actionId': request['action_record']['action_id'], 'decision': 'allow-always'})
    assert status == 200
    assert result['decision_state'] == 'allowed'
    assert len(services.approval_trust_summary()['items']) == expected_items
    saved = services.action_service.get_action(request['action_record']['action_id'])
    assert saved['resolution']['persistent'] is (expected_items == 1)


def test_failed_trust_write_does_not_create_reusable_memory_trust(tmp_path, monkeypatch):
    from openclaw_guard.engine.approval import ApprovalTrustStore
    store = ApprovalTrustStore(tmp_path / 'trust.json')
    def fail_write(_payload):
        raise OSError('fixture disk failure')
    monkeypatch.setattr(store, '_write', fail_write)
    with pytest.raises(OSError):
        store.add('failed-fingerprint', action_id='fixture-action', scope='workspace')
    assert store.contains('failed-fingerprint') is False
    assert store.list() == []
    assert not store.path.exists()
