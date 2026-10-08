"""减少同步整表写入仍须在Hook返回前持久保存状态与事件序号。"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from openclaw_guard.engine.experiment_components import ExperimentComponents, using
from openclaw_guard.services import build_services


@pytest.mark.parametrize('mode,expected_action,expected_status,max_writes', [
    ('allow', 'allow', 'executing', 3),
    ('ask', 'require_approval', 'pending_approval', 2),
    ('block', 'block', 'blocked', 2),
])
def test_hook_state_is_durable_before_response_with_bounded_writes(tmp_path, mode, expected_action, expected_status, max_writes):
    """读取真实磁盘工件，防止减少写入后只保留内存状态。"""
    config = tmp_path / 'openclaw.json'
    config.write_text('{}')
    with using(ExperimentComponents(semantic_llm=False)):
        services = build_services(tmp_path, config_path=config)
        if mode == 'allow':
            payload = {'toolName': 'read', 'params': {'path': str(tmp_path / 'public.txt')}}
        else:
            payload = {'toolName': 'exec', 'params': {'command': 'python3 -c "print(1)"', 'cwd': str(tmp_path)}}
        if mode == 'block':
            original = services.policy_engine.decide
            def block(*args, **kwargs):
                decision = original(*args, **kwargs)
                decision.action = 'block'
                return decision
            decision_patch = patch.object(services.policy_engine, 'decide', side_effect=block)
        else:
            decision_patch = patch.object(services.policy_engine, 'decide', wraps=services.policy_engine.decide)
        try:
            with decision_patch, patch.object(services.action_service, '_save_all', wraps=services.action_service._save_all) as saver:
                result = services.handle_before_tool_call({**payload, 'runId': 'durability-run',
                    'sessionId': 'durability-session', 'toolCallId': 'durability-call'})
            assert result['action'] == expected_action
            assert saver.call_count <= max_writes
            persisted = json.loads(services.action_service.actions_path.read_text())['items']
            assert len(persisted) == 1
            action = persisted[0]
            assert action['status'] == expected_status
            assert action['last_event_seq'] > 0
            assert action['decision']['action'] == ('ask' if mode == 'ask' else mode)
            assert action['event']['metadata']['tool_call_id'] == 'durability-call'
            restored = build_services(tmp_path, config_path=config)
            try:
                saved = restored.action_service.get_action(action['action_id'])
                assert saved['status'] == expected_status
                assert saved['last_event_seq'] == action['last_event_seq']
            finally:
                restored.audit_store.close()
        finally:
            services.audit_store.close()
