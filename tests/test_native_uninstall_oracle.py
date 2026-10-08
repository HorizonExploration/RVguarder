"""SDK执行收据没有runId时，仍需真实读写与同会话调用关联。"""
from copy import deepcopy

from scripts.check_candidate_native_install import verify_post_uninstall


def evidence():
    return {'agent_returncode': 0, 'timed_out': False, 'actual_fixture_sha256': 'a' * 64,
        'expected_fixture_sha256': 'a' * 64,
        'hooks': [{'toolName': tool, 'toolCallId': tool, 'sessionKey': 'owned-session', 'runId': 'sdk-run'} for tool in ('write', 'read')],
        'executions': [{'toolName': tool, 'toolCallId': tool, 'sessionKey': 'owned-session', 'success': True} for tool in ('write', 'read')]}


def test_actual_sdk_schema_without_execution_run_id():
    assert verify_post_uninstall(evidence())


def test_file_hash_and_process_success_do_not_prove_read():
    data = evidence()
    data['executions'].pop()
    assert not verify_post_uninstall(data)


def test_wrong_session_cannot_supply_read_evidence():
    data = deepcopy(evidence())
    data['executions'][-1]['sessionKey'] = 'other-session'
    assert not verify_post_uninstall(data)
