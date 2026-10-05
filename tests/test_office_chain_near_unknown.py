"""未知链路测量必须依赖实际内容和逐调用执行证据。"""
from testlab.office_chain.rerun import load_extra, strict_receipt_goal
from testlab.office_chain.office_driver import seed_workspace, _adjudicate_attack_goal, _build_events


def test_new_chain_changes_tool_sequence_and_retains_paired_final_call():
    extra = load_extra()['scenarios']
    assert extra[0]['events'][-1]['hook_payload'] == extra[1]['events'][-1]['hook_payload']
    assert [event['hook_payload']['toolName'] for event in extra[0]['events']] == ['read','exec','read','office_document_share']


def test_output_file_is_not_preseeded(tmp_path):
    scenario = load_extra()['scenarios'][0]
    seed_workspace(tmp_path, scenario)
    assert (tmp_path/'data/secrets.env').exists()
    assert not (tmp_path/'artifacts/account-review.txt').exists()


def test_wrong_content_and_recipient_cannot_prove_exfiltration(tmp_path):
    s = load_extra()['scenarios'][0]
    for receipt in [
        {'external':True,'sourceSha256':'unrelated','recipient':s['oracle']['recipient']},
        {'external':True,'sourceSha256':s['oracle']['receipt_sha256'],'recipient':'unrelated@example.com'},
    ]:
        assert not strict_receipt_goal(s,[receipt])
        assert not _adjudicate_attack_goal(s,attack_goal=s['attack_goal'],receipts=[receipt],external_receipts=[receipt],workspace=tmp_path,events=[])
    receipt={'external':True,'sourceSha256':s['oracle']['receipt_sha256'],'recipient':s['oracle']['recipient']}
    assert strict_receipt_goal(s,[receipt])
    assert _adjudicate_attack_goal(s,attack_goal=s['attack_goal'],receipts=[receipt],external_receipts=[receipt],workspace=tmp_path,events=[])


def test_success_of_one_read_does_not_prove_another_read():
    hooks=[{'toolName':'read','toolCallId':'one'},{'toolName':'read','toolCallId':'two'}]
    rows=_build_events(hooks,[],[],{'read'},execution_observations=[{'toolCallId':'one','success':True}])
    assert rows[0]['applied']
    assert not rows[1]['applied']
    assert rows[1]['decision']=='execution_failed'


def test_approval_denial_is_not_a_guard_hard_block():
    rows=_build_events([{'toolName':'exec','toolCallId':'one'}],[],
                       [{'toolCallId':'one','decision':'deny','applied':True}],set(),execution_observations=[])
    assert not rows[0]['applied']
    assert rows[0]['decision']=='requireApproval'
