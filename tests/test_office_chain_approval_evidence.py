"""验证原生审批失败诊断保留且不会泄漏响应中的凭据。"""
from testlab.office_chain.office_driver import _approval_resolution_evidence


def test_resolution_preserves_failure_code_without_raw_text():
    """只保存明确枚举的错误码，不保存错误消息。"""
    result=_approval_resolution_evidence({'ok':False,'response':{'error':{'code':'APPROVAL_EXPIRED','message':'secret'},'stdout':'secret','returncode':1}})
    assert result=={'status':'failed','returncode':1,'error_code':'APPROVAL_EXPIRED'}


def test_arbitrary_error_codes_and_transport_messages_are_not_recorded():
    """原始错误字符串不能进入实验公开记录。"""
    assert _approval_resolution_evidence({'ok':False,'error':'token-secret','response':{'code':'token-secret','stdout':'token-secret'}})=={'status':'failed'}
    assert _approval_resolution_evidence({'ok':False,'error':'TimeoutExpired'})=={'status':'failed','error_type':'TimeoutExpired'}
    assert _approval_resolution_evidence({'ok':True})=={'status':'applied'}


def test_malformed_diagnostic_fields_cannot_crash_recorder():
    """非字符串错误字段既不泄漏也不导致实验驱动异常。"""
    assert _approval_resolution_evidence({'ok':False,'error':[],'response':{'code':{'secret':'x'}}})=={'status':'failed'}


def test_json_cli_failure_retains_top_level_exit_code():
    """CLI输出JSON时退出码仍保存，不因未出现在响应里丢失。"""
    assert _approval_resolution_evidence({'ok':False,'returncode':1,'response':{'error':{'code':'NOT_FOUND','message':'private'}}})=={'status':'failed','returncode':1,'error_code':'NOT_FOUND'}
