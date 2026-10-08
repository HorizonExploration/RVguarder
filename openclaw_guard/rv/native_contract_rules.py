"""读取型网络工具的显式基础规约；与原67条文件分开，计入实际有效规则。"""
from __future__ import annotations

from copy import deepcopy


def native_request_monitor() -> dict:
    """前置成功获取不能自匹配当前请求；普通后续获取保留审批。"""
    office = {'office_message_send': 'message.send', 'office_network_post': 'network.egress',
              'office_document_share': 'network.egress'}
    fetch = ['web_fetch', 'web_search', 'x_search']
    source = {'all_of': ['contract:untrusted_input'],
        'tool': {'event_model': 'tool-call-v1', 'effects_any_of': ['read'], 'execution_states': ['succeeded']}}
    rules = []
    for tool, operation in [(None, None), *office.items()]:
        terminal = {'tool': {'event_model': 'tool-call-v1', 'effects_any_of': ['egress'],
            **({'names': [tool]} if tool else {'excluded_names': [*office, *fetch]})}}
        rule = {'id': 'native_remote_content_egress_block' + ('__' + tool if tool else ''),
            'from': '*', 'verdict': 'block', 'when': {**deepcopy(terminal),
                'sequence': {'steps': [deepcopy(source), deepcopy(terminal)]}}}
        if tool:
            rule['unless_authorized'] = {'tool_name': tool, 'operation_family': operation}
        rules.append(rule)
    rules.append({'id': 'native_remote_request_review', 'from': '*', 'verdict': 'ask',
        'when': {'all_of': ['contract:remote_request'], 'tool': {'event_model': 'tool-call-v1'}}})
    return {'name': 'NativeRequestBoundaryMonitor', 'initial': 'idle', 'source': 'handwritten',
            'source_ids': ['native-read-and-egress-contract-v1'], 'rules': rules}
