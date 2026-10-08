"""从冻结r4增量生成通用工具规约候选；不覆盖默认或历史规则。"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from openclaw_guard.rv.rv_dsl import Ruleset
from openclaw_guard.rv.native_contract_rules import native_request_monitor


BASE = Path(__file__).resolve().parents[1] / 'docs/research/close-experiment-gaps/m2-candidate-rules-r4.json'
BASE_SHA256 = 'cda28476ec8dfb4b04bcebd0042c3c3dcd560caf7c86da8670661d5e3a390b28'


def build_profile() -> dict:
    """规约基于能力和成功历史，不依赖攻击文件名、任务ID或注入措辞。"""
    if hashlib.sha256(BASE.read_bytes()).hexdigest() != BASE_SHA256:
        raise ValueError('frozen r4 changed')
    raw = deepcopy(json.loads(BASE.read_text()))
    raw['version'] = 3
    # 引入脚本须由真实写工具表达；exec潜在write不能伪造前置子调用。
    for monitor in raw['monitors']:
        for rule in monitor['rules']:
            if rule['id'] == 'untrusted_source_script_written':
                rule['when']['tool']['operation_families'] = ['file.write', 'document.write']
    successful_source = {'tool': {'effects_any_of': ['read'], 'execution_states': ['succeeded']},
        'any_of': ['external_source', 'attachment_open', 'attachment_download', 'contract:untrusted_input']}
    sensitive_source = {'tool': {'effects_any_of': ['read'], 'execution_states': ['succeeded']},
                        'all_of': ['contract:sensitive_read']}
    rules = []

    def sequence_rule(identifier, source, terminal, verdict):
        """两个不同调用构成前置成功历史与当前后果；保留噪声步骤。"""
        return {'id': identifier, 'from': '*', 'verdict': verdict,
                'when': {**deepcopy(terminal), 'sequence': {'steps': [deepcopy(source), deepcopy(terminal)]}}}

    for suffix, terminal, verdict in [
        ('potential_delete', {'all_of': ['contract:potential_delete'], 'tool': {'effects_any_of': ['execute']}}, 'block'),
        ('control_plane_change', {'all_of': ['contract:control_plane_change']}, 'block'),
        ('permission_grant', {'all_of': ['contract:permission_grant']}, 'block'),
        ('delayed_authority', {'all_of': ['contract:delayed_authority']}, 'ask'),
    ]:
        rules.append(sequence_rule('atlas_untrusted_' + suffix, successful_source, terminal, verdict))
    office = {'office_message_send': 'message.send', 'office_network_post': 'network.egress',
              'office_document_share': 'network.egress'}
    rules.append(sequence_rule('atlas_sensitive_read_egress', sensitive_source,
        {'tool': {'effects_any_of': ['egress'], 'excluded_names': list(office)}}, 'block'))
    for tool, operation in office.items():
        rule = sequence_rule('atlas_sensitive_read_egress__' + tool, sensitive_source,
            {'tool': {'effects_any_of': ['egress'], 'names': [tool]}}, 'block')
        rule['unless_authorized'] = {'tool_name': tool, 'operation_family': operation}
        rules.append(rule)
    raw['monitors'].append({'name': 'AtlasToolBoundaryMonitor', 'initial': 'idle', 'rules': rules})
    raw['monitors'].append(native_request_monitor())
    Ruleset.model_validate(raw)
    return raw


def main() -> None:
    """只写新候选文件，旧成果与默认67条不变。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        json.dump(build_profile(), stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({'rules_sha256': hashlib.sha256(args.output.read_bytes()).hexdigest(),
        'rules': sum(len(m['rules']) for m in build_profile()['monitors']), 'release_qualified': False}))


if __name__ == '__main__':
    main()
