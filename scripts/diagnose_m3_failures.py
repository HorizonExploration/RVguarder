"""从冻结原始记录复算未通过原因；不修改实验数据或扩大安全分母。"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path


def main() -> None:
    """保存正常审批来源、阶段计时和未防止动作的规则证据。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    data = json.loads(args.results.read_text())
    timings = defaultdict(list)
    approval_groups = Counter()
    approval_evidence, failures, hashes = [], [], {}
    for row in data['results']:
        if row['arm'] != 'Full':
            continue
        path = Path(row['raw'])
        raw = json.loads(path.read_text())
        hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        for action in raw['actions']:
            metadata = action['event']['metadata']
            decision = action['decision']
            policy = decision.get('policy_decision') or {}
            for key, value in metadata.get('pipeline_timings_ms', {}).items():
                timings[key].append(value)
            if row['variant'] == 'benign' and decision['action'] == 'ask':
                key = (metadata.get('tool_name'), policy.get('match_status'), tuple(policy.get('conflicts', [])))
                approval_groups[key] += 1
                approval_evidence.append({'scenario_id': row['scenario_id'], 'tool': key[0],
                    'action_id': action['action_id'], 'policy_effect': policy.get('effect'),
                    'match_status': key[1], 'conflicts': list(key[2]),
                    'selected_rule_ids': policy.get('selected_rule_ids', []),
                    'candidate_rule_ids': policy.get('candidate_rule_ids', [])})
            if row['variant'] == 'attack' and row['attack_goal_achieved'] is True:
                steps = metadata.get('rv_trace') or []
                if metadata.get('tool_name') in {'exec', 'automations'}:
                    failures.append({'scenario_id': row['scenario_id'], 'tool': metadata.get('tool_name'),
                        'action': decision['action'], 'policy_match_status': policy.get('match_status'),
                        'candidate_rule_ids': policy.get('candidate_rule_ids', []),
                        'effects': steps[0].get('effects') if len(steps) == 1 else None,
                        'rv_trigger': (metadata.get('rv_result') or {}).get('triggered_by'),
                        'actual_goal_achieved': True})
    report = {'scope': 'Frozen holdout diagnosis only; post-fix code not re-evaluated here',
        'source_sha256': hashlib.sha256(args.results.read_bytes()).hexdigest(), 'raw_sha256': hashes,
        'normal_approval_groups': [{'tool': key[0], 'status': key[1], 'conflicts': list(key[2]), 'count': count}
            for key, count in sorted(approval_groups.items())],
        'normal_approval_evidence': approval_evidence, 'unprevented_action_evidence': failures,
        'stage_timings': {key: {'n': len(values), 'nearest_rank_p95_ms': sorted(values)[math.ceil(.95 * len(values)) - 1],
                               'max_ms': max(values)} for key, values in timings.items()},
        'timing_limits': 'Backend total_ms stops before persistence and response; stages cannot explain the full SDK callback gap.'}
    with args.output.open('x') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({'normal_ask_actions': len(approval_evidence), 'unprevented_key_actions': len(failures)}))


if __name__ == '__main__':
    main()
