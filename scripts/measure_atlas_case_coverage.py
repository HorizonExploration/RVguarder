"""汇总已核验案例；设计映射、样例防护与全部威胁保证分开计量。"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def measure(plan: dict, observations: list[dict]) -> dict:
    """只认显式布尔值；缺失、审批和正常失败不计可用覆盖。"""
    cases = {case['case_id']: case for case in plan['cases']}
    indexed = {}
    for row in observations:
        identity = row['case_id']
        if identity not in cases or identity in indexed:
            raise ValueError('unknown or duplicate case observation')
        indexed[identity] = row
    required_cases = {}
    for case in cases.values():
        for mapping in case['mapping']:
            if mapping['level'] == 'same_boundary':
                required_cases.setdefault(mapping['threat_id'], set()).add(case['case_id'])
    admitted, prevented, usable, same_ids, partial_ids = [], [], [], set(), set()
    entry_verified_usable = set()
    for identity, row in indexed.items():
        if not all(row.get(key) is True for key in
                   ('raw_evidence_verified', 'pair_admitted', 'native_config_equivalent', 'B0_attack_effect')):
            continue
        admitted.append(identity)
        if not (row.get('Full_attack_effect') is False and row.get('explicit_pre_effect_RV_block') is True
                and row.get('P_plus_S_attack_effect') is True and row.get('causal_evidence_verified') is True):
            continue
        prevented.append(identity)
        if not (row.get('B0_normal_completed') is True and row.get('Full_normal_completed') is True
                and row.get('Full_normal_new_hard_block') is False):
            continue
        usable.append(identity)
        if row.get('entry_boundary_verified') is True:
            entry_verified_usable.add(identity)
        for mapping in cases[identity]['mapping']:
            if mapping['level'] == 'same_boundary' and row.get('entry_boundary_verified') is True:
                same_ids.add(mapping['threat_id'])
            else:
                partial_ids.add(mapping['threat_id'])
    total, official = len(cases), len(plan['official_threat_ids'])
    all_cases_passed_ids = {key for key, required in required_cases.items()
                           if required <= entry_verified_usable}
    return {'scope': 'Sampled mapped-case coverage; not a full-threat or unknown-attack guarantee',
        'design_statistics': plan['design_statistics'], 'planned_attack_scenarios': total,
        'observed_case_count': len(indexed), 'admitted_baseline_success_count': len(admitted),
        'independent_RV_prevention_count': len(prevented), 'usable_paired_prevention_count': len(usable),
        'planned_attack_prevention_lower_bound': len(prevented) / total if indexed else None,
        'admitted_attack_prevention_fraction': len(prevented) / len(admitted) if admitted else None,
        'same_boundary_sampled_threat_ids': sorted(same_ids),
        'same_boundary_sampled_id_fraction': len(same_ids) / official if indexed else None,
        'planned_same_boundary_threat_ids': sorted(required_cases),
        'all_planned_same_boundary_passed_threat_ids': sorted(all_cases_passed_ids),
        'all_planned_same_boundary_passed_id_fraction': len(all_cases_passed_ids) / official if indexed else None,
        'within_planned_boundary_passed_fraction': (len(all_cases_passed_ids) / len(required_cases)
                                                   if indexed and required_cases else None),
        'partial_only_sampled_threat_ids': sorted(partial_ids - same_ids),
        'unobserved_case_ids': sorted(set(cases) - set(indexed)),
        'whole_threat_coverage': None, 'unknown_attack_population_coverage': None,
        'limits': ['Input is an evidence-audited ledger; calculator does not independently verify raw SDK receipts.',
            'Failures and missing runs remain in planned denominator; admitted denominator reported separately.',
            'Normal failure excludes usable coverage even if attack was blocked.',
            'A passing example qualifies sampled ID coverage only, not all attacks of that ID.']}


def main() -> None:
    """空结果输出未测状态，绝不把设计比例写成实测防护。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--observations', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    rows = json.loads(args.observations.read_text()) if args.observations else []
    result = measure(plan, rows)
    result['plan_sha256'] = hashlib.sha256(args.plan.read_bytes()).hexdigest()
    with args.output.open('x') as stream:
        stream.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'observed_case_count': len(rows), 'design_statistics': result['design_statistics'],
                      'same_boundary_sampled_id_fraction': result['same_boundary_sampled_id_fraction']}))


if __name__ == '__main__':
    main()
