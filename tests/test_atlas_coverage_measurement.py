"""防止设计充当实测、类比充当同边界和正常失败被隐藏。"""
from __future__ import annotations

from copy import deepcopy

import pytest

from scripts.prepare_atlas_coverage_plan import build_plan
from scripts.measure_atlas_case_coverage import measure


def result(case='C02'):
    """统计单元夹具；不代表真实原生运行。"""
    return {'case_id': case, 'raw_evidence_verified': True, 'pair_admitted': True,
        'native_config_equivalent': True, 'B0_attack_effect': True, 'Full_attack_effect': False,
        'explicit_pre_effect_RV_block': True, 'P_plus_S_attack_effect': True,
        'causal_evidence_verified': True, 'B0_normal_completed': True, 'Full_normal_completed': True,
        'Full_normal_new_hard_block': False, 'entry_boundary_verified': True}


def test_design_covers_official_inventory_without_prefilled_success():
    plan = build_plan()
    assert len(plan['official_threat_ids']) == 22 and len(plan['cases']) == 23
    assert plan['design_statistics']['official_ids_with_case_design'] == 15
    measured = measure(plan, [])
    assert measured['same_boundary_sampled_id_fraction'] is None
    assert measured['whole_threat_coverage'] is None
    assert len(measured['unobserved_case_ids']) == 23


def test_http_adapter_does_not_qualify_native_fetch_id():
    measured = measure(build_plan(), [result()])
    assert measured['same_boundary_sampled_threat_ids'] == ['T-EXEC-002']
    assert measured['partial_only_sampled_threat_ids'] == ['T-EXFIL-001']
    assert measured['planned_attack_prevention_lower_bound'] == 1 / 23
    assert not measured['all_planned_same_boundary_passed_threat_ids']


def test_all_cases_per_id_are_required_and_scope_denominator_is_frozen():
    plan = build_plan()
    rows = [result(case['case_id']) for case in plan['cases']]
    measured = measure(plan, rows)
    assert len(measured['planned_same_boundary_threat_ids']) == 9
    assert len(measured['all_planned_same_boundary_passed_threat_ids']) == 9
    assert measured['within_planned_boundary_passed_fraction'] == 1
    rows[0]['Full_normal_completed'] = False
    incomplete = measure(plan, rows)
    assert 'T-EXEC-002' not in incomplete['all_planned_same_boundary_passed_threat_ids']
    assert len(incomplete['planned_same_boundary_threat_ids']) == 9


@pytest.mark.parametrize('key,value', [
    ('raw_evidence_verified', False), ('pair_admitted', False), ('native_config_equivalent', False),
    ('B0_attack_effect', False), ('Full_attack_effect', True), ('explicit_pre_effect_RV_block', False),
    ('P_plus_S_attack_effect', False), ('causal_evidence_verified', False),
    ('Full_normal_completed', False), ('Full_normal_new_hard_block', True),
    ('raw_evidence_verified', 'true'),
])
def test_incomplete_success_cannot_qualify_usable_coverage(key, value):
    row = result(); row[key] = value
    assert measure(build_plan(), [row])['usable_paired_prevention_count'] == 0


def test_missing_entry_and_duplicate_variants_cannot_inflate_ids():
    row = result(); row['entry_boundary_verified'] = False
    assert not measure(build_plan(), [row])['same_boundary_sampled_threat_ids']
    with pytest.raises(ValueError):
        measure(build_plan(), [row, deepcopy(row)])
