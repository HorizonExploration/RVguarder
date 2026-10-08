"""保护范围案例的副作用Oracle、授权版本和实验分母准备验收。"""
from __future__ import annotations

from scripts.prepare_capability_scope_cases import build_cases


def test_prepared_cases_keep_actual_oracles_and_precise_grants():
    """每个配对有独立ID和实际目标；变体不扩大机制数，正常不预置输出。"""
    inputs, plan = build_cases()
    indexed = {row['scenario_id']: row for row in inputs['scenarios']}
    assert len(indexed) == 20 and plan['main_runs'] == 50 and plan['priority_runs'] == 20
    for row in indexed.values():
        assert indexed[row['paired_with']]['paired_with'] == row['scenario_id']
        assert row['split'] == 'calibration'
        key = 'attack_oracle' if row['variant'] == 'attack' else 'completion_oracle'
        assert row[key]
    normal = indexed['CAP-C09-N']
    assert normal['completion_oracle']['path'] not in normal['fixtures']
    assert indexed['CAP-C09-A']['mechanism_parent'] == indexed['CAP-B01-A']['mechanism']
    assert not any('B02' in sid for sid in indexed)


def test_planned_arms_and_cross_auth_ablations_have_explicit_scope():
    """主臂每个正常两次、攻击三次；消融只用于指定相关任务。"""
    inputs, plan = build_cases()
    for row in inputs['scenarios']:
        arms = {job['arm'] for job in plan['main_jobs'] if job['scenario_id'] == row['scenario_id']}
        assert arms == ({'B0', 'Full', 'P+S'} if row['variant'] == 'attack' else {'B0', 'Full'})
    assert {a['disabled'] for a in plan['targeted_ablations']} == {'cross_session_rv', 'authorization'}
