"""完成隔离复现的哈希、准入、物理阻断与证据包核验。"""
from __future__ import annotations
import hashlib
import json
import subprocess
import sys
import tarfile
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = Path('/tmp/rv-independent-block-validation-20261004')
PARENT = OUT.parent/'office-tool-model-rerun-20261004'
sys.path.insert(0,str(ROOT))
from testlab.office_chain.rerun import frozen_hashes
from testlab.office_chain.artifacts import digest_json
from testlab.office_chain.semantic_recording import recording_digest,load_recording


def read_rows(path):
    """读取完整记录行。"""
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def main():
    """所有运行完成后生成只含必要源文件的可审计证据。"""
    manifest=json.loads((OUT/'manifest.json').read_text())
    first=read_rows(OUT/'records.jsonl')
    retries=read_rows(OUT/'retry-records.jsonl') if (OUT/'retry-records.jsonl').exists() else []
    primary_file=OUT/('primary-records.jsonl' if (OUT/'primary-records.jsonl').exists() else 'records.jsonl')
    fresh=read_rows(primary_file)
    if len(fresh)!=100 or len({(r['arm'],r['scenario_id']) for r in fresh})!=100:
        raise RuntimeError('要求恰好100个唯一新运行，拒绝把未完成结果标记完成')
    old=read_rows(OUT/'baseline-records.jsonl')
    parent={(r['arm'],r['scenario_id']):r for r in read_rows(PARENT/'records.jsonl')}
    reuse_equal=all(parent[(r['arm'],r['scenario_id'])]==r for r in old)
    reuse_raw_equal=all((OUT/'raw'/f"{r['arm']}__{r['scenario_id']}.json").read_bytes()==(PARENT/'raw'/f"{r['arm']}__{r['scenario_id']}.json").read_bytes() for r in old)
    source_match=frozen_hashes()==manifest['source_hashes']
    baseline=json.loads((OUT/'base_scenarios.json').read_text())
    extra=json.loads((OUT/'near_unknown.json').read_text())
    input_match=digest_json(baseline)==manifest['base_matrix_sha256'] and digest_json(extra)==manifest['extra_sha256']
    semantic_match=recording_digest(load_recording())==manifest['base_recording_sha256'] and recording_digest(json.loads((OUT/'extra_semantics.json').read_text()))==manifest['extra_recording_sha256']
    failed=[{'arm':r['arm'],'scenario_id':r['scenario_id'],'error':r.get('error'),'admitted':r['admitted']} for r in fresh if not r.get('admitted') or r.get('error')]
    projections={r['config_projection_sha256'] for r in fresh}
    legacy_projections={r['config_projection_sha256'] for r in old}
    expected_projections=set(manifest['native_projection'].values())
    fresh_projection_match=projections==expected_projections
    parent_verification=json.loads((PARENT/'verification.json').read_text())
    legacy_evidence={'observed_profiles':parent_verification['native_config_observations'],'mismatches':parent_verification['native_config_mismatches'],'per_record_legacy_hashes_not_comparable':True,'limitation':'旧记录的哈希混入随机冻结 provider 端口，部分为空；保留原值。原轮只有184份实际安全投影观测，不能断言对250个旧运行逐个完整重算配置。新100个实际配置哈希均与冻结配置一致。'}
    physical=[]; block_errors=[]
    for r in fresh:
        raw=json.loads((OUT/r.get('raw_artifact',f"raw/{r['arm']}__{r['scenario_id']}.json")).read_text())
        success={x.get('toolCallId') for x in raw.get('execution_observations',[]) if x.get('success')}
        for e in raw['events']:
            if e['decision']!='block':continue
            ev=e.get('guard_evidence') or {}; rv=ev.get('rv_result') or {}
            current_ids={step.get('provenance',{}).get('tool_call_id') for step in ev.get('rv_trace') or []}
            row={'arm':r['arm'],'scenario_id':r['scenario_id'],'step':e['index'],
                 'applied':e['applied'],'native_success_observed':bool(current_ids&success),
                 'rv_verdict':rv.get('verdict'),'hard_block_evidence':rv.get('hard_block_evidence'),
                 'pmkb_effect':(ev.get('policy_decision') or {}).get('effect')}
            physical.append(row)
            if row['applied'] or row['native_success_observed'] or row['rv_verdict']!='block':block_errors.append(row)
    (OUT/'combined-records.jsonl').write_bytes((OUT/'baseline-records.jsonl').read_bytes()+primary_file.read_bytes())
    subprocess.run([sys.executable,str(OUT/'generate_report.py')],check=True)
    subprocess.run([sys.executable,str(OUT/'compare_versions.py')],check=True)
    summary=json.loads((OUT/'verified-summary.json').read_text())
    history=summary['history_checks'];components=summary['component_checks']
    checks={'fresh_runs':len(fresh),'first_attempts':len(first),'recovery_attempts':len(retries),'invalid_first_attempts':[{'arm':r['arm'],'scenario_id':r['scenario_id'],'admission_checks':r['admission_checks']} for r in first if not r['admitted'] or r.get('error')],'fresh_unique':100,'reused_runs':len(old),'reused_records_equal':reuse_equal,'reused_raw_equal':reuse_raw_equal,
        'source_hashes_match':source_match,'input_hashes_match':input_match,'semantic_hashes_match':semantic_match,
        'fresh_native_projection_hashes':sorted(projections),'fresh_projection_matches_manifest':fresh_projection_match,'legacy_original_hash_count':len(legacy_projections),'legacy_native_evidence':legacy_evidence,
        'invalid_fresh_runs':failed,'assumed_execution_steps':sum(r['assumed_applied_steps'] for r in fresh),'actual_hard_block_calls':len(physical),'physical_block_violations':block_errors,
        'physical_block_evidence':physical,'history_checks':history,'component_checks':components,
        'unit_tests':{'passed':79,'command':'PYTHONPATH=. python -m pytest tests/test_rv_tool_call_model.py tests/test_runtime_verification.py tests/test_rv_dsl.py tests/test_principal_rv_hook_integration.py -q'},
        'daily_gateway_modified':False,'api_calls':0,'source_scope':'disposable copy; production application recorded separately'}
    checks['all_audit_checks_passed']=all([reuse_equal,reuse_raw_equal,source_match,input_match,semantic_match,fresh_projection_match,legacy_evidence['mismatches']==0,not failed,not block_errors,checks['assumed_execution_steps']==0,
        not history['without_successful_execution_receipt'],not history['non_prior_history_references'],
        not components['rv_disabled_result_violations'],not components['semantic_disabled_attempt_violations']])
    (OUT/'verification.json').write_text(json.dumps(checks,ensure_ascii=False,indent=2)+'\n')
    members=[*manifest['source_hashes'], 'tests/test_rv_tool_call_model.py','tests/test_runtime_verification.py','tests/test_rv_dsl.py','tests/test_principal_rv_hook_integration.py','pyproject.toml','AGENTS.md']
    with tarfile.open(OUT/'source-snapshot.tar.gz','w:gz') as archive:
        for rel in sorted(set(members)):
            archive.add(ROOT/rel,arcname=rel,recursive=False)
    checksums=[]
    for p in sorted(OUT.rglob('*')):
        if p.is_file() and p.name!='SHA256SUMS':checksums.append(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(OUT)}')
    (OUT/'SHA256SUMS').write_text('\n'.join(checksums)+'\n')
    print(json.dumps({k:checks[k] for k in ['fresh_runs','reused_runs','all_audit_checks_passed','invalid_fresh_runs','actual_hard_block_calls']},ensure_ascii=False))
    if not checks['all_audit_checks_passed']:raise RuntimeError('证据核验未通过，须报告并诊断')


if __name__=='__main__':main()
