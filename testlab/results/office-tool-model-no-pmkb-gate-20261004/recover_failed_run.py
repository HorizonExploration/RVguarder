"""保留准入失败原记录，按冻结配置做单场景基础设施恢复复跑。"""
from __future__ import annotations
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

OUT=Path(__file__).resolve().parent
ROOT=Path('/tmp/rv-independent-block-validation-20261004')
sys.path.insert(0,str(ROOT))
from testlab.office_chain.rerun import frozen_hashes
from testlab.office_chain.guard_driver import cleanup_new_sandboxes,run_scenario_guard
from testlab.office_chain.office_driver import resolve_toolchain,_docker_ps_ids
from testlab.office_chain.records import build_run_record
from testlab.office_chain.artifacts import canonical_json


def main():
    """只恢复未准入记录，不重跑有效但攻击成功的样本。"""
    manifest=json.loads((OUT/'manifest.json').read_text())
    rows=[json.loads(x) for x in (OUT/'records.jsonl').read_text().splitlines() if x]
    if len(rows)!=100:raise RuntimeError('主矩阵未结束，禁止并行清理实验沙箱')
    if frozen_hashes()!=manifest['source_hashes']:raise RuntimeError('冻结源码漂移')
    failed=[r for r in rows if not r['admitted'] or r.get('error')]
    target=OUT/'retries';target.mkdir(exist_ok=True);(target/'raw').mkdir(exist_ok=True)
    done=[]
    if (OUT/'retry-records.jsonl').exists():done=[json.loads(x) for x in (OUT/'retry-records.jsonl').read_text().splitlines() if x]
    scenarios={s['scenario_id']:s for s in json.loads((OUT/'base_scenarios.json').read_text())['scenarios']}
    toolchain=resolve_toolchain()
    for row in failed:
        sid=row['scenario_id'];arm=row['arm']
        if any(r['scenario_id']==sid and r['arm']==arm for r in done):continue
        print('RECOVERY',arm,sid,flush=True)
        with tempfile.TemporaryDirectory(prefix='rv-gate-recovery-') as temp:
            work=Path(temp);before=_docker_ps_ids(toolchain)
            try:
                payload=run_scenario_guard(scenarios[sid],arm=arm,working_root=work,
                    workspace=work/'workspace',profile_home=work/'profile',toolchain=toolchain,
                    timeout=180,approval_policy='allow-once')
            finally:
                cleanup_new_sandboxes(before,toolchain=toolchain)
                if (work/'workspace').exists():
                    subprocess.run([toolchain['docker'],'run','--rm','--network','none','--user','0:0','--entrypoint','chown',
                        '-v',f'{work / "workspace"}:/cleanup','openclaw-sandbox:bookworm-slim','-R',f'{os.getuid()}:{os.getgid()}','/cleanup'],check=True,capture_output=True,timeout=30)
        record=build_run_record(payload,scenarios[sid],arm=arm,repeat=2,approval_policy='allow-once')
        record.update(evaluation_group='original_rerun',oracle_basis='legacy_effect_capture_not_content_exfil_proof',
            raw_artifact=f'retries/raw/{arm}__{sid}__repeat2.json',
            recovery_reason='Original run was unadmitted; native allow-once resolution applied=False, not RV block. Preserve original run and do not increase independent denominator.')
        (OUT/record['raw_artifact']).write_text(json.dumps(payload,ensure_ascii=False,indent=2)+'\n')
        with (OUT/'retry-records.jsonl').open('a') as stream:stream.write(canonical_json(record)+'\n')
        done.append(record)
        print('RECOVERY RESULT',arm,sid,'admitted',record['admitted'],'goal',record['attack_goal_achieved'],'error',record['error'],flush=True)
    replacements={(r['arm'],r['scenario_id']):r for r in done if r['admitted'] and not r.get('error')}
    primary=[replacements.get((r['arm'],r['scenario_id']),r) for r in rows]
    (OUT/'primary-records.jsonl').write_text(''.join(canonical_json(r)+'\n' for r in primary))
    manifest['status']='complete_after_infrastructure_recovery' if all(r['admitted'] and not r.get('error') for r in primary) else 'complete_with_errors'
    manifest['recovery']={'initial_attempts':len(rows),'retry_attempts':len(done),'independent_arm_scenario_pairs':len(primary),
        'original_failures_preserved':failed,'rules_changed':False,'primary_records':'primary-records.jsonl','first_attempt_records':'records.jsonl','retry_records':'retry-records.jsonl'}
    (OUT/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')


if __name__=='__main__':main()
