"""小规模官方威胁迁移校准：真实SDK/Docker配对与RV消融，结果不限成功。"""
from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
from pathlib import Path

from scripts.review_m2_native_acceptance import native_contract
from testlab.office_chain.arms import arm_spec
from testlab.office_chain.authorized_driver import resolve_toolchain, run_authorized_scenario
from testlab.office_chain.native_oracles import evaluate_native_oracles, validate_observation_inputs


def run_job(job: dict) -> dict:
    """worker独立拥有Gateway、Guard、Docker及私有宿主证明。"""
    scene, arm = job['scenario'], job['arm']
    disabled = arm_spec(arm).disabled_components
    observation = run_authorized_scenario(scene, output=Path(job['raw']), rules_path=Path(job['rules']),
                                          arm=arm, disabled=disabled)
    outcome = evaluate_native_oracles(scene, observation)
    try:
        verification = validate_observation_inputs(scene, observation, arm=arm, disabled=disabled)
        if observation['rules_sha256'] != job['rules_sha256']:
            raise ValueError('rules drift')
    except ValueError as error:
        outcome.update(admitted=False)
        verification = {'error': str(error)}
    rv = [{key: a['event']['metadata'].get('rv_result', {}).get(key) for key in
           ('verdict', 'triggered_by', 'triggered_rule_id', 'matched_history_step_ids', 'hard_block_evidence')}
          for a in observation['actions'] if a['decision']['action'] == 'block']
    return {'scenario_id': scene['scenario_id'], 'arm': arm, 'raw': job['raw'],
            **outcome, 'input_verification': verification, 'blocks': rv}


def main() -> None:
    """选定两组后冻结运行；不重跑主矩阵，不作整体Q5判优。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    document = json.loads(args.inputs.read_text())
    rules = Path(document['rules_path'])
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    if digest(rules) != document['rules_sha256']:
        parser.error('candidate rules drift')
    selected = ['ATLAS-C01-A', 'ATLAS-C01-N', 'ATLAS-C03-A', 'ATLAS-C03-N']
    scenes = {s['scenario_id']: s for s in document['scenarios']}
    jobs = []
    for index, sid in enumerate(selected):
        arms = ['B0', 'Full'] if index % 2 == 0 else ['Full', 'B0']
        if scenes[sid]['variant'] == 'attack':
            arms.append('P+S')
        jobs.extend({'scenario': scenes[sid], 'arm': arm, 'rules': str(rules),
            'rules_sha256': digest(rules), 'raw': str(args.output / 'raw' / f'{arm}__{sid}.json')} for arm in arms)
    args.output.mkdir(parents=True, exist_ok=False)
    files = set(Path('openclaw_guard').rglob('*.py')) | set(Path('openclaw_guard/policy/data').rglob('*.json'))
    files |= set(Path('testlab/office_chain').rglob('*.py')) | set(Path('testlab/office_chain/native_office_plugin').glob('*.js'))
    files |= set(Path('policies').rglob('*.json')) | {rules, args.inputs, Path(__file__), Path('scripts/prepare_atlas_cases.py'),
        Path('scripts/review_m2_native_acceptance.py')}
    freeze = {'files': {str(p): digest(p) for p in sorted(files)}, 'runtime': json.loads(json.dumps(resolve_toolchain(), default=str)),
        'selected_before_execution': selected, 'planned_runs': len(jobs),
        'scope': 'Known revealed calibration; two pairs plus RV ablations. Not holdout or autonomous layer.',
        'semantics': 'local heuristic; no API, not online Full semantic evaluation',
        'adjudication': 'automatic allow-once on all actual native prompts; not human approval',
        'source_url': document['source_url'], 'release_qualified': False}
    (args.output / 'freeze.json').write_text(json.dumps(freeze, indent=2) + '\n')
    rows = []
    with ProcessPoolExecutor(max_workers=2) as executor:
        for row in executor.map(run_job, jobs):
            rows.append(row)
            (args.output / 'progress.json').write_text(json.dumps({'completed': len(rows), 'planned': len(jobs)}) + '\n')
            print(json.dumps({'completed': len(rows), 'planned': len(jobs)}), flush=True)
    drift = [p for p, sha in freeze['files'].items() if digest(Path(p)) != sha]
    equivalence = {}
    for sid in selected:
        observations = {r['arm']: json.loads(Path(r['raw']).read_text()) for r in rows if r['scenario_id'] == sid}
        hashes = {arm: hashlib.sha256(json.dumps({'contract': native_contract(ob), 'runtime': ob['runtime']},
            sort_keys=True).encode()).hexdigest() for arm, ob in observations.items()}
        equivalence[sid] = {'passed': len(set(hashes.values())) == 1, 'arm_projection_sha256': hashes,
            'scope': 'Same pre-existing restricted native contract normalization; per-run private identifiers excluded'}
    report = {'scope': freeze['scope'], 'rows': rows, 'source_drift': drift,
        'native_config_equivalence': equivalence, 'merge_into_M3_denominator': False,
        'all_admitted': all(r['admitted'] for r in rows), 'release_qualified': False}
    with (args.output / 'results.json').open('x') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({'completed': len(rows), 'all_admitted': report['all_admitted'], 'source_drift': drift}))


if __name__ == '__main__':
    main()
