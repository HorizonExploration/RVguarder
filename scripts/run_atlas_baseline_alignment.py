"""仅补齐SDK写入迁移元数据后的四次B0；冻结复用的六次插件运行。"""
from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from scripts.run_atlas_plugin_experiment import run_job
from scripts.review_m2_native_acceptance import native_contract
from testlab.office_chain import authorized_driver as driver


SDK_META = {'lastTouchedVersion': '2026.9.5', 'migrations': {
    'modelPolicyAllowlist': True, 'utilityModelSeparation': True}}


def aligned_baseline(job: dict) -> dict:
    """保留全部原生策略；B0采用插件臂SDK实际写入的相同迁移标记。"""
    original = driver.resolve_b0_config
    def config(*args, **kwargs):
        """显式冻结标记，避免只在插件臂发生SDK配置迁移。"""
        value = original(*args, **kwargs)
        if 'meta' in value:
            raise ValueError('unexpected baseline metadata')
        value['meta'] = json.loads(json.dumps(SDK_META))
        return value
    with patch.object(driver, 'resolve_b0_config', config):
        return run_job(job)


def main() -> None:
    """逐项校验旧源码、输入、收据与SDK安装证据；不覆盖任何旧批次。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prior', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    old_freeze = json.loads((args.prior / 'freeze.json').read_text())
    if any(digest(Path(p)) != sha for p, sha in old_freeze['files'].items()):
        raise ValueError('cannot reuse plugin runs after frozen source/input drift')
    prior = json.loads((args.prior / 'results.json').read_text())
    if not prior['all_admitted'] or not prior['all_archive_installations_verified'] or prior['source_drift']:
        raise ValueError('prior plugin runs not reusable')
    selected = old_freeze['selected_before_execution']
    scenes = {s['scenario_id']: s for s in json.loads(args.inputs.read_text())['scenarios']}
    reused = [r for r in prior['rows'] if r['arm'] != 'B0']
    for row in reused:
        ob = json.loads(Path(row['raw']).read_text())
        if native_contract(ob).get('meta') != SDK_META:
            raise ValueError('SDK metadata differs from preregistered alignment')
    args.output.mkdir(parents=True, exist_ok=False)
    freeze = {**old_freeze, 'files': {**old_freeze['files'], str(Path(__file__)): digest(Path(__file__))},
        'planned_runs': 10, 'new_runs': 4, 'reused_runs': 6, 'baseline_meta_before_execution': SDK_META,
        'reused_raw_sha256': {r['raw']: digest(Path(r['raw'])) for r in reused},
        'prior_results_sha256': digest(args.prior / 'results.json'),
        'scope': 'Revealed calibration with SDK-metadata-aligned B0; four new baselines and six frozen reused plugin runs. Not holdout.'}
    (args.output / 'freeze.json').write_text(json.dumps(freeze, indent=2) + '\n')
    rules = json.loads(args.inputs.read_text())['rules_path']
    jobs = [{'scenario': scenes[sid], 'arm': 'B0', 'rules': rules, 'rules_sha256': digest(Path(rules)),
        'archive': str(args.archive.resolve()), 'raw': str(args.output / 'raw' / f'B0__{sid}.json')} for sid in selected]
    rows = [{**r, 'reused_from': str(args.prior)} for r in reused]
    with ProcessPoolExecutor(max_workers=2) as executor:
        for row in executor.map(aligned_baseline, jobs):
            rows.append(row)
            print(json.dumps({'new_baselines_completed': len(rows)-len(reused), 'planned': 4}), flush=True)
    drift = [p for p, sha in freeze['files'].items() if digest(Path(p)) != sha]
    drift += [p for p, sha in freeze['reused_raw_sha256'].items() if digest(Path(p)) != sha]
    equivalence = {}
    for sid in selected:
        observations = {r['arm']: json.loads(Path(r['raw']).read_text()) for r in rows if r['scenario_id'] == sid}
        hashes = {arm: digest_projection(ob) for arm, ob in observations.items()
                  if 'native_config' in ob and 'runtime' in ob}
        equivalence[sid] = {'passed': len(hashes) == len(observations) and len(set(hashes.values())) == 1,
                            'arm_projection_sha256': hashes}
    report = {'scope': freeze['scope'], 'rows': rows, 'source_drift': drift,
        'native_config_equivalence': equivalence, 'all_admitted': all(r['admitted'] for r in rows),
        'all_archive_installations_verified': all(r['sdk_archive']['verified'] for r in reused),
        'merge_into_M3_denominator': False, 'release_qualified': False}
    (args.output / 'results.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'all_admitted': report['all_admitted'], 'source_drift': drift,
                     'all_equivalent': all(v['passed'] for v in equivalence.values())}))


def digest_projection(observation: dict) -> str:
    """使用原有严格配置比较器；不删除迁移标记或放宽验收门。"""
    return hashlib.sha256(json.dumps({'contract': native_contract(observation),
        'runtime': observation['runtime']}, sort_keys=True).encode()).hexdigest()


if __name__ == '__main__':
    main()
