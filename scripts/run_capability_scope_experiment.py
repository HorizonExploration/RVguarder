"""冻结当前可执行案例并调度真实原生实验；准备阶段不启动工具或调用API。"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from scripts.run_atlas_native_pilot import run_job
from scripts.review_m2_native_acceptance import native_contract
from testlab.office_chain.office_driver import resolve_toolchain


ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    """计算文件冻结摘要。"""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_new(path: Path, value: dict) -> None:
    """创建新证据文件，拒绝覆盖旧记录。"""
    with path.open('x') as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def select_jobs(inputs: dict, plan: dict, batch: str) -> list[dict]:
    """验证完整配对矩阵后选择批次，拒绝重复、未知或缺失实验臂。"""
    scenes = {s['scenario_id']: s for s in inputs['scenarios']}
    if len(scenes) != len(inputs['scenarios']):
        raise ValueError('duplicate scenario')
    jobs = plan['main_jobs']
    expected = {(sid, arm) for sid, scene in scenes.items()
                for arm in (('B0', 'Full', 'P+S') if scene['variant'] == 'attack' else ('B0', 'Full'))}
    keys = [(j['scenario_id'], j['arm']) for j in jobs]
    if len(keys) != len(set(keys)) or set(keys) != expected:
        raise ValueError('matrix differs from paired scenarios')
    if any(j['batch'] not in {'priority', 'remaining'} for j in jobs):
        raise ValueError('unknown batch')
    selected = [j for j in jobs if batch == 'all' or j['batch'] == batch]
    ids = {j['scenario_id'] for j in selected}
    if not selected or {(j['scenario_id'], j['arm']) for j in selected} != {
            key for key in expected if key[0] in ids}:
        raise ValueError('incomplete batch pair')
    if any(scenes[sid]['paired_with'] not in ids for sid in ids):
        raise ValueError('attack/normal pair split across batches')
    return selected


def preflight() -> dict:
    """实测工具链准入；不可用仅记录，不伪造运行时版本。"""
    try:
        runtime = resolve_toolchain()
        return {'ready': bool(runtime['node_admission_ok']), 'runtime': runtime}
    except RuntimeError as error:
        return {'ready': False, 'error': str(error), 'runtime': None}


def prepare(inputs_path: Path, plan_path: Path, output: Path, batch: str) -> dict:
    """锁定源代码、规则和执行顺序，生成可审核批次且不运行案例。"""
    inputs_path, plan_path = inputs_path.resolve(), plan_path.resolve()
    inputs = json.loads(inputs_path.read_text())
    plan = json.loads(plan_path.read_text())
    jobs = select_jobs(inputs, plan, batch)
    rules = (ROOT / inputs['rules_path']).resolve()
    if digest(rules) != inputs['rules_sha256']:
        raise ValueError('candidate rules drift')
    # 覆盖驱动依赖、生成插件和配置；不收集.env或私有运行时数据。
    files = {inputs_path, plan_path, rules, Path(__file__).resolve()}
    for directory in ('openclaw_guard', 'testlab/office_chain', 'policies', 'scripts'):
        files.update(p.resolve() for p in (ROOT / directory).rglob('*')
                     if p.is_file() and p.suffix in {'.py', '.js', '.mjs', '.json'})
    freeze = {'files': {str(p): digest(p) for p in sorted(files)},
              'inputs': str(inputs_path), 'run_plan': str(plan_path), 'rules': str(rules),
              'selected_before_execution': list(dict.fromkeys(j['scenario_id'] for j in jobs)),
              'jobs': jobs, 'planned_runs': len(jobs), 'batch': batch,
              'runtime': None, 'status': 'prepared_not_executed',
              'scope': 'Revealed calibration; fixed native trajectories; not holdout or autonomous layer.',
              'semantics': 'local heuristic; no API calls',
              'adjudication': 'allow-once for every actual native prompt; ask is not prevention',
              'release_qualified': False}
    output.mkdir(parents=True, exist_ok=False)
    write_new(output / 'freeze.json', freeze)
    write_new(output / 'preflight.json', preflight())
    write_new(output / 'inputs-snapshot.json', inputs)
    write_new(output / 'run-plan-snapshot.json', plan)
    return freeze


def verify_freeze(freeze: dict) -> list[str]:
    """检查冻结内容仍一致；代码变化必须另建批次。"""
    return [name for name, expected in freeze['files'].items()
            if not Path(name).is_file() or digest(Path(name)) != expected]


def execute(output: Path) -> dict:
    """串行运行隔离实例并保存每次结果；首次基础设施失败后停止并保留失败。"""
    freeze = json.loads((output / 'freeze.json').read_text())
    if (output / 'execution.json').exists() or (output / 'results.json').exists():
        raise ValueError('batch already started; use a new batch, never overwrite evidence')
    drift = verify_freeze(freeze)
    if drift:
        raise ValueError('frozen source drift: ' + ', '.join(drift))
    admission = preflight()
    if not admission['ready']:
        raise RuntimeError(admission.get('error', 'Node runtime not admitted'))
    # freeze.json在准备时创建；实际运行时单独封存，不覆盖准备记录。
    write_new(output / 'execution.json', {'runtime': admission['runtime'], 'planned_runs': freeze['planned_runs']})
    inputs = json.loads(Path(freeze['inputs']).read_text())
    scenes = {s['scenario_id']: s for s in inputs['scenarios']}
    rows, failures = [], []
    for item in freeze['jobs']:
        sid, arm = item['scenario_id'], item['arm']
        job = {'scenario': scenes[sid], 'arm': arm, 'rules': freeze['rules'],
               'rules_sha256': inputs['rules_sha256'],
               'raw': str(output.resolve() / 'raw' / f'{arm}__{sid}.json')}
        try:
            row = run_job(job)
        except Exception as error:
            failures.append({'scenario_id': sid, 'arm': arm, 'error_type': type(error).__name__,
                             'raw': job['raw'], 'admitted': False})
            break
        rows.append(row)
        write_new(output / f'result-{len(rows):03d}.json', row)
        print(json.dumps({'completed': len(rows), 'planned': freeze['planned_runs'],
                          'scenario_id': sid, 'arm': arm, 'admitted': row['admitted']}), flush=True)
        if verify_freeze(freeze):
            break
    equivalence = {}
    for sid in freeze['selected_before_execution']:
        projected = {}
        for row in rows:
            if row['scenario_id'] == sid:
                raw = json.loads(Path(row['raw']).read_text())
                projected[row['arm']] = hashlib.sha256(json.dumps(
                    {'contract': native_contract(raw), 'runtime': raw['runtime']}, sort_keys=True).encode()).hexdigest()
        expected = {j['arm'] for j in freeze['jobs'] if j['scenario_id'] == sid}
        equivalence[sid] = {'passed': set(projected) == expected and len(set(projected.values())) == 1,
                            'arm_projection_sha256': projected}
    report = {'scope': freeze['scope'], 'rows': rows, 'failures': failures,
              'planned_runs': freeze['planned_runs'], 'completed_runs': len(rows),
              'source_drift': verify_freeze(freeze), 'native_config_equivalence': equivalence,
              'all_admitted': len(rows) == freeze['planned_runs'] and all(r['admitted'] for r in rows),
              'merge_into_M3_denominator': False, 'release_qualified': False}
    write_new(output / 'results.json', report)
    return report


def main() -> None:
    """默认仅准备；显式执行已冻结目录才启动真实实验。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path)
    parser.add_argument('--run-plan', type=Path)
    parser.add_argument('--batch', choices=('priority', 'remaining', 'all'), default='priority')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    if args.execute:
        report = execute(args.output)
        print(json.dumps({'completed_runs': report['completed_runs'], 'all_admitted': report['all_admitted']}))
    else:
        if args.inputs is None or args.run_plan is None:
            parser.error('preparation requires --inputs and --run-plan')
        frozen = prepare(args.inputs, args.run_plan, args.output, args.batch)
        print(json.dumps({'prepared_runs': frozen['planned_runs'], 'executed_runs': 0}))


if __name__ == '__main__':
    main()
