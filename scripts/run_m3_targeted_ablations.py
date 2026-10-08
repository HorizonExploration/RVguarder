"""执行揭盲前指定的消融；不增加主矩阵独立场景分母。"""
import argparse
import hashlib
import json
from pathlib import Path

from testlab.office_chain.authorized_driver import run_authorized_scenario
from testlab.office_chain.native_oracles import evaluate_native_oracles


def main() -> None:
    """单次运行并保留失败；主矩阵完成前仅输出运行计数。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--preregistration', type=Path, required=True)
    parser.add_argument('--recording', type=Path, required=True)
    parser.add_argument('--rules', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    scenes = {s['scenario_id']: s for s in json.loads(args.inputs.read_text())['scenarios']}
    registration = json.loads(args.preregistration.read_text())
    if registration.get('selected_before_holdout_unblinding') is not True:
        raise ValueError('pre-registration required')
    recording = json.loads(args.recording.read_text())
    args.output.mkdir(parents=True, exist_ok=False)
    paths = set(Path('openclaw_guard').rglob('*.py')) | set(Path('testlab/office_chain').rglob('*.py'))
    paths |= set(Path('testlab/office_chain/native_office_plugin').glob('*.js'))
    paths |= set(Path('openclaw_guard/policy/data').rglob('*.json')) | set(Path('policies').rglob('*.json'))
    paths |= {args.inputs, args.preregistration, args.recording, args.rules, Path(__file__)}
    frozen = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
    (args.output / 'freeze.json').write_text(json.dumps({'files': frozen, 'registration': registration}, indent=2))
    rows = []
    for job in registration['rows']:
        raw = args.output / 'raw' / (job['arm'] + '__' + job['scenario_id'] + '.json')
        observed = run_authorized_scenario(scenes[job['scenario_id']], output=raw, rules_path=args.rules,
            arm=job['arm'], disabled=job['disabled'], recording=recording)
        rows.append({**job, 'raw': str(raw), **evaluate_native_oracles(scenes[job['scenario_id']], observed)})
        print(json.dumps({'completed_targeted_runs': len(rows)}), flush=True)
    drift = [p for p, sha in frozen.items() if hashlib.sha256(Path(p).read_bytes()).hexdigest() != sha]
    (args.output / 'results.json').write_text(json.dumps({'rows': rows, 'source_drift': drift,
        'merge_into_main_denominator': False, 'release_qualified': False}, indent=2) + '\n')


if __name__ == '__main__':
    main()
