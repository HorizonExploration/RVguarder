"""真实DeepSeek自主Agent补充层；不与固定轨迹安全比例合并。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import urllib.request
from unittest.mock import patch

from testlab.office_chain import authorized_driver
from testlab.office_chain.frozen_provider import FrozenTrajectoryProvider
from testlab.office_chain.native_oracles import evaluate_native_oracles
from testlab.office_chain.record_semantics import _load_dotenv


class AutonomousProvider(FrozenTrajectoryProvider):
    """代理实际SDK模型请求，绝不返回预设工具链或直接执行工具。"""
    observations: list[dict] = []

    def __init__(self, scenario: dict) -> None:
        """场景只用于fixture和宿主控制；实际动作由真实模型自主选择。"""
        self._scenario = scenario
        self._model_id = 'rvguard-office-chain-fixed-v1'
        self._observations = type(self).observations

    def chat_completion(self, request: dict) -> dict:
        """原生工具schemas和上下文原样传给指定DeepSeek模型。"""
        payload = dict(request)
        payload.update(model='deepseek-v4-flash', stream=False, max_tokens=4096)
        payload.pop('stream_options', None)
        base = os.environ.get('DEEPSEEK_BASE_URL', 'https://api.deepseek.com').rstrip('/')
        req = urllib.request.Request(base+'/chat/completions', data=json.dumps(payload).encode(),
            headers={'Authorization':'Bearer '+os.environ['DEEPSEEK_API_KEY'],'Content-Type':'application/json'})
        with urllib.request.urlopen(req, timeout=60) as response:
            result = json.load(response)
        calls = [call for choice in result.get('choices', [])
                 for call in choice.get('message', {}).get('tool_calls', [])]
        self._observations.append({'scenario_id':self._scenario['scenario_id'],
            'requested_model':'deepseek-v4-flash','reported_model':result.get('model'),
            'usage':result.get('usage'), 'attempted_model_tool_calls':calls})
        return result


def main() -> None:
    """仅在正式补充输入和冻结规则明确后运行，每臂隔离profile/Docker。"""
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs',type=Path,required=True)
    parser.add_argument('--rules',type=Path,required=True)
    parser.add_argument('--recording',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    _load_dotenv(Path('.env'))
    if not os.environ.get('DEEPSEEK_API_KEY'):
        parser.error('authorized project API key unavailable')
    data=json.loads(args.inputs.read_text())
    if data.get('status') != 'frozen_autonomous_supplement':
        parser.error('autonomous input must be separately frozen')
    args.output.mkdir(parents=True,exist_ok=False)
    recording=json.loads(args.recording.read_text())
    paths=set(Path('openclaw_guard').rglob('*.py')) | set(Path('testlab/office_chain').rglob('*.py'))
    paths |= set(Path('testlab/office_chain/native_office_plugin').glob('*.js'))
    paths |= set(Path('openclaw_guard/policy/data').rglob('*.json')) | set(Path('policies').rglob('*.json'))
    paths |= {args.inputs,args.rules,args.recording,Path(__file__)}
    frozen={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
    (args.output/'freeze.json').write_text(json.dumps({'files':frozen,
        'runtime':authorized_driver.resolve_toolchain(),
        'requested_model':'deepseek/deepseek-v4-flash','guard_semantics':'frozen replay; unmatched prompts fall back locally',
        'merge_into_fixed_trajectory_denominator':False,'release_qualified':False},default=str,indent=2)+'\n')
    results=[]
    for index, scenario in enumerate(data['scenarios']):
        for arm in (('B0','Full') if index % 2 == 0 else ('Full','B0')):
            AutonomousProvider.observations=[]
            raw=args.output/'raw'/f"{arm}__{scenario['scenario_id']}.json"
            with patch.object(authorized_driver, 'FrozenTrajectoryProvider', AutonomousProvider):
                observation=authorized_driver.run_authorized_scenario(scenario,output=raw,rules_path=args.rules,
                    arm=arm,recording=recording,timeout=300,evidence_layer='real_autonomous_agent')
            row={'scenario_id':scenario['scenario_id'],'arm':arm,'raw':str(raw),
                 'evidence_layer':'real_autonomous_agent','merge_into_fixed_trajectory_denominator':False,
                 **evaluate_native_oracles(scenario,observation),'model_requests':AutonomousProvider.observations}
            results.append(row)
            (args.output/'progress.json').write_text(json.dumps({'runs':results},ensure_ascii=False,indent=2)+'\n')
            print(json.dumps({k:v for k,v in row.items() if k!='model_requests'},ensure_ascii=False),flush=True)
    drift=[p for p,digest in frozen.items() if hashlib.sha256(Path(p).read_bytes()).hexdigest()!=digest]
    (args.output/'results.json').write_text(json.dumps({'scope':'autonomous supplementary only',
        'source_drift':drift,'runs':results},ensure_ascii=False,indent=2)+'\n')


if __name__ == '__main__':
    main()
