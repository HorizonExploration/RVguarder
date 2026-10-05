"""比较冻结配对结果与历史无门版本，不将历史样本重新计数。"""
from __future__ import annotations
import json
from pathlib import Path
from collections import Counter

OUT = Path(__file__).resolve().parent
PARENT = OUT.parent/'office-tool-model-rerun-20261004'
HISTORICAL = OUT.parent/'office-attack-chain-v1-gatefix-clean'


def load(path):
    """读取唯一实验记录。"""
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def valid(row):
    """仅使用成功准入且无运行错误的记录。"""
    return row.get('admitted') and not row.get('error')


def main():
    """输出逐场景变化、真实后果与正常任务退化。"""
    current = {(r['arm'],r['scenario_id']):r for r in load(OUT/('primary-records.jsonl' if (OUT/'primary-records.jsonl').exists() else 'records.jsonl'))}
    results = {}
    for label, source in [('gated_parent', PARENT),('historical_ungated',HISTORICAL)]:
        old = {(r['arm'],r['scenario_id']):r for r in load(source/'records.jsonl')}
        by_group = {}
        for arm in ['P+C','Full']:
            for group in ['original_rerun','near_unknown']:
                for split in ['calibration','holdout']:
                    keys = sorted(k for k,r in current.items() if r['arm']==arm
                                  and r['evaluation_group']==group and r['split']==split
                                  and k in old and valid(r) and valid(old[k]))
                    if not keys:
                        continue
                    attacks = [k for k in keys if current[k]['variant']=='attack']
                    normal = [k for k in keys if current[k]['variant']=='benign']
                    rows = []
                    for k in keys:
                        a,b=old[k],current[k]
                        changed = {field: {'before':a[field], 'after':b[field]} for field in
                                   ['attack_goal_achieved','business_task_completed',
                                    'hard_blocked_required_steps','approvals_required']
                                   if a[field]!=b[field]}
                        if changed:
                            rows.append({'scenario_id':k[1],'variant':b['variant'],'changes':changed})
                    by_group[f'{group}/{split}/{arm}']={
                        'paired':len(keys),'attack_total':len(attacks),'normal_total':len(normal),
                        'old_prevented':sum(not old[k]['attack_goal_achieved'] for k in attacks),
                        'new_prevented':sum(not current[k]['attack_goal_achieved'] for k in attacks),
                        'prevention_gains':[k[1] for k in attacks if old[k]['attack_goal_achieved'] and not current[k]['attack_goal_achieved']],
                        'prevention_regressions':[k[1] for k in attacks if not old[k]['attack_goal_achieved'] and current[k]['attack_goal_achieved']],
                        'old_normal_completed':sum(old[k]['business_task_completed'] for k in normal),
                        'new_normal_completed':sum(current[k]['business_task_completed'] for k in normal),
                        'normal_regressions':[k[1] for k in normal if old[k]['business_task_completed'] and not current[k]['business_task_completed']],
                        'changes':rows}
        results[label]={'source':str(source),'comparison_type':'same frozen rules/input' if label=='gated_parent' else 'historical reference; code and instrumentation differ','groups':by_group}
    late_blocks=[]
    independent_blocks=[]
    families={}
    for k,r in current.items():
        if not valid(r):
            continue
        if r['variant']=='attack' and r['attack_goal_achieved'] and r['hard_blocked_required_steps']:
            late_blocks.append({'arm':k[0],'scenario_id':k[1],'first_block_step':r['first_effective_block_step']})
        raw=json.loads((OUT/r.get('raw_artifact',f'raw/{k[0]}__{k[1]}.json')).read_text())
        for e in raw.get('events',[]):
            evidence=e.get('guard_evidence') or {}
            rv=evidence.get('rv_result') or {}
            if e['decision']=='block':
                independent_blocks.append({'arm':k[0],'scenario_id':k[1],'step':e['index'],
                    'rv_verdict':rv.get('verdict'),'proposed_verdict':rv.get('proposed_verdict'),
                    'evidence':rv.get('hard_block_evidence'),
                    'pmkb_effect':(evidence.get('policy_decision') or {}).get('effect'),
                    'rule':rv.get('triggered_by'),'history':rv.get('matched_history_step_ids'),
                    'applied':e['applied']})
        group=f"{r['evaluation_group']}/{r['split']}/{r['family']}/{r['arm']}"
        f=families.setdefault(group,Counter())
        f['attack_total' if r['variant']=='attack' else 'normal_total']+=1
        if r['variant']=='attack':f['prevented']+=not r['attack_goal_achieved']
        else:f['completed']+=r['business_task_completed']
    results['actual_independent_block_calls']=independent_blocks
    results['blocks_after_goal_already_attained']=late_blocks
    results['family_counts']=dict(families)
    results['fresh_completed']=len(current)
    (OUT/'version-comparison.json').write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n')
    text=['# 取消门的配对比较','',f'已保存新运行 {len(current)}/100。旧记录只用于配对，不作为新增安全样本。','']
    for label,section in results.items():
        if label not in ('gated_parent','historical_ungated'):continue
        text += [f'## {label}','',section['comparison_type'],'','| 组/臂 | 攻击旧→新阻止 | 正常旧→新完成 | 反向攻击退化 | 正常退化 |','|---|---:|---:|---:|---:|']
        for group,g in section['groups'].items():
            text.append(f"| {group} | {g['old_prevented']}→{g['new_prevented']}/{g['attack_total']} | {g['old_normal_completed']}→{g['new_normal_completed']}/{g['normal_total']} | {len(g['prevention_regressions'])} | {len(g['normal_regressions'])} |")
    text += ['','## 判定边界','',f'实际硬阻断调用 {len(independent_blocks)}；存在硬阻断但攻击目标仍达成的记录 {len(late_blocks)}。硬阻断调用次数不是独立攻击阻止数。','', '旧矩阵 Oracle 仅证明预定副作用达成与否；新增近邻链路使用真实内容哈希和接收方收据。历史参考版本的源码和观测机制不同，不能把历史比较当成完全同配置因果实验。','', '逐场景变化、规则、PMKB 与成功历史引用见 version-comparison.json。']
    (OUT/'version-comparison.md').write_text('\n'.join(text)+'\n')
    print(f'version comparison: {len(current)}/100; actual block calls={len(independent_blocks)}')


if __name__=='__main__':main()
