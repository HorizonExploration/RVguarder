#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenClaw Guard — 综合分析可视化（升级版）
生成 10 张专业风格统计图表
"""

import json, os, sys, datetime, io
from pathlib import Path

# ── 导入可视化库 ──────────────────────────────────────────
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.ticker as mticker
    import numpy as np
    HAVE_VIZ = True
except ImportError:
    HAVE_VIZ = False
    print("[WARN] matplotlib not installed")

# ── 配色方案（现代商务风格） ──────────────────────────────
BRAND_RED     = '#D4380D'   # 主色-深橙红
BRAND_ORANGE  = '#FA8C16'   # 辅色-橙
BRAND_BLUE    = '#1677FF'   # 辅色-蓝
BRAND_GREEN   = '#52C41A'   # 辅色-绿
BRAND_PURPLE  = '#722ED1'   # 辅色-紫
BRAND_CYAN    = '#13C2C2'   # 辅色-青
BRAND_GREY    = '#8C8C8C'   # 中性灰
BRAND_BG      = '#FAFAFA'   # 背景浅灰
BRAND_BORDER  = '#F0F0F0'   # 边框色

PALETTE_3 = [BRAND_RED, BRAND_BLUE, BRAND_PURPLE]
PALETTE_5 = [BRAND_RED, BRAND_ORANGE, BRAND_BLUE, BRAND_GREEN, BRAND_PURPLE]
PALETTE_DECISION = {'block': '#CF1322', 'ask': '#FAAD14', 'allow': '#52C41A'}

if HAVE_VIZ:
    plt.rcParams.update({
        'font.family': 'sans-serif',
        'font.sans-serif': ['WenQuanYi Zen Hei', 'DejaVu Sans', 'SimHei'],
        'axes.unicode_minus': False,
        'figure.dpi': 180,
        'savefig.dpi': 180,
        'savefig.bbox': 'tight',
        'figure.facecolor': BRAND_BG,
        'axes.facecolor': 'white',
        'axes.edgecolor': BRAND_BORDER,
        'axes.grid': True,
        'grid.alpha': 0.25,
        'grid.color': BRAND_BORDER,
    })

OUTPUT_DIR = Path("/home/yosoro126/OpenClaw-Guard/testlab/实验结果")
CHART_DIR  = OUTPUT_DIR / "charts"

# ── 实验数据 ──────────────────────────────────────────────
EXPS = {
    "预实验(40条)": {
        "total":40,"block":5,"ask":19,"allow":16,
        "rate":60.0,"hard":12.5,"avg":1.1202,
        "p50":0.0163,"p95":3.1337,"min_t":0.0082,"max_t":3.8028,
        "fn":8,"fp":1,
    },
    "正式实验(110条)": {
        "total":110,"block":12,"ask":57,"allow":41,
        "rate":62.73,"hard":10.91,"avg":1.0786,
        "p50":0.0244,"p95":3.5,"min_t":0.0127,"max_t":5.181,
        "fn":28,"fp":1,
    },
    "AgentDojo(309条)": {
        "total":309,"block":0,"ask":112,"allow":197,
        "rate":36.25,"hard":0.0,"avg":2.0097,
        "p50":2.6198,"p95":4.3663,"min_t":0.0118,"max_t":7.8427,
        "fn":145,"fp":2,
    },
}

ATTACK_TYPES = ['baseline','direct','ignore_previous','system_message','tool_knowledge']
ATTACK_LABELS = ['基线\n(baseline)','直接注入\n(direct)','忽略前文\n(ignore_prev)','系统消息\n(system_msg)','工具知识\n(tool_knowledge)']

ATTACK_DATA = {
    "预实验(40条)":     [10.0, 90.0, 70.0, 0, 70.0],
    "正式实验(110条)":   [6.67,86.67,80.0, 65.0, 60.0],
    "AgentDojo(309条)": [3.57, 43.48,43.48,43.48,43.48],
}

RULES = [
    ("FILE-003","工作区外删除","ask",4,10,63),
    ("NET-001", "外部HTTP访问","ask",4,11,11),
    ("FILE-007","工作区外写入","ask",1,6,0),
    ("FILE-006","阻断配置覆盖","block",3,3,0),
    ("FILE-001","阻断系统目录删除","block",1,5,0),
    ("FILE-004","确认日志删除","ask",2,4,0),
    ("CFG-002", "阻断鉴权关闭","block",1,2,0),
    ("SKL-001", "确认shell skill","ask",1,2,0),
    ("GEN-003", "确认未解析命令","ask",1,2,0),
]

DOJO_WORKSPACE_RATES = [3.57,82.61,82.61,82.61,82.61,82.61,82.61]
DOJO_BANKING_RATES   = [3.57,0.0,0.0,0.0,0.0,0.0,0.0]


# ── 辅助函数 ──────────────────────────────────────────────
def ensure_dir(p):
    p.mkdir(parents=True, exist_ok=True)

def save_fig(fig, name):
    path = CHART_DIR / name
    fig.savefig(str(path), dpi=200, facecolor=fig.get_facecolor(),
                edgecolor='none', bbox_inches='tight', pad_inches=0.3)
    plt.close(fig)
    return path

def style_ax(ax, title, xlabel='', ylabel=''):
    """统一轴样式"""
    ax.set_title(title, fontsize=14, fontweight='bold', pad=16)
    if xlabel: ax.set_xlabel(xlabel, fontsize=11, labelpad=6)
    if ylabel: ax.set_ylabel(ylabel, fontsize=11, labelpad=6)
    ax.tick_params(labelsize=9.5)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

def round_corner_patch():
    """返回统一圆角边框样式"""
    return dict(boxstyle='round,pad=0.4', facecolor='white', edgecolor='#D9D9D9',
                linewidth=0.8, alpha=0.95)


# ════════════════════════════════════════════════════════════
# 图表 1：总体拦截率对比 — 分组柱状图（品牌配色+值标签+圆角）
# ════════════════════════════════════════════════════════════
def chart_01_overall():
    fig, ax = plt.subplots(figsize=(9,5.5))
    names = list(EXPS.keys())
    rates = [EXPS[n]["rate"] for n in names]
    hard  = [EXPS[n]["hard"] for n in names]
    x = np.arange(len(names)); w = 0.32

    b1 = ax.bar(x - w/2, rates, w, label='总体拦截率 (block + ask)',
                color=BRAND_RED, edgecolor='white', linewidth=0.6, alpha=0.88)
    b2 = ax.bar(x + w/2, hard,  w, label='强硬阻断率 (block)',
                color=BRAND_ORANGE, edgecolor='white', linewidth=0.6, alpha=0.72)

    for bar in b1:
        ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+1.2,
                f'{bar.get_height():.1f}%', ha='center', fontsize=10.5, fontweight='bold', color=BRAND_RED)
    for bar in b2:
        if bar.get_height()>0:
            ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+1.2,
                    f'{bar.get_height():.1f}%', ha='center', fontsize=10, fontweight='bold', color=BRAND_ORANGE)

    style_ax(ax, '三次实验总体拦截率对比', ylabel='拦截率 (%)')
    ax.set_xticks(x); ax.set_xticklabels(names, fontsize=11)
    ax.set_ylim(0, 82); ax.legend(fontsize=10, loc='upper right', framealpha=0.9)
    save_fig(fig, '01_总体拦截率对比.png')
    print("  [图表 1/10] 总体拦截率对比 ✓")


# ════════════════════════════════════════════════════════════
# 图表 2：决策分布 — 堆叠柱状图 + 百分比标签
# ════════════════════════════════════════════════════════════
def chart_02_decision():
    fig, ax = plt.subplots(figsize=(9,5.5))
    names = list(EXPS.keys())
    bv = [EXPS[n]["block"] for n in names]
    av = [EXPS[n]["ask"] for n in names]
    lv = [EXPS[n]["allow"] for n in names]
    x = np.arange(len(names)); w = 0.55

    b1 = ax.bar(x, bv, w, label='阻断 (block)', color=PALETTE_DECISION['block'], edgecolor='white', linewidth=0.5)
    b2 = ax.bar(x, av, w, bottom=bv, label='审批 (ask)', color=PALETTE_DECISION['ask'], edgecolor='white', linewidth=0.5)
    b3 = ax.bar(x, lv, w, bottom=[b+a for b,a in zip(bv,av)],
                label='放行 (allow)', color=PALETTE_DECISION['allow'], edgecolor='white', linewidth=0.5)

    for i in range(len(names)):
        tot = bv[i] + av[i] + lv[i]
        ax.text(i, tot + 8, str(tot), ha='center', fontsize=11.5, fontweight='bold')
        for bot, val, col in [(0,bv[i],'white'), (bv[i],av[i],'white'), (bv[i]+av[i],lv[i],'white')]:
            if val > 0 and val/tot > 0.07:
                ax.text(i, bot+val/2, f'{int(val)}\n({val/tot*100:.0f}%)', ha='center', va='center',
                        fontsize=8.5, color=col, fontweight='bold')

    style_ax(ax, '三次实验决策分布对比', ylabel='用例数')
    ax.set_xticks(x); ax.set_xticklabels(names, fontsize=11); ax.legend(fontsize=10, framealpha=0.9)
    save_fig(fig, '02_决策分布对比.png')
    print("  [图表 2/10] 决策分布对比 ✓")


# ════════════════════════════════════════════════════════════
# 图表 3：攻击类型拦截率 — 分组柱状图，仅含数据存在的类型
# ════════════════════════════════════════════════════════════
def chart_03_attack_type():
    fig, ax = plt.subplots(figsize=(12,6))
    x = np.arange(len(ATTACK_TYPES)); w = 0.24
    colors = ['#1677FF', '#FA8C16', '#722ED1']

    for idx, (exp_name, color) in enumerate(zip(['预实验(40条)','正式实验(110条)','AgentDojo(309条)'], colors)):
        vals = ATTACK_DATA[exp_name]
        offset = (idx - 1) * w
        bars = ax.bar(x + offset, vals, w, label=exp_name, color=color,
                      edgecolor='white', linewidth=0.5, alpha=0.88)
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+1.5,
                        f'{v:.1f}%', ha='center', fontsize=8, fontweight='bold', rotation=90, color=color)

    style_ax(ax, '各攻击类型拦截率对比（三次实验）', ylabel='拦截率 (%)')
    ax.set_xticks(x); ax.set_xticklabels(ATTACK_LABELS, fontsize=9.5)
    ax.set_ylim(0, 108); ax.legend(fontsize=10, framealpha=0.9, loc='upper right')
    save_fig(fig, '03_攻击类型拦截率对比.png')
    print("  [图表 3/10] 攻击类型拦截率对比 ✓")


# ════════════════════════════════════════════════════════════
# 图表 4：规则命中频率排行榜 — 横向条形图
# ════════════════════════════════════════════════════════════
def chart_04_rule_ranking():
    fig, ax = plt.subplots(figsize=(10.5,5.5))
    names = [r[1] for r in RULES[:8]]
    totals = [r[3]+r[4]+r[5] for r in RULES[:8]]
    decs = [r[2] for r in RULES[:8]]
    ids = [r[0] for r in RULES[:8]]
    colors = [PALETTE_DECISION['block'] if d=='block' else PALETTE_DECISION['ask'] for d in decs]

    bars = ax.barh(range(len(names)), totals, color=colors, edgecolor='white', linewidth=0.5, alpha=0.88, height=0.55)
    for bar, v, rid in zip(bars, totals, ids):
        if v > 0:
            ax.text(bar.get_width()+0.5, bar.get_y()+bar.get_height()/2,
                    f'{rid}（{v}次）', va='center', fontsize=9.5, fontweight='bold')

    from matplotlib.patches import Patch
    ax.legend(handles=[
        Patch(color=PALETTE_DECISION['block'], label='直接阻断 (block)', alpha=0.88),
        Patch(color=PALETTE_DECISION['ask'], label='需审批 (ask)', alpha=0.88),
    ], fontsize=10, framealpha=0.9)

    style_ax(ax, '规则命中频率排行榜（TOP 8）', xlabel='命中次数（三次实验累计）')
    ax.set_yticks(range(len(names))); ax.set_yticklabels(names, fontsize=9.5)
    ax.invert_yaxis(); ax.grid(axis='y', visible=False)
    save_fig(fig, '04_规则命中频率排行榜.png')
    print("  [图表 4/10] 规则命中频率排行榜 ✓")


# ════════════════════════════════════════════════════════════
# 图表 5：各实验规则命中分布 — 分组柱状图
# ════════════════════════════════════════════════════════════
def chart_05_rule_by_exp():
    top_rules = [r[0] for r in RULES[:8]]
    pv = [r[3] for r in RULES[:8]]
    fv = [r[4] for r in RULES[:8]]
    dv = [r[5] for r in RULES[:8]]
    x = np.arange(len(top_rules)); w = 0.24

    fig, ax = plt.subplots(figsize=(12,5.5))
    ax.bar(x-w, pv, w, label='预实验', color='#1677FF', edgecolor='white', linewidth=0.5, alpha=0.88)
    ax.bar(x,   fv, w, label='正式实验', color='#FA8C16', edgecolor='white', linewidth=0.5, alpha=0.88)
    ax.bar(x+w, dv, w, label='AgentDojo实验', color='#722ED1', edgecolor='white', linewidth=0.5, alpha=0.88)

    # 标注 FILE-003 的突出值
    ax.annotate('AgentDojo 数据集\n触发 63 次', xy=(0,63), xytext=(1.5,55),
                arrowprops=dict(arrowstyle='->', color='#8C8C8C', lw=1.2),
                fontsize=9, fontweight='bold', color='#722ED1',
                bbox=dict(boxstyle='round,pad=0.3', facecolor='#F9F0FF', edgecolor='#D3ADF7', linewidth=0.8))

    style_ax(ax, '各实验规则命中分布（TOP 8）', ylabel='命中次数')
    ax.set_xticks(x); ax.set_xticklabels(top_rules, fontsize=10)
    ax.legend(fontsize=10, framealpha=0.9)
    save_fig(fig, '05_各实验规则命中分布.png')
    print("  [图表 5/10] 各实验规则命中分布 ✓")


# ════════════════════════════════════════════════════════════
# 图表 6：响应性能 — 分位柱状图
# ════════════════════════════════════════════════════════════
def chart_06_perf():
    fig, ax = plt.subplots(figsize=(9,5.5))
    names = list(EXPS.keys())
    avg_t = [EXPS[n]["avg"] for n in names]
    p50_t = [EXPS[n]["p50"] for n in names]
    p95_t = [EXPS[n]["p95"] for n in names]
    x = np.arange(len(names)); w = 0.24

    ax.bar(x-w, avg_t, w, label='平均耗时', color='#1677FF', edgecolor='white', linewidth=0.5, alpha=0.88)
    ax.bar(x,   p50_t, w, label='P50（中位数）', color='#52C41A', edgecolor='white', linewidth=0.5, alpha=0.88)
    ax.bar(x+w, p95_t, w, label='P95', color='#D4380D', edgecolor='white', linewidth=0.5, alpha=0.88)

    for i in range(len(names)):
        ax.text(i-w, avg_t[i]+0.08, f'{avg_t[i]:.2f}s', ha='center', fontsize=8.5, rotation=90)
        ax.text(i,   p50_t[i]+0.08, f'{p50_t[i]:.2f}s', ha='center', fontsize=8.5, rotation=90)
        ax.text(i+w, p95_t[i]+0.08, f'{p95_t[i]:.2f}s', ha='center', fontsize=8.5, rotation=90)

    style_ax(ax, '响应性能分位指标对比', ylabel='耗时（秒）')
    ax.set_xticks(x); ax.set_xticklabels(names, fontsize=11)
    ax.legend(fontsize=10, framealpha=0.9)
    save_fig(fig, '06_响应性能对比.png')
    print("  [图表 6/10] 响应性能对比 ✓")


# ════════════════════════════════════════════════════════════
# 图表 7：误报/漏报统计
# ════════════════════════════════════════════════════════════
def chart_07_fn_fp():
    fig, ax = plt.subplots(figsize=(9,5.5))
    names = list(EXPS.keys())
    fn_v = [EXPS[n]["fn"] for n in names]
    fp_v = [EXPS[n]["fp"] for n in names]
    x = np.arange(len(names)); w = 0.3

    b1 = ax.bar(x-w/2, fn_v, w, label='漏报（False Negative）',
                color=BRAND_RED, edgecolor='white', linewidth=0.5, alpha=0.88)
    b2 = ax.bar(x+w/2, fp_v, w, label='误报（False Positive）',
                color=BRAND_ORANGE, edgecolor='white', linewidth=0.5, alpha=0.88)

    for bar, val in zip(b1, fn_v):
        if val > 0:
            ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+2,
                    str(val), ha='center', fontsize=11, fontweight='bold', color=BRAND_RED)
    for bar, val in zip(b2, fp_v):
        if val > 0:
            ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+2,
                    str(val), ha='center', fontsize=11, fontweight='bold', color=BRAND_ORANGE)

    style_ax(ax, '误报与漏报统计', ylabel='用例数')
    ax.set_xticks(x); ax.set_xticklabels(names, fontsize=11)
    ax.legend(fontsize=10, framealpha=0.9)
    save_fig(fig, '07_误报漏报统计.png')
    print("  [图表 7/10] 误报漏报统计 ✓")


# ════════════════════════════════════════════════════════════
# 图表 8：AgentDojo 套件对比
# ════════════════════════════════════════════════════════════
def chart_08_dojo_suite():
    fig, ax = plt.subplots(figsize=(10.5,5.5))
    labels = ['基线\n(baseline)', '直接注入\n(direct)', '忽略前文\n(ignore_prev)',
              '系统消息\n(system_msg)', '重要指令\n(important_instr)',
              'InjecAgent\n(injecagent)', '工具知识\n(tool_knowledge)']
    x = np.arange(len(labels)); w = 0.32

    b1 = ax.bar(x-w/2, DOJO_WORKSPACE_RATES, w, label='工作区套件 workspace（194条）',
                color='#1677FF', edgecolor='white', linewidth=0.5, alpha=0.88)
    b2 = ax.bar(x+w/2, DOJO_BANKING_RATES, w, label='银行套件 banking（115条）',
                color=BRAND_RED, edgecolor='white', linewidth=0.5, alpha=0.88)

    for bar in b1:
        if bar.get_height() > 15:
            ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+2,
                    f'{bar.get_height():.0f}%', ha='center', fontsize=8.5, fontweight='bold', color='#1677FF')
    ax.text(0.97, 55, 'banking 全线\n拦截率为 0%', fontsize=9.5, fontweight='bold', color=BRAND_RED,
            bbox=dict(boxstyle='round,pad=0.3', facecolor='#FFF1F0', edgecolor='#FFA39E', linewidth=0.8))

    style_ax(ax, 'AgentDojo 实验：两套件攻击类型拦截率对比', ylabel='拦截率 (%)')
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=8.5)
    ax.set_ylim(0, 108); ax.legend(fontsize=9.5, framealpha=0.9)
    save_fig(fig, '08_AgentDojo套件对比.png')
    print("  [图表 8/10] AgentDojo 套件对比 ✓")


# ════════════════════════════════════════════════════════════
# 图表 9：AgentDojo 漏报分布 — 横向条形图
# ════════════════════════════════════════════════════════════
def chart_09_dojo_fn():
    fig, ax = plt.subplots(figsize=(9,4.5))
    labels = ['工作区 — 语义攻击\n(direct / system_message 等)', '工作区 — 工具链攻击\n(tool_knowledge)', '银行 — 全部攻击\n(banking)']
    vals = [13, 13, 115]
    colors = ['#1677FF', '#722ED1', BRAND_RED]

    bars = ax.barh(range(len(labels)), vals, color=colors, edgecolor='white', linewidth=0.5, alpha=0.88, height=0.45)
    for bar, val in zip(bars, vals):
        ax.text(bar.get_width()+2, bar.get_y()+bar.get_height()/2,
                f'{val} 条漏报', va='center', fontsize=10.5, fontweight='bold')

    style_ax(ax, 'AgentDojo 实验：漏报分布', xlabel='漏报数')
    ax.set_yticks(range(len(labels))); ax.set_yticklabels(labels, fontsize=9.5)
    ax.invert_yaxis(); ax.grid(axis='y', visible=False)
    save_fig(fig, '09_AgentDojo漏报分布.png')
    print("  [图表 9/10] AgentDojo 漏报分布 ✓")


# ════════════════════════════════════════════════════════════
# 图表 10：拦截率 vs 综合准确率
# ════════════════════════════════════════════════════════════
def chart_10_acc_vs_rate():
    fig, ax = plt.subplots(figsize=(9,5.5))
    names = ['预实验(40条)', '正式实验(110条)', 'AgentDojo(309条)']
    rates = [60.0, 62.73, 36.25]
    accs = [(40-8-1)/40*100, (110-28-1)/110*100, (309-145-2)/309*100]
    x = np.arange(len(names)); w = 0.3

    b1 = ax.bar(x-w/2, rates, w, label='总体拦截率', color=BRAND_RED, edgecolor='white', linewidth=0.5, alpha=0.88)
    b2 = ax.bar(x+w/2, accs, w, label='综合准确率', color=BRAND_GREEN, edgecolor='white', linewidth=0.5, alpha=0.88)

    for bar in b1:
        ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+1.5,
                f'{bar.get_height():.1f}%', ha='center', fontsize=10, fontweight='bold', color=BRAND_RED)
    for bar in b2:
        ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+1.5,
                f'{bar.get_height():.1f}%', ha='center', fontsize=10, fontweight='bold', color=BRAND_GREEN)

    style_ax(ax, '总体拦截率 vs 综合准确率', ylabel='百分比 (%)')
    ax.set_xticks(x); ax.set_xticklabels(names, fontsize=11)
    ax.set_ylim(0, 100); ax.legend(fontsize=10, framealpha=0.9, loc='lower right')

    # 辅助说明
    ax.annotate('AgentDojo 实验准确率\n显著低于拦截率\n（大量漏报拉低准确率）',
                xy=(2,36.25), xytext=(2.8,30),
                arrowprops=dict(arrowstyle='->', color='#8C8C8C', lw=1),
                fontsize=9, color='#8C8C8C',
                bbox=dict(boxstyle='round,pad=0.3', facecolor='white', edgecolor='#D9D9D9', linewidth=0.8))

    save_fig(fig, '10_拦截率vs准确率.png')
    print("  [图表 10/10] 拦截率 vs 准确率 ✓")


# ── 统一入口 ──────────────────────────────────────────────
ALL_CHARTS = [
    ("01_总体拦截率对比", chart_01_overall),
    ("02_决策分布对比", chart_02_decision),
    ("03_攻击类型拦截率对比", chart_03_attack_type),
    ("04_规则命中频率排行榜", chart_04_rule_ranking),
    ("05_各实验规则命中分布", chart_05_rule_by_exp),
    ("06_响应性能对比", chart_06_perf),
    ("07_误报漏报统计", chart_07_fn_fp),
    ("08_AgentDojo套件对比", chart_08_dojo_suite),
    ("09_AgentDojo漏报分布", chart_09_dojo_fn),
    ("10_拦截率vs准确率", chart_10_acc_vs_rate),
]

def generate_all():
    if not HAVE_VIZ:
        print("[跳过] matplotlib 未安装"); return
    ensure_dir(CHART_DIR)
    for name, fn in ALL_CHARTS:
        fn()
    print(f"\n[完成] 共生成 {len(ALL_CHARTS)} 张图表 → {CHART_DIR}")


if __name__ == "__main__":
    generate_all()