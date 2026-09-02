import matplotlib.pyplot as plt
import numpy as np
import os

# 确保输出目录存在
output_dir = '/home/yosoro126/OpenClaw-RVGuarder/docs/improve/assets'
os.makedirs(output_dir, exist_ok=True)

# 为了避免 Linux 环境缺少中文字体导致方块，图表内使用英文标签
# 图表 1: 核心指标对比
labels = ['Interception Rate', 'Hard Block Rate', 'FN Rate', 'Accuracy']
v0_1 = [36.25, 0.0, 46.9, 53.07]
v0_2 = [44.98, 30.1, 38.51, 59.87]

x = np.arange(len(labels))
width = 0.35

fig, ax = plt.subplots(figsize=(9, 5))
rects1 = ax.bar(x - width/2, v0_1, width, label='v0.1.0', color='#94a3b8')
rects2 = ax.bar(x + width/2, v0_2, width, label='v0.2.0 (Semantic)', color='#3b82f6')

ax.set_ylabel('Percentage (%)')
ax.set_title('Performance Metrics Comparison (v0.1.0 vs v0.2.0)')
ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.set_ylim(0, 100)
ax.legend()

# 柱状图上添加数值标签
for rects in [rects1, rects2]:
    for rect in rects:
        height = rect.get_height()
        ax.annotate(f'{height}%',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=9)

plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'metrics_comparison.png'), dpi=300)
plt.close()

# 图表 2: 决策分布对比
labels_dec = ['Block', 'Ask', 'Allow']
v0_1_dec = [0, 112, 197]
v0_2_dec = [93, 46, 170]

x_dec = np.arange(len(labels_dec))

fig, ax = plt.subplots(figsize=(7, 5))
rects_dec1 = ax.bar(x_dec - width/2, v0_1_dec, width, label='v0.1.0', color='#94a3b8')
rects_dec2 = ax.bar(x_dec + width/2, v0_2_dec, width, label='v0.2.0 (Semantic)', color='#10b981')

ax.set_ylabel('Number of Cases')
ax.set_title('Decision Distribution (Total 309 cases)')
ax.set_xticks(x_dec)
ax.set_xticklabels(labels_dec)
ax.set_ylim(0, 250)
ax.legend()

for rects in [rects_dec1, rects_dec2]:
    for rect in rects:
        height = rect.get_height()
        ax.annotate(f'{height}',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom')

plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'decision_distribution.png'), dpi=300)
plt.close()

print("Charts generated successfully.")
