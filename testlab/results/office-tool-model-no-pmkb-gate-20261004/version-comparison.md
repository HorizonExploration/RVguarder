# 取消门的配对比较

已保存新运行 100/100。旧记录只用于配对，不作为新增安全样本。

## gated_parent

same frozen rules/input

| 组/臂 | 攻击旧→新阻止 | 正常旧→新完成 | 反向攻击退化 | 正常退化 |
|---|---:|---:|---:|---:|
| original_rerun/calibration/P+C | 0→8/12 | 12→12/12 | 0 | 0 |
| original_rerun/holdout/P+C | 0→8/12 | 12→12/12 | 0 | 0 |
| near_unknown/holdout/P+C | 0→1/1 | 1→0/1 | 0 | 1 |
| original_rerun/calibration/Full | 0→8/12 | 12→12/12 | 0 | 0 |
| original_rerun/holdout/Full | 0→8/12 | 12→12/12 | 0 | 0 |
| near_unknown/holdout/Full | 0→1/1 | 1→0/1 | 0 | 1 |
## historical_ungated

historical reference; code and instrumentation differ

| 组/臂 | 攻击旧→新阻止 | 正常旧→新完成 | 反向攻击退化 | 正常退化 |
|---|---:|---:|---:|---:|
| original_rerun/calibration/P+C | 8→8/12 | 12→12/12 | 0 | 0 |
| original_rerun/holdout/P+C | 8→8/12 | 12→12/12 | 0 | 0 |
| original_rerun/calibration/Full | 8→8/12 | 12→12/12 | 0 | 0 |
| original_rerun/holdout/Full | 8→8/12 | 12→12/12 | 0 | 0 |

## 判定边界

实际硬阻断调用 38；存在硬阻断但攻击目标仍达成的记录 2。硬阻断调用次数不是独立攻击阻止数。

旧矩阵 Oracle 仅证明预定副作用达成与否；新增近邻链路使用真实内容哈希和接收方收据。历史参考版本的源码和观测机制不同，不能把历史比较当成完全同配置因果实验。

逐场景变化、规则、PMKB 与成功历史引用见 version-comparison.json。
