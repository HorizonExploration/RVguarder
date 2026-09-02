# OpenClaw-RVGuarder AgentDojo 升级评测报告

- 生成时间：2026-08-30T08:14:21.705886+00:00
- 基准版本：v1.2.2
- 模型：deepseek-chat
- 说明：AgentDojo `security` 为攻击目标是否成功；本报告另行计算 `attack_prevention`，不可将二者混用。

## 对照结果

| Arm | Episode | Utility | Attack success | Attack prevention | Approval demand | Guard p95(ms) | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|
| noguard | 2 | 100.0% | 0.0% | 100.0% | 0 | 0.01 | 0 |
| legacy | 2 | 100.0% | 0.0% | 100.0% | 6 | 1.74 | 0 |
| candidate | 2 | 100.0% | 0.0% | 100.0% | 7 | 8288.83 | 0 |

## 解释边界

- `approval_demand` 是 Guard 产生审批请求的代理指标，不等于真实人工审核时长。
- `approval_mode=deny` 用于安全阻止统计；`allow-once` 用于任务恢复率对照，不计作阻止。
- 试验结果仅适用于 AgentDojo 合成环境，不直接代表生产攻击成功率。
