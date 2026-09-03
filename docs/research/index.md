# 研究与规划索引

> **核对日期：** 2026-09-03
> **原则：** 研究结论服务于当前代码；已被融合或替代的材料保留在 `docs/archive/research/` 供追溯。

## 当前有效

| 文档 | 关注点 | 结论/用途 |
| --- | --- | --- |
| [权限模型知识库与跨会话 RV 最终方案](./permission-model-kb-and-cross-session-rv-plan.md) | 权限本体、PMKB、最小权限、危险组合和跨 session RV | 当前权限治理的总设计基线 |
| [PMKB 网络案例基础知识库升级结果报告](./pmkb-network-baseline-implementation-report-2026-08-28.md) | `1.1.0` 基础规则、接入链路、首次验收和边界 | 首次交付历史快照；增量改造以现行架构结果为准 |
| [OpenClaw 审批交接与误拦截优化结果](./openclaw-approval-chain-optimization-report-2026-08-30.md) | 原生工具映射、长审批说明、session 升权、超时收拢和定向回归 | 当前 OpenClaw 交接修复的证据与启用说明 |
| [权限语义与运行时验证专项研究报告](./agent-permission-rv-research-report-2026-08-25.md) | 权限风险分级、组合风险、攻击验证和指标 | 设计依据与后续研究输入 |
| [OpenClaw 汇报整合简报：权限建模主线](./openclaw-architecture-brief-2026-08-31.md) | 四张架构图的整合口径、事实边界和待重跑说明 | 提供给 OpenClaw 优化汇报 |

## 阅读提示

- 规则内容和办公场景案例见 [`semantic/`](../semantic/method.md)；本目录不重复维护规则条目。
- OpenClaw 对接约束见[前后端交接改造报告](../architecture/frontend-handoff-redesign-report.md)和[运行时 Hook 文档](../features/runtime-hook.md)。
- 系统级落地结果见[权限知识库与 RV 运行时架构结果](../architecture/permission-kb-runtime-architecture.md)；本目录的研究报告用于解释依据、指标和后续验证，不覆盖代码事实。
- 研究材料中的“目标”“建议”“待验证”不是已实现能力，落地状态以[项目记忆](../architecture/project-memory.md)为准。

## 历史研究

NL→Automata 早期计划、组会汇报和项目介绍仍保留在 `docs/archive/research/`，避免与当前 PMKB/RV 方案混淆。
