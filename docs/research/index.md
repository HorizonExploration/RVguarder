# 研究与规划索引

> **核对日期：** 2026-10-08
> **原则：** 研究结论服务于当前代码；已被融合或替代的材料保留在 `docs/archive/research/` 供追溯。

## 当前有效

| 文档 | 关注点 | 结论/用途 |
| --- | --- | --- |
| [官方编号覆盖实验扩展方案](../atlas-coverage-experiment-plan.md) | 23组配对、15/22编号映射、同边界与局部后果分别计量 | 68.2%是设计涉及比例；实测未运行；全部计划样例通过才计严格采样覆盖 |
| [保护范围内的优化与具体实验方案](../capability-scope-optimization-and-experiment-plan.md) | 变量绑定能力修复、20场景与52次定向运行设计 | 定向154项＋准备2项通过；已生成案例，原生实验尚未启动 |
| [插件安全能力与边界总报告](../rvguarder-security-capabilities-and-boundaries.md) | 已有攻击成果、具体案例、22项威胁、不能防护的情形 | 综合自包含说明；无需往返查阅其他报告，保留规则版本与证据层级 |
| [官方22项威胁与工具规约升级](./close-experiment-gaps/atlas-model-upgrade-v1.md) | 全量威胁映射、有限能力、成功历史和真实接收方 | 当前全量1105通过；默认有效72条、可选122条；内联删除专项RV独立阻断，未作新整体优越性结论 |
| [威胁覆盖条件矩阵](./close-experiment-gaps/atlas-threat-coverage-v1.md) | 每项官方威胁的可观测边界与条件 | 分开理论后果防护、原生证据和Hook外缺口，不推定未知攻击覆盖率 |
| [实验缺口整改执行记录](./close-experiment-gaps/README.md) | 冻结判据、问题台账、资源授权与实际内容证据 | M0–M2 已复核；M3 holdout 防止 8/15，正常 15/15 完成；审批与延迟未通过 Q5，候选未满足发布门 |
| [最新计划与清理状态](./close-experiment-gaps/plan-status-2026-10-08.md) | 已完成、未通过和待验收项；缓存清理去向 | 删除466个可再生成文件，约7.52 MiB；重要证据、失败记录和候选保留 |
| [ATLAS插件实验答辩报告](./close-experiment-gaps/atlas-plugin-report-v1.md) | 官方威胁映射、真实SDK插件安装与RV消融 | HTTP和凭据外发在Full中独立阻断；合法对照完成；仅验证所测运行时后果 |
| [本轮缺陷与整改](./close-experiment-gaps/m3-m4-defect-followup.md) | 原生注册、消融组件污染、wheel 前端、审批与计时 | 校准防住 8/10 攻击，10/10 正常完成；两项定时任务持久化仍未防住 |
| [权限模型知识库与跨会话 RV 最终方案](./permission-model-kb-and-cross-session-rv-plan.md) | 权限本体、PMKB、最小权限、危险组合和跨 session RV | 当前权限治理的总设计基线 |
| [PMKB 网络案例基础知识库升级结果报告](./pmkb-network-baseline-implementation-report-2026-08-28.md) | `1.1.0` 基础规则、接入链路、首次验收和边界 | 首次交付历史快照；增量改造以现行架构结果为准 |
| [权限语义与运行时验证专项研究报告](./agent-permission-rv-research-report-2026-08-25.md) | 权限风险分级、组合风险、攻击验证和指标 | 设计依据与后续研究输入 |
| [OpenClaw 汇报整合简报：权限建模主线](./openclaw-architecture-brief-2026-08-31.md) | 四张架构图的整合口径、事实边界和待重跑说明 | 提供给 OpenClaw 优化汇报 |
| [组会汇报：权限建模 + 三态收敛 + 审批 Checkpoint（2026-09-13）](./group-meeting-report-2026-09-13.md) | 合并 8.31（未举行的汇报）与 9 月进展：权限建模主线、评测、实测验证数字、边界与风险、汇报口径速查 | 组会汇报底稿；数字以该文实跑记录为准 |

## 阅读提示

- 规则内容和办公场景案例见 [`semantic/`](../semantic/method.md)；本目录不重复维护规则条目。
- OpenClaw 对接约束见[前后端交接改造报告](../architecture/frontend-handoff-redesign-report.md)和[运行时 Hook 文档](../features/runtime-hook.md)。
- 系统级落地结果见[权限知识库与 RV 运行时架构结果](../architecture/permission-kb-runtime-architecture.md)；本目录的研究报告用于解释依据、指标和后续验证，不覆盖代码事实。
- 研究材料中的“目标”“建议”“待验证”不是已实现能力，落地状态以[项目记忆](../architecture/project-memory.md)为准。

## 历史研究

NL→Automata 早期计划、组会汇报、审批交接现场报告和项目介绍仍保留在 `docs/archive/research/`，避免与当前 PMKB/RV 方案混淆。

历史审批交接证据保存在 `docs/archive/research/openclaw-approval-chain-optimization-report-2026-08-30.md`（归档不参与站点构建）。
