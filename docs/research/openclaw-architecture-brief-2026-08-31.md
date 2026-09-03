# OpenClaw 汇报整合简报：权限建模主线

> **接收方：** OpenClaw 汇报优化助手
> **日期：** 2026-08-31
> **事实源：** `docs/architecture/permission-modeling-diagrams.md` 及其链接的当前架构文档
> **状态更新（2026-09-03）：** 本文保留 2026-08-31 组会简报语境；其中旧引擎、旧 PMKB 计数和未提交文件数量均为历史快照，不是当前事实。当前事实见[工程统一报告](../architecture/v070-engineering-unification-report-2026-09-02.md)。

## 使用任务

请结合本简报和四张架构图，优化 OpenClaw-RVGuarder 的组会汇报稿。汇报主线必须是：

> 权限建模是核心主线，PMKB 是权限知识库载体，权限自动机和 RV 是运行时验证机制，OpenClaw 原生审批是唯一决策入口。

## 必须保留的事实

- 当前版本口径：`v0.7.0-dev` / PMKB `1.1.0`。
- Authorization Trace 采用九维权限本体：主体、执行体、操作、资源、范围、数据、上下文、覆盖度、来源。
- PMKB 当前规模：28 operations、35 authored rules、47 `LEGACY-*` 兼容记录、29 traces、9 relations、29 test vectors。
- `PermissionClosure`、`PermissionDiff` 和 `RiskGraph` 已进入权限判断链路。
- PMKB 可编译为权限监视器，并与 session-local / principal-global RV 协同。
- OpenClaw 原生审批是唯一批准/拒绝入口；Guard Dashboard 只读同步、解释和审计。
- `before_prompt_build` 只审计，不生成 pending approval。
- AgentDojo 框架已完成，但首轮数据无效：`max_tool_iters=2` 导致执行链截断，noguard 攻击基线为 0，candidate 曾有 Hook token 401；所有首轮预防率和负载指标作废，必须重跑。

## 推荐汇报顺序

1. 用“以前只能回答是否安全，现在能回答凭什么安全”引出权限建模；
2. 展示九维 Authorization Trace，说明工具调用如何变成可追溯权限证据；
3. 展示 PMKB 目录，说明规则、最小权限 Trace、危险组合和回归向量如何共同构成知识库；
4. 展示 PMKB→MonitorSpec→RV，说明权限策略如何进入自动机和跨会话主体状态；
5. 最后展示 OpenClaw 审批交接，强调 Guard 不维护第二套审批状态；
6. 单独说明 AgentDojo 首轮实验作废及重跑门槛，不得把无效数据写成防护结论。

## 不应出现的表达

- 不要把 AgentDojo 首轮“100% 预防率”作为有效实验结论。
- 本快照当时不应说 DetectionEngine 已经删除；2026-09-02 工程统一后，生产 DetectionEngine 已退役，LEGACY 记录仅保留用于回放。
- 不要说已经完成真实流量下人工审批下降 40%；这仍是路线图验收目标。
- 不要把 `unknown` scope、unknown tool 或不可信文本解释成宽泛授权。
- 不要把 Guard 页面描述为第二个审批中心。

## 可直接复用的结论

OpenClaw-RVGuarder 本阶段的主要进展不是增加了多少条规则，而是建立了从权限语义、知识库证据到运行时验证的闭环：Authorization Trace 描述权限，PMKB 承载权限，Closure/Diff 和 RiskGraph 分析权限，自动机和 RV 验证权限，OpenClaw 负责最终审批。下一步应先重跑有效的 AgentDojo 基线，再据此评估安全收益、审批负载和可用性。

## 图稿入口

- [四张权限主线架构图](../architecture/permission-modeling-diagrams.md)
- [权限知识库与 RV 运行时架构结果](../architecture/permission-kb-runtime-architecture.md)
- [OpenClaw 审批交接与误拦截优化结果](./openclaw-approval-chain-optimization-report-2026-08-30.md)
