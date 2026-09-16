# 架构文档索引

> **核对日期：** 2026-09-15
> **文档状态：** 现行架构入口

本目录只放面向当前实现的架构说明。历史选型、已完成重构计划和旧版本快照统一移至 `docs/archive/`，不再参与现行导航。当前实现、测试基线和已知边界以[项目理解与当前记忆](./project-memory.md)为最高优先级。

## 推荐阅读顺序

| 顺序 | 文档 | 用途 |
| --- | --- | --- |
| 0 | [项目理解与当前记忆](./project-memory.md) | 当前代码边界、运行链路、版本与维护规则 |
| 1 | [架构总览](./overview.md) | 分层结构、组件职责和端到端决策流 |
| 2 | [权限建模与端到端架构图](./permission-modeling-diagrams.md) | 组会汇报用四张图：权限本体、PMKB、自动机和 OpenClaw 交接 |
| 3 | [权限知识库与 RV 运行时架构结果](./permission-kb-runtime-architecture.md) | 本次升级的现行实现、数据合同、语义命中、权限建模和跨 session RV |
| 4 | [RV 权限自动机架构](./rv-permission-automata.md) | 三类自动机、PMKB 编译合同、作用域和旧结构迁移 |
| 5 | [三态控制面与 RV 提交边界](./three-state-rv-runtime-plan-2026-09-03.md) | allow/ask/block、preview 与成功回调提交边界 |
| 6 | [旧规则迁移矩阵](./legacy-rule-migration-matrix.md) | 47 条旧规则的迁移事实、删除门槛和分组计划 |
| 7 | [RV 层技术报告](./rv-engine-report.md) | ToolCallIR、ChainRule DSL、窗口与主体证据状态 |
| 8 | [前后端交接改造报告](./frontend-handoff-redesign-report.md) | OpenClaw 单一审批入口、SSE 同步和前端状态模型 |
| 9 | [项目现状分析](./project-status-analysis.md) | 已完成能力、风险清单和后续优先级 |
| 10 | [质量保障方案](./quality-assurance.md) | 测试分层、合约门禁、性能和回归策略 |

## 当前架构要点

```text
OpenClaw before_tool_call
  → Hook Bridge / BehaviorEvent
  → 语义与 PMKB 单步授权
  → RV preview（有效窗口纯回放）
  → 主体证据只读校验
  → OpenClaw requireApproval / block / allow
  → resolution/SSE 只读同步与审计
  → 成功 after_tool_call 后提交 RV/主体证据
```

- OpenClaw 原生审批页是 Hook 决策唯一入口，Guard 页面不再创建第二个审批源。
- PMKB `1.1.0` 基线直接参与运行时决策；新规则通过离线回放和有限事件样本验证，不设置自然日 shadow gate。
- 语义层先把工具调用归一化为 Authorization Trace，再由 `TraceCompiler` 做覆盖感知匹配；未知工具或缺失特征不会被“相似度”误放行。
- PMKB 同时校验单步规则、最小必要权限闭包/差分和危险权限组合；证据进入 Guard 页面，审批仍只回到 OpenClaw。历史 `LEGACY-*` 记录只用于回放证据，不再驱动第二个在线规则引擎。
- RV 分为行为 DSL、PMKB 权限自动机和可选基线 DFA 三族；PMKB 规则为 session 监视器，权限组合关系为 `(principal_id, agent_id, capability_lineage)` 隔离的 principal 监视器。
- 默认且唯一 RV 规则路径为 DSL；历史 `OPENCLAW_RV_RULE_MODE=fsm` 偏好值只归一化为 DSL，不再加载手写监视器。
- Hook 后端故障采用分级策略：低风险只读调用可放行并审计，高影响调用暂停；`failClosed=true` 可统一暂停。
- FastAPI 是默认且唯一 HTTP 入口；旧版 stdlib HTTP 实现已从生产包移除，历史源文件保存在 Git 归档中。

## 相关入口

- [研究与规划索引](../research/index.md)
- [语义理解与 PMKB](../semantic/method.md)
- [测试设计索引](../test-design/index.md)
- [路线图](../ops/roadmap.md)
- 历史材料归档说明：`docs/archive/README.md`
