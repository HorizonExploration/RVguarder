# 架构文档索引

> **核对日期：** 2026-08-28
> **文档状态：** 现行架构入口

本目录只放面向当前实现的架构说明。历史选型、已完成重构计划和旧版本快照统一移至 `docs/archive/`，不再参与现行导航。当前实现、测试基线和已知边界以[项目理解与当前记忆](./project-memory.md)为最高优先级。

## 推荐阅读顺序

| 顺序 | 文档 | 用途 |
| --- | --- | --- |
| 0 | [项目理解与当前记忆](./project-memory.md) | 当前代码边界、运行链路、版本与维护规则 |
| 1 | [架构总览](./overview.md) | 分层结构、组件职责和端到端决策流 |
| 2 | [RV 层技术报告](./rv-engine-report.md) | ToolCallIR、约束引擎、ChainRule、FSM 和会话状态 |
| 3 | [RV 落地审计报告](./nl-automata-rv-landing-report.md) | RV 阶段 A–F 的代码核验和整改闭环 |
| 4 | [前后端交接改造报告](./frontend-handoff-redesign-report.md) | OpenClaw 单一审批入口、SSE 同步和前端状态模型 |
| 5 | [项目现状分析](./project-status-analysis.md) | 已完成能力、风险清单和后续优先级 |
| 6 | [质量保障方案](./quality-assurance.md) | 测试分层、合约门禁、性能和回归策略 |
| 7 | [目标架构参考](./target-architecture.md) | 仍有效的目标设计；与当前事实冲突时以当前记忆和代码为准 |

## 当前架构要点

```text
OpenClaw before_tool_call
  → Hook Bridge / BehaviorEvent
  → 语义与单步规则
  → PMKB / 约束推理
  → ChainRule RV（可回退 FSM）
  → session 级风险升级
  → OpenClaw requireApproval / block / allow
  → resolution/SSE 只读同步与审计
```

- OpenClaw 原生审批页是 Hook 决策唯一入口，Guard 页面不再创建第二个审批源。
- PMKB `1.1.0` 基线直接参与运行时决策；新规则通过离线回放和有限事件样本验证，不设置自然日 shadow gate。
- 默认 RV 模式为 DSL；`OPENCLAW_RV_RULE_MODE=fsm` 仅用于兼容回退。
- 默认 HTTP 入口仍是 `legacy_web.py`，FastAPI 通过 `--fastapi` 启用；该双轨边界是已知维护风险。

## 相关入口

- [研究与规划索引](../research/index.md)
- [语义理解与 PMKB](../semantic/method.md)
- [测试设计索引](../test-design/index.md)
- [路线图](../ops/roadmap.md)
- 历史材料归档说明：`docs/archive/README.md`
