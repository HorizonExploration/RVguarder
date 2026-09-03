# 历史文档归档

本目录保存已经完成、被新方案替代或仅用于内部执行的材料。归档是为了保留决策依据、实验记录和审计线索，不代表这些文档仍描述当前实现。阅读时请先看[项目理解与当前记忆](../architecture/project-memory.md)；发生冲突时以当前代码和现行文档为准。

## 目录

| 子目录 | 内容 | 当前替代入口 |
| --- | --- | --- |
| `architecture/` | v0.2.1–v0.3.0 架构分析、框架选型、重构快照 | [`architecture/`](../architecture/index.md) |
| `research/` | 早期 NL→Automata 方案、组会汇报、项目介绍 | [`research/`](../research/index.md) |
| `plans/` | 已执行的内部研究/修复/文档实施计划 | [路线图](../ops/roadmap.md)及对应现行报告 |
| `specs/` | 已完成的阶段性升级规格 | [权限模型最终方案](../research/permission-model-kb-and-cross-session-rv-plan.md) |
| `experiments/` | RV 与静态检测的历史对比实验设计 | [`test-design/`](../test-design/index.md) |
| `semantic/` | 已被当前语义合同替代的旧设计稿 | [`semantic/`](../semantic/index.md) |
| `test-design/` | 已被当前测试合同替代的旧测试设计 | [`test-design/`](../test-design/index.md) |

## 归档规则

1. 历史材料不参与 VuePress 现行页面生成和侧栏导航，但保留 Git 历史和原始内容。
2. 若归档文档仍被当前文档引用，引用必须明确标注“历史参考”，不能将其当作现行规范。
3. 新研究结论应更新现行索引或项目记忆，不在归档目录继续追加当前状态。
4. `testlab/results/`、AgentDojo 原始数据和运行时证据不属于文档归档清理范围，除非另有明确的数据保留策略。
