# 权限建模与端到端架构图设计

## 目标

为组会汇报提供一组与当前实现一致的架构图，围绕“权限建模为主线、PMKB 为载体、RV 为验证机制、OpenClaw 为审批决策中心”解释项目工作。

## 图稿范围

1. 总体架构：展示 OpenClaw Hook、Guard 后端、PMKB/RV、前端和审计的分层及审批交接。
2. 权限建模：展示 Hook 事件如何归一化为九维 Authorization Trace，并完成覆盖感知匹配、闭包/差分和风险组合分析。
3. PMKB：展示操作目录、规则、Trace、关系、测试向量、校验和 legacy 迁移的知识库结构。
4. 编译与端到端：展示 PolicyBundle 如何编译为权限监视器，和 session/principal RV、OpenClaw 审批、SSE 审计之间的时序。

## 表达约束

- 标注当前实现、兼容过渡和待重跑状态，不将路线图能力画成已完成能力。
- 使用 Mermaid 作为源格式，便于 VuePress 渲染和汇报前导出 SVG/PNG。
- 图中不引入代码中不存在的组件名；关键节点使用仓库实际模块名。
- OpenClaw 原生审批是唯一决策入口，Guard 前端为只读同步和解释界面。

## 验收标准

- 四张图均能在 VuePress 文档中渲染。
- 图稿文档被架构索引和 VuePress sidebar 发现。
- OpenClaw 整合简报包含图稿入口、已实现边界、待重跑的 AgentDojo 说明和可直接复用的汇报口径。
- 文档构建和 diff 检查通过。
