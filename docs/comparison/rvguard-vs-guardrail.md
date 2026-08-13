# OpenClaw-RVGuarder vs Guardrail 对比分析

## 一、定位与设计理念

**Guardrail（以 Invariant Labs 为代表）：**
- 定位是通用 LLM Agent 安全防护层，面向任何 LLM 应用
- 核心机制：在 LLM 调用前插入 Policy Services 层，对 Trace 进行规则检查
- 特征：与具体平台解耦，适用于多种 Agent 框架

**OpenClaw-RVGuarder（本项目）：**
- 定位是 OpenClaw 专属的非侵入式安全增强客户端
- 核心机制：通过 OpenClaw 原生 Hook 接入 before_tool_call / after_tool_call，在不修改 OpenClaw 源码的前提下执行安全决策
- 特征：深度绑定 OpenClaw 生态，提供从基线扫描 → 语义理解 → 执行前审批 → 运行时验证 → 审计追溯的完整闭环

**核心差异：** Guardrail 是通用防护层（偏策略引擎），RVGuard 是面向特定平台的深度安全插件（偏全链路治理）。

## 二、架构对比

**Guardrail 架构：**
- User → Gateway → API → Analysis / Policy Services → LLM
- 在 LLM 调用层的上游做规则检查
- 规则由开发者预定义，以 DSL 或 JSON 表达

**RVGuard 架构：**
- User → OpenClaw → Guard Hook → SemanticEnhancer → DetectionEngine → RuntimeVerificationEngine → GuardController → 执行/阻断
- 深度嵌入 OpenClaw 工具调用的执行路径
- 三层决策：语义层（意图理解）+ 规则层（47条规则）+ RV层（6个FSM监视器）

## 三、安全能力对比

**【单步规则检测】**
- Guardrail: ✅ 支持，基于预定义规则
- RVGuard: ✅ 支持，47条语义标签规则 + 5条办公策略

**【语义理解】**
- Guardrail: ❌ 主要依赖关键词/正则匹配
- RVGuard: ✅ 双模式语义增强（LLM模式 + 本地规则化降级），7维度标签体系

**【链式/时序检测】**
- Guardrail: ❌ 单步独立判定，无法检测跨步骤组合攻击
- RVGuard: ✅ 滑动窗口 + 6个FSM监视器，支持多种时序模式
  - 先搜索后删除链
  - 先关闭审计后改配置链
  - 收集→打包→外传三步链

**【约束保真】**
- Guardrail: ❌ 不验证自然语言约束是否在Trace中保留
- RVGuard: ✅ 语义层提取约束条件（排除项、时间范围、作用域），缺失时自动升级为 ask

**【基线扫描与审计】**
- Guardrail: ❌ 不提供
- RVGuard: ✅ SQLite + JSONL 双写审计链 + 哈希完整性校验 + JSON/CSV 导出

**【用户审批工作台】**
- Guardrail: ❌ 无前端界面
- RVGuard: ✅ 本地 Web 工作台，支持动作级审批、状态可视化、Trace Timeline

**【非侵入性】**
- Guardrail: ✅ 不修改下游代码
- RVGuard: ✅ 不修改 OpenClaw 源码，通过 Hook 机制接入

## 四、典型攻击场景对比——钓鱼邮件

在隐蔽指令注入的钓鱼邮件场景中：
- Guardrail：每一步独立判定 ALLOW/ASK，用户在第⑤步确认后数据仍会泄露
- RVGuard：语义层标记文件来源为不可信 + 检测敏感数据 → RV 引擎滑动窗口识别"不可信来源→读取敏感数据→外传"时序模式 → 自动 BLOCK，无需用户判断

结论：RVGuard 的时序检测能力使其在链式攻击场景下具有本质性的安全优势。

---

# 未来发展方向

## 近期（1-2个月）
- P0 场景全量覆盖：消息群发/广播、数据库导出、文件批量操作的业务规则完善与测试
- 审计存储重构（已落地）：动作/审计存储已迁移到 SQLite 表（`openclaw_guard/storage/db_store.py` 的 `SQLiteStore`，可选 `SQLAlchemyStore`），统一哈希链保护
- 前端页面补齐：安全规则管理页面 UI 开发、分页/无限滚动机制
- P1 场景开发：文档外发、代提交审批、代码推送等 6 个场景的监视器开发
- 依赖声明完善：在 pyproject.toml 中完整声明 Python 依赖

## 中期（3-6个月）
- 用户自定义规则系统：自然语言规则 → LLM 结构化提取 → 用户确认 → 写入 policies/
- Back-Translation 验证层：将 Trace 反向重写为自然语言，与原始输入对比，检测约束丢失
- DSL 语法设计（已落地）：JSON 规则模板已过渡到 `openclaw_guard/rv/rv_dsl.py`，即当前默认的 `dsl` 规则驱动模式
- RV 规约自动生成（已规划）：NL2Spec 管线（QA 分解 + ChainRule 合成 + 反例验证），详见 [nl-automata-rv-upgrade.md](../research/nl-automata-rv-upgrade.md)
- 多 Agent 协作场景支持：跨 Agent Trace 的联合时序验证

## 远期（6-12个月）
- 自适应规则学习：RV 命中违规窗口时，自动抽取共性模式生成候选规则
- 龙虾盒子原生集成：作为 OpenClaw 硬件的预装安全组件
- 社区规则市场：用户可分享/下载办公场景安全规则包
- 多平台支持：从 OpenClaw 扩展到其他 Agent 框架（LangChain、AutoGPT 等）
- 形式化验证报告：每次执行后生成 Trace 级别的安全证明

---

RVGuard 的目标不是替换 Guardrail，而是在 Guardrail 的通用策略层之上，构建一层面向特定平台的深度安全治理层——从策略到执行、从单步到时序、从检测到审计的完整闭环。
