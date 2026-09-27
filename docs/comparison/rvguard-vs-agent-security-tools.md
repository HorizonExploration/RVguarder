# RVguarder vs 主流 Agent 安全工具对比分析

> 版本：v0.2 | 初稿日期：2026-08-05 | 当前复核：2026-09-09 | 状态：调研快照
> 关联文档：[RV 权限自动机架构](../architecture/rv-permission-automata.md)、[rv-engine-report.md](../architecture/rv-engine-report.md)

---

## 一、对比对象清单

| 工具 | 类型 | 核心机制 | 定位 |
|---|---|---|---|
| **RVguarder**（本项目） | 运行时验证插件 | Hook 拦截 + 语义理解 + PMKB 规则 + ChainRule DSL + 滑动窗口 | OpenClaw 办公场景专用 |
| **Guardrails AI** | 输出验证框架 | RAIL DSL 声明约束 + validators | LLM 输出结构化/质量 |
| **NVIDIA NeMo Guardrails** | 对话护栏框架 | Colang DSL + 5 层护栏（输入/对话/检索/执行/输出） | 企业对话应用 |
| **Llama Guard** | 内容安全分类器 | 微调分类模型，分类输入/输出是否 unsafe | 内容审核 |
| **AgentSpec** (ICSE 2026) | 运行时约束 DSL | trigger/predicate/enforcement 三要素规则 + ANTLR 解析 | 通用 LLM Agent |
| **GuardAgent** (ICML 2025) | 护栏 Agent | 知识驱动 LLM 生成护栏代码并执行 | 通用 LLM Agent |
| **Vigil** | Prompt 注入扫描 | 向量相似度 + YARA + 分类器多扫描器管线 | LLM 输入/输出检测 |
| **VIGIL** (verify-before-commit) | 工具流注入防御 | 验证-再提交协议，防止工具流注入 | Agent 工具调用链 |

---

## 二、逐项对比

### 2.1 与 AgentSpec 对比（最相近的学术工作）

AgentSpec（ICSE 2026，SMU）提出的规则三要素：**trigger（触发事件）→ predicate（谓词条件）→ enforcement（执行方式）**，与 RVGuard 高度同构：

| 维度 | AgentSpec | RVGuard（现状） | RVGuard（升级方向） |
|---|---|---|---|
| 规则模型 | `rule @xx trigger X check P enforce E` | `chain_rules: {from, to, when, verdict}` | 相同，扩 entity/时间原语 |
| 谓词表达 | `is_destructive_cmd`、`obstacle_distance_leq(n)` | `all_of/any_of/none_of` 标签集合 | 扩展 `entity_*` / `step_gap` / `state_counter` |
| 执行方式 | `user_inspection` / `llm_self_examine` / `invoke_action` | `allow/ask/block`（内部 `escalate` 仅升权） | 保持三态，完善证据可观测性 |
| LLM 生成规则 | OpenAI o1 自动生成规则（精度 95.56%） | 手写 `rv_rules.json` | NL2Spec 自动生成 + 反例验证闭环 |
| 跨会话状态 | 无（单步判定） | session 窗口 + 主体 `(principal, agent, lineage)` 成功证据 | 完善跨进程恢复与长期稳定性 |
| 性能 | 谓词评估 1.11-2.83ms | 窗口查询 ms 级 | 保持 |
| 与平台绑定 | 解耦（LangChain 等） | 深度绑定 OpenClaw Hook | 保持 |

**关键差距**：AgentSpec 已实现 **LLM 自动生成规则 + 谓词** 并用基准验证（生成规则在具身代理任务达到 95.56% 精度），这正是 RVGuard 的 NL2Spec 阶段（E）要做的。AgentSpec 的可验证成果可以直接作为我们的对标基准。

### 2.2 与 GuardAgent 对比（护栏 Agent 路线）

GuardAgent（ICML 2025）路线：**LLM 将安全请求转译为可执行护栏代码**，通过代码执行的确定性保证安全判定。

| 维度 | GuardAgent | RVGuard |
|---|---|---|
| 护栏形态 | 每次生成 Python 防护代码并执行 | 编译 ChainRule → `_SpecDrivenMonitor` |
| 确定性来源 | 代码执行天然确定 | DSL 状态迁移天然确定 |
| LLM 角色 | 任务规划 + 代码生成（每请求调用） | 语义标注（每事件调用）+ NL2Spec（离线生成规则） |
| 延迟 | 代码生成+执行开销大 | 语义标注一次，RV 判定零 LLM 调用 |
| 记忆机制 | 经验记忆模块（in-context retrieval） | 无（可借鉴） |
| 评测基准 | EICU-AC（98%）、Mind2Web-SC（83%） | 无正式基准（可借鉴） |

**关键差距**：GuardAgent 的"代码即护栏"思想与 RVGuard 的"规约编译为监视器"是同一思想的两种实现。RVGuard 优势是**运行时零 LLM 调用**（护栏提前编译好）；GuardAgent 优势是**护栏形态无限灵活**（代码能表达任何逻辑）。值得借鉴的点：GuardAgent 的 **memory-based in-context 演示检索** 可引入到 NL2Spec 生成器中，让 LLM 参考历史已验证的规则模板。

### 2.3 与 NeMo Guardrails 对比（工业级护栏框架）

NeMo（NVIDIA）是工业界最成熟的护栏框架，其 **Colang DSL** 与 RVGuard 的 ChainRule DSL 定位相似但更偏对话流控制。

| 维度 | NeMo Guardrails | RVGuard |
|---|---|---|
| DSL | Colang（Python 风格对话流建模） | ChainRule JSON（声明式时序规约） |
| 护栏层次 | 5 层：输入/对话/检索/执行/输出 | 单层：工具调用执行路径 |
| 语义匹配 | KNN 向量意图匹配（Colang 1.0） | LLM 语义标注（7 维度标签） |
| 时序能力 | 无显式状态时序验证 | 滑动窗口 + DSL 时序链 |
| 依赖 | NVIDIA NIM 微服务 + GPU 加速（重） | 纯 Python + DeepSeek API（轻） |
| 适用场景 | 企业客服/对话 | OpenClaw 个人办公工具链 |

**关键差距**：NeMo 的 **Retrieval Rails（检索护栏）** 和 **Execution Rails（执行护栏）** 分层思想值得借鉴——RVGuard 目前只有执行路径护栏，没有对 RAG 检索内容和工具输出的护栏层。

### 2.4 与 Guardrails AI / Llama Guard / Vigil 对比（内容与输出侧）

这三者是**内容侧**工具，与 RVGuard 的**行为侧**定位互补：

| 工具 | 检测对象 | 机制 | 与 RVGuard 关系 |
|---|---|---|---|
| Guardrails AI | LLM 输出 | RAIL 声明式 validator（类型/结构/安全） | 互补：可接在回复扫描链路 |
| Llama Guard | 输入/输出文本 | 分类模型直接判定 safe/unsafe | 互补：可替代部分规则匹配 |
| Vigil | Prompt/响应 | 向量+YARA+分类器多扫描器 | 互补：可增强 prompt injection 检测 |
| VIGIL (ACL 2026) | 工具流 | verify-before-commit 协议 | 同向：但聚焦注入防御而非时序链 |

**结论**：这些工具不构成直接竞争，而是**可组合的检测层**。RVGuard 的差异化竞争力不在内容审核（那是 Llama Guard 的地盘），而在**跨步骤行为链的时序验证**——内容工具只看单条文本，RVGuard 看的是整个动作序列。

---

## 三、能力矩阵总览

| 能力 | RVGuard | AgentSpec | GuardAgent | NeMo | Guardrails AI | Llama Guard |
|---|---|---|---|---|---|---|
| 单步规则匹配 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 语义理解（LLM） | ✅ | ❌（谓词硬编码） | ✅（代码生成） | ✅（意图匹配） | ❌ | ❌ |
| 时序/链式检测 | ✅（DSL 监视器+窗口） | ❌ | ❌ | ❌ | ❌ | ❌ |
| 会话级状态 | ✅ | ❌ | ❌ | ✅（对话流） | ❌ | ❌ |
| 参数化/实体判定 | ✅ | ✅（谓词参数） | ✅（代码任意） | ❌ | ❌ | ❌ |
| LLM 自动生成规则 | ❌（规划中） | ✅（95.56% 精度） | ✅ | ❌ | ❌ | ❌ |
| 反例验证闭环 | ✅（离线 SpecValidator） | ❌ | ❌ | ❌ | ❌ | ❌ |
| 审计链/哈希 | ✅ | ❌ | ❌ | ✅（对话日志） | ❌ | ❌ |
| 审批工作台 UI | ✅（Hook 只读同步，OpenClaw 原生审批） | ❌ | ❌ | ❌ | ❌ | ❌ |
| 平台绑定 | OpenClaw | 通用 | 通用 | 通用 | 通用 | 通用 |
| 运行时开销 | ms 级（RV 零 LLM） | ms 级（1.42ms 解析） | 高（代码生成） | 中（5 层检查） | 低 | 低（模型推理） |

---

## 四、本项目差异化定位

### 4.1 独有能力（其他工具没有）

1. **行为链时序验证**：滑动窗口 + ChainRule DSL 检测跨步骤攻击链（先搜索后删除、收集→打包→外传）。所有对比工具均为单步判定。
2. **审计链完整性**：SQLite + JSONL 双写 + 哈希链校验，符合企业合规要求。
3. **审批工作台**：本地 Web UI 动作级审批 + Trace Timeline 可视化。
4. **办公场景专属策略**：PMKB 35 条原生规则 + 47 条 LEGACY 回放记录，以及 DSL 生成监视器，针对 OpenClaw 个人办公场景深度定制。

### 4.2 需要补齐的差距（他山之石）

| 差距 | 对标工具 | 引入方式 |
|---|---|---|
| LLM 自动生成规则 | AgentSpec（95.56% 精度） | NL2Spec 阶段：QA 分解 + ChainRule 合成 + 反例验证 |
| 规则生成的经验记忆 | GuardAgent（memory-based in-context） | NL2Spec 生成器内嵌已验证规则模板库 |
| 检索/工具输出护栏 | NeMo（Retrieval/Execution Rails） | 扩展 RAG 内容来源可信度判定 |
| 正式评测基准 | AgentSpec（EICU-AC/Mind2Web-SC） | 建立 OpenClaw 办公场景攻击基准（正/负例 trace 库） |
| prompt injection 强化 | Vigil / VIGIL | 可在语义层补充注入检测扫描器（可选） |

---

## 五、结论

**RVGuard 不是通用 LLM 护栏的替代品，而是专注 OpenClaw 办公场景的深度安全治理层**：

- 与 AgentSpec 同类（规约驱动运行时约束），AgentSpec 的 LLM 规则生成成果可直接对标；
- 与 GuardAgent 同类（护栏即代码/规约），RVGuard 在运行时开销上有本质优势；
- 与 NeMo/Guardrails AI/Llama Guard 是互补关系（内容审核 vs 行为验证）。

未来发展的核心差异化路径已明确：**把 AgentSpec 证明可行的 LLM 规则生成 + GuardAgent 的记忆检索 + NeMo 的分层护栏思想，整合进现有的 ChainRule DSL 编译链**，形成"NL 策略 → 规约 → 运行时验证"的完整闭环。

---

## 六、参考资料

| 工具 | 参考来源 |
|---|---|
| AgentSpec | https://arxiv.org/pdf/2503.18666 （ICSE 2026） |
| GuardAgent | https://arxiv.org/abs/2406.09187 （ICML 2025，PMLR v267:68316-68342） |
| NeMo Guardrails | https://github.com/NVIDIA/NeMo-Guardrails |
| Guardrails AI | https://www.guardrailsai.com / https://github.com/guardrails-ai/guardrails |
| Llama Guard | https://arxiv.org/abs/2312.06674 |
| Vigil (prompt 扫描) | https://github.com/deadbits/vigil-llm |
| VIGIL (verify-before-commit) | https://arxiv.org/abs/2601.05755 （ACL 2026） |
