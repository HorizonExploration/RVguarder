# OpenClaw-RVGuarder：自然语言驱动的自动机生成与运行时验证

> **归档状态（2026-08-28）：** 历史项目介绍；当前项目定位见 [`README.md`](../../README.md) 和 [`research/index.md`](../../research/index.md)。

> **面向 OpenClaw 智能体的运行时安全防护框架**
> 版本：v0.6.0（阶段 A–F 已全部落地） | 整理日期：2026-08-14
> 关联文档：[历史 NL→Automata 计划](./nl-automata-rv-upgrade-plan.md)、[工具对比](../../comparison/rvguard-vs-agent-security-tools.md)、[RV 层技术报告](../../architecture/rv-engine-report.md)

---

## 一、问题与核心思路

OpenClaw 等 AI Agent 框架赋予了大模型直接操作本地系统（文件、网络、应用）的能力——权限越高，潜在风险越大：恶意插件、越权操作、Prompt 注入、链式攻击、执行不透明、token 浪费。

传统防护（静态 Guardrails）的问题是**单步独立判定**：每次工具调用时单独检查"这一步是否违规"。这在单步违规场景（如直接 `rm -rf`）有效，但在链式攻击场景下完全失效——**每一步单独看都合法，串起来就是数据泄露**：

```
① file_read（打开外部附件）→ ALLOW
② file_read（提取客户数据）→ ALLOW
③ file_search（搜索通讯录）→ ALLOW
④ file_write（合并数据）→ ALLOW
⑤ mail_send（外发）→ ASK（用户大概率确认）→ 数据泄露
```

我们的核心思路是一条贯穿的升级线索：

> **自然语言输入 → 语义理解（NL2Spec）→ 受限规则匹配 → 自动生成自动机 → 运行时验证**

并贯穿一条不可动摇的设计原则：

> **LLM 提议，确定性引擎裁决** —— LLM 只负责提取意图与生成候选规约，所有生效判定由约束引擎与 FSM 监视器确定性执行（"概率组件不控制状态"）。

---

## 二、自然语言自动生成自动机（NL → Automata）

### 2.1 三模型融合自动机架构

| 模型 | 来源 | 方法 | 语义 | 维护 |
|---|---|---|---|---|
| **行为基线自动机（白）** | 审计日志 | φ 抽象 + 前缀树 + 状态合并 | 统计异常 | 自动更新 |
| **安全策略自动机（黑）** | `rv_rules.json` | `compile_monitors` 编译为 FSM | 规则违规 | 安全团队 |
| **NL2Spec 生成自动机（定制）** | 用户自然语言策略 | NL2Spec + Spec 校验 + 反例闭环 | 自定义安全策略 | 声明式管理 |

### 2.2 白模型：从审计日志自动学习 DFA（阶段 C）

不需要人工写规则，从正常会话 trace 自动学习"正常行为应该长什么样"：

1. **φ 确定性抽象**：`RvTraceStep` → `(event_type, entity_kind, label_class)` 三元组
2. **前缀树构建**：把正常 trace 组织为前缀树
3. **状态合并**：频率驱动 / EDSM 合并 → 紧凑 DFA
4. **运行时偏离检测**：`BaselineMonitor` 判定当前 trace 合法/偏离，返回 `(is_anomaly, current_state)`

关键特性：纯 Python 实现，收敛只需百分之几的训练数据（ASG 论文结论），自动机比原始 trace 小 1–3 个数量级。

### 2.3 黑模型：参数化策略自动机（阶段 D）

在 ChainRule FSM 基础上扩展三类受控原语：

- **QEA 式参数化切片**：`quantifier: forall/exists` + `bind_vars`，per-binding 独立 FSM 实例（如"对每个收件人独立检查"）
- **TAG 式时间原语**：`step_gap_within_seconds` / `step_gap_at_least_seconds`
- **实体级守卫**：`entity_any_of / entity_all_of`（domain_in / domain_not_in 等）+ `state_counter` 状态计数器

**关键设计**：守卫全部固化为受控原语——LLM 只能"选原语、填参数"，不开放自由逻辑。这是有实证依据的：文献表明 LLM 直接生成 guards 的准确率仅 F1=0.23，而受控原语规避了这个问题。

### 2.4 定制模型：NL2Spec 自动生成（阶段 E，核心能力）

用户用自然语言写安全策略（"含机密的日报禁止群发"），系统自动生成经过验证的监控器：

```
用户 NL 策略
   ↓ LLM QA 分解（提取意图与约束，不直接生成 JSON）
Q1 涉及哪些事件步骤？
Q2 有哪些实体约束？（收件人域名、文件路径、时间范围）
Q3 违规时 verdict 是什么？
   ↓ 确定性合成
ChainRule IR（Pydantic 校验）→ compile_monitors() → 合并进 rv_rules.json
   ↓ SpecValidator 反例闭环
语法校验 → 正/负例 trace 注入 → 冲突检测 → 失败则回喂 LLM 修正
   ↓ 直至 0 错误或达到最大轮次（人工介入兜底）
```

三大保障：
- **反例验证闭环**：生成规则必须通过正/负例 trace 库验证才生效（对标 AutoSafeLTL 的规约验证闭环）
- **来源回映射**：生成的规则标记 `origin: "nl2spec"` + `source_nl`，前端可展示"这条规则来自用户的哪句话"
- **经验模板库**：GuardAgent 式 memory——已验证规则入模板库，加速同类规则生成

---

## 三、受限自然语言规则（Restricted NL Rules）

我们刻意选择"受限"而非"自由"的自然语言规则，基于三条设计原则：

### 3.1 细粒度单一职责（scaling law 教训）

- 每个监视器规则 **≤5 步**，每个约束 **≤3 个实体条件**
- 依据：NL-to-LTL Scaling Law 研究——LLM 翻译精度随规约复杂度急剧衰减

### 3.2 守卫受控，不开放自由逻辑

- LLM 只从受控原语库中选择并填参（`entity_*` / `step_gap_*` / `state_counter` / `quantifier`）
- 直接生成 guards 的 LLM 准确率只有 F1=0.23，受控原语是可靠性的底线

### 3.3 确定性校验闭环，LLM 不直接产状态

- LLM 输出的是结构化 IR（QA 分解结果），ChainRule 由确定性代码合成
- SpecValidator 负责语法、反例注入、冲突检测、修正回环（带最大轮次保护）
- **原则：状态与生效判定永远不经过概率组件**

---

## 四、约束引擎规则匹配（Constraint Engine）

### 4.1 结构化 IR（阶段 A）：从"贴标签"到"完整语义模型"

升级前，语义层只输出扁平 labels，实体/约束/置信度在 `_build_rv_trace()` 中被直接丢弃。升级后：

`ToolCallIR` 携带 **11 字段完整语义模型**：

```
tool_name / arguments / permission_level（read_only/user/elevated/sudo）
side_effect（none/write_local/network_egress/config_mutate/destructive）
irreversibility / entities（kind/value/sensitivity）
constraints（time_range/scope/exclusion）
intent / confidence
```

所有新字段可选，`labels`/`props` 保留——完全向后兼容现有 47 条规则与 6 个监视器。

### 4.2 五类约束推理（阶段 B）：从"标签布尔交集"到"加权约束评分"

升级前：47 条规则本质是 `tag in labels` 的布尔交集——无法表达实体条件（如"收件人域名 != internal"）、无法利用置信度、无法跨事件关联。

升级后：`ConstraintEngine` 对每条 `ConstraintRule` 计算 **加权匹配分**：

| 约束类型 | 权重 | 示例 |
|---|---|---|
| ActionConstraint（动作类型） | 0.25 | 步骤 event ∈ 允许列表 |
| TagConstraint（标签） | 0.40 | 含 `external_recipient` 标签 |
| EntityConstraint（实体） | 0.35 | 收件人域名 ∈ 黑名单域 |
| SensitivityConstraint（敏感度） | — | 数据敏感级 ≥ confidential |
| TemporalConstraint（时序） | — | 窗口内步骤间隔 |

**置信度门控**（三档）：`confidence ≥ 0.8` 正常判定；`0.5–0.8` 降级（block→escalate, ask→verify）；`< 0.5` 回退保守策略。默认阈值 0.5，低置信度规则不参与判定。

### 4.3 渐进迁移与一致性保障

- 先迁移 10 条高频规则（CMD/FILE/NET），其余 37 条渐进替换
- 双定义并存期间，**一致性测试兜底**：`test_migrated_rules_align_with_detection` 断言两处定义逐字段对齐，任一漂移 CI 即失败
- 实测性能：约束引擎 **0.07ms/次**、RV 引擎 **0.08ms/次**（纯内存，无 LLM 调用）

### 4.4 五级干预（阶段 F）

决策从 4 级扩展为 **5 级**：`allow / ask / revise / escalate / block`

- **revise（新增）**：拒绝执行但附带修正建议（如"已移除外部收件人，是否发送仅内部版本？"），前端一键采用
- **会话级状态追踪** `SessionSafetyState`：per-session 风险分累积，连续 3 次 ask 自动升级 escalate，连续 escalate 升级 block

---

## 五、与同类型 AgentSpec / Guardrail 开源工具对比

### 5.1 最相近的学术工作：AgentSpec（ICSE 2026）

AgentSpec 的规则模型 **trigger（触发事件）→ predicate（谓词条件）→ enforcement（执行方式）** 与我们的 ChainRule FSM **高度同构**：

| 维度 | AgentSpec | OpenClaw-RVGuarder |
|---|---|---|
| 规则模型 | `rule @xx trigger X check P enforce E` | `chain_rules: {from, to, when, verdict}` |
| 谓词表达 | `is_destructive_cmd` 等硬编码谓词 | `all_of/any_of/none_of` + `entity_*`/`step_gap_*`/`state_counter` 受控原语 |
| 执行方式 | `user_inspection` / `llm_self_examine` / `invoke_action` | `allow/ask/revise/escalate/block` 五级 |
| LLM 生成规则 | OpenAI o1 自动生成（精度 95.56%） | NL2Spec QA 分解 + 确定性合成 + **反例验证闭环** |
| 时序/链式检测 | ❌ 单步判定 | ✅ FSM + 滑动窗口跨步链检测 |
| 跨会话状态 | ❌ 无 | ✅ per-session 风险累积 + 升级链 |
| 语义理解 | ❌ 谓词硬编码 | ✅ LLM + 本地双模式，7 维度标签 |
| 审计完整性 | ❌ | ✅ SHA-256 哈希链 + SQLite/JSONL 双写 |
| 审批工作台 | ❌ | ✅ 本地 Web UI + Trace Timeline |
| 运行时开销 | 谓词评估 1.11–2.83ms | 约束 0.07ms / RV 0.08ms（RV 判定零 LLM） |

**关键差异**：AgentSpec 证明了"LLM 自动生成规则"可行（95.56% 精度），这是我们的对标基准；但我们补上了 AgentSpec 没有的两块——**反例验证闭环**（生成规则必须通过正/负例 trace 验证才生效）和**跨步骤时序验证**（FSM 状态驱动，AgentSpec 是单步谓词判定）。

### 5.2 护栏 Agent 路线：GuardAgent（ICML 2025）

| 维度 | GuardAgent | OpenClaw-RVGuarder |
|---|---|---|
| 护栏形态 | 每次生成 Python 防护代码并执行 | 编译 ChainRule → FSM（提前编译好） |
| LLM 角色 | 任务规划 + 代码生成（每请求调用） | 语义标注 + 离线 NL2Spec 生成 |
| 运行时开销 | 代码生成 + 执行开销大 | RV 判定**零 LLM 调用** |
| 记忆机制 | 经验记忆模块（in-context retrieval） | ✅ 已借鉴：NL2Spec 内嵌已验证规则模板库 |

**同构关系**："代码即护栏"与"规约编译为 FSM"是同一思想的两种实现。我们胜在运行时零 LLM 调用（护栏提前编译），GuardAgent 胜在护栏形态无限灵活。

### 5.3 工业级框架：NVIDIA NeMo Guardrails / Guardrails AI

| 维度 | NeMo Guardrails | Guardrails AI | OpenClaw-RVGuarder |
|---|---|---|---|
| DSL | Colang（对话流建模） | RAIL 声明式 validator | ChainRule JSON（声明式 FSM 规约） |
| 护栏层次 | 5 层（输入/对话/检索/执行/输出） | 输出验证 | 工具调用执行路径 + 行为链 |
| 时序验证 | ❌ 无显式 FSM | ❌ | ✅ 滑动窗口 + FSM |
| 依赖 | NVIDIA NIM + GPU（重） | 轻 | 纯 Python + DeepSeek API（轻） |
| 定位 | 企业对话应用 | LLM 输出质量 | OpenClaw 个人办公工具链 |

**关系**：互补而非竞争。NeMo 的 Retrieval/Execution Rails 分层思想值得借鉴（我们目前只有执行路径护栏）；Guardrails AI 可接在回复扫描链路。

### 5.4 内容安全侧：Llama Guard / LlamaFirewall / Vigil

- **Llama Guard / LlamaFirewall**：分类模型直接判定文本 safe/unsafe——**内容侧**
- **Vigil**：Prompt 注入扫描（向量 + YARA + 分类器）——**输入侧**
- 共同点：只看**单条文本**，不看**动作序列**

**我们的差异化竞争力不在内容审核，而在跨步骤行为链的时序验证**——内容工具看单条文本，RVGuard 看整个动作序列（搜索→打包→外传 三步链）。

### 5.5 能力矩阵总览

| 能力 | RVGuard | AgentSpec | GuardAgent | NeMo | Guardrails AI | Llama Guard |
|---|---|---|---|---|---|---|
| 单步规则匹配 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 语义理解（LLM） | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ |
| **时序/链式检测** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| 会话级状态 | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ |
| 参数化/实体判定 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| LLM 自动生成规则 | ✅（+反例闭环） | ✅（95.56%） | ✅ | ❌ | ❌ | ❌ |
| **反例验证闭环** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| 审计链/哈希 | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ |
| 审批工作台 UI | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| 运行时开销 | 0.07–0.08ms（零 LLM） | 1.11–2.83ms | 高（代码生成） | 中（5 层检查） | 低 | 低（模型推理） |
| 平台绑定 | OpenClaw | 通用 | 通用 | 通用 | 通用 | 通用 |

---

## 六、落地效果与验证

### 6.1 必要性的实证：钓鱼邮件链式攻击

攻击者伪装合作方发送含隐藏 Sheet 的 Excel（内嵌"系统自动化指令"），AI 助手读取后把隐藏指令当作合法流程执行。**前 4 步单步全合法**，静态 Guardrails 全部放行；RV 引擎通过 FSM 状态追踪：

```
idle → external_source_read → sensitive_data_extracted → ... → blocked 🛑
```

状态跨步骤持久化，不管中间缺了哪一步、插入多少干扰事件，链一旦形成即被阻断。

### 6.2 测试与性能

- 全量回归：**340 passed / 18 skipped / 0 failed**
- 性能冒烟：约束引擎 0.07ms/次、RV 引擎 0.08ms/次、会话状态 1000 次 0.75ms
- 6 个办公场景 FSM 监视器 + 47 条单步规则 + 5 条办公策略 + 10 条约束规则
- AgentDojo 评测：语义层上线后强硬阻断率 0% → 30.1%，P95 延迟 4.37s → 3.25s（-25.5%）

---

## 七、结论

**OpenClaw-RVGuarder 不是通用 LLM 护栏的替代品，而是专注 OpenClaw 办公场景的深度安全治理层。**

我们的独特组合拳：

1. **NL → 自动机全链路**：用户自然语言策略 → LLM 提取意图 → 确定性合成 ChainRule → 反例验证闭环 → 编译为 FSM 监视器
2. **受限自然语言规则**：受控原语 + 细粒度单一职责 + "LLM 提议、确定性裁决"，兼顾灵活性与可靠性
3. **约束引擎**：五类约束加权匹配 + 三档置信度门控 + 渐进迁移，规则可解释、可验证、可审计
4. **差异化能力**：跨步骤时序验证（所有对比工具均为单步判定）、审计哈希链、审批工作台、办公场景专属策略

> 一句话：**Guardrail 检查"这一步有没有问题"，RVGuard 看"这几步串起来有没有问题"。**
