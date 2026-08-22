# 组会汇报：RV 升级方案落地——从调研到实现的完整闭环

> 承接文档上文《NL 驱动自动机生成与运行时验证升级方案》（v0.1，调研阶段）
> 汇报日期：2026-08-14 | 状态：阶段 A–F 已全部落地并通过审计整改

---

## 〇、汇报概览

上次汇报时，NL→Automata 升级方案还停留在"调研阶段"：引擎选型未定、LLM 生成规则只是设想、干预层缺 revise。本次汇报的内容是：**该方案已全部落地，并通过一次自审审计 + 当日整改闭环**。

围绕四个主题展开：

1. **自然语言自动生成自动机** —— 用户一句话策略 → 自动生成验证过的监控器
2. **受限自然语言规则** —— 为什么"受限"反而是可靠性的来源
3. **约束引擎规则匹配** —— 从"标签布尔交集"到"五类约束加权推理"
4. **同类型 AgentSpec / Guardrail 工具对比** —— 我们做了什么别人没做的事

---

## 一、自然语言自动生成自动机（NL → Automata）

### 1.1 为什么需要"自动生成自动机"

升级前的痛点：

- 6 个办公场景监视器全部**手写** `rv_rules.json`，安全策略每加一条都要人工编码
- 手写规约无法覆盖长尾策略（"含机密的日报禁止群发"这类用户自定义策略，只能等开发者排期）
- 没有人验证手写规约是否正确——写错了就是漏检或误报

升级线索（与上次汇报的目标架构一致）：

> **自然语言输入 → 语义理解（NL2Spec）→ 受限规则匹配 → 自动生成自动机 → 运行时验证**

### 1.2 三模型融合自动机架构

| 模型 | 来源 | 方法 | 语义 | 维护 |
|---|---|---|---|---|
| 行为基线自动机（白） | 审计日志 | φ 抽象 + 前缀树 + 状态合并 | 统计异常 | 自动更新 |
| 安全策略自动机（黑） | rv_rules.json | compile_monitors 编译 FSM | 规则违规 | 安全团队 |
| NL2Spec 生成自动机（定制） | 用户 NL 策略 | NL2Spec + Spec 校验 + 反例闭环 | 自定义策略 | 声明式管理 |

### 1.3 白模型：从审计日志自动学习 DFA（阶段 C）

不需要人工写规则，从正常会话 trace 学习"正常行为长什么样"：

1. **φ 确定性抽象**：`RvTraceStep → (event_type, entity_kind, label_class)` 三元组
2. **前缀树构建**：正常 trace 组织为前缀树
3. **状态合并**：频率驱动 / EDSM 合并 → 紧凑 DFA
4. **运行时偏离检测**：`BaselineMonitor` 返回 `(is_anomaly, current_state)`

关键特性：纯 Python 实现（不引入 AALpy）；收敛只需百分之几的正常会话数据（ASG 论文结论）；自动机比原始 trace 小 1–3 个数量级。

### 1.4 黑模型：参数化策略自动机（阶段 D）

在 ChainRule FSM 上扩展三类**受控原语**：

- **QEA 式参数化切片**：`quantifier: forall/exists` + `bind_vars`，per-binding 独立 FSM 实例（如"对每个收件人独立检查"）
- **TAG 式时间原语**：`step_gap_within_seconds` / `step_gap_at_least_seconds`
- **实体级守卫 + 状态计数器**：`entity_any_of / entity_all_of`、`state_counter {var, op, threshold}`

> 关键设计：守卫全部固化为受控原语——LLM 只能"选原语、填参数"，不开放自由逻辑。实证依据：LLM 直接生成 guards 准确率仅 F1=0.23（SMF 论文），受控原语从机制上规避此问题。

### 1.5 定制模型：NL2Spec 自动生成（阶段 E，核心能力）

用户用自然语言写策略，系统自动生成**经过验证**的监控器：

```
用户 NL 策略（"含机密的日报禁止群发"）
  ↓ LLM QA 分解（只提取意图与约束，不直接生成 JSON）
  Q1 涉及哪些事件步骤？
  Q2 有哪些实体约束？（收件人域名 / 文件路径 / 时间范围）
  Q3 违规时 verdict 是什么？
  ↓ 确定性合成
  ChainRule IR（Pydantic 校验）→ compile_monitors() → 合并进 rv_rules.json
  ↓ SpecValidator 反例闭环
  语法校验 → 正/负例 trace 注入 → 冲突检测 → 失败回喂 LLM 修正
  ↓ 直至 0 错误或达到最大轮次（人工介入兜底）
```

三大保障：

- **反例验证闭环**：生成规则必须通过正/负例 trace 库验证才生效（对标 AutoSafeLTL 的验证闭环）
- **来源回映射**：生成规则标记 `origin: "nl2spec"` + `source_nl`，前端可展示"这条规则来自哪句话"
- **经验模板库**：GuardAgent 式 memory，已验证规则入模板库，同类规则生成加速

### 1.6 里程碑推进

```
v0.3.0（ChainRule 规约驱动）
  → v0.4.0 ✅ IR 结构化 + 约束推理引擎 + 置信度门控（阶段 A/B）
  → v0.5.0 ✅ 基线自动机 + 参数化监视器（阶段 C/D）
  → v0.6.0 ✅ NL2Spec 生成 + 反例闭环 + revise 干预 + 会话状态（阶段 E/F）
```

---

## 二、受限自然语言规则（Restricted NL Rules）

### 2.1 为什么是"受限"而不是"自由"

直觉上，"自由自然语言 → 任意逻辑"最灵活，但两个实证教训否定了它：

- **LLM 直接生成 guards 的准确率只有 F1=0.23**（Structure/Event-Driven SMF 论文）：让 LLM 写条件逻辑，大部分是错的
- **NL-to-LTL Scaling Law**：LLM 翻译精度随规约复杂度急剧衰减，规则越长越不可靠

所以我们的设计是**在灵活性与可靠性之间取受控点**：

| 约束维度 | 限制 | 依据 |
|---|---|---|
| 步数 | 每个监视器规则 ≤5 步 | scaling law：复杂度衰减 |
| 实体条件 | 每个约束 ≤3 个实体条件 | scaling law |
| 逻辑形态 | 只能选受控原语填参（entity_* / step_gap_* / state_counter / quantifier） | F1=0.23 教训 |
| 产出路径 | LLM 只出结构化 IR，ChainRule 由确定性代码合成 | 概率组件不控制状态 |

### 2.2 规则的声明式形态

ChainRule 是 JSON 声明式规约，人可读、机器可执行：

```json
{
  "chain_rules": [{
    "from": "sensitive_data_extracted",
    "to": "mail_send",
    "when": { "all_of": ["external_recipient"] },
    "verdict": "block"
  }]
}
```

### 2.3 反例验证闭环（可靠性的底线）

- 正/负例 trace 库（办公场景各 ≥5 条）作为持续回归基准
- SpecValidator：语法校验 + 反例注入 + 冲突检测 + 修正回环（最大轮次保护）
- **LLM 生成 → 确定性验证 → 不合格回炉重生成**，直至收敛或人工介入

### 2.4 可追溯性

每条生成规则带 `origin` + `source_nl` 元数据，审计与前端展示都能回答"这条规则为什么存在、来自哪句自然语言"。

---

## 三、约束引擎规则匹配（Constraint Engine）

### 3.1 升级前后对比

| 维度 | 升级前 | 升级后 |
|---|---|---|
| 输入 | 扁平 labels 标签 | ToolCallIR（11 字段结构化语义模型） |
| 匹配 | `tag in labels` 布尔交集 | 五类约束加权评分 |
| 置信度 | 无 | 三档门控（默认阈值 0.5） |
| 表达力 | 无法表达实体条件 | 实体 / 敏感度 / 时序约束 |
| 决策 | 4 级 | 5 级（新增 revise） |

### 3.2 ToolCallIR：从"贴标签"到"完整语义模型"（阶段 A）

```
tool_name / arguments / permission_level（read_only/user/elevated/sudo）
side_effect（none/write_local/network_egress/config_mutate/destructive）
irreversibility / entities（kind/value/sensitivity）
constraints（time_range/scope/exclusion）/ intent / confidence
```

所有新字段可选，`labels`/`props` 保留——**完全向后兼容**现有 47 条规则与 6 个监视器。

### 3.3 五类约束与加权评分（阶段 B）

| 约束类型 | 权重 | 示例 |
|---|---|---|
| ActionConstraint（动作类型） | 0.25 | 步骤 event ∈ 允许列表 |
| TagConstraint（标签） | 0.40 | 含 external_recipient 标签 |
| EntityConstraint（实体） | 0.35 | 收件人域名 ∈ 黑名单域 |
| SensitivityConstraint（敏感度） | — | 数据敏感级 ≥ confidential |
| TemporalConstraint（时序） | — | 窗口内步骤间隔 |

规则升级示例（NET-005）：从"标签匹配"升级为"动作约束 + 敏感度约束（min_level=confidential）+ 实体约束（domain_not_in 白名单）+ verdict=block"。

### 3.4 置信度三档门控

- `confidence ≥ 0.8`：正常判定
- `0.5 ~ 0.8`：降级处理（block→escalate, ask→verify）
- `< 0.5`：回退保守策略

> 审计发现原默认值 0.0 导致门控形同虚设，已修复为默认 0.5（P0 整改，当日闭环）。

### 3.5 渐进迁移与一致性保障

- 先迁移 10 条高频规则（CMD/FILE/NET），其余 37 条渐进替换
- 双定义并存期由**一致性测试兜底**：`test_migrated_rules_align_with_detection` 断言两处定义逐字段对齐，漂移即 CI 失败
- 实测性能：约束引擎 **0.07ms/次**、RV 引擎 **0.08ms/次**（纯内存，RV 判定零 LLM 调用）

### 3.6 五级干预 + 会话状态（阶段 F）

- 决策从 4 级扩展为 5 级：`allow / ask / revise / escalate / block`
- **revise（新增）**：拒绝执行但附带修正建议（"已移除外部收件人，是否发送仅内部版本？"），前端一键采用
- **SessionSafetyState**：per-session 风险分累积 + 升级链（连续 3 次 ask → escalate，连续 escalate → block）

---

## 四、同类型 AgentSpec / Guardrail 开源安全工具对比

### 4.1 对比对象全景

| 工具 | 类型 | 核心机制 | 定位 |
|---|---|---|---|
| OpenClaw-RVGuarder（本项目） | 运行时验证插件 | Hook 拦截 + 语义理解 + 约束推理 + FSM + 滑动窗口 | OpenClaw 办公场景专用 |
| AgentSpec（ICSE 2026） | 运行时约束 DSL | trigger → predicate → enforcement 三要素 + ANTLR 解析 | 通用 LLM Agent |
| GuardAgent（ICML 2025） | 护栏 Agent | LLM 生成护栏代码并执行 + 经验记忆 | 通用 LLM Agent |
| NeMo Guardrails（NVIDIA） | 对话护栏框架 | Colang DSL + 5 层护栏 | 企业对话应用 |
| Guardrails AI | 输出验证框架 | RAIL DSL + validators | LLM 输出结构化/质量 |
| Llama Guard / LlamaFirewall（Meta） | 内容安全分类器 | 微调模型判定 unsafe | 内容审核 |
| Vigil / VIGIL | 注入扫描 | 向量 + YARA + 分类器 | 输入/输出检测 |

### 4.2 AgentSpec（最相近的学术工作）

AgentSpec 规则模型：`rule @xx trigger X check P enforce E`——与我们 ChainRule FSM **高度同构**。

| 维度 | AgentSpec | RVGuard |
|---|---|---|
| 规则模型 | trigger→predicate→enforcement | chain_rules: {from, to, when, verdict} |
| 谓词表达 | 硬编码谓词（is_destructive_cmd 等） | 受控原语（entity_* / step_gap_* / state_counter） |
| 执行方式 | user_inspection / llm_self_examine / invoke_action | allow / ask / revise / escalate / block |
| LLM 生成规则 | OpenAI o1 生成，精度 95.56% | NL2Spec QA 分解 + 确定性合成 + **反例验证闭环** |
| 时序/链式检测 | ❌ 单步判定 | ✅ FSM + 滑动窗口跨步链检测 |
| 跨会话状态 | ❌ 无 | ✅ per-session 风险累积 + 升级链 |
| 语义理解 | ❌ 谓词硬编码 | ✅ LLM + 本地双模式，7 维度标签 |
| 审计完整性 | ❌ | ✅ SHA-256 哈希链 + 双写 |
| 审批工作台 | ❌ | ✅ 本地 Web UI + Trace Timeline |
| 运行时开销 | 谓词评估 1.11–2.83ms | 约束 0.07ms / RV 0.08ms（判定零 LLM） |

**我们补上了 AgentSpec 没有的两块**：① 反例验证闭环（生成规则必须通过正/负例验证才生效）；② 跨步骤时序验证（AgentSpec 是单步谓词判定，无法检测"搜索→打包→外传"三步链）。

### 4.3 GuardAgent（护栏 Agent 路线）

- "代码即护栏"与"规约编译为 FSM"是同一思想的两种实现
- 我们胜在**运行时零 LLM 调用**（护栏提前编译好，判定零推理）；GuardAgent 每请求代码生成，开销大
- 借鉴点：GuardAgent 的 memory-based 经验检索 → 已引入 NL2Spec 模板库

### 4.4 NeMo / Guardrails AI / Llama Guard / Vigil

- **NeMo**：5 层护栏分层思想可借鉴（我们目前只有执行路径护栏，RAG 检索护栏是扩展方向）；但依赖 NVIDIA NIM + GPU，重
- **Guardrails AI**：输出侧 validator，可接回复扫描链路，互补
- **Llama Guard / Vigil**：内容侧单条文本判定，与我们的行为侧互补——内容工具看"这句话安全吗"，我们看"这个动作序列安全吗"

### 4.5 能力矩阵与差异化定位

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
| 运行时开销 | 0.07–0.08ms | 1.11–2.83ms | 高 | 中 | 低 | 低（模型推理） |

**差异化定位**：RVGuard 不是通用 LLM 护栏的替代品，而是**专注 OpenClaw 办公场景的深度安全治理层**——把 AgentSpec 证明可行的 LLM 规则生成、GuardAgent 的记忆检索、NeMo 的分层思想，整合进 ChainRule FSM 引擎，形成"NL 策略 → 自动机 → 运行时验证"的完整闭环。

> **一句话：Guardrail 检查"这一步有没有问题"，RVGuard 看"这几步串起来有没有问题"。**

---

## 五、落地效果与数据

- 全量回归：**340 passed / 18 skipped / 0 failed**（较 v0.3.0 基线 +9 用例）
- 性能冒烟：约束引擎 0.07ms/次、RV 引擎 0.08ms/次、会话状态 1000 次 0.75ms
- 自审审计：发现 7 处"验收标准打折"（3 High），**当日 P0→P1→P2 全部整改闭环**
- AgentDojo 评测（语义层上线时）：强硬阻断率 0% → 30.1%，P95 延迟 4.37s → 3.25s（-25.5%）
- 钓鱼邮件实证：外部附件 → 提取敏感数据 → 外发，FSM 状态跨步持久化，链形成即 block

---

## 六、下一步计划

| 优先级 | 事项 | 说明 |
|---|---|---|
| P0 | 审计存储迁移 SQLite 表 | controlled-actions.json 独立存储绕过哈希链；双轨不同步（文档已建议，未做） |
| P1 | 对比实验 v2.0 落地 | test_rv_vs_static_experiment.py：5 实验组 25+ 用例（方案已设计，未实现） |
| P1 | 前端首屏体积优化 | 61KB JS → 目标 20KB gzip 内 |
| P1 | 双轨 HTTP 收敛 | 默认切 FastAPI，冻结 legacy_web |
| P2 | 约束引擎替换全部 47 条 lambda | 当前 10 条已迁移 |
| P3 | Spot 离线增强 | 用 LTL 验证手写 FSM 正确性（可选） |

---

## 附：汇报口径速查

- **30 秒版**：我们把"自然语言安全策略"自动变成了"验证过的监控自动机"，约束引擎做加权推理，置信度门控兜底，revise 干预带修正建议；对比 AgentSpec 等工具，我们独有跨步骤时序验证 + 反例验证闭环 + 审计链。
- **3 分钟版**：讲 1.5（NL2Spec 流程）+ 3.3（约束引擎）+ 4.2（AgentSpec 对比表）+ 钓鱼邮件实证。
- **10 分钟版**：按正文顺序过一遍，重点停在 1.5 / 二 / 3.4 / 4.5。
