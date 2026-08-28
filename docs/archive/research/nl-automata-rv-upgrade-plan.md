# NL 驱动自动机生成与运行时验证 · 分阶段实施升级计划

> **归档状态（2026-08-28）：** 已完成的早期 NL→Automata 计划；当前 RV 事实见 [`architecture/rv-engine-report.md`](../../architecture/rv-engine-report.md)。

> 版本：v1.0 | 日期：2026-08-11 | 状态：**已完成**  
> 关联文档：[rvguard-vs-agent-security-tools.md](../../comparison/rvguard-vs-agent-security-tools.md)（对比）、[rv-engine-report.md](../../architecture/rv-engine-report.md)（技术报告）、[roadmap.md](../../ops/roadmap.md)（路线图）

---

## 一、调研结论总结

### 1.1 近期调研确认的方向

1. **不走 LTL 路线**：LTL 语义基于无限序列（ω-自动机），与有限滑窗场景不匹配；参数绑定有组合爆炸风险；引入 Spot/Owl 破坏轻量纯 Python 定位。**保留现有 ChainRule FSM 引擎，扩展其规约来源与表达能力。**
2. **核心升级线索**：`自然语言输入 → 语义理解（NL2Spec）→ 受限规则匹配 → 自动生成自动机 → 运行时验证`。
3. **三层现状差距**：
   - 语义理解：LLM 已提取 entities/constraints/confidence 但被丢弃，`rv_trace` 只传扁平 `props` 标签
   - 规则匹配：47 条 `tag in labels` 布尔 lambda，无实体/敏感度/时序/置信度判定
   - RV 引擎：手写 `rv_rules.json`，无参数化切片，无自动生成，无反例验证闭环
4. **对标工具确认**：AgentSpec（ICSE 2026）证明 LLM 生成规则精度可达 95.56%；GuardAgent（ICML 2025）证明"护栏即规约"确定性执行；NeMo/Guardrails AI/Llama Guard 为内容侧互补工具。

### 1.2 当前 v0.3.0 已完成（12 项里程碑）

语义理解（v0.2.0）→ 办公规则 → 原生钩子拦截 → 双端同步 → 熔断器 → RV 6 监视器 → 前端 RV 面板 → FastAPI 层 → Pydantic v2 → 旧版 HTTP 保留 → SQLAlchemyStore 可选存储 → **ChainRule 规约驱动（v0.3.0）**

### 1.3 待补齐差距（来自对比分析）

| 差距 | 对标 | 引入方式 |
|---|---|---|
| LLM 自动生成规则 | AgentSpec | NL2Spec：QA 分解 + ChainRule 合成 + 反例验证 |
| 规则生成经验记忆 | GuardAgent | NL2Spec 生成器内嵌已验证规则模板库 |
| 检索/工具输出护栏 | NeMo | 扩展 RAG 内容来源可信度判定 |
| 正式评测基准 | AgentSpec | 建立办公场景攻击基准（正/负例 trace 库） |
| prompt injection 强化 | Vigil / VIGIL | 语义层补充注入检测（可选） |

---

## 二、分阶段实施计划总览

| 阶段 | 版本 | 主题 | 核心交付 | 依赖 | 对标 | 状态 |
|---|---|---|---|---|---|---|---|
| **A** | v0.4.0 | IR 结构化 | ToolCallIR + 语义层透传实体/约束/置信度 | 无 | NEXUS | ✅ |
| **B** | v0.4.0 | 约束推理引擎 | ConstraintRule DSL + 替换 47 条 lambda + 置信度门控 | A | G-SPEC | ✅ |
| **C** | v0.5.0 | RV 基线自动机 | BaselineLearner（φ抽象+前缀树+合并）+ 偏离检测 | A | ASG | ✅ |
| **D** | v0.5.0 | RV 参数化 | QEA 式 bind_vars + entity 守卫 + step_gap 时间原语 | A | MARQ / TAG | ✅ |
| **E** | v0.6.0 | NL2Spec 生成 | Nl2SpecGenerator + SpecValidator 反例闭环 | D | NL2Spec / AutoSafeLTL | ✅ |
| **F** | v0.6.0 | 干预升级 | revise 干预 + SessionSafetyState 会话追踪 | B | NEXUS / IntentionReasoner | ✅ |

> 与 roadmap P0/P1 并行维护项：RV 状态持久化、熔断器告警、审计日志轮转 —— 穿插在各阶段间完成，不单独成阶段。

---

## 三、阶段详述

### 阶段 A：IR 结构化（v0.4.0，先导阶段）

**目标**：让"实体/约束/置信度"不再在语义层被丢弃，为规则匹配与 RV 提供结构化输入。

| 任务 | 说明 | 验收标准 |
|---|---|---|
| A1. 定义 ToolCallIR 数据模型 | `rv/ir.py`：tool_name/arguments/permission_level/side_effect/sensitivity/irreversibility/entities/constraints/intent/confidence + 兼容 `labels`/`rv_props` | Pydantic/`@dataclass` 模型可实例化，字段齐全 |
| A2. 改造 semantic_enhancer prompt | 要求 LLM 输出结构化 JSON（而非仅 labels），few-shot 示例保证一致 | LLM 模式输出通过 schema 校验，失败回退本地规则 |
| A3. 透传 rv_trace 实体/约束 | `_build_rv_trace()` 输出 `RvTraceStep`（含 entities/constraints/confidence） | 现有 6 个监视器兼容（props 保留），新增字段可用 |
| A4. 单元测试 | `tests/test_ir.py` + 现有 semantic 测试回归 | 全部通过，无新增失败 |

**关键设计**：所有新字段可选，`labels`/`props` 保留 —— 向后兼容现有 47 条规则与 6 个监视器。

---

### 阶段 B：约束推理引擎（v0.4.0）

**目标**：将规则匹配从"标签布尔交集"升级为"四类约束推理 + 置信度门控"。

| 任务 | 说明 | 验收标准 |
|---|---|---|
| B1. 定义 ConstraintRule/EntityConstraint/SensitivityConstraint/TemporalConstraint | `rv/constraints.py`，对应 G-SPEC 四类约束 | 模型可解析 JSON/直接实例化 |
| B2. 实现 ConstraintEngine | `_match_score` 加权计算 + `confidence_threshold` 门控 | 命中规则返回 (rule, score)，低于阈值不命中 |
| B3. 迁移高频规则 | 先迁移 10 条高频规则（CMD/FILE/NET），剩余 37 条渐进 | 迁移规则行为与旧 lambda 一致（对既有测试集） |
| B4. 置信度门控决策 | confidence≥0.8 正常判定 / 0.5-0.8 降级 / <0.5 保守回退 | 门控逻辑单测覆盖三档 |
| B5. 回归测试 | `tests/test_constraints.py` + `test_detection.py` 全量 | 无回归 |

**关键设计**：ConstraintEngine 与现有 DetectionEngine 并存过渡，`rv_rule_mode` 环境变量控制启用。

---

### 阶段 C：RV 基线自动机（v0.5.0）

**目标**：从审计日志自动学习"正常办公行为 DFA"，提供统计异常检测（白模型）。

| 任务 | 说明 | 验收标准 |
|---|---|---|
| C1. trace 抽象器 | `rv/trace_abstractor.py`：RvTraceStep → `(event_type, entity_kind, label_class)` 三元组 | 抽象函数单测覆盖各场景 |
| C2. 前缀树 + 状态合并 | `rv/baseline_learner.py`：前缀树构建 + 频率驱动合并（EDSM 备选） | 输出紧凑 DFA，比原始 trace 小 1 个数量级 |
| C3. 运行时偏离检测 | `rv/baseline_monitor.py`：DFA 判定当前 trace 合法/偏离 | 偏离时返回 (is_anomaly, current_state) |
| C4. 离线训练脚本 | `scripts/train_baseline.py`：审计日志 → 基线自动机序列化 | 训练/加载/序列化闭环可用 |
| C5. 测试 | `tests/test_baseline_learner.py` | 正例 trace 全接受，构造反例偏离被检出 |

**关键设计**：纯 Python 实现（不引入 AALpy 外部依赖），收敛只需少量正常会话 trace（ASG 论文：百分之几数据）。

---

### 阶段 D：RV 参数化（v0.5.0）

**目标**：让现有 ChainRule FSM 支持实体绑定、时间窗口与状态计数器。

| 任务 | 说明 | 验收标准 |
|---|---|---|
| D1. QEA 式 bind_vars | `rv_rules.json` 支持 `quantifier: forall/exists` + `bind_vars`，WindowManager 按绑定切片 | per-binding 独立 FSM 实例，量化判定正确 |
| D2. entity 级守卫 | StepRequirement 支持 `entity_any_of/entity_all_of`（domain_in/domain_not_in 等） | 实体条件参与步骤匹配 |
| D3. 时间原语 | `step_gap_within_seconds` / `step_gap_at_least_seconds` | 时间窗约束生效 |
| D4. 状态计数器 | `state_counter: {var, op, threshold}` 守卫 | FSM 可记忆累积量（如敏感文件数≥3） |
| D5. 测试 | `tests/test_rv_dsl_ext.py` + `test_rv.py` 回归 | 新增原语用例全过，旧用例无回归 |

**关键设计**：守卫全部固化为受控原语（LLM 只选原语填参数），不开放自由逻辑 —— 规避 LLM 生成 guards 低准确率（F1=0.23）问题。

---

### 阶段 E：NL2Spec 生成（v0.6.0，核心能力）

**目标**：用户自然语言安全策略 → LLM QA 分解 → ChainRule 合成 → 反例验证闭环 → 合并 rv_rules.json。

| 任务 | 说明 | 验收标准 |
|---|---|---|
| E1. QA 分解翻译器 | `spec/nl2spec_generator.py`：Q1 事件步骤 / Q2 实体约束 / Q3 verdict → 结构化 IR | 输出 IR 通过 Pydantic 校验 |
| E2. ChainRule 合成器 | IR → Ruleset 编译（复用 `compile_monitors`） | 生成规则可被现有引擎执行 |
| E3. SpecValidator | 语法校验 + 反例注入（正/负例 trace 库） + 冲突检测 | 漏报/误报自动识别并生成修正 prompt |
| E4. 反例循环修正 | 反例 → 回喂 LLM → 再验证，直至 0 错或人工介入 | 迭代收敛，有最大轮次保护 |
| E5. 经验模板库 | GuardAgent 式 memory：已验证规则入模板库，加速同类规则生成 | 模板检索命中率 >50% |
| E6. 规则来源标记 | 生成的规则 `origin: "nl2spec"` + `source_nl` 回映射 | 前端可展示"规则来自哪句话" |
| E7. 测试 + 基准 | `tests/test_nl2spec.py` + 办公场景攻击基准（正/负例 trace 库） | 对标 AgentSpec：生成规则精度 >90% |

**关键设计**：LLM 不直接生成 JSON —— 只负责提取意图与约束（QA 分解），确定性代码合成 ChainRule。遵循"概率组件不控制状态"原则。

---

### 阶段 F：干预升级（v0.6.0）

**目标**：干预从 4 级到 5 级（新增 revise），会话级风险状态追踪。

| 任务 | 说明 | 验收标准 |
|---|---|---|
| F1. revise 干预 | `Verdict(action="revise", revision_hint)` —— 拒绝 + 修改建议 | 前端展示修正建议，用户可一键采用 |
| F2. SessionSafetyState | 会话级 risk_score / blocked_count / escalation_level / 干预历史 | 连续 ask 自动升级 escalate，连续 escalate 升级 block |
| F3. 前端适配 | 工作台支持 revise 交互 + 会话状态展示 | UI 单测通过 |
| F4. 测试 | `tests/test_intervention.py` | 升级链逻辑全覆盖 |

---

## 四、里程碑与版本规划

```
v0.3.0（当前）═══════════▶  v0.4.0 ✅  ═══════════▶  v0.5.0 ✅  ═══════════▶  v0.6.0 ✅
 ChainRule 规约驱动         IR 结构化            RV 基线 + 参数化       NL2Spec + 干预升级
                           + 约束推理引擎        （白模型 + QEA/TAG）   + 反例验证闭环
                           + 置信度门控          + 时间原语
```

| 版本 | 里程碑 | 可交付验收 |
|---|---|---|
| v0.4.0 | 语义理解 + 规则匹配升级 | 结构化 IR 全链路透传；约束引擎上线；无回归 |
| v0.5.0 | RV 自动机升级 | 基线自动机偏离检测可用；参数化监视器（实体/时间/计数）可用 |
| v0.6.0 | NL2Spec + 干预闭环 | NL 策略一键生成已验证规则；revise 干预 + 会话状态 |

---

## 五、风险与对策

| 风险 | 等级 | 对策 |
|---|---|---|
| LLM 生成规则质量不稳定 | 高 | 确定性 SpecValidator 反例闭环 + 最大迭代轮次 + 人工确认；守卫固化为受控原语 |
| 基线自动机误报（正常操作被标异常） | 中 | 只做"偏离提示"而非直接 block；阈值可调；人工标注反馈重训 |
| 实体提取引入延迟/成本 | 中 | 复用现有 LLM 通道（一次调用），失败本地回退；RV 判定零 LLM 调用 |
| 向后兼容破坏 | 中 | 所有新字段可选，`labels`/`props` 保留；新旧引擎并存过渡 |
| 无正式攻击基准导致验收无据 | 中 | 阶段 E 建立办公场景正/负例 trace 库，作为持续回归基准 |

---

## 六、设计原则（贯穿全程）

1. **LLM 提议，确定性引擎裁决**：LLM 生成候选规约/提取实体，不控制状态；所有生效判定由 ConstraintEngine + `_SpecDrivenMonitor` 确定性执行。
2. **向后兼容**：新字段可选，旧接口保留，新旧引擎并存过渡。
3. **细粒度单一职责**：每个监视器规则 ≤5 步，每个约束 ≤3 个实体条件（规避 LLM 精度随复杂度衰减）。
4. **纯 Python 零重量依赖**：不引入 C++/Java 运行时；AALpy 等库只参考算法不自带依赖。
5. **守卫受控**：LLM 只选原语填参数，不开放自由逻辑（LLM guards 生成准确率仅 F1=0.23）。
