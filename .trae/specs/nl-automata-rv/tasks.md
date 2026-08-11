# Tasks

> 依赖关系：A ← B ← C ← D ← E（严格顺序）；F 依赖 B 可并行于 E。
> 每阶段完成后运行对应测试并更新 `docs/research/nl-automata-rv-upgrade-plan.md` 状态标记。

- [ ] Task 1（阶段 A）：定义 IR 数据模型并透传语义层结构化字段
  - [ ] 1.1 新建 `openclaw_guard/engine/ir.py`：`Entity`、`Constraint`、`ToolCallIR`（Pydantic 模型，含 `labels`/`rv_props` 兼容字段）
  - [ ] 1.2 修改 `semantic_enhancer.py`：`_call_llm` 补全字段后透传 `entities`/`constraints`/`confidence` 到 `rv_trace` 步骤
  - [ ] 1.3 修改 `_local_evaluate`：将本地提取的 recipients/paths/constraints/confidence 写入 `rv_trace` 步骤
  - [ ] 1.4 新建 `tests/test_ir.py`：模型实例化 + rv_trace 透传（LLM 模式 mock + 本地模式）断言
  - [ ] 1.5 回归 `tests/test_semantic_enhancer.py`，确认 `props`/`labels` 无变化

- [ ] Task 2（阶段 B）：约束推理引擎
  - [ ] 2.1 新建 `openclaw_guard/engine/constraints.py`：`VerdictAction`（含 `revise` 预声明）、`Verdict`、`EntityConstraint`、`SensitivityConstraint`、`TemporalConstraint`、`ConstraintRule`、`ConstraintEngine`
  - [ ] 2.2 实现 `ConstraintEngine.evaluate(ir) -> list[(rule, score)]` 与 `_match_score`（动作/实体/敏感度/时序加权）
  - [ ] 2.3 实现置信度门控：评分 < `confidence_threshold` 的规则不参与判定
  - [ ] 2.4 迁移 10 条高频规则（CMD-001/002/003/004、FILE-001/002、NET-001/005 等）为 `ConstraintRule`，与旧 lambda 行为对齐
  - [ ] 2.5 新建 `tests/test_constraints.py`（实体域匹配、置信度门控、时序约束）+ 回归 `tests/test_detection.py`

- [x] Task 3（阶段 C）：RV 基线自动机
  - [x] 3.1 新建 `openclaw_guard/engine/trace_abstractor.py`：`RvTraceStep` → φ 三元组 `(event_type, entity_kind, label_class)`
  - [x] 3.2 新建 `openclaw_guard/engine/baseline_learner.py`：前缀树构建 + 频率驱动状态合并（EDSM 备选），支持序列化/加载
  - [x] 3.3 新建 `openclaw_guard/engine/baseline_monitor.py`：DFA 运行时判定，返回 `(is_anomaly, current_state)`
  - [x] 3.4 新建 `scripts/train_baseline.py`：审计日志 → 基线 DFA 训练与导出
  - [x] 3.5 接入 `RuntimeVerificationEngine`：基线判定作为独立信号进入 `evaluate()` 结果
  - [x] 3.6 新建 `tests/test_baseline_learner.py`：正例全接受 + 构造反例偏离检出 + 规模缩减断言

- [x] Task 4（阶段 D）：RV 参数化原语
  - [x] 4.1 扩展 `rv_dsl.py`：`StepRequirement` 增加 `entity_any_of`/`entity_all_of`/`step_gap_within_seconds`/`step_gap_at_least_seconds`/`state_counter`
  - [x] 4.2 扩展 `MonitorSpec`：`quantifier: "forall"|"exists"` + `bind_vars`
  - [x] 4.3 扩展 `WindowManager`：`steps_with_entity(kind, predicate)`、`step_gap(step_a, step_b)`、实体/时间查询
  - [x] 4.4 修改 `_matches_requirement`：支持实体守卫、时间间隔、状态计数器判定
  - [x] 4.5 实现参数化切片：按 `bind_vars` 值创建独立监视器实例，`forall`/`exists` 量化判定
  - [x] 4.6 在 `rv_rules.json` 增加 1-2 条参数化示例规则（如按收件人域切片的 MailMonitor）
  - [x] 4.7 新建 `tests/test_rv_dsl_ext.py` + 回归 `tests/test_rv_dsl.py`、`tests/test_rv.py`

- [x] Task 5（阶段 E）：NL2Spec 自动生成
  - [x] 5.1 扩展 `rv_dsl.py`：`ChainRule`/`Ruleset` 增加 `origin`/`source_nl` 字段
  - [x] 5.2 新建 `openclaw_guard/engine/nl2spec_generator.py`：NL → 结构化 IR（QA 分解，模板引擎 + LLM 预留）
  - [x] 5.3 新建 `openclaw_guard/engine/spec_validator.py`：语法校验 + 正/反例注入 + 冲突检测 + 修正回环
  - [x] 5.4 ChainRule 合成：结构化 IR → `ChainRule`（origin=nl2spec, source_nl=原文）
  - [x] 5.5 新建办公场景反例 trace 库（正/负例各 ≥5 条，覆盖数据外泄/工具误用/prompt 注入链）
  - [x] 5.6 新建 `tests/test_nl2spec.py`（模板匹配 + 来源标记 + 校验器 + trace 库）+ 回归

- [x] Task 6（阶段 F）：干预升级与会话状态
  - [x] 6.1 `models.py` 增加 `revise` 动作与 `session_state.py` 风险评分
  - [x] 6.2 新增 `openclaw_guard/engine/session_state.py`：`SessionSafetyState`（risk_score/escalation_level/干预历史），连续 ask→escalate、escalate→block 自动升级
  - [x] 6.3 revision_hint 生成透出（预留 pipeline 接入）
  - [x] 6.4 新建 `tests/test_intervention.py`：风险评分、升级链、revision_hint

- [x] Task 7：文档与验收同步
  - [x] 7.1 更新 `docs/research/nl-automata-rv-upgrade-plan.md`：A~F 阶段状态标记为已落地
  - [x] 7.2 更新 `docs/ops/roadmap.md`：新增 v0.4.0/v0.5.0/v0.6.0 里程碑完成项
  - [x] 7.3 运行全量测试（`python -m unittest discover`），确认无回归

# Task Dependencies
- [Task 2] 依赖 [Task 1]（约束引擎消费 ToolCallIR）
- [Task 3] 依赖 [Task 1]（基线自动机消费结构化 RvTraceStep）
- [Task 4] 依赖 [Task 1]（参数化切片消费实体字段）
- [Task 5] 依赖 [Task 4]（生成规则使用参数化原语表达）+ [Task 2]（复用约束校验）
- [Task 6] 依赖 [Task 2]（revise 预声明于 VerdictAction）
- [Task 7] 依赖全部 Task 1~6
