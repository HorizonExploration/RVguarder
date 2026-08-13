# NL 驱动自动机生成与运行时验证升级 Spec

## Why
当前 v0.3.0 的安全判定链路存在三处结构短板：语义层已提取的实体/约束/置信度在 `rv_trace` 中被丢弃（仅传扁平 `props` 标签）；规则匹配为 47 条 `tag in labels` 布尔 lambda，无法表达实体条件与置信度门控；RV 规约全部手写 `rv_rules.json`，无法从自然语言策略自动生成，且无参数化切片与反例验证闭环。目标是以「自然语言输入 → 语义理解（NL2Spec）→ 受限规则匹配 → 自动生成自动机 → 运行时验证」为主线，分六个阶段（A~F）落地升级。

## What Changes
- **阶段 A（IR 结构化）**：新增 `rv/ir.py` 定义 `ToolCallIR`/`Entity`/`Constraint`；`semantic_enhancer` 的 `rv_trace` 透传 entities/constraints/confidence；保留 `props`/`labels` 向后兼容。
- **阶段 B（约束推理引擎）**：新增 `rv/constraints.py` 定义四类约束（Entity/Sensitivity/Temporal/Action）+ `ConstraintEngine` 加权评分 + 置信度门控；渐进迁移高频规则。
- **阶段 C（RV 基线自动机）**：新增 `rv/trace_abstractor.py`（φ 抽象）、`rv/baseline_learner.py`（前缀树+状态合并）、`rv/baseline_monitor.py`（DFA 偏离检测）；离线训练脚本。
- **阶段 D（RV 参数化）**：扩展 `rv_dsl.py` 的 `StepRequirement`（`entity_*` 守卫、`step_gap_*` 时间原语、`state_counter` 计数器）与 `MonitorSpec`（`quantifier`/`bind_vars`）；`WindowManager` 增加实体/时间查询。
- **阶段 E（NL2Spec 生成）**：新增 `spec/nl2spec_generator.py`（QA 分解→ChainRule 合成）与 `spec/spec_validator.py`（语法校验+反例注入+冲突检测），生成规则标记 `origin`/`source_nl`。
- **阶段 F（干预升级）**：`Verdict` 增加 `revise`；新增会话级 `SessionSafetyState`（风险分累积+自动升级）。
- **BREAKING（无）**：全部阶段向后兼容，`props`/`labels`/`OPENCLAW_RV_RULE_MODE` 语义保持不变，新旧引擎并存过渡。

## Impact
- Affected specs: 语义理解（SemanticEnhancer）、检测引擎（DetectionEngine）、RV 引擎（RuntimeVerificationEngine / WindowManager / rv_dsl）、干预决策（Controller）、审计链（AuditStore）。
- Affected code:
  - `openclaw_guard/engine/semantic_enhancer.py`（rv_trace 透传 + prompt 结构化）
  - `openclaw_guard/rv/rv_dsl.py`（原语扩展 + quantifier/bind_vars + origin/source_nl）
  - `openclaw_guard/rv/runtime_verification.py`（实体/时间查询 + 参数化切片 + 基线监视器接入）
  - `openclaw_guard/engine/detection.py`（约束引擎接入与规则迁移）
  - `openclaw_guard/engine/pipeline.py`（IR 消费 + 会话状态传递）
  - `openclaw_guard/rv/rv_rules.json`（示例参数化规则 + 生成规则来源标记）
  - `docs/architecture/*`、`docs/research/*`（状态与验收更新）

## ADDED Requirements

### Requirement: rv_trace 结构化透传（阶段 A）
系统 SHALL 在语义层输出的 `rv_trace` 每个步骤中携带结构化实体、约束与置信度，同时保留原有 `props` 标签集合。

#### Scenario: LLM 模式透传
- **WHEN** LLM 语义分析成功且输出含 `semantic.entities` / `semantic.constraints` / `semantic.confidence`
- **THEN** `rv_trace` 步骤 SHALL 包含 `entities`、`constraints`、`confidence` 字段
- **AND** `props` 字段 SHALL 保持不变（向后兼容现有监视器）

#### Scenario: 本地降级模式透传
- **WHEN** 语义分析回退到本地规则（`_local_evaluate`）
- **THEN** 本地已提取的 recipients/paths/constraints/confidence SHALL 一并写入 `rv_trace` 步骤

#### Scenario: 数据模型可用
- **WHEN** 开发者导入 `openclaw_guard.engine.ir`
- **THEN** 可实例化 `ToolCallIR`、`Entity`、`Constraint`，且字段类型受 Pydantic/`@dataclass` 约束

---

### Requirement: 约束推理引擎（阶段 B）
系统 SHALL 提供基于四类约束（动作/实体/敏感度/时序）的规则匹配引擎，并支持置信度门控，替代纯标签布尔交集。

#### Scenario: 实体级规则判定
- **WHEN** 一条规则声明 `EntityConstraint(kind="recipient", match_type="domain_not_in", values=["internal.com"])`
- **THEN** 该规则 SHALL 在事件实体收件人命中外部域时匹配，未命中时不匹配

#### Scenario: 置信度门控
- **WHEN** 规则命中评分低于其 `confidence_threshold`
- **THEN** 该规则 SHALL 不参与最终判定
- **AND** 评分高于阈值时按评分参与决策

#### Scenario: 渐进迁移
- **WHEN** 约束引擎启用
- **THEN** 已迁移规则行为 SHALL 与旧 lambda 规则一致（对既有测试集）
- **AND** 未迁移规则 SHALL 继续走原检测路径

---

### Requirement: RV 基线自动机（阶段 C）
系统 SHALL 从审计/会话 trace 离线学习"正常办公行为 DFA"，并在运行时检测当前 trace 的偏离。

#### Scenario: 离线训练
- **WHEN** 给定一组正常会话 trace（`RvTraceStep` 序列）
- **THEN** 训练脚本 SHALL 产出紧凑 DFA（前缀树 + 状态合并），并支持序列化/加载
- **AND** 自动机规模 SHALL 显著小于原始 trace 规模（论文参考：小 1-3 个数量级）

#### Scenario: 运行时偏离检测
- **WHEN** 当前会话 trace 沿 DFA 走到未定义转换或非接受状态
- **THEN** `BaselineMonitor` SHALL 返回 `is_anomaly=True` 及当前状态
- **AND** 正常 trace 不产生误报（对训练集内路径）

#### Scenario: 与现有引擎共存
- **WHEN** 基线监视器启用
- **THEN** 其判定结果 SHALL 作为独立信号输入 RV 裁决层，不改变现有监视器行为

---

### Requirement: RV 参数化原语（阶段 D）
系统 SHALL 扩展 ChainRule DSL 以支持实体绑定（QEA 式参数化切片）、时间间隔与状态计数守卫。

#### Scenario: QEA 式参数化切片
- **WHEN** `MonitorSpec` 声明 `quantifier="forall"` 与 `bind_vars=["recipients"]`
- **THEN** 引擎 SHALL 按每个绑定值创建独立监视器实例并独立推进状态
- **AND** `forall` 要求所有绑定实例合规，`exists` 要求至少一个实例触发

#### Scenario: 实体级守卫
- **WHEN** `StepRequirement` 声明 `entity_any_of`（如收件人域命中外部域）
- **THEN** 步骤匹配 SHALL 基于事件实体值判定，而非仅标签集合

#### Scenario: 时间间隔与状态计数
- **WHEN** `StepRequirement` 声明 `step_gap_within_seconds` / `step_gap_at_least_seconds` / `state_counter`
- **THEN** 判定 SHALL 使用步骤时间戳差值与累计计数状态

---

### Requirement: NL2Spec 自动生成（阶段 E）
系统 SHALL 支持将用户自然语言安全策略翻译为已验证的 ChainRule 规约并合并进规则集。

#### Scenario: QA 分解翻译
- **WHEN** 用户提供自然语言策略（如"禁止把含机密的附件转发到外部邮箱"）
- **THEN** 生成器 SHALL 按事件步骤/实体约束/verdict 三个子问题分解并输出结构化 IR
- **AND** IR SHALL 通过 Pydantic 校验（LLM 不直接产出 JSON 规则）

#### Scenario: 反例验证闭环
- **WHEN** 候选规约编译为监视器后对正/负例 trace 库执行验证
- **THEN** 漏报（攻击链未被拦）或误报（合法链被拦）SHALL 生成修正反馈回喂翻译器
- **AND** 迭代至 0 错或达到最大轮次后停止，未通过规则不合并

#### Scenario: 规则来源可追溯
- **WHEN** 生成规则写入规则集
- **THEN** 规则 SHALL 携带 `origin="nl2spec"` 与 `source_nl` 原始语句，供前端展示与审计

---

### Requirement: 干预升级与会话状态（阶段 F）
系统 SHALL 提供 `revise` 干预动作与会话级风险状态追踪。

#### Scenario: revise 干预
- **WHEN** 违规判定携带 `revision_hint`
- **THEN** 决策 SHALL 返回 `revise` 动作并附带修改建议文本

#### Scenario: 会话级状态升级
- **WHEN** 同一会话连续触发 `ask`
- **THEN** 风险分累积，达到阈值后自动升级为 `escalate`
- **AND** 连续 `escalate` 可继续升级为 `block`

## MODIFIED Requirements

### Requirement: SemanticEnhancer 输出结构
**修改点**：`rv_trace` 步骤结构由 `{step_id, event, props}` 扩展为 `{step_id, event, props, entities?, constraints?, confidence?}`（全部可选，向后兼容）。

### Requirement: ChainRule DSL 表达能力
**修改点**：`StepRequirement` 新增 `entity_any_of`/`entity_all_of`/`step_gap_within_seconds`/`step_gap_at_least_seconds`/`state_counter`；`MonitorSpec` 新增 `quantifier`/`bind_vars`；`ChainRule`/`Ruleset` 新增 `origin`/`source_nl` 可选字段。

### Requirement: WindowManager 查询能力
**修改点**：新增按实体值查询（`steps_with_entity`）、步骤时间差查询（`step_gap`），并支持参数化切片索引。

## REMOVED Requirements
无（全部阶段保持向后兼容，无移除项）。
