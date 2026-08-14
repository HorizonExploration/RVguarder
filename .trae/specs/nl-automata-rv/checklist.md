# Checklist

> 核验日期：2026-08-14。标记说明：`[x]` 达标 / `[ ]` 未达标（含异常编号）。

## 阶段 A：rv_trace 结构化透传
- [x] `openclaw_guard/rv/ir.py` 定义 `Entity`/`Constraint`/`ToolCallIR`，字段类型受 Pydantic 约束
- [x] LLM 模式：`rv_trace` 步骤含 `entities`/`constraints`/`confidence`，`props` 不变
- [x] 本地模式：`rv_trace` 步骤透传 recipients/paths/constraints/confidence
- [x] `tests/test_ir.py` 通过；`tests/test_semantic_enhancer.py` 无回归
- [x] `ToolCallIR` 补齐 A1 语义模型字段（tool_name/arguments/permission_level/side_effect/sensitivity/irreversibility/intent，全部可选，向后兼容）

## 阶段 B：约束推理引擎
- [x] `constraints.py` 五类约束齐备（Action/Tag/Entity/Sensitivity/Temporal），`ConstraintEngine` 挂载 Sensitivity/Temporal 判定
- [x] 置信度门控：语义置信度（`ToolCallIR.confidence`）低于 `confidence_threshold`（默认 0.5）的规则不参与判定
- [x] ≥10 条高频规则迁移为 `ConstraintRule`，行为与旧 lambda 对齐
- [x] `tests/test_constraints.py` 通过；`tests/test_detection.py` 无回归

## 阶段 C：RV 基线自动机
- [x] `trace_abstractor.py` φ 抽象正确（RvTraceStep → 三元组）
- [x] `baseline_learner.py` 前缀树+状态合并产出紧凑 DFA，支持序列化/加载
- [x] `baseline_monitor.py` 偏离检测返回 `(is_anomaly, current_state)`
- [x] `tests/test_baseline_learner.py`：正例全接受、反例偏离检出、规模缩减

## 阶段 D：RV 参数化原语
- [x] `StepRequirement` 支持 `entity_*`/`step_gap_*`/`state_counter`
- [x] `MonitorSpec` 支持 `quantifier`/`bind_vars`，参数化切片 per-binding 独立推进
- [x] `WindowManager` 支持实体查询与步骤时间差查询
- [x] `rv_rules.json` 含 ≥1 条参数化示例规则
- [x] `tests/test_rv_dsl_ext.py` 通过；`test_rv_dsl.py`/`test_rv.py` 无回归

## 阶段 E：NL2Spec 自动生成
- [x] `nl2spec_generator.py` QA 分解输出结构化 IR，通过 Pydantic 校验
- [x] `spec_validator.py` 语法校验+正/负例注入+冲突检测+修正回环（含最大轮次保护）
- [x] 生成规则标记 `origin="nl2spec"`/`source_nl`，可被 `compile_monitors` 执行
- [x] 办公场景反例 trace 库正/负例各 ≥5 条
- [x] `tests/test_nl2spec.py` 通过（SpecValidator 测试位于 `TestSpecValidator` 类，无独立 `test_spec_validator.py` 文件）

## 阶段 F：干预升级与会话状态
- [x] `revise` 干预落地：`_apply_session_escalation` 在会话风险达修正阈值时返回 `revise` 并透出 `revision_hint`；`controller` 映射 revise→`pending_approval`
- [x] `SessionSafetyState` 连续 ask→escalate、escalate→block 升级逻辑正确（ask→escalate 已补）
- [x] `pipeline.py` 会话状态读写（`_apply_session_escalation`）
- [x] `tests/test_intervention.py` 通过
- [x] 前端 revise 交互（修正建议展示 + 采用建议按钮）与会话状态展示已实现

## 全局
- [x] 全部阶段向后兼容：`props`/`labels`/`OPENCLAW_RV_RULE_MODE` 语义不变
- [x] 全量测试通过，无回归
- [x] `docs/research/nl-automata-rv-upgrade-plan.md` A~F 状态标记已落地
- [x] `docs/ops/roadmap.md` v0.4.0/v0.5.0/v0.6.0 里程碑已更新
