# Checklist

## 阶段 A：rv_trace 结构化透传
- [ ] `openclaw_guard/engine/ir.py` 定义 `Entity`/`Constraint`/`ToolCallIR`，字段类型受 Pydantic 约束
- [ ] LLM 模式：`rv_trace` 步骤含 `entities`/`constraints`/`confidence`，`props` 不变
- [ ] 本地模式：`rv_trace` 步骤透传 recipients/paths/constraints/confidence
- [ ] `tests/test_ir.py` 通过；`tests/test_semantic_enhancer.py` 无回归

## 阶段 B：约束推理引擎
- [ ] `constraints.py` 定义四类约束 + `ConstraintEngine`，评分/门控逻辑正确
- [ ] 置信度低于 `confidence_threshold` 的规则不参与判定
- [ ] ≥10 条高频规则迁移为 `ConstraintRule`，行为与旧 lambda 对齐
- [ ] `tests/test_constraints.py` 通过；`tests/test_detection.py` 无回归

## 阶段 C：RV 基线自动机
- [ ] `trace_abstractor.py` φ 抽象正确（RvTraceStep → 三元组）
- [ ] `baseline_learner.py` 前缀树+状态合并产出紧凑 DFA，支持序列化/加载
- [ ] `baseline_monitor.py` 偏离检测返回 `(is_anomaly, current_state)`
- [ ] `tests/test_baseline_learner.py`：正例全接受、反例偏离检出、规模缩减

## 阶段 D：RV 参数化原语
- [ ] `StepRequirement` 支持 `entity_*`/`step_gap_*`/`state_counter`
- [ ] `MonitorSpec` 支持 `quantifier`/`bind_vars`，参数化切片 per-binding 独立推进
- [ ] `WindowManager` 支持实体查询与步骤时间差查询
- [ ] `rv_rules.json` 含 ≥1 条参数化示例规则
- [ ] `tests/test_rv_dsl_ext.py` 通过；`test_rv_dsl.py`/`test_rv.py` 无回归

## 阶段 E：NL2Spec 自动生成
- [ ] `nl2spec_generator.py` QA 分解输出结构化 IR，通过 Pydantic 校验
- [ ] `spec_validator.py` 语法校验+正/负例注入+冲突检测+修正回环（含最大轮次保护）
- [ ] 生成规则标记 `origin="nl2spec"`/`source_nl`，可被 `compile_monitors` 执行
- [ ] 办公场景反例 trace 库正/负例各 ≥5 条
- [ ] `tests/test_nl2spec.py`、`tests/test_spec_validator.py` 通过

## 阶段 F：干预升级与会话状态
- [ ] `revise` 动作与 `revision_hint` 生效
- [ ] `SessionSafetyState` 连续 ask→escalate、escalate→block 升级逻辑正确
- [ ] `pipeline.py` 会话状态读写与 `revise` 透出
- [ ] `tests/test_intervention.py` 通过

## 全局
- [ ] 全部阶段向后兼容：`props`/`labels`/`OPENCLAW_RV_RULE_MODE` 语义不变
- [ ] 全量测试 `python -m unittest discover` 通过，无回归
- [ ] `docs/research/nl-automata-rv-upgrade-plan.md` A~F 状态标记已落地
- [ ] `docs/ops/roadmap.md` v0.4.0/v0.5.0/v0.6.0 里程碑已更新
