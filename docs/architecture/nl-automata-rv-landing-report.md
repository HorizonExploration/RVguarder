# NL 驱动自动机生成与运行时验证 · 升级方案落地情况检查报告

> **审计日期**：2026-08-14
> **审计范围**：`nl-automata-rv-upgrade-plan.md`（v1.0，2026-08-11 标记「已完成」）阶段 A–F 全量落地情况
> **配套规格**：`.trae/specs/nl-automata-rv/{spec.md, tasks.md, checklist.md}`
> **审计基准**：`git` master（审计时 `e30879f`），全量测试基线 **331 passed / 18 skipped / 0 failed**（整改后基准 `2a4bccd` / **340 passed**，见第八节）

---

## 一、升级项清单（检查清单）

> 责任分工：本项目为单人开发，以下统一标注「核心开发」。
> 时间节点：升级方案未给出逐阶段计划完成时间；实际节奏为 2026-08-11 当日完成 A/C 与 D/F，08-14 完成目录拆分与收敛。下表「计划」列以方案发布日 08-11 为基准，「实际」列取自 git 提交记录。

| 阶段 | 版本 | 升级项 | 预期交付标准（节选） | 计划 | 实际 |
|---|---|---|---|---|---|
| A | v0.4.0 | IR 结构化 | `ToolCallIR`（11 字段）+ `rv_trace` 透传 entities/constraints/confidence + `props` 向后兼容 | 08-11 | 08-11（`10b8aea`） |
| B | v0.4.0 | 约束推理引擎 | 四类约束（Entity/Sensitivity/Temporal/Action）+ 加权评分 + 置信度三档门控 + 迁移 10 条规则 | 08-11 | 08-11~08-14 |
| C | v0.5.0 | RV 基线自动机 | φ 抽象 + 前缀树/状态合并 + 偏离检测 + 离线训练脚本 | 08-11 | 08-11（`10b8aea`） |
| D | v0.5.0 | RV 参数化 | `entity_*`/`step_gap_*`/`state_counter` + `quantifier`/`bind_vars` | 08-11 | 08-11（`310e4ed`） |
| E | v0.6.0 | NL2Spec 生成 | QA 分解 + ChainRule 合成 + 反例验证闭环 + `origin`/`source_nl` + 正/负例 trace 库 | 08-11 | 08-11（`310e4ed`） |
| F | v0.6.0 | 干预升级 | `revise` 干预 + `SessionSafetyState`（ask→escalate→block）+ 前端适配 | 08-11 | 08-11（`310e4ed`） |
| 7 | — | 文档与验收同步 | 计划文档状态标记 + roadmap 更新 + 全量测试 | 08-11 | 08-14 |

---

## 二、逐项核验结果

### 阶段 A：IR 结构化 — **部分达标**

| 检查项 | 结果 | 说明 |
|---|---|---|
| `rv/ir.py` 定义 `Entity`/`Constraint`/`ToolCallIR` | ✅ | 三个 Pydantic 模型存在 |
| `ToolCallIR` 字段齐全（11 字段） | ❌ | 实际仅 6 字段：`step_id/event/props/entities/constraints/confidence`；**缺 `tool_name/arguments/permission_level/side_effect/sensitivity/irreversibility/intent`** |
| LLM 模式 rv_trace 透传 | ✅ | `semantic_enhancer.py` 第 212–226 行写入 entities/constraints/confidence |
| 本地模式 rv_trace 透传 | ✅ | 第 378–406 行同样透传 |
| `props` 向后兼容 | ✅ | `props` 字段保留，6 监视器零修改 |
| `tests/test_ir.py` | ✅ | 存在，测试通过 |

### 阶段 B：约束推理引擎 — **部分达标**

| 检查项 | 结果 | 说明 |
|---|---|---|
| 四类约束模型 | ❌ | 实际仅 3 类：`ActionConstraint`/`TagConstraint`/`EntityConstraint`；**缺 `SensitivityConstraint`/`TemporalConstraint`** |
| `ConstraintEngine` 加权评分 | ✅ | `_match_score` + `_WEIGHTS`（action 0.25 / tags 0.40 / entity 0.35） |
| `evaluate_steps` 消费 ToolCallIR | ✅ | dict → `ToolCallIR.model_validate` 转换，跳过无法结构化步骤 |
| 置信度三档门控（≥0.8 / 0.5–0.8 / <0.5） | ❌ | `confidence_threshold` 默认 `0.0`，10 条迁移规则均未设置阈值 → **门控形同虚设**，仅剩「score>0 即命中」 |
| 迁移 10 条高频规则 | ✅ | `migrated_constraint_rules()` 返回 10 条，与 detection 的 `match_labels` 行为对齐 |
| pipeline 接入 | ✅ | `_apply_constraint_engine` 已接入 chat + hook 两条流水线，支持 `OPENCLAW_RV_CONSTRAINT_MODE` 开关 |
| `tests/test_constraints.py` | ✅ | 存在，测试通过 |

### 阶段 C：RV 基线自动机 — **达标**

| 检查项 | 结果 | 说明 |
|---|---|---|
| `trace_abstractor.py` φ 抽象 | ✅ | 存在 |
| `baseline_learner.py` 前缀树 + 状态合并 | ✅ | 存在，支持序列化/加载 |
| `baseline_monitor.py` 偏离检测 | ✅ | 返回 `(is_anomaly, current_state)` |
| `scripts/train_baseline.py` | ✅ | 存在 |
| 接入 `RuntimeVerificationEngine` | ✅ | `_init_baseline_monitor` + `_run_baseline`（`runtime_verification.py:326/492`） |
| `tests/test_baseline_learner.py` | ✅ | 存在，测试通过 |

> 说明：默认不加载 DFA（`baseline_dfa_path=None` 时监视器为 None），属设计性开关而非缺陷，但需在文档明确「基线异常检测默认关闭」。

### 阶段 D：RV 参数化 — **达标**

| 检查项 | 结果 | 说明 |
|---|---|---|
| `StepRequirement` 扩展 `entity_*`/`step_gap_*`/`state_counter` | ✅ | 已实现 |
| `MonitorSpec` 支持 `quantifier`/`bind_vars` | ✅ | 已实现 |
| `WindowManager` 实体/时间查询 | ✅ | 已实现 |
| `rv_rules.json` 参数化示例规则 | ✅ | 已增加 |
| `tests/test_rv_dsl_ext.py` | ✅ | 存在，测试通过 |

### 阶段 E：NL2Spec 生成 — **达标（含一处文件名偏差）**

| 检查项 | 结果 | 说明 |
|---|---|---|
| `nl2spec_generator.py` QA 分解 | ✅ | 存在，模板引擎 + LLM 预留 |
| `spec_validator.py` 语法/反例/冲突/回环 | ✅ | 存在，`validate_and_fix` 含最大轮次保护 |
| `origin`/`source_nl` 来源标记 | ✅ | 已实现 |
| 正/负例 trace 库 | ✅ | `eval_traces.py` |
| `nl2spec_compile` 接入 GuardServices | ✅ | `services.py:729` |
| `tests/test_spec_validator.py` | ⚠️ | **文件不存在**；SpecValidator 测试实际位于 `tests/test_nl2spec.py` 的 `TestSpecValidator` 类（功能覆盖，文件名与 checklist 不符） |

### 阶段 F：干预升级 — **部分达标（两处关键缺失）**

| 检查项 | 结果 | 说明 |
|---|---|---|
| `revise` 动作预声明 | ✅ | `DecisionAction` Literal 含 `revise`；`revision_hint()` 方法存在 |
| `SessionSafetyState` 会话状态 | ✅ | 存在，`record()`/`status()`/`reset()` |
| 连续 escalate→block 升级 | ✅ | 连续 3 次 escalate 或 escalate+elevated/critical → block |
| 连续 ask→escalate 升级 | ❌ | **`record()` 无 ask→escalate 升级链**，仅 escalate→block |
| `revise` 裁决真正生效 | ❌ | **无任何代码路径返回 `revise`**：pipeline 只升权为 `block`，controller 无 revise 映射，仅 tasks 6.3 自述「预留 pipeline 接入」 |
| 前端 revise 交互 + 会话状态展示 | ❌ | 前端仅 `escalate` 样式，无 `revise` 交互与会话状态展示 |
| `tests/test_intervention.py` | ✅ | 存在（覆盖 risk_score/升级链/revision_hint，但未覆盖 ask→escalate 与 revise 生效） |

### Task 7：文档与验收同步 — **部分达标**

| 检查项 | 结果 | 说明 |
|---|---|---|
| 计划文档状态标记 | ✅ | `upgrade-plan.md` A–F 均标 ✅ |
| roadmap 更新 | ✅ | 已更新 |
| 全量测试 | ✅ | 331 passed / 18 skipped |
| `checklist.md` 勾选 | ❌ | **全部检查项仍为 `[ ]` 未勾选**，与 `tasks.md` 全 `[x]` 矛盾，验收记录环节缺失 |

---

## 三、异常项明细（滞后 / 卡点 / 状态）

| # | 异常项 | 严重等级 | 滞后性质 | 卡点原因 | 当前状态 |
|---|---|---|---|---|---|
| E1 | 阶段 F `revise` 干预未真正落地 | **High** | 未完成就标记「已完成」 | `revise` 仅做 Literal 预声明 + `revision_hint()`，tasks 6.3 自认「预留 pipeline 接入」，controller/前端均未实现 | 半成品：模型层有、决策层无 |
| E2 | 阶段 F `ask→escalate` 升级链缺失 | **High** | 验收标准未满足 | `SessionSafetyState.record()` 只实现 escalate→block，缺 ask 自动升级 | 升级链不完整 |
| E3 | 阶段 B 置信度三档门控未实现 | **High** | 验收标准未满足 | `confidence_threshold` 默认 0.0，10 条迁移规则未设阈值 → 门控失效 | 字段存在但等于无门控 |
| E4 | 阶段 B 约束类型缩水（4→3） | **Medium** | 规格偏差 | `SensitivityConstraint`/`TemporalConstraint` 未实现，用 `TagConstraint` 顶替 | 与 spec B1 不符 |
| E5 | 阶段 A `ToolCallIR` 字段缩水（11→6） | **Medium** | 规格偏差 | 缺少 tool_name/arguments/permission_level/side_effect/sensitivity/irreversibility/intent | 与 spec A1 不符 |
| E6 | 前端 revise/会话状态展示缺失（F3） | **Medium** | 未启动 | 依赖 E1，revise 未落地导致前端无适配对象 | 未启动 |
| E7 | `checklist.md` 未同步 + `test_spec_validator.py` 文件名不符 + 注释引用已删函数 | **Low** | 验收记录缺失 | 文档与代码迭代不同步；`constraints.py:262` 注释仍引用 P0 已删的 `_semantic_predicates` | 待清理 |

---

## 四、已落地项运行效果验证

### 4.1 功能符合性

| 能力 | 验证结论 |
|---|---|
| rv_trace 结构化透传 | ✅ LLM/本地双模式均透传，`props` 向后兼容，6 监视器无回归 |
| 约束引擎接入热路径 | ✅ chat + hook 两条流水线均接入，`OPENCLAW_RV_CONSTRAINT_MODE` 开关生效 |
| 基线自动机 | ✅ 训练/序列化/加载/偏离检测闭环可用（默认关闭需显式开启） |
| RV 参数化原语 | ✅ 实体/时间/计数守卫 + 参数化切片测试通过 |
| NL2Spec 生成 | ✅ 模板生成 + 反例验证 + 来源标记 + `nl2spec_compile` 接入服务层 |

### 4.2 稳定性与性能

| 项 | 结论 |
|---|---|
| 全量回归 | ✅ **331 passed / 18 skipped / 0 failed**（与升级前基线一致，无回归） |
| 性能风险 | ✅ 低：约束引擎/会话状态均为纯内存操作，无外部 IO/LLM 调用；RV 判定零 LLM |
| 性能基准 | ⚠️ 无专门性能基准测试（升级方案验收标准未含性能数字，仅功能验收） |

### 4.3 新旧业务衔接与兼容性

| 项 | 结论 |
|---|---|
| 向后兼容 | ✅ `props`/`labels` 保留，新旧引擎并存（约束引擎升权不降权） |
| 开关控制 | ✅ `OPENCLAW_RV_CONSTRAINT_MODE` / `OPENCLAW_RV_SESSION_STATE` 环境变量可关闭新功能 |
| 未预见故障 | ✅ 未发现线上故障或兼容性破坏（检测规则 P0 收敛后 35 项关键测试 + 331 项全量通过） |

---

## 五、复盘总结

### 5.1 已完成项复盘

阶段 C（基线自动机）、D（RV 参数化）、E（NL2Spec）实现完整、测试覆盖到位、接入真实，是本次升级中质量最高的三块。阶段 A/B/F 存在不同程度的「验收标准打折」：

- **阶段 A**：核心价值（rv_trace 结构化透传）已达成，但 `ToolCallIR` 字段大幅缩水，实际上只是「rv_trace 步骤 + 3 个结构化字段」的轻量封装，未实现 spec 承诺的「工具调用完整语义模型」。
- **阶段 B**：约束引擎框架与接入真实可用，但「置信度门控」这一 spec 明确要求的核心安全机制**形同虚设**（默认 0.0），四类约束缩水为三类。
- **阶段 F**：`SessionSafetyState` 已接入，但 `revise` 这一 spec 标题级能力**停留在预声明**，ask→escalate 升级链缺失。

### 5.2 未完成项推进障碍分析

| 障碍 | 影响项 | 根因 |
|---|---|---|
| 「预留」式落地 | E1/E6 | 将 spec 要求的 `revise` 干预降级为「预留 pipeline 接入」，未做 controller 决策映射与前端适配 |
| 门控默认值失控 | E3 | `confidence_threshold` 默认 0.0 + 迁移规则未设阈值，门控从「三档」退化为「无门控」 |
| 规格与实现脱节 | E4/E5 | 实现时未严格对照 spec 的字段/约束清单，导致缩水 |
| 验收记录缺失 | E7 | `checklist.md` 未随 `tasks.md` 同步勾选，验收环节形同虚设 |

### 5.3 已落地项运行风险评估

| 风险 | 等级 | 说明 |
|---|---|---|
| 约束引擎门控失效 | **高** | 置信度门控不生效，低置信度规则也参与判定，违背「概率组件不控制状态」设计原则 |
| 会话升级链不完整 | **中** | 连续 ask 无法自动升级 escalate，会话风险累积失去「渐进收紧」能力 |
| revise 能力缺失 | **中** | 用户无法获得「带修正建议的拒绝」，体验与 NEXUS 对标能力缺失 |
| 规则双轨（约束 10 条 + detection 47 条） | **中** | 10 条规则两处定义，同步维护成本（P1 待办） |

---

## 六、整改方案与时间规划

### P0（本周内，正确性优先）

| 整改项 | 关联异常 | 具体动作 | 验收 |
|---|---|---|---|
| 修复置信度门控 | E3 | 为 10 条迁移规则设置合理 `confidence_threshold`（如 0.7），或实现三档门控函数；补单测覆盖三档 | 门控生效，低置信度规则不参与判定 |
| 补 ask→escalate 升级链 | E2 | 在 `SessionSafetyState.record()` 增加「连续 ask 达阈值 → escalate」逻辑 | `test_intervention.py` 覆盖 ask 升级链 |

### P1（下个迭代，能力补全）

| 整改项 | 关联异常 | 具体动作 | 验收 |
|---|---|---|---|
| 落地 revise 干预 | E1/E6 | controller 增加 revise 映射 + `revision_hint` 透出；前端工作台增加 revise 交互与会话状态展示 | 违规携带 hint 时返回 revise，前端可一键采用建议 |
| 补齐 ToolCallIR 字段 | E5 | 按 spec A1 补齐字段（或明确裁剪并同步 spec，二选一，不得「默认缩水」） | 模型字段与 spec 一致，或 spec 正式降级 |
| 补齐 Sensitivity/Temporal 约束 | E4 | 实现两类约束 + `ConstraintRule` 挂载 + 单测 | 四类约束齐备 |

### P2（文档与验收治理）

| 整改项 | 关联异常 | 具体动作 | 验收 |
|---|---|---|---|
| 同步 checklist.md | E7 | 逐项勾选并核对，补 `test_spec_validator.py`（或修正 checklist 文件名） | checklist 与 tasks/代码三方一致 |
| 清理过时注释 | E7 | 修正 `constraints.py:262` 引用已删函数的注释 | pyflakes/文档无死引用 |

---

## 七、结论

本次升级（阶段 A–F）**总体落地约 70%**：C/D/E 三阶段实现完整、接入真实、测试达标；A/B/F 存在「验收标准打折」——其中置信度门控失效（E3）、revise 未落地（E1）、ask→escalate 缺失（E2）属**High 级异常**，应优先整改。核心风险在于「规格文档与代码实现脱节」及「验收记录缺失」，建议将 `checklist.md` 纳入提交前强制勾选，避免「标记已完成但验收未执行」再次发生。

---

## 八、整改执行结果（2026-08-14）

| 整改项 | 关联异常 | 结果 |
|---|---|---|
| 修复置信度门控 | E3 | ✅ 已改为语义置信度门控（默认阈值 0.5），单测覆盖 |
| 补 ask→escalate 升级链 | E2 | ✅ 已补，连续 3 次 ask → escalate |
| 落地 revise 干预 | E1 | ✅ `_apply_session_escalation` 达阈值返回 `revise` 并透出 `revision_hint`；`controller` 映射 revise→`pending_approval`；Hook 返回 `revision_hint` |
| 补齐 Sensitivity/Temporal 约束 | E4 | ✅ 新增两类约束并挂载 `ConstraintEngine`，单测覆盖 |
| 补齐 ToolCallIR 字段 | E5 | ✅ 补齐 A1 七字段（tool_name/arguments/permission_level/side_effect/sensitivity/irreversibility/intent，全部可选） |
| 前端 revise + 会话状态展示 | E6 | ✅ 前端展示修正建议 + 「采用建议」按钮 + 会话状态展示 |
| 清理过时注释 | E7 | ✅ `constraints.py` 死引用已修正 |
| `test_spec_validator.py` 文件名 | E7 | ✅ checklist 已注明：SpecValidator 测试位于 `tests/test_nl2spec.py` 的 `TestSpecValidator` 类，无独立文件 |
| 规则双轨（10 条两处定义） | 5.3 风险 | ✅ 保留双定义，新增一致性测试兜底：`tests/test_constraints.py::test_migrated_rules_align_with_detection` 断言两处定义逐字段对齐，任一漂移即失败，同步维护成本由 CI 承担 |
| 性能基准缺失 | 4.2 | ✅ 新增 `tests/test_perf_smoke.py` 冒烟基准（宽松阈值 50ms）：约束引擎 0.07ms/次、RV 引擎 0.08ms/次、会话状态 1000 次 0.75ms（本机实测） |
| 基线异常检测默认关闭 | 阶段 C 说明 | ✅ 已在 `project-status-analysis.md` C-6 与 `rv-engine-report.md` 已知边界 2 明确「默认不加载 DFA，需显式配置 `OPENCLAW_RV_BASELINE_DFA_PATH`」 |

**整改后全量回归：340 passed / 18 skipped / 0 failed + 新增性能冒烟 3 用例。**

---

*本报告基于代码静态核验 + git 历史 + 全量测试基线生成。*
