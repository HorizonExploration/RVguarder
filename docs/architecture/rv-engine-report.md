# RV 层（运行时验证）技术报告

> 版本：v1.1 | 初稿日期：2026-08-11 | 当前复核：2026-09-15
> 范围：`openclaw_guard/rv/`（运行时验证）+ `openclaw_guard/spec/`（规约生成与校验）两个子包
> 关联文档：[RV 权限自动机架构](./rv-permission-automata.md)（现行合同）、[路线图](../ops/roadmap.md)（当前推进）；历史 NL→Automata 计划位于 `docs/archive/research/nl-automata-rv-upgrade-plan.md`

> **当前实现更新（2026-09-15）**：本报告保留 RV 引擎的机制细节；早期的 DetectionEngine/双轨描述仅是历史快照。生产 RV 已收敛为 ChainRule DSL 生成路径，手写 FSM 与 `transitions` 已移除。PMKB、Authorization Trace、危险权限组合和主体跨 session 状态的现行交互以[权限知识库与 RV 运行时架构结果](./permission-kb-runtime-architecture.md)为准。
> ConstraintEngine、SessionSafetyState 与 revise 已不在生产路径；当前 RV 仅在工具成功后提交 trace，
> 并从 TTL 有效窗口重放自动机。现行控制面说明见[三态控制面与 RV 提交边界](./three-state-rv-runtime-plan-2026-09-03.md)。

---

## 0. 核心结论：自动机是「自动生成」的吗？

这是理解当前 RV 层最关键的一个问题。答案需要拆成四层，**不能笼统回答「是」或「否」**：

| 层级 | 产物 | 生成方式 | 是否自动 |
|------|------|---------|:---:|
| ① 运行时 DSL 监视器 | `_SpecDrivenMonitor` / `_ParameterizedMonitor` | `compile_monitors()` 从规约**确定性编译** | ✅ 唯一生产路径 |
| ② 安全规约（默认） | `rv_rules.json` 的 8 条 `MonitorSpec` | 开发者**手写** JSON | ❌ 手写 |
| ③ 基线自动机（阶段 C） | `BaselineDFA` | 从正常 trace **统计自动学习**（前缀树 + 状态合并） | ✅ 自动学习 |
| ④ NL2Spec 生成（阶段 E） | `Ruleset(origin="nl2spec")` | 10 个内置模板 + **关键词匹配**生成 | ⚠️ 半自动 |

**一句话结论**：

> 当前运行路径 = **手写规约 + 确定性编译**；规约本身是手写的，监视器由 DSL 编译生成。真正的「LLM 自动生成规约」能力在 `nl2spec_generator.py` 中**只预留了接口（`use_llm=True` 返回 None）**，目前可用的只有模板关键词匹配这一档。基线 DFA 则是另一种「自动学习」，但它属于**白模型统计偏离检测**，不承载安全规约。

---

## 1. 模块清单（拆分后）

RV 层在本次重构中从 `engine/` 拆分为两个子包，与在线检测（`engine/`）解耦：

```
openclaw_guard/
├── engine/                # 在线安全决策（第一道防线：单步检测 + 编排）
└── rv/                    # 运行时验证（第二道防线：跨步链式判定）
    ├── runtime_verification.py   # RV 主引擎 + WindowManager 滑动窗口
    ├── rv_dsl.py                 # ChainRule 规约 DSL + 监视器编译
    ├── rv_rules.json             # 默认规约（8 个 MonitorSpec，单一规则源）
    ├── ir.py                     # ToolCallIR 结构化中间表示
    ├── baseline_learner.py       # 基线 DFA 学习器（前缀树 + 状态合并）
    ├── baseline_monitor.py       # 基线偏离检测监视器
    └── trace_abstractor.py       # trace → φ 三元组抽象
└── spec/                  # NL2Spec 规约生成与校验（离线能力）
    ├── nl2spec_generator.py      # NL → Ruleset 生成器（模板引擎 + LLM 预留）
    ├── spec_validator.py         # SpecValidator 反例验证闭环
    ├── eval_traces.py            # 办公场景正/负例 trace 库
    └── session_state.py          # PrincipalSecurityState 主体授权证据状态
```

### 职责边界

| 子包 | 定位 | 触发时机 | 是否在线热路径 |
|------|------|---------|:---:|
| `rv/` | 跨步链式风险判定 | 每个事件步 `evaluate()` | ✅ 热路径 |
| `spec/` | 规约的「生产者/校验器/主体证据」 | 离线生成、校验；成功回调后更新主体证据 | ⚠️ 仅主体证据更新在线 |

---

## 2. 运行时验证核心流程

### 2.1 引擎编排

`RuntimeVerificationEngine`（`rv/runtime_verification.py`）是 RV 层的中心，负责：

1. **per-session 窗口隔离**：`preview/evaluate(rv_trace, session_key=...)` 为每个 OpenClaw 会话维护独立的 `WindowManager`；preview 只回放，evaluate 才提交。
2. **规则模式选择**：`rule_mode` 参数 → `OPENCLAW_RV_RULE_MODE` 环境变量 → 默认 `dsl`。
3. **懒加载初始化**：监视器模板首次 `evaluate` 时才编译，避免拖慢启动。
4. **判定融合**：取所有监视器中风险等级最高的 `verdict` 作为最终结果。

### 2.2 判定融合（升权不降权）

```
verdict 风险等级：ok(1) < ask(2) < escalate(3) < block(4)；公开控制面将 `escalate` 折叠为 `ask`。
```

在 `engine/pipeline.py` 的 `_apply_rv_if_available()` 中，RV 判定与单步检测判定比较：

- `rv_level > det_level` 时，RV 覆盖原有决策（`block` 覆盖 `ask` 等）
- RV 只「升权不降权」，不会把 `block` 降级为 `allow`

Hook 路径在 `controller.decide()` 前调用 `preview()`，只有 `after_tool_call` 成功回调才调用
`evaluate()` 提交行为窗口；被拒绝、阻断或失败的调用不进入攻击链。聊天路径沿用同一
三态合并规则。

### 2.3 窗口能力

`WindowManager`（滑动窗口，默认 10 步 / 300 秒 TTL）提供：

| 能力 | 方法 | 用途 |
|------|------|------|
| 序列匹配 | `sequence_matches()` | 有序攻击链检测 |
| 累积计数 | `cumulative_count()` | 批量阈值（如敏感文件数 ≥3） |
| 存在性检查 | `contains_any()` | 跨事件关联 |
| 标签检索 | `steps_with_label()` | 按标签回溯 |
| 实体检索 | `steps_with_entity(kind, predicate)` | 阶段 D：按实体类别+域匹配回溯 |
| 时间间隔 | `step_gap(older, newer)` | 阶段 D：两步时间差 |
| 时间门槛 | `age_of_oldest()` | 窗口最老条目年龄 |
| 序列化 | `to_dict()` / `from_dict()` | 状态持久化 |

### 2.4 与 PMKB 和主体级 RV 的边界

RV 不替代 PMKB 的单步权限判断，而是在 PMKB 产生 `PolicyDecision` 后继续验证行为序列：

```text
SemanticEnhancer → TraceCompiler → PMKB（单步/最小权限/RiskGraph） → RV（序列）
```

`RuntimeVerificationEngine` 的窗口仍按 `session_id` 隔离，避免会话之间相互污染；另外，
`services.py` 中的 `PrincipalSecurityState` 按
`(principal_id, agent_id, capability_lineage)` 保存主体能力风险，用于跨 session 关联敏感
读取、权限授予与外联等事件。主体状态有 TTL、数量上限并写入 `runtime/rv-state.json`；缺少
可信身份时不做跨 session 合并。两类 RV 结果都只能提升、不能降低 PMKB 的安全处置。

---

## 3. 规约 DSL（rv_dsl.py）

### 3.1 数据模型

```
Ruleset
└── MonitorSpec（name / initial / quantifier / bind_vars）
    └── ChainRule（id / from / to / verdict / when / origin / source_nl）
        └── StepRequirement（单步 + 窗口 + 实体 + 时间 + 计数原语）
```

### 3.2 匹配原语全集

`StepRequirement` 支持三类原语：

**单步属性匹配**

| 原语 | 语义 |
|------|------|
| `event` | 精确事件类型 |
| `all_of` | 标签全命中（AND） |
| `any_of` | 标签任一命中（OR） |
| `none_of` | 标签全不命中 |

**窗口分析匹配**

| 原语 | 语义 | 底层 API |
|------|------|---------|
| `count_gte` | 窗口内累积计数 | `cumulative_count()` |
| `window_any_of` | 窗口内存在性检查 | `contains_any()` |
| `sequence` | 有序序列匹配 | `sequence_matches()` |
| `window_age_gt_seconds` | 窗口年龄门槛 | `age_of_oldest()` |

**阶段 D 扩展原语**

| 原语 | 语义 |
|------|------|
| `entity_all_of` / `entity_any_of` | 实体守卫（`value_in` / `domain_in` / `domain_not_in`） |
| `step_gap_within_seconds` / `step_gap_at_least_seconds` | 两步时间间隔约束 |
| `state_counter` | 状态计数器（`lt` / `lte` / `gt` / `gte`） |

### 3.3 编译机制（自动合成）

`compile_monitors(ruleset)` 对每个 `MonitorSpec`：

- 检测 `bind_vars` → 用 `_ParameterizedMonitor` 包装（参数化切片）
- 否则用 `type()` 动态创建 `_SpecDrivenMonitor` 子类（从规约的 `from`/`to` 状态集合自动合成监视器）

`_SpecDrivenMonitor.feed()` 每步执行顺序：

1. 先执行**非判决状态转移规则**（`from → to`，`from` 支持 `*` 通配），并更新 `state_counter`
2. 再执行**判决规则**（带 `verdict`），取命中规则中风险等级最高的 `verdict`

这是「规约驱动」的核心：**开发者只声明规约（状态、转移、匹配条件、裁决），运行时监视器由引擎确定性编译**，而非维护多套手写业务实现。

---

## 4. 现有规约清单（8 个监视器）

`rv/rv_rules.json` 是单一规则源，当前 8 个 `MonitorSpec`：

| 监视器 | 来源 | 能力 | 说明 |
|--------|------|------|------|
| MailMonitor | DSL 规约 | 敏感数据 + 外部收件人 → block | 由历史行为规则迁移 |
| ReportMonitor | DSL 规约 | 内部源日报外发 → block | 由历史行为规则迁移 |
| SecurityChainMonitor | DSL 规约 | 下载→外传 / 凭据→外传链 → escalate | 由历史行为规则迁移 |
| BroadcastMonitor | DSL 规约 | 群发 / 群发+外部 → ask/block | 由历史行为规则迁移 |
| DataExportMonitor | DSL 规约 | 批量导出数据 → 分级 | 由历史行为规则迁移 |
| BatchFileMonitor | DSL 规约 | 批量文件操作 → 分级 | 由历史行为规则迁移 |
| **PerRecipientMailMonitor** | 阶段 D | `quantifier: forall` + `bind_vars: ["recipients"]` + 实体守卫（`domain_not_in`） | 参数化示例 |
| **StateCounterDemoMonitor** | 阶段 D | `idle → warm` 自环 + `state_counter gte` → ask | 状态计数器示例 |

> 前 6 个是主路径规约；后 2 个是阶段 D 的原语演示规则（参数化 / 状态计数器），用于验证新原语能力。

---

## 5. 三类「自动机」来源详解

### 5.1 手写规约（默认主路径）

- 位置：`rv/rv_rules.json`
- 方式：开发者手写 `MonitorSpec` → `ChainRule` → `StepRequirement`
- 特点：**规约手写，监视器自动编译**。这是默认 `dsl` 模式的规则来源。

### 5.2 历史手写监视器（已退役）

早期版本曾在 `rv/rv_monitors.py` 中用 `transitions` 维护六套手写业务状态机。该实现与
DSL 规则重复，且会造成规则命中不一致；本轮已从生产代码、依赖和测试入口删除。旧代码只在
Git 历史与 `docs/archive/` 报告中保留，不可通过配置重新启用。

### 5.3 基线自动机（统计自动学习）

- 位置：`rv/baseline_learner.py` + `rv/baseline_monitor.py` + `rv/trace_abstractor.py`
- 方式：
  1. `trace_abstractor.abstract_step()` 把 `RvTraceStep` 抽象为 φ 三元组 `(event_type, entity_kind, label_class)`
  2. `BaselineLearner` 构建前缀树，再**频率驱动状态合并**（EDSM 备选），输出紧凑 DFA
  3. `BaselineMonitor` 在运行时判定当前 trace 是否偏离 DFA
- 特点：这是**真正「自动生成」的自动机**，但属于「白模型」——学习「正常办公行为」，检测**偏离**，而非承载安全规约。训练入口在 `scripts/train_baseline.py`。

### 5.4 NL2Spec 生成（模板自动生成，LLM 预留）

- 位置：`spec/nl2spec_generator.py`
- 方式：`generate_ruleset(nl_policy)` 用 **10 个内置模板 + 关键词匹配**生成 `Ruleset`（`origin="nl2spec"`、`source_nl=原文`）
- 内置模板覆盖：`rm -rf` / `curl | sh` / 外发邮件 / 删除凭据 / sudo 提权 / 导出数据 / 群发 / 禁用审计 / 敏感查询 / 持久化
- 特点：**LLM 模式（`use_llm=True`）仅预留接口，当前返回 None**。即「自然语言 → 规约」目前只有确定性模板匹配可用，尚未接入真实 LLM。

---

## 6. 规约校验闭环（spec/spec_validator.py）

`SpecValidator` 提供生成规约的质量保障：

| 能力 | 说明 |
|------|------|
| 语法校验 | 校验 `Ruleset` 结构合法性 |
| 正/负例注入 | 把 `eval_traces.py` 的正/负例 trace 注入引擎（`engine._spec_ruleset`），检验规约是否漏报/误报 |
| 冲突检测 | 检测规则间冲突 |
| 迭代修正 | `validate_and_fix()` 回喂生成器，直至收敛或达到最大轮次 |

`spec/eval_traces.py` 提供办公场景评估基准：6 条正常 trace + 7 条攻击链 trace（数据外泄 / sudo 提权 / `curl|sh` / 群发外发 / 批量导出 / 凭证链 / 审计关闭）。

---

## 7. 主体授权证据状态（spec/session_state.py）

`PrincipalSecurityState` 只保存可信主体在成功执行后的有限授权证据，不做会话累计分数或
历史 `revise` 重试干预：

| 项 | 值 |
|----|----|
| 记录边界 | 仅 `after_tool_call` 成功后的可信 principal/agent/lineage |
| 状态内容 | 有效 grant、敏感 lineage、撤销记录和 TTL |
| 预判 | `evaluate()` 只读，不扩展授权；`record()` 成功后提交 |
| 风险输出 | 只返回 `openclaw_approval` 或 `block`，不生成 `revise` |

> `GuardServices.apply_principal_rv()` 在执行前只读检查主体状态；`record_executed_principal_action()`
> 在成功回调后写入状态并持久化到 `runtime/rv-state.json`。状态按
> `(principal_id, agent_id, capability_lineage)` 隔离并受 TTL/数量上限约束。

---

## 8. 配置方式

| 配置项 | 来源 | 说明 |
|--------|------|------|
| `OPENCLAW_RV_RULE_MODE` | 环境变量 | 历史配置可读；运行时固定归一化为 `dsl` |
| `OPENCLAW_RV_RULES_PATH` | 环境变量 | 自定义规约文件路径 |
| `OPENCLAW_RV_BASELINE_DFA_PATH` | 环境变量 | 基线 DFA 加载路径 |
| `preferences.json` `rv_mode` / `rv_rule_mode` | Dashboard `/api/rv/toggle` | RV 总开关 / 运行时切换 rule_mode |
| `window_size` / `window_ttl_seconds` | 引擎构造参数 | 窗口大小与过期时间（默认 10 / 300s） |

---

## 9. 测试覆盖

| 测试文件 | 覆盖目标 |
|----------|---------|
| `tests/test_runtime_verification.py` | WindowManager + DSL 引擎集成/会话隔离 |
| `tests/test_rv_dsl.py` | DSL 规约加载/编译/匹配原语/历史模式归一化 |
| `tests/test_rv_dsl_ext.py` | 阶段 D：实体守卫/状态计数器/时间间隔/参数化 |
| `tests/test_baseline_learner.py` | 基线 DFA 学习/偏离检测/规模缩减 |
| `tests/test_ir.py` | ToolCallIR 模型与透传 |
| `tests/test_nl2spec.py` | 模板匹配/来源标记/校验器/trace 库 |
| `tests/test_pipeline.py` | RV overlay / per-session 隔离 / 完整链路 |
| `tests/test_three_state_control.py` | 三态控制面、未知工具、preview/TTL 与 Hook 注册边界 |
| `tests/test_perf_smoke.py` | RV 与流水线性能冒烟基准 |

历史全量测试数字仅作快照；当前回归基线以[项目理解与当前记忆](./project-memory.md)和 CI 输出为准。

---

## 10. 已知边界与后续方向

1. **LLM 自动生成未落地**：`nl2spec_generator.py` 的 `use_llm=True` 仅预留接口，当前「自然语言 → 规约」只有模板关键词匹配。
2. **基线自动机默认不启用**：`BaselineMonitor` 需显式配置 `OPENCLAW_RV_BASELINE_DFA_PATH` 加载 DFA，默认引擎不加载。
3. **权限规则与行为规约边界**：PMKB 负责单步权限语义，`rv_rules.json` 负责跨步行为约束；两者通过 synthetic step 传递证据，不共享可变监视器状态。
4. **窗口大小边界**：默认 10 步，攻击链起手事件可能被挤出窗口；TTL 和窗口上限需要按场景调优。
5. **真实 OpenClaw 证据仍需补齐**：回调延迟、Gateway 重启和网络断开场景已有本地回归，仍需真机观测数据验证。

---

*本报告基于对 `openclaw_guard/rv/` 与 `openclaw_guard/spec/` 全部源码、`rv_rules.json`、相关测试与升级计划文档的完整阅读与分析。*
