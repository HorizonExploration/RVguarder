# 权限知识库与权限建模运行时升级结果

> **状态：** 当前实现结果与架构事实源
> **核对日期：** 2026-08-30
> **PMKB 版本：** `1.1.0`
> **测试基线：** 改造前全量回归 `513 passed / 18 skipped / 4 subtests passed`；本次改造采用 OpenClaw 交接链路定向回归，结果见第 8 节。

本文档说明本次升级实际交付的权限规则知识库（Permission Model Knowledge Base，PMKB）、权限建模、最小权限校验、危险权限组合检测和跨 session 运行时验证。它不是下一阶段愿景：已实现部分以代码和测试为证据，未实现部分明确列在“当前边界”中。

## 1. 结论与范围

本次升级完成了第一版可直接接入 Hook 链路的权限治理基础设施：

1. 把工具调用规范化为 `principal / operation / resource / scope / data / context` 的 Authorization Trace；
2. 用版本化 JSON PMKB 管理操作目录、规则、最小权限 Trace、危险组合关系和正反例向量；
3. 在执行前运行规则匹配、覆盖度判断、权限闭包、最小权限差分和 RiskGraph 组合检查；
4. 将结果以单调方式叠加到既有检测和 RV 决策，PMKB 只能提高风险处置等级，不能降低既有 `block` 或审批；
5. 按可信 `principal + agent + capability_lineage` 保存跨 session 的主体能力风险状态，并在重启后恢复快照；
6. 保留 OpenClaw 原生审批作为唯一用户确认入口，Guard Dashboard 只读展示证据和同步状态。

本次没有完成以下工作：

- 47 条历史单步检测规则已完成兼容迁移并经逐条回放：ConstraintEngine 和 PMKB 均可按同一旧 ID 判定（完成数 `47 / 47`）；生产 DetectionEngine 已删除，冻结元数据只保留为回放证据；详见[旧规则迁移矩阵](./legacy-rule-migration-matrix.md)；
- 未实现从人工审批记录自动学习并永久生成 `allow` 规则；
- 未提供完整的用户权限管理 UI 和企业级目录同步；
- 尚无真实个人办公流量的人工审批下降实测，因此路线图中的 `-40%`、`-60%` 是验收目标，不是已达成结果。

## 2. 总体架构与运行顺序

```text
OpenClaw before_tool_call
  → tool_hook_bridge / BehaviorEvent
  → SemanticEnhancer
       ├─ entities / labels / classification / purpose / confidence
       └─ rv_trace（历史步骤与实体）
  → PolicyBundle.load + TraceCompiler
       └─ AuthorizationTrace（操作、资源、主体、覆盖度、来源）
  → AuthorizationPolicyEngine（PMKB 原生规则 + 历史兼容记录）
       ├─ PolicyEvaluator（规则匹配与风险评分）
       ├─ PermissionClosure + PermissionDiff（最小权限）
       └─ RiskGraph（危险权限组合）
  → ConstraintEngine（可选约束升权）
  → PermissionAutomatonCompiler（PMKB → 权限监视器）
  → RuntimeVerificationEngine（行为 DSL + session/principal 权限监视器）
  → SessionSafetyState / PrincipalSecurityState（累计风险）
  → GuardController
  → allow / revise / requireApproval / block
  → OpenClaw 原生审批、onResolution、SSE 只读同步
  → after_tool_call 审计
```

代码对应关系：

| 层 | 实现 |
| --- | --- |
| 事件与语义输入 | `openclaw_guard/engine/pipeline.py`、`engine/semantic_enhancer.py`、`integrations/tool_hook_bridge.py` |
| Trace 编译 | `openclaw_guard/policy/trace.py` |
| PMKB 加载与 schema 校验 | `openclaw_guard/policy/catalog.py`（`PolicyBundle`）、`policy/models.py` |
| 规则匹配与风险评分 | `openclaw_guard/policy/evaluator.py` |
| 最小权限闭包/差分 | `openclaw_guard/policy/permission_diff.py` |
| 组合风险图 | `openclaw_guard/policy/risk_graph.py` |
| 统一权限处置 | `openclaw_guard/policy/engine.py` |
| PMKB 权限自动机编译 | `openclaw_guard/policy/rv_compiler.py` |
| session / principal RV | `openclaw_guard/rv/runtime_verification.py`、`openclaw_guard/spec/session_state.py` |
| OpenClaw 审批和同步 | `openclaw_guard/integrations/hook_runtime.py`、`services.py` |

## 3. PMKB 知识库结构

源码运行时读取 `policies/permissions/`，打包安装后读取
`openclaw_guard/policy/data/permissions/`。两份目录必须保持 JSON 内容和版本一致，测试会执行 parity 校验。

| 文件 | 当前数量 | 作用 |
| --- | ---: | --- |
| `schema/permissions.schema.json` | 1 | 约束 bundle 必须包含 operations、rules、traces、relations、vectors |
| `catalog/operation-catalog.json` | 28 operations | 工具名/别名到 canonical permission family 的映射，含本地 `file.read` 与 `conversation.message` |
| `rules/p0-office.json` | 32 authored rules（其中 22 条 `P1-*`） | 单步权限规则、匹配条件、处置效果和来源 |
| 运行时兼容规则 | 47 `LEGACY-<old-id>` records | 由 47 条 DetectionRule 的 action type + semantic labels 生成，同时进入 ConstraintEngine、PMKB 评估与权限监视器 |
| `traces/p0-office.json` | 29 traces | 每条规则对应的最小必要权限范围和正反例 |
| `relations/p0-combinations.json` | 9 relations | `toxic_with`、`conflicts`、`implies` 等权限关系 |
| `tests/p0-vectors.json` | 29 vectors | 固定输入、预期效果和回归类别 |

每个规则记录至少包含：`id`、`version`、`effect`、`priority`、`match`、`required_fields`、`negative_conditions`、`source`、`test_vectors`、`rollback_state`、`positive_examples` 和 `negative_examples`。加载器会拒绝重复 ID、未知 operation、版本不一致或缺少必填字段的 bundle，并递归冻结已加载记录，防止运行时篡改。

## 4. 权限模型

### 4.1 Authorization Trace 本体

`TraceCompiler` 不把工具名直接当作权限，而是把 Hook 事件和语义结果归一化为以下对象：

| 维度 | 字段 | 来源与安全含义 |
| --- | --- | --- |
| 主体 | `principal.id/type/trust` | 人、Agent、Skill 或 Service；只有可信身份可参与跨 session 合并 |
| 执行体 | `agent_id`、`capability_lineage` | 区分同一用户下的 Agent 和能力来源，防止错误继承 |
| 操作 | `operation.family/tool_id/aliases` | 由工具目录和 action fallback 解析；无法解析则为 `unknown_tool` |
| 资源 | `resource.type/ids` | 路径、URL、收件人、文档、表等实体 |
| 范围 | `resource.scope` | `workspace / managed_project / outside / external / unknown`，不能把 unknown 当作宽泛许可 |
| 数据 | `data.classification/quantity` | `public / internal / sensitive / secret` 和数量 |
| 上下文 | `recipient_zone/purpose` | 内部/外部目的地和业务目的 |
| 覆盖度 | `coverage.status/missing_features/gaps/conflicts` | `complete / partial / unknown / conflict` |
| 来源 | `provenance/source/trust`、`confidence` | 记录语义来源和字段可信度，不让不可信文本直接变成授权 |

身份处理有一个重要安全边界：Hook 桥接事件不会仅凭语义文本认定 principal；缺少可信身份时使用 `unknown`，相关权限状态不能用于跨 session 继承。

### 4.2 语义理解到规则命中

规则命中不是单纯的关键词布尔交集，当前流程为：

1. 从 `tool_name`、API 名和 action type 解析 canonical operation；
2. 合并语义层 `entities`、`labels`、`classification`、`purpose` 和历史 `rv_trace`；
3. 提取资源 ID、工作区范围、收件人区域、数据敏感度和可信主体；
4. 对规则的 required fields、positive predicates 和 negative conditions 逐项比较；
5. 将编译器覆盖缺口合并到规则证据，生成候选规则和 `match_status`。

候选规则有四种状态：

- `matched`：操作和所需特征均有证据；
- `partial`：规则可定位，但缺少资源、主体、目的地等字段；
- `unknown`：工具映射或覆盖状态无法确认；
- `conflict`：规则条件或语义约束出现冲突。

匹配分数是解释性证据，不是放行开关：

```text
score = 0.40 × operation_action
      + 0.25 × required_field_completeness
      + 0.20 × predicate_specificity
      + 0.15 × provenance_trust
```

exact operation 的 action 分为 `1.0`，alias 为 `0.5`；任何 `unknown/conflict` 覆盖状态都会阻止 `auto_allow_audit`。无法匹配的工具不会静默放行，而是带 `tool_mapping` 缺口进入审批或澄清。

### 4.3 基线操作与默认效果

| 权限族 | 典型操作 | PMKB 基线效果 |
| --- | --- | --- |
| `directory.read`、`table.read` | 工作区目录/表读取 | 资源已解析且分类低影响时 `auto_allow_audit` |
| `document.write`、`file.write` | 文档、Wiki、云盘或文件写入 | `openclaw_approval` |
| `data.export` | 表格/数据库导出 | 普通导出审批；敏感/秘密数据 `block` |
| `network.egress` | 网络请求、Webhook | `openclaw_approval` |
| `secret.read`、`credential.read` | 秘密、凭据读取 | `openclaw_approval` |
| `process.execute` | 命令/进程执行 | `openclaw_approval` |
| `session.token.read` | Cookie、OAuth、会话令牌 | `block` |
| `identity.permission.grant` | 角色或 OAuth scope 授予 | `openclaw_approval` |
| `identity.auth.modify` | MFA、设备或应用凭据修改 | `openclaw_approval` |
| `audit.modify` | 关闭审计、修改日志 | `openclaw_approval` |

上述 `auto_allow_audit` 只适用于证据完整、工作区边界明确且低敏感度的读取；缺少 principal、resource、scope 或 recipient 时，状态会降为 partial/unknown 并提高处置等级。

## 5. 权限组合与最小权限验证

### 5.1 已持有权限与新增请求

Hook 事件可携带 `current_permissions`、`requested_permissions` 和 `required_trace`：

```text
current_permissions
  → CapabilityGrant 校验（主体、委派、scope、TTL、expiry）
  → PermissionClosure（显式 implies 闭包）
  → requested_permissions 与 required_trace
  → PermissionDiff
       ├─ requested_delta
       ├─ redundant_permissions
       ├─ excessive_permissions
       ├─ scope_expansions
       └─ hard_violations
```

关键规则：

- 没有 `current_permissions` 时默认无已授权权限，不伪造已有许可；
- 已过期、撤销、主体不匹配或委派证据不完整的 grant 不进入闭包，并生成验证缺口；
- scope、resource、field、purpose 和 TTL 都参与比较；
- required Trace 的 `unknown` scope 不是通配符；
- 发生 scope expansion 或超出 required Trace 时，至少进入 OpenClaw 审批；只有明确硬违规直接 `block`；
- PermissionRef 是不可变、可哈希对象，避免运行时或测试修改 PMKB 证据。

### 5.2 危险组合 RiskGraph

RiskGraph 将稀疏权限关系作为超边索引，只检查被当前权限族触发的关系。当前网络案例基础关系包括：

| 组合 | 效果 | 案例含义 |
| --- | --- | --- |
| `credential.read + network.egress + external_target` | `block` | 凭据读取后向外部目标传输 |
| `session.token.read + network.egress + external_target` | `block` | 会话令牌读取后外传 |
| `identity.permission.grant + data.export + external_recipient + sensitive_data` | `block` | 新增权限后立即敏感数据外发 |
| `identity.auth.modify + audit.modify` | `openclaw_approval` | 身份控制和审计能力同时变化 |

每个组合证据包含 `trace_id`、关系版本、命中的 permission family、principal、capability lineage、资源范围、数据分类和来源。RiskGraph 不替代 session RV：它判断“权限集合是否危险”，RV 判断“行为序列是否形成链式风险”。

## 6. 与 RV 的协同

当前有三个互补的自动机族和两个状态域。完整的编译合同、图示和旧结构迁移表见[RV 权限自动机架构](./rv-permission-automata.md)。

### 6.0 PMKB 权限自动机

PMKB 规则与危险组合关系会在本地 bundle 装载时由 `PermissionAutomatonCompiler` 生成 `MonitorSpec`：每条规则对应一个 session 监视器，每条可执行关系对应一个 principal 监视器。运行时把 Authorization Trace 和 PolicyDecision 规范化为 `pmkb.permission` synthetic step，再由 `StepRequirement.policy` 读取 `selected_rule_ids`、`combo_violations`、effect、匹配状态、操作族、闭包后的权限族和风险分数。

这不是用 DFA 重复实现 PolicyEvaluator：规则谓词、权限闭包、TTL/委派校验和 RiskGraph 仍以 PMKB 引擎的结果为权威；自动机负责将已验证的权限结论纳入 RV 标准监视器、作用域隔离、timing 和审计接口。因此未知或缺字段的请求不会因自动机存在而被放行。

### 6.1 session-local RV

`RuntimeVerificationEngine` 按 `session_id` 为滑动窗口和监视器分区，默认窗口为 10 步。它检测搜索→删除、读取敏感数据→外传、批量操作、关闭审计→改配置等行为序列，避免不同会话互相污染。

### 6.2 principal-global RV

主体能力状态使用以下不可替代的键：

```text
(principal_id, agent_id, capability_lineage)
```

`goal_id` 可用于任务分区，但不能单独证明身份。可信身份不完整时不会合并跨 session 状态；不同主体、Agent 或能力谱系一定创建独立状态。状态保存在 `runtime/rv-state.json`，有 TTL 和数量上限，重启后恢复。

审批通过的 Hook 动作会记录为主体有效能力，后续 session 的行为可以与此前已批准的敏感读取、权限授予或外联行为组合评估。principal RV 的效果只能把原决策提升为审批或阻断，不能降级既有安全结论。

## 7. 决策与 OpenClaw 交接

PMKB 效果到 Guard 动作的映射为：

| PMKB effect | Guard action | OpenClaw 行为 |
| --- | --- | --- |
| `auto_allow_audit` | `allow` | 继续执行并记录审计 |
| `clarify_then_retry` | `revise` | 返回修正提示，不执行当前请求 |
| `openclaw_approval` | `ask` | 返回 `requireApproval`，由 OpenClaw 原生页面确认 |
| `block` | `block` | 直接阻断 |

决策合并按严重度单调提升：`allow < ask/revise < escalate < block`。Guard 页面只读显示：
`policy_version`、`effect`、`match_status`、`missing_features`、`requested_delta`、`excessive_permissions`、`combo_violations`、`risk_score`、`replay_hash` 和 timing。

`before_prompt_build` 只是非阻塞意图预检查，始终返回 allow 并写审计，不创建待审批动作；只有 `before_tool_call` 能创建 `pending_approval`。OpenClaw 的 `onResolution` 是唯一审批结果来源，Guard 通过 resolution/SSE/增量查询同步，不提供第二个批准按钮。

本次 OpenClaw 交接修复补充了三项运行时约束：

- 原生 `sessions_*`、`session_status`、`memory_*`、`agents_list`、`get_goal` 被映射为明确的只读 permission family，并按 `tool_origin=openclaw_native`、`risk_class=low` 进入 PMKB；控制面读取不会因为缺少文件路径或 Agent 身份而被误判为普通命令审批。
- `sessions_send`、`sessions_spawn` 及计划/目标写入不继承上述只读信任，仍需要审批或进一步判定；Shell/exec 读取仍必须满足 workspace/managed_project 边界和只读特征。
- 发送给 OpenClaw 的审批标题和说明分别限制为 80/240 字符，避免长命令触发 `plugin.approval.request` schema 错误；Guard 继续保留完整技术证据。超过 6 分钟没有回调的 Hook 审批会进入 `approval_timeout`，防止 Dashboard 永久显示孤儿待确认。

## 8. 验证证据与当前指标

本次升级的测试证据包括：

- `tests/test_pmkb_network_baseline.py`：版本、目录 parity、网络案例规则、Trace、RiskGraph 和统一引擎；
- `tests/test_policy_catalog.py`、`test_policy_models.py`、`test_policy_vectors.py`：schema、冻结、版本和正反例；
- `tests/test_authorization_trace.py`、`test_policy_pipeline.py`：语义到 Hook 决策的运行时接入；
- `tests/test_permission_diff.py`、`test_permission_risk_graph.py`：最小权限、scope expansion 和危险组合；
- `tests/test_principal_capability_rv.py`、`test_principal_rv_hook_integration.py`：跨 session 主体状态和持久化；
- `tests/test_permission_rv_compiler.py`：PMKB 规则/关系自动机编译、effect 投影和 principal 作用域隔离；
- 当前全量回归：`545 passed / 18 skipped / 4 subtests passed`（2026-09-02）；改造前基线 `513 passed / 18 skipped / 4 subtests passed` 仅作历史对照。
- 本次定向回归覆盖 Hook 配置清理、OpenClaw 原生工具映射、PMKB 命中、Trace 编译、session 升权、审批同步、超时收拢和审批文案边界；最终结果为 `192 passed / 4 subtests passed`，详见[审批交接优化结果报告](../research/openclaw-approval-chain-optimization-report-2026-08-30.md)。

路线图目标 `complete coverage ≥85%`、`unknown rate ≤10%`、`low-risk auto-allow precision ≥99%`、`high-risk recall ≥98%`、人工审批量下降 40% 等，当前仅是发布和扩大自动放行范围的验收门槛，尚未由真实个人使用数据验证。

## 9. 当前边界与后续顺序

1. 先补齐工具映射、资源/主体/目的地特征，降低 `unknown/partial`，并用离线向量和最多 20 条相关事件做有限样本校验；不设置一周以上 shadow 观察期；
2. 将仍由 LEGACY 标签表达的高频规则逐条原生化为 PMKB 主体、资源、范围和权限谓词，建立统一规则来源和冲突检查；
3. 增加用户策略叠加层，限定主体、Agent、资源、TTL 和可撤销范围，不能降低 PMKB hard-block；
4. 接入真实使用指标，按规则版本比较命中率、未知率、人工审批量、误报率和高风险召回率；
5. 再评估前端 PMKB 证据视图、文档站 CI、OpenAPI 和生产目录同步。

相关入口：[PMKB 基线条目说明](../semantic/pmkb-network-case-baseline.md)、[语义理解方法](../semantic/method.md)、[路线图](../ops/roadmap.md)、[项目理解与当前记忆](./project-memory.md)。
