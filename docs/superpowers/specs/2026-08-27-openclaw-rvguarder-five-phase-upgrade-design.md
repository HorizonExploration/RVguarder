# OpenClaw-RVGuarder 五阶段安全升级设计规格

**状态：** 用户已确认的设计规格，待据此拆分执行计划
**日期：** 2026-08-27
**关联研究：** `docs/research/permission-model-kb-and-cross-session-rv-plan.md`
**关联资料：** `/home/yosoro126/documents/openclaw-rvguarder-literature/`

## 1. 目标

在不新增第二审批中心、不让 LLM 充当最终授权决策者的前提下，分阶段降低低风险请求的人工审批负载，并提高工具调用、权限组合和跨 session 风险的可解释检测能力。

最终目标：

- Guard 负责结构化提取、确定性策略、风险证据、审计和状态同步；OpenClaw 负责 Hook 审批卡片和最终人工审批。
- 低风险、证据完整、最小权限范围内的请求自动放行并审计。
- 未覆盖、高影响、冲突或组合风险请求只产生一条 OpenClaw 原生审批。
- 硬阻断、身份不可信、证据完整性异常的请求失败关闭。

## 2. 范围与非目标

### 2.1 本轮范围

1. OpenClaw 插件 Hook 合约、审批回调和 Guard 前端只读同步。
2. 权限模型知识库（PMKB）、语义/参数特征、规则覆盖和正向许可模板。
3. 权限闭包、申请增量、最小必要 Trace 和危险组合检测。
4. 主体/能力谱系约束下的跨 session 运行时验证与状态恢复。
5. 本地攻击回放、影子模式、灰度和量化评估。

### 2.2 非目标

- 不用 OPA、Cedar、OpenFGA、SpiceDB 替换当前在线 Python 引擎；仅吸收其模型、schema、测试和关系图思想，后续单独评估适配器。
- 不在 Guard 页面实现 Hook 的批准/拒绝按钮。
- 不把真实凭据、外部账户、真实 OpenClaw 高风险工具纳入攻击测试。
- 不依据向量相似度或 LLM 输出直接作 `allow` 决策。
- 不以文本相似度、工具名相同或单独的 `goal_id` 合并跨 session 状态。

## 3. 不可违反的全局约束

- OpenClaw 是 Hook 审批唯一所有者；Hook 动作的 Guard API 保持只读同步语义。
- 所有外部 Hook 输入均按不可信数据处理；字段缺失、格式异常或关联失败必须显式记录。
- 现有 `DetectionEngine`、ConstraintEngine、RV DSL/FSM 保持可兼容和可回退，不做一次性替换。
- `before_tool_call` 的本地确定性决策不得等待 LLM、向量服务或远程知识库。
- 每个规则、权限关系、风险组合都必须带版本、来源、正例、反例和回滚状态。
- 每阶段完成前均须执行后端测试、前端构建、文档构建和针对该阶段的性能/回归测试。
- 未经用户批准不得新增需要安装的第三方依赖。

## 4. OpenClaw 合约基线

本项目插件必须以 OpenClaw 的 typed `api.on(...)` Hook 为边界，而不是假设自定义回调语义。

| 合约点 | 设计决定 |
|---|---|
| `before_tool_call` | 唯一能够产生 `requireApproval` 的 Guard Hook；接收工具名、参数、run/session/tool-call 标识，返回 allow/block/requireApproval。 |
| `requireApproval` | 显式传递 `title`、`description`、`severity`、`allowedDecisions`、`timeoutMs`、`onResolution`。 |
| `onResolution` | 只接受 OpenClaw 的 `allow-once`、`allow-always`、`deny`、`timeout`、`cancelled`；Guard 按幂等键写入同一动作。 |
| `allow-always` | 首版只提供 `allow-once` 与 `deny`；只有实现了插件侧持久信任范围、TTL、撤销和审计后才开放。 |
| `before_prompt_build` | 仅用于非阻塞预检查或授权后的 prompt enrichment；不得创建审批单。需要原始对话内容时才开启 `allowConversationAccess`。 |
| 超时 | 移除 `timeoutBehavior`；Guard 决策请求限制在短预算内，Hook 注册使用明确 `timeoutMs`，避免默认 Hook 等待耗尽。 |
| 运行验证 | 配置改动后重启 Gateway；用 `openclaw plugins inspect <id> --runtime --json` 与 `openclaw gateway status --deep --require-rpc` 验证。 |

权威参考：

- [OpenClaw Plugin hooks](https://docs.openclaw.ai/plugins/hooks)
- [OpenClaw Plugin permission requests](https://docs.openclaw.ai/plugins/plugin-permission-requests)
- [OpenClaw configuration reference](https://docs.openclaw.ai/gateway/configuration-reference)
- [OpenClaw plugin CLI](https://docs.openclaw.ai/cli/plugins)

## 5. 飞书权限分类的可迁移设计

飞书开放平台的权限实践提供了个人办公场景所需的粒度参考：应用先声明能力范围，再按业务域、读写动作、资源协作者/可见范围和字段级权限进行约束；机器人身份、用户委托身份和应用发布/管理员审批也相互区分。项目只借鉴这种分层方法，不直接复制飞书 scope 名称或假设 Guard 能替代飞书的授权系统。

### 5.1 权限分类映射

| 飞书式分类 | 本项目统一模型 | 个人办公示例 | 默认风险 |
|---|---|---|---|
| 应用/机器人身份 | `principal`、`agent_id`、`capability_lineage`、`grant_mode` | 用户委托的 agent、独立 bot、skill | 身份混淆可能造成 confused deputy |
| 即时消息 | `message.read/send`、`message.bulk_send` | 读取单聊、发送单聊、群发、发送附件 | 外部/群发不可逆 |
| 通讯录 | `directory.read_basic`、`directory.read_sensitive` | 获取姓名、邮箱、组织关系 | 个人信息暴露 |
| 云文档/知识库/云盘 | `document.read/write/share/export`、`file.read/write/delete` | 读取本人文档、编辑共享文档、生成外链 | 共享范围扩张、批量外发 |
| 电子表格/多维表格 | `table.read/write/export/manage` | 读取字段、更新记录、导出表格、改字段权限 | 批量数据泄露或篡改 |
| 日历/会议 | `calendar.freebusy/read/create/update/delete/invite`、`meeting.recording.read` | 查空闲、创建会议、邀请外部人员、下载录制 | 外部通知、隐私泄露、不可逆取消 |
| 审批/工作流 | `workflow.read/submit/approve/reject/delegate` | 代提交、批量审批、跳过审批人 | 业务控制绕过 |
| 事件/回调/网络 | `event.subscribe`、`network.connect/egress` | 接收事件、调用外部 webhook、上传附件 | 数据外发与供应链风险 |
| 应用配置/发布 | `app.install`、`scope.grant`、`config.modify`、`audit.modify` | 安装 skill、扩大应用 scope、关闭审计 | 持久化越权、绕过监控 |

每个业务域至少拆成 `read`、`create`、`update`、`delete`、`share/export` 和 `admin/delegate` 六类动作；动作之外必须记录资源范围。比如 `document.read` 仅表示动作，不代表可以读取所有文档；最终权限应表达为：

```text
document.read
+ resource_scope = own | explicitly_shared | workspace | external
+ data_classification = public | internal | sensitive | secret
+ field_scope = named_fields | all_fields
+ quantity_limit = N
+ purpose = summarize | prepare_meeting | export_report
+ ttl = duration
```

### 5.2 飞书经验转化为本项目的三个安全边界

1. **应用授权与运行时授权分离。** 飞书应用发布、管理员授予 scope 属于静态能力授予；OpenClaw 每次 Hook 调用属于运行时决策。前者写入 `capability`，后者校验本次 `requested_delta`，不能因为应用曾经获得过宽 scope 就自动放行所有动作。
2. **身份方式必须进入 Trace。** `send_as_bot`、`send_as_user`、用户委托 token 和 skill 继承能力在模型中必须是不同的 `principal/grant_mode`。只有用户身份一致、委托链完整时，才可以把一次批准的能力绑定到后续动作。
3. **资源协作者与字段级授权不可丢失。** 文档被添加为应用协作者、表格只开放部分字段、知识库节点只读等信息，分别建模为 resource relationship 和 field scope；仅记录 `document.read` 或 `table.read` 会产生过度授权假象。

### 5.3 个人办公可信资源的初始规则

在没有组织管理员策略输入时，采用默认拒绝外部边界、显式收敛可信资源的方式：

- `own` 和用户明确共享的单个资源可作为候选可信范围；不能把整个云盘、整个通讯录或整个租户默认视为可信。
- 内部收件人、域名、群组和 webhook 必须进入版本化 allowlist，并记录来源与过期时间；未知外部目标保持 `openclaw_approval`。
- 只读权限默认可进入低风险模板；`write/delete/share/export/admin` 不因同一资源的 read 权限而继承。
- 机器人发信与用户代发、内部群发与外部群发、查看忙闲与读取会议内容必须分别建模。
- 字段级敏感数据（邮箱、联系方式、财务、凭据、聊天记录、会议录音）在 `data.classification` 中单独标注；导出/外发时以最高敏感字段决定风险。
- 所有临时授权都带 `purpose`、`ttl`、`issuer` 和撤销事件；到期后自动回到 `unknown`，而不是继续沿用历史批准。

这套边界可覆盖当前个人办公矩阵中的日历、会议、文档、即时消息、表格、审批、代码仓库和云盘场景，同时避免把飞书租户级管理权限误当作普通办公权限。

参考材料：

- [飞书开放平台](https://open.feishu.cn/)
- [会议室预定 Pad 集成方案：接口权限与机器人通讯录范围](https://open.feishu.cn/community/articles/7271149634339618818)
- [动态用户组与审批联动：临时权限、到期回收与台账](https://open.feishu.cn/community/articles/7329821392785326082)
- [云文档对外分享自动化：时长、关闭日期与统一台账](https://open.feishu.cn/community/articles/7304485933503987713)

## 6. 目标架构

```text
OpenClaw before_prompt_build ──> Guard precheck telemetry (non-blocking)

OpenClaw before_tool_call
  -> Hook payload normalization
  -> Authorization Trace construction
  -> PMKB coverage + deterministic rule evaluation
  -> permission delta + least-privilege + toxic-combination checks
  -> session RV + principal/capability RV
  -> Guard decision
     -> allow: OpenClaw executes tool
     -> requireApproval: OpenClaw owns one approval card
     -> block: OpenClaw blocks tool

OpenClaw onResolution / after_tool_call
  -> idempotent action update + audit append + durable event
  -> SSE cursor replay / HTTP reconciliation
  -> Guard read-only dashboard
```

流水线顺序固定为：

```text
normalize -> annotate -> permission_normalize -> coverage
          -> permission_risk -> detect/constraint -> RV
          -> controller -> audit/event/sync
```

现有 detection、constraint 和 RV 仍可提升风险等级，但不能把 `block`、`ask`、`revise` 降级为 `allow`。

## 7. 核心数据契约

### 7.1 Authorization Trace

在现有 `ToolCallIR` 保持兼容的前提下，新增或标准化以下字段：

```json
{
  "trace_id": "request-or-hook-key",
  "sequence": 0,
  "principal": {"id": "...", "type": "human|agent|skill|service", "trust": "verified|unknown"},
  "agent_id": "...",
  "session_id": "...",
  "goal_id": "optional-task-partition",
  "capability_lineage": ["grant-..."],
  "operation": {"family": "file.read", "tool_id": "...", "arguments": {}},
  "resource": {"type": "file", "ids": [], "scope": "workspace|outside|external"},
  "data": {"classification": "public|internal|sensitive|secret", "quantity": 1},
  "context": {"recipient_zone": "internal|external|unknown", "purpose": "..."},
  "provenance": {"source": "user|tool_output|memory|system", "trust": "..."},
  "coverage": {"status": "complete|partial|unknown", "matched_rules": [], "gaps": [], "conflicts": []},
  "confidence": {"operation": 1.0, "resource": 1.0, "scope": 1.0}
}
```

### 7.2 PolicyDecision

所有决策层必须消费/输出统一证据，避免 DetectionRule 与 ConstraintRule 双轨漂移：

```json
{
  "effect": "allow|clarify|openclaw_approval|block|partial_grant",
  "match_status": "matched|partial|unknown|conflict",
  "match_confidence": 0.0,
  "risk_score": 0,
  "selected_rule_ids": [],
  "candidate_rule_ids": [],
  "missing_features": [],
  "requested_delta": [],
  "redundant_permissions": [],
  "excessive_permissions": [],
  "combo_violations": [],
  "policy_version": "...",
  "replay_hash": "..."
}
```

`match_confidence` 只表示信息与规则覆盖的确定程度；`risk_score` 只用于无硬约束时的排序。两者不得相互替代。

### 7.3 审批与同步状态

Hook 动作保存：`action_id`、`hook_key`、`run_id`、`tool_call_id`、`principal_id`、`policy_version`、`decision_state`、`execution_state`、`sync_state`、`event_seq`、`resolution`。

- `hook_key = runId + toolCallId`；缺失时使用规范化输入指纹，但标记低可信关联。
- 相同 `action_id + decision_state` 回调幂等；相反决策写入冲突审计，不覆盖已决结果。
- 前端以 `event_seq` 递增消费 SSE；重连传递 `Last-Event-ID` 或 `after_seq`，再通过单动作查询对账。

## 8. 五阶段交付

### 阶段 1：OpenClaw 合约与审批同步基础

**目的：** 消除伪审批、缩短 Hook 决策等待、保证 OpenClaw 审批回写的一致性。

**代码边界：**

- `openclaw_guard/integrations/hook_runtime.py`
- 生成的 `runtime/openclaw-guard-plugin/index.js`
- `openclaw_guard/integrations/tool_hook_bridge.py`
- `openclaw_guard/engine/pipeline.py`
- `openclaw_guard/core/action_service.py`
- `openclaw_guard/api/_handlers.py`、`openclaw_guard/events.py`
- `frontend/src/store.js`、`frontend/src/api.js`、`frontend/src/pages/Dashboard.jsx`、`frontend/src/pages/Actions.jsx`

**实现：**

1. 增加独立 precheck payload/endpoint；`before_prompt_build` 不再发送伪 `toolName`。
2. 生成插件中将 `{ name: ... }` 改为官方 `registrationId`，给策略 Hook 设置短 `timeoutMs`。
3. `before_tool_call` 仅在 Guard 返回 `openclaw_approval` 时返回 `requireApproval`，并只提供 `allow-once/deny`。
4. 移除 `timeoutBehavior` 和 180 秒同步决策等待；失败关闭/失败打开由显式配置与审计状态表达。
5. 以持久化动作记录为真相源；EventBus 只作通知，SSE 重连可回放或降级对账。
6. 前端显示审批所有者、同步状态、最后事件序号和延迟，不显示 Hook 本地批准按钮。

**阶段退出：** 每个工具调用最多一个待审批动作；precheck 无待审批；重复/乱序 resolution 不篡改结果；运行态检查通过。

### 阶段 2：PMKB 与规则匹配升级

**目的：** 将“标签精确命中失败就审批”改为可解释的覆盖、澄清和低风险许可。

**代码边界：**

- 新建 `openclaw_guard/policy/ontology.py`、`catalog.py`、`evaluator.py`
- 新建 `policies/permissions/` 下的 versioned JSON/YAML 资料
- 扩展 `openclaw_guard/rv/ir.py`、`engine/semantic_enhancer.py`、`engine/detection.py`、`rv/constraints.py`
- 新建规则覆盖、同义改写、参数解析和许可模板测试

**实现：**

1. 规范权限族、工具别名、资源类型、作用域、数据级别、风险元数据和来源。
2. 参数结构化：命令动词/路径/管道/重定向、URL、邮箱、收件人、批量数、否定和排除条件。
3. 将规则统一为有 ID、版本、前置条件、effect、例外、正反例和 test vector 的 policy record。
4. 输出 `complete/partial/unknown/conflict` 覆盖结论及缺失字段，不再让低置信度结果静默消失。
5. 建立受限正向许可模板，支持 `auto_allow_audit`、`clarify_then_retry`、`openclaw_approval`、`fail_closed` 四级路由。

**阶段退出：** 高价值场景完整覆盖率相对基线提升至少 25 个百分点；未知率不高于 10%；低风险自动放行精确率至少 99%。

### 阶段 3：权限组合与最小权限决策

**目的：** 对已有权限与新增申请做组合安全校验和业务最小必要 Trace 校验。

**代码边界：**

- 新建 `openclaw_guard/policy/permission_diff.py`、`risk_graph.py`
- 扩展 PolicyDecision、pipeline、审计导出和前端 Action 证据展示
- 新建权限闭包、冗余、作用域扩张、SoD、危险组合测试

**实现：**

1. 计算 `P_effective`、`requested_delta`、`P_after`，支持角色继承、临时授权、能力委派、撤销和过期。
2. 建立 `implies`、`conflicts`、`toxic_with`、`delegates`、`owns` 关系与稀疏超边索引。
3. 对 `secret.read + egress`、`credential.read + execute`、`config.modify + audit.disable` 等首批组合实施硬约束。
4. 将申请权限和任务所需 Trace 比对，输出冗余、过度权限和范围扩张；允许 `partial_grant` 只保留必要权限。
5. 采用约束型决策：硬阻断优先；只有无硬约束时再使用 0～100 的可解释风险分数。

**阶段退出：** 危险组合召回率至少 98%，硬阻断漏报为 0；所有审批均展示新增权限、最小权限差异和命中证据。

### 阶段 4：跨 session 运行时验证

**目的：** 在可信主体和能力谱系范围内识别跨 session 的权限积累与数据流风险。

**代码边界：**

- 扩展 `openclaw_guard/spec/session_state.py`、`rv/runtime_verification.py`
- 新建全局安全状态/持久化适配器，复用现有 SQLite/JSON 能力
- 扩展审计、状态查询、snapshot/replay、跨 session 夹具

**实现：**

1. 保留 session-local FSM/RV；新增 principal/capability/goal 分层状态。
2. 将 `goal_id` 限定为任务分区；只有 principal、agent、capability lineage 一致时才允许合并。
3. 记录单调序号、TTL、snapshot、replay hash、撤销与过期事件；重启后恢复等价状态。
4. 对同一可信谱系的“敏感读取 → 外发”等链条做跨 session 检测；身份缺失或不一致进入隔离/审批。

**阶段退出：** 跨 session 攻击夹具被识别；不同主体的错误合并率为 0；重放前后决策、策略版本和审计证据一致。

### 阶段 5：攻击验证、影子与灰度

**目的：** 证明审批负载下降并未以危险误放行为代价。

**代码边界：**

- `testlab/research/` 本地夹具、场景、oracle 和报告生成
- 新建指标聚合/导出能力和影子模式开关
- 更新 API、运行、研究和运维文档

**实现：**

1. 将 AgentDojo/InjecAgent/PyRIT/garak 的思路映射为本地无副作用测试，不复制真实凭据或攻击载荷。
2. 建立安全正例、风险反例、边界样例和未知样例四个互斥集。
3. 影子模式并行运行旧/新引擎，只记录差异不改变线上审批。
4. 评估覆盖率、精确率、召回率、人工审批量、同步延迟、P50/P95/P99 和审计完整性。
5. 从低风险许可模板开始灰度；任一硬风险漏报、自动放行精确率下滑或同步异常立即回滚规则版本。

**阶段退出：** 总人工审批下降至少 40%，低风险审批下降至少 60%，高风险召回至少 98%，自动放行精确率至少 99%，本地确定性匹配 P95 不高于 50ms，审批同步 P95 不高于 1 秒。

## 9. 验证策略

每阶段均遵循测试先行：

1. 为新增接口/规则写失败测试和最小 mock 输入。
2. 运行聚焦测试确认失败原因是功能未实现。
3. 实施最小变更使测试通过。
4. 执行全量 `python -m pytest -q`、前端 `npm run build`、文档 `npm run docs:build`。
5. 对 Hook 生成物执行 `node --check`，并用 OpenClaw CLI 在已安装环境中做 runtime inspection。
6. 记录性能基线和策略版本；只在满足阶段门槛后扩大自动放行范围。

## 10. 回滚策略

- 每个 policy bundle、权限关系和风险组合都有独立 `policy_version` 与启停开关。
- 规则或模型升级失败时，回退到前一版本的 catalog/rules，不删除审计记录和历史实验产物。
- PMKB、权限组合和跨 session 监控初始均可以影子模式运行。
- Hook 合约异常时，按部署配置选择 fail-closed 或明确记录的 fail-open；不得无日志地降级。
- Guard 前端同步异常不会改变 OpenClaw 的审批所有权或审批结果。

## 11. 文档与可观测性要求

- `docs/api/http.md`：Hook payload、审批同步、SSE cursor 和状态字段。
- `docs/features/runtime-hook.md`：官方 Hook 合约映射、配置、重启和诊断命令。
- `docs/semantic/method.md`：Authorization Trace、PMKB、匹配状态和澄清路由。
- `docs/ops/roadmap.md`：阶段状态、指标和回滚门槛。
- 每次策略决策写入 `policy_version`、`match_status`、`unknown_reason`、`rule_evidence`、`risk_score`、`human_override`、`final_outcome` 与延迟字段。

## 12. 规格自检结论

- 五个阶段覆盖了 Hook 合约、匹配治理、权限组合、跨 session RV 和攻击验证。
- 每个阶段都有明确代码边界、不可违反约束、量化退出标准和可回退边界。
- 本规格不要求新增在线外部策略引擎或第二审批界面。
- 实际阈值在阶段 1 基线和阶段 5 影子数据产生前均为发布门槛，不视为已达成结果。
