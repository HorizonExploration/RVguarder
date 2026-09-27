# 前端与前后端交接架构改造报告

> **报告日期**：2026-08-23（当前契约于 2026-09-09 复核）
> **适用版本**：RVguarder v0.7.0-dev（含 PMKB 1.2.0）
> **关联记忆**：[项目理解与当前记忆](./project-memory.md)

PMKB 的语义命中、权限组合和 RV 结果现在作为 Guard 只读证据附着在动作记录上；本报告聚焦
前后端交接和审批所有权，不重复定义 PMKB 数据模型，详见[权限知识库与 RV 运行时架构结果](./permission-kb-runtime-architecture.md)。

## 一、结论摘要

当前后端已经形成“语义分析 → PMKB 单步授权 → RV 预判 → Hook 拦截 → 审计”的安全链路；前端承担摘要展示、动作列表、RV 状态和同步状态查询。页面仍是轻量控制面，不拥有 Hook 审批权。

改造前最主要的问题是 Hook 审批职责分裂：同一个 OpenClaw 工具调用同时在 OpenClaw 原生页面和 Guard 页面显示审批弹窗，两个页面都可以发起批准/拒绝，造成状态竞争和同步延迟。该问题已收敛，当前职责明确为：

> **OpenClaw 原生页面是 Hook 工具调用的唯一审批权威；Guard 前端不再审批 Hook 动作，只负责解释风险、展示状态、同步结果和审计取证。**

Guard 仍然保留“是否需要审批”的安全决策权，但不再执行第二次用户批准。Guard 的目标是尽快把 OpenClaw 的审批结果同步到本地动作记录、Trace、审计和 Dashboard。

## 二、当前架构与问题证据

> 本节记录改造前的双审批基线；改造后的事实以第九节“落地记录”和目标职责划分为准。

### 2.1 改造前的双审批基线（历史快照）

```text
OpenClaw before_tool_call
  → Guard /api/hook/before-tool-call
  → Detection + RV
  → Guard 返回 requireApproval
  → OpenClaw 原生审批卡片
       ├─ OpenClaw 用户批准/拒绝
       │    └─ 插件 onResolution
       │         └─ POST /api/hook/resolve-approval
       │              └─ Guard 更新本地 action
       └─ Guard Dashboard 同时显示 approve/reject
            └─ POST /api/actions/approve 或 reject
                 └─ 后台线程调用 Gateway resolve
```

这是 2026-08-23 记录的改造前链路。当前插件已实现 `requireApproval.onResolution`，而 [ActionCard.jsx](../../frontend/src/components/ActionCard.jsx) 对 `hook_bridge` 动作隐藏批准/拒绝按钮；Guard 页面只读显示 OpenClaw 的 resolution 和执行状态。

### 2.2 为什么会出现“响应慢”

#### Guard 页面批准后 OpenClaw 页面变化慢

Guard 侧批准会先更新本地 action，然后在后台线程调用 Gateway 的 `resolve_plugin_approval`。这条路径有几个问题：

- 前端收到“已批准”提示，不代表 OpenClaw Gateway 已确认；
- Gateway 调用在后台线程执行，没有返回明确的同步状态；
- OpenClaw 原生审批卡片的状态变化依赖 Gateway 处理，Guard 页面无法判断当前处于“已发送”还是“已生效”；
- 两个页面同时具有审批权，可能产生重复或冲突决策。

#### OpenClaw 页面批准后 Guard 页面变化慢（历史问题与当前修复）

旧实现主要依赖完整 `/api/summary` 轮询，且曾在发布 `action.resolved` SSE 事件前未完成动作落盘，导致前端立即回读时可能看到旧状态。当前前端以 SSE 为主、10 秒轻量摘要为降级对账；后端已改为**先持久化决策、再发布事件**，并在 `sync.approval` 输出回调计数和延迟指标。

因此剩余延迟主要来自 OpenClaw Gateway 回调、网络断开或回调超时，而非 Guard 的事件发布竞态：

```text
OpenClaw resolution
  → HTTP 回调
  → Guard 持久化动作/审计
  → 发布 action.resolved SSE
  → 前端按 action_id 增量回读
```

## 三、目标职责划分

| 能力 | OpenClaw 原生页面 | Guard 后端 | Guard 前端 |
|---|---|---|---|
| 判断是否需要审批 | 接收结果 | **安全决策权威** | 展示决策原因 |
| 显示审批弹窗 | **唯一审批 UI** | 不显示 | 不再显示二次审批按钮 |
| 用户批准/拒绝 | **唯一用户操作入口** | 接收并记录 resolution | 只读展示 |
| Hook 阻塞/放行 | 执行实际挂起与恢复 | 返回 `requireApproval` / `block` | 不直接控制执行 |
| 风险解释 | 基础标题/描述 | 产生语义、规则、RV、会话证据 | 完整展示证据 |
| 审计 | OpenClaw 自身执行记录 | **完整安全审计链** | 查询和筛选 |
| 状态同步 | 产生 resolution/after-tool-call | **状态源和事件源** | 实时订阅/降级轮询 |

这里的“唯一审批权威”只针对 `hook_bridge` 工具动作。未来如果保留聊天中继（非真实工具执行）的 Guard 本地确认流程，应在数据模型中明确标记 `source=chat_relay`，不能与 Hook 审批混用。

## 四、现行同步架构

### 4.1 单向审批、双向状态同步

```text
Guard 决策：ASK（内部 ESCALATE 仅升权）
        │
        ▼
OpenClaw 原生审批卡片（唯一用户操作）
        │
        ├─ allow-once / deny
        ├─ deny / timeout / cancelled
        ▼
Guard /api/hook/resolve-approval
        │
        ├─ 幂等写入 action resolution
        ├─ 写入审计哈希链
        ├─ 发布 action.resolved 事件
        └─ 更新 Guard Dashboard
        │
        ▼
after_tool_call
        └─ executed / failed 最终对账
```

### 4.2 动作状态模型

兼容字段 `status` 仍保留，但当前实现用独立字段区分“用户决定”“工具执行”和“同步状态”，避免继续扩展单一字符串状态：

```text
decision_state:
  pending → allowed | denied | timed_out | cancelled

execution_state:
  not_started → running → executed | failed

sync_state:
  local_only → callback_received → reconciled | conflict | stale
```

API 返回同时保留 `status` 兼容值和以下结构化字段：

```json
{
  "action_id": "guard-action-123",
  "hook_key": "run-123/tool-456",
  "source": "hook_bridge",
  "decision_state": "allowed",
  "execution_state": "running",
  "sync_state": "callback_received",
  "resolution": {
    "decision": "allow-once",
    "source": "openclaw",
    "received_at": "2026-08-23T12:00:00Z"
  },
  "last_event_seq": 7
}
```

### 4.3 幂等与冲突规则

`/api/hook/resolve-approval` 必须按 `action_id + decision` 或 `hook_key + decision` 幂等：

- 相同 resolution 重复到达：返回 200，不重复执行副作用；
- 已收到 `allow` 后再次收到 `deny`：标记 `conflict`，写审计，不覆盖已有权威决定；
- 已收到 `deny` 后出现 `after_tool_call executed`：标记 `reconciliation_error`，触发告警；
- 找不到 action：保留回调事件到 orphan event 日志，不能静默丢弃；
- callback 超时：前端显示“等待 OpenClaw 回调”，而不是显示“审批失败”。

## 五、前端页面改造建议

### 5.1 安全总览

首页只回答五个问题：

1. Guard 当前是否在线；
2. Hook 是否已加载并真正拦截；
3. 当前是否有待 OpenClaw 处理的审批；
4. 最近是否出现高风险链；
5. 最近一次同步是否成功。

Hook 动作卡片不再显示“批准/拒绝”，改为：

- “请在 OpenClaw 审批中心处理”；
- “打开 OpenClaw”链接；
- 等待中 / 已收到批准 / 已拒绝 / 执行中 / 已完成；
- 最近同步时间和同步延迟；
- 查看风险证据。

### 5.2 审批中心

Guard 页面保留审批记录，但 Hook 动作全部只读：

| 区域 | 内容 |
|---|---|
| 待 OpenClaw 处理 | action、工具、风险级别、原因、创建时间 |
| 已收到 resolution | allow/deny/timeout/cancelled、来源、时间 |
| 执行结果 | running/executed/failed、耗时、错误 |
| 详情面板 | 原始意图、参数摘要、命中规则、RV 链、约束评分、会话状态 |

只有明确标记为 `chat_relay` 的本地动作，才允许保留 Guard 本地确认按钮。

### 5.3 运行时防护页

将当前散落在首页的 RV 状态集中展示：

- RV 总开关；
- ChainRule DSL 规则模式（历史 `fsm` 配置值仅归一化，不加载旧实现）；
- 当前监视器数量和状态；
- session 数量；
- 最近触发的规则；
- 当前有效 RV 窗口与主体成功证据状态；
- baseline DFA 是否启用。

### 5.4 基线与审计页

将当前 `Settings` 页面拆为“基线与审计”：

- 基线扫描启动、进度和结果；
- 检查项分组；
- 审计哈希链完整性；
- 导出任务状态；
- 最近告警和修复建议。

## 六、前后端接口改造

### 6.1 首要接口

```text
POST /api/hook/before-tool-call
POST /api/hook/resolve-approval
POST /api/hook/after-tool-call
GET  /api/actions/{action_id}
GET  /api/actions?status=&source=&limit=
GET  /api/events?after_seq=      # SSE，首选
GET  /api/summary                 # 轻量摘要，不再承载完整状态
```

### 6.2 Resolution 回调响应

`/api/hook/resolve-approval` 应立即返回确认结果，不等待前端刷新或后续执行：

```json
{
  "ok": true,
  "accepted": true,
  "action_id": "guard-action-123",
  "decision_state": "allowed",
  "sync_state": "callback_received",
  "event_seq": 7,
  "received_at": "2026-08-23T12:00:00Z",
  "latency_ms": 148.2
}
```

### 6.3 SSE 事件

当前实现使用单向 SSE，减少 WebSocket 的复杂度：

```text
GET /api/events?after_seq=7
```

事件示例：

```json
{
  "type": "action.resolved",
  "seq": 7,
  "action_id": "guard-action-123",
  "decision": "allow-once",
  "source": "openclaw",
  "at": "2026-08-23T12:00:00Z"
}
```

前端断线时使用 `Last-Event-ID` 或 `after_seq` 补偿；SSE 不可用时，降级到单动作轮询，而不是每次重新请求完整 `summary`。

### 6.4 统一错误模型（已落地）

前端 `api.js` 的 fetch 封装会对非 2xx 响应抛出带 payload 的错误，`apiErrorMessage()` 按 `detail`、`message`、`error` 顺序提取用户可读信息。后端错误响应仍以 FastAPI 路由返回的 JSON 为准；涉及 Hook 的错误应同时记录 `request_id`/动作 ID，避免把网络失败显示成“已批准”。当前约定示例：

```json
{
  "ok": false,
  "error": {
    "code": "gateway_unreachable",
    "message": "无法连接 OpenClaw gateway",
    "retryable": true,
    "request_id": "req-123"
  }
}
```

## 七、迁移步骤与完成情况

### 阶段 1：先关闭双审批入口（已完成）

- Guard Dashboard 对 `hook_bridge` 动作隐藏 approve/reject；
- 卡片改为只读同步状态；
- 保留后端 `/api/actions/approve` 兼容接口，但拒绝处理 Hook 来源动作；
- `chat_relay` 动作暂时保持原有本地确认逻辑；
- 增加日志字段区分 `resolution_source=openclaw` 和 `resolution_source=guard`。

### 阶段 2：修复即时同步（核心链路已完成）

- 让 `resolve-approval` 幂等并立即返回；
- 增加单动作查询接口；
- 前端从全量 summary 轮询改为动作状态轮询；
- 加入 SSE 事件通道；
- 展示“回调已收到”和“执行已完成”两个不同状态。

### 阶段 3：重做页面信息架构（后续）

- Dashboard 改为安全态势；
- Actions 改为审批中心 + 详情面板；
- Settings 拆分为基线审计和系统设置；
- 增加 Runtime、Policies/Integrations 页面；
- 规则页从后端读取规则，不再维护 `rules-data.js` 副本。

### 阶段 4：补测试和性能门禁（持续）

- OpenClaw resolution callback 正常、重复、冲突、超时测试；
- Guard 页面只读 Hook 动作测试；
- 两个浏览器上下文模拟 OpenClaw/Guard 同步测试；
- SSE 断线重连和轮询降级测试；
- 记录 callback-to-render 延迟 p50/p95；
- `summary` 与事件接口分别做响应时间基准。

## 八、验收标准

### 审批职责

- Hook 工具动作在 Guard 页面不再出现可执行的 approve/reject 按钮；
- OpenClaw 原生审批是唯一用户决策入口；
- Guard 页面能明确显示“等待 OpenClaw 处理”。

### 同步时效

- `resolve-approval` 回调写入本地状态：p95 ≤ 300ms；
- Guard 页面收到 resolution：SSE 模式 p95 ≤ 1s；
- 无 SSE 时单动作轮询模式 p95 ≤ 2s；
- resolution 到 `after_tool_call` 的最终状态可对账。

### 一致性与安全

- 重复 callback 不产生重复审计或重复执行；
- allow/deny 冲突会被记录并告警；
- Gateway 不可达时页面显示真实同步状态，不显示虚假的“已批准”；
- 页面不会展示未脱敏的敏感凭据或完整秘密参数；
- 所有状态变化带 `action_id`、`event_seq`、时间戳和来源。

## 九、审批交接改造落地记录（截至 2026-09-09）

本轮已落地阶段 1–2 的核心链路：

- `hook_bridge` 动作在 Guard 页面隐藏批准/拒绝按钮，后端 `/api/actions/approve` 与 `/api/actions/reject` 对其返回 `409 hook_approval_owned_by_openclaw`；
- `/api/hook/resolve-approval` 支持幂等 resolution、冲突标记、来源/时间/序号返回和 orphan event 记录；
- 动作新增 `source`、`decision_state`、`execution_state`、`sync_state`、`resolution`、`last_event_seq` 字段；
- 新增 `GET /api/actions/{action_id}` 和 `GET /api/events`，由 FastAPI 提供 SSE；
- 前端以 SSE 为主、10 秒轻量摘要为降级对账，不再以 1.5 秒完整 summary 作为主要刷新机制；
- summary 支持 `view=compact`，首页只请求概览数据，Skills 页按需加载完整 summary；
- `sync.approval` 提供回调总数、accepted/idempotent/conflict/orphan/invalid/error 计数及最近 128 个延迟样本的 p95；
- 统一前端错误信息读取 `detail`、`message`、`error` 和错误对象本身；
- 新增审批同步回归测试，并更新 Playwright 预期为“Hook 页面只读”；本轮 Chromium 已覆盖 callback → SSE → Guard UI 的即时更新，最终 Python 全量计数以项目记忆和验证记录为准；Checkpoint 摘要、脱敏详情和精确授权撤销入口已纳入交接页面。

当前仍待后续阶段处理：SSE 事件持久化与跨进程恢复、页面信息架构的完整拆分、真实 OpenClaw Gateway 的端到端 p95 采集。当前本地 SSE/HTTP 冒烟只证明 Guard 进程内链路，不等同于真实 Gateway 可用性证明。

## 十、最终建议

本项目不应继续维护“OpenClaw 审批 + Guard 审批”两套并行入口。更稳妥的架构是：

```text
Guard：判断风险、解释风险、记录风险、同步状态
OpenClaw：展示审批、接受用户决定、恢复或拒绝工具执行
```

这样可以消除重复审批、降低 Gateway 状态竞争，并让 Guard 前端从“第二个审批器”转变为真正的安全控制面和取证界面。
