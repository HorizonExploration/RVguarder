# HTTP 接口

当前本地 Web 工作台仅使用 FastAPI HTTP 服务，主要接口如下。

## 服务模式

- 默认且唯一使用 FastAPI + uvicorn（`openclaw_guard/web/` 包）
- 旧版 stdlib HTTP 实现已移出生产包；依赖缺失时不会静默回退，必须安装 FastAPI Web extra

## 配置入口（影响行为）

以下配置用于控制存储后端与 RV 规则文件，属于启动期配置；RV 规则模式不再提供生产切换。

### 存储后端选择：`DB_STORE_MODE`

- 环境变量：`DB_STORE_MODE`（或 `OPENCLAW_GUARD_DB_STORE_MODE`）
- 可选值：
  - `native`（默认）：使用内建 `SQLiteStore/PostgreSQLStore`
  - `sqlalchemy`：使用 `SQLAlchemyStore`（需要安装 `[postgres]` extra，含 `psycopg2-binary` 与 `sqlalchemy[asyncio]>=2.0`）
- 配合数据库连接：
  - `DATABASE_URL`（或 `OPENCLAW_GUARD_DATABASE_URL`）可指定 `postgresql://...` 或 `sqlite:///...`

### RV 规则模式：DSL-only

- `ChainRule DSL → compile_monitors()` 是唯一生产路径。
- 历史 `OPENCLAW_RV_RULE_MODE=fsm` 或 `/api/rv/toggle` 的 `rule_mode=fsm` 输入会被归一化为 `dsl`，不会加载手写 FSM，也不会改变审批流程。
- `/api/rv/toggle` 仍只负责 `enabled` 总开关；旧 `rule_mode` 字段仅为旧配置平滑迁移保留。

### RV 规则文件路径：`OPENCLAW_RV_RULES_PATH`

- 环境变量：`OPENCLAW_RV_RULES_PATH`
- 用于覆盖 RV 规则文件路径（默认使用内建规则文件），RV 引擎在加载规则时读取

## GET `/api/health`

健康检查接口，返回服务存活状态以及当前实际加载的策略指纹。插件或排障脚本可用这些字段
判断 Guard 是否仍运行旧进程/旧规则包。

```json
{
  "ok": true,
  "policy_version": "1.2.0",
  "policy_rule_count": 79,
  "policy_fingerprint": "<16 位哈希前缀>"
}
```

## GET `/api/summary`

返回聚合状态，包括：

使用 `?view=compact` 时返回首页所需的轻量摘要；不带参数时返回完整详情。

- `generated_at`：生成时间（ISO 8601）
- `product`：产品信息
- `target`：目标 OpenClaw 信息
- `paths`：路径
- `settings`
- `capabilities`
- `baseline`
- `actions`
- `console`：控制台摘要
- `chat`
- `hook`
- `execution_guard`
- `sync.approval`：OpenClaw 审批回调聚合计数与 `latency_ms`（count/last/min/max/p95）
- `skills`
- `channels`
- `preferences`：偏好设置（含 RV 模式等）
- `audit`
- `policy`
- `rv`：RV 引擎状态（mode/engine）

## GET `/api/actions`

返回动作列表：

```json
{
  "items": []
}
```

可选查询参数：`status`、`source`（`hook_bridge`/`chat_relay`）和 `limit`。

## GET `/api/actions/{action_id}`

返回单个动作的最新状态，用于 SSE 事件后的增量刷新。

## GET `/api/baseline/latest`

返回最新基线扫描结果。

## GET `/api/audit/export`

导出审计数据到 `output/audit/`（生成 `audit-export.json` / `audit-export.csv`）。

## GET `/api/runtime/refresh`

重新探测当前 OpenClaw 运行目标，并刷新：

- `config_path`
- `profile`
- `gateway_urls`
- `auth_mode`
- `hook`

这个接口适合在你已经重启 OpenClaw gateway 后，让 Guard 立刻重新判断当前 Hook 状态。

## GET `/api/debug/logs`

返回运行时日志记录。

## GET `/api/rv/status`

返回 RV 引擎当前状态（用于前端展示与回归断言）。

响应体示例：

```json
{
  "ok": true,
  "mode": true,
  "engine": {
    "window_size": 0,
    "monitor_count": 6,
    "rule_mode": "dsl",
    "session_key": "_default",
    "monitor_states": {},
    "window_snapshot": []
  },
  "session_count": 1
}
```

字段说明：

- `mode`：是否启用 RV（来自 `preferences.json`，默认 true）
- `engine.rule_mode`：当前规则模式（固定为 `dsl`）
- `engine.window_snapshot`：窗口快照（仅保留 props 的前 6 个用于 UI 展示）

## POST `/api/rv/toggle`

切换 RV 启用状态，并可选地切换规则模式。

请求体：

```json
{
  "enabled": true,
  "rule_mode": "dsl"
}
```

- `enabled`：是否启用 RV（缺省为 true）
- `rule_mode`：可选；传入时会同时切换 RV 引擎规则模式并写入 `preferences.json`

响应体：

```json
{
  "ok": true,
  "rv_mode": true,
  "rule_mode": "dsl"
}
```

## POST `/api/baseline/run`

立即执行基线扫描。

## POST `/api/actions/ingest`

接收外部行为事件（聊天/语义增强入口），返回动作处理结果。

## POST `/api/actions/approve`

请求体：

```json
{
  "action_id": "xxxx",
  "confirmation_text": "EXECUTE"
}
```

Hook 动作不能通过 Guard 页面审批，会返回 `409 hook_approval_owned_by_openclaw`。Hook 的唯一审批入口是 OpenClaw 原生审批卡片；该接口仅兼容 `chat_relay` 等本地动作。

## POST `/api/actions/reject`

请求体：

```json
{
  "action_id": "xxxx"
}
```

Hook 动作不能通过 Guard 页面拒绝，会返回 `409 hook_approval_owned_by_openclaw`。Hook 拒绝结果由 OpenClaw 原生审批卡片产生并回调 Guard。

## POST `/api/actions/clear`

清空所有动作历史记录。

## POST `/api/hook/before-tool-call`

RVguarder 本地插件内部使用的同步审批接口。

用途：

- 接收 OpenClaw 的 `before_tool_call`
- 生成动作记录
- 执行 `allow / require_approval / block`；内部 RV `escalate` 在 Hook 出口统一折叠为 `require_approval`
- 返回给 OpenClaw 的 `requireApproval` 遵循官方 `BeforeToolCallResult` 类型
- `require_approval` 返回 `title`、`message`、`user_summary`、`approval`、`allowed_decisions`、`policy_version` 和 `technical_reason`；
  OpenClaw 弹窗只使用中文 `title/message`，技术原因仅供 Guard 审计和排障。
- `before_prompt_build` 不属于生产插件注册的 Hook；该接口只处理实际 `before_tool_call`。

## POST `/api/hook/after-tool-call`

RVguarder 本地插件内部使用的结果回写接口。

用途：

- 接收 OpenClaw 的 `after_tool_call`
- 把动作状态改成 `executed` 或 `failed`
- 写入审计与日志

## POST `/api/hook/resolve-approval`

OpenClaw 原生审批卡片 `onResolution` 回调使用的接口。

用途：

- 接收 OpenClaw 插件 `onResolution` 的审批结果
- 同步更新 Guard `action_service` 中动作状态

请求体：

```json
{
  "actionId": "xxxx",
  "decision": "allow-once"
}
```

- `actionId` 也兼容 `action_id` 字段名
- `decision` 支持 `allow-once` / `allow-always` / `deny` / `timeout` / `cancelled`（兼容下划线旧格式）；`allow-always` 仅在低风险精确命令满足资格时接受，否则返回 `400 allow_always_not_eligible`
- `allow-always` 会写入 `runtime/approval-trust.json`，默认 30 天有效；fingerprint 同时绑定工具、完整参数、工作目录和 agent/principal
- `allow-always` 还要求已验证的 agent/principal、服务端确认的 Hook token 上下文（并绑定当前安装实例）、确定性只读命令和非敏感目标；`.env`、`.git`、凭据/密钥路径、命令中的凭据参数以及无法收敛参数的未知工具会返回 `400 allow_always_not_eligible`
- 权限证据同时返回 `effective_permissions`、`p_after`、`scope_expansions` 和 `hard_violations`，用于核对主体当前授权、申请后授权集合及最小权限越界。
- 相同决策重复回调幂等返回；相反决策会返回 `409 resolution_conflict`
- 响应包含 `decision_state`、`sync_state`、`event_seq`、`received_at` 和 `latency_ms`

## GET `/api/events`

Guard 前端使用的 Server-Sent Events（SSE）单向事件流。

- 支持 `after_seq` 查询参数和 `Last-Event-ID` 断线补偿
- 事件类型包括 `action.created`、`action.resolved`、`action.updated`、`action.timeout`、`action.conflict`
- SSE 不可用时，前端使用轻量摘要和单动作查询进行降级对账

## GET `/api/approval-trust`

返回当前未过期的精确命令授权记录，供 Guard 设置页展示。

## POST `/api/approval-trust/revoke`

请求体 `{ "fingerprint": "..." }`，撤销一条精确命令授权；撤销不影响历史审计记录。

## POST `/api/skills/upsert`

创建或更新一个 skill 配置。

请求体：

```json
{
  "name": "my-skill",
  "enabled": true,
  "description": "...",
  "permissions": ["read", "write"]
}
```

## POST `/api/skills/delete`

删除一个 skill 配置。

请求体：

```json
{
  "name": "my-skill"
}
```

## POST `/api/channels/upsert`

创建或更新一个 channel 配置。

请求体：

```json
{
  "name": "my-channel",
  "enabled": true,
  "target": "..."
}
```

## POST `/api/channels/delete`

删除一个 channel 配置。

请求体：

```json
{
  "name": "my-channel"
}
```

## POST `/api/audit/export`

导出审计数据到 `output/audit/`（生成 `audit-export.json` / `audit-export.csv`）。

## 错误返回

接口失败时会返回：

```json
{
  "error": "message_empty",
  "error_code": "message_empty",
  "detail": "输入不能为空。"
}
```

常见的错误码：

| 错误码 | 含义 |
|--------|------|
| `message_empty` | 输入不能为空 |
| `action_not_found` | 未找到对应动作记录 |
| `action_already_terminal` | 同一 after_tool_call 已经提交过，拒绝重复提交 |
| `hook_context_mismatch` | after_tool_call 与 before_tool_call 的工具、运行或身份上下文不一致 |
| `gateway_unreachable` | 无法连接 OpenClaw gateway |
| `hook_unauthorized` | Hook 鉴权失败 |
| `internal_error` | 服务内部错误 |

## 策略证据（只读）

动作和审计查询可在 `decision.policy_decision` 中返回 PMKB 证据。Guard API 对这些字段
只读展示（read-only），不能从 Dashboard 修改审批结果：

```json
{
  "policy_decision": {
    "effect": "openclaw_approval",
    "match_status": "partial",
    "missing_features": ["context.recipient_zone"],
    "requested_delta": [
      {"family": "data.export", "scope": "own", "classification": "internal"}
    ],
    "redundant_permissions": [],
    "excessive_permissions": [],
    "combo_violations": [],
    "policy_version": "1.2.0"
  }
}
```

`effect` 依次支持 `auto_allow_audit`、`openclaw_approval` 和
`block`；`match_status` 为 `matched`、`partial`、`unknown` 或 `conflict`。`requested_delta`、
`redundant_permissions` 和 `excessive_permissions` 是 `PermissionRef` 对象数组；若 UI
需要显示 `data.export(scope=own)`，必须明确这是 display transform，不是 API 序列化值。
评估耗时不嵌入 `policy_decision`，而是记录在 event metadata/pipeline timings 中；当前实现
字段为 `policy_ms`。`evaluation_ms` 与发布窗口聚合的 `p95_ms` 是后续只读指标采集器的
兼容字段，未在当前版本承诺。`policy_version`
用于回放与 bundle rollback；证据字段必须原样保留，即使 action 已由其他安全层升级。
