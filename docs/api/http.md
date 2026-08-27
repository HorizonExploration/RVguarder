# HTTP 接口

当前本地 Web 工作台使用内建 HTTP 服务，主要接口如下。

## 服务模式

- 默认使用 stdlib `legacy_web`（`openclaw_guard/legacy_web.py`，`ThreadingHTTPServer`），零额外依赖
- 传入 `--fastapi` 时切换到 FastAPI + uvicorn（`openclaw_guard/web/` 包）；若 FastAPI 缺失则自动回退到 legacy 模式

## 配置入口（影响行为）

以下配置用于控制存储后端与 RV 规则驱动模式，属于“启动期配置 + 运行时可切换”的范畴：

### 存储后端选择：`DB_STORE_MODE`

- 环境变量：`DB_STORE_MODE`（或 `OPENCLAW_GUARD_DB_STORE_MODE`）
- 可选值：
  - `native`（默认）：使用内建 `SQLiteStore/PostgreSQLStore`
  - `sqlalchemy`：使用 `SQLAlchemyStore`（需要安装 `[postgres]` extra，含 `psycopg2-binary` 与 `sqlalchemy[asyncio]>=2.0`）
- 配合数据库连接：
  - `DATABASE_URL`（或 `OPENCLAW_GUARD_DATABASE_URL`）可指定 `postgresql://...` 或 `sqlite:///...`

### RV 规则模式默认值：`OPENCLAW_RV_RULE_MODE`

- 环境变量：`OPENCLAW_RV_RULE_MODE`
- 可选值：
  - `dsl`（默认）：规约驱动（ChainRule/DSL → 编译 → 监视器）
  - `fsm`：回退到手写 FSM 监视器
- 运行时也可通过 `/api/rv/toggle` 的 `rule_mode` 字段覆盖（并持久化到 `preferences.json`）

### RV 规则文件路径：`OPENCLAW_RV_RULES_PATH`

- 环境变量：`OPENCLAW_RV_RULES_PATH`
- 用于覆盖 RV 规则文件路径（默认使用内建规则文件），RV 引擎在加载规则时读取

## GET `/api/health`

健康检查接口，返回服务存活状态。

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
- `engine.rule_mode`：当前规则模式（`dsl`/`fsm`）
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

OpenClaw Guard 本地插件内部使用的同步审批接口。

用途：

- 接收 OpenClaw 的 `before_tool_call`
- 生成动作记录
- 执行 `allow / require_approval / block / escalate`
- 返回给 OpenClaw 的 `requireApproval` 遵循官方 `BeforeToolCallResult` 类型
- 当请求的 `toolName` 为 `before_prompt_build` 时，该接口仅执行意图预检查，返回
  `{"action":"allow","precheck":true}`，不会写入动作记录或发布 `action.created`。

## POST `/api/hook/after-tool-call`

OpenClaw Guard 本地插件内部使用的结果回写接口。

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
- `decision` 支持 `allow-once` / `allow-always` / `deny` / `timeout` / `cancelled`（同时兼容 `allow_once` / `allow_always` 旧格式）
- 相同决策重复回调幂等返回；相反决策会返回 `409 resolution_conflict`
- 响应包含 `decision_state`、`sync_state`、`event_seq` 和 `received_at`

## GET `/api/events`

Guard 前端使用的 Server-Sent Events（SSE）单向事件流。

- 支持 `after_seq` 查询参数和 `Last-Event-ID` 断线补偿
- 事件类型包括 `action.created`、`action.resolved`、`action.updated`、`action.conflict`
- SSE 不可用时，前端使用轻量摘要和单动作查询进行降级对账

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
    "policy_version": "1.0.0"
  }
}
```

`effect` 依次支持 `auto_allow_audit`、`clarify_then_retry`、`openclaw_approval` 和
`block`；`match_status` 为 `matched`、`partial`、`unknown` 或 `conflict`。`requested_delta`、
`redundant_permissions` 和 `excessive_permissions` 是 `PermissionRef` 对象数组；若 UI
需要显示 `data.export(scope=own)`，必须明确这是 display transform，不是 API 序列化值。
评估耗时不嵌入 `policy_decision`，而是记录在 event metadata/pipeline timings 中：
`evaluation_ms` 是本次本地 evaluator 耗时，`p95_ms` 是发布窗口统计值。`policy_version`
用于回放与 bundle rollback；证据字段必须原样保留，即使 action 已由其他安全层升级。
