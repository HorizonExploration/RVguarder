# HTTP 接口

当前本地 Web 工作台使用内建 HTTP 服务，主要接口如下。

## GET `/api/summary`

返回聚合状态，包括：

- 产品信息
- 目标 OpenClaw 信息
- 路径
- settings
- capabilities
- baseline
- actions
- chat
- hook
- execution_guard
- skills
- channels
- audit
- policy

## GET `/api/actions`

返回动作列表：

```json
{
  "items": []
}
```

## GET `/api/baseline/latest`

返回最新基线扫描结果。

## GET `/api/audit/export`

导出审计数据。

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

## POST `/api/baseline/run`

立即执行基线扫描。

## POST `/api/actions/approve`

请求体：

```json
{
  "action_id": "xxxx",
  "confirmation_text": "EXECUTE"
}
```

如果动作来自运行时 Hook，这个接口会通过 Gateway 远程调用同步审批结果到 OpenClaw，让原工具调用继续执行。

## POST `/api/actions/reject`

请求体：

```json
{
  "action_id": "xxxx"
}
```

如果动作来自运行时 Hook，这个接口会通过 Gateway 远程调用同步拒绝结果到 OpenClaw，让原工具调用收到拒绝。

## POST `/api/actions/clear`

清空所有动作历史记录。

## POST `/api/hook/before-tool-call`

OpenClaw Guard 本地插件内部使用的同步审批接口。

用途：

- 接收 OpenClaw 的 `before_tool_call`
- 生成动作记录
- 执行 `allow / require_approval / block / escalate`
- 返回给 OpenClaw 的 `requireApproval` 遵循官方 `BeforeToolCallResult` 类型

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

导出审计数据到 `exports/`。

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
