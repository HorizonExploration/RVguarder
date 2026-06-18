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
- console
- chat
- hook
- audit
- policy

## GET `/api/conversation`

返回当前会话摘要：

- `messages`
- `pending_requests`
- `request_count`
- `workspace`
- `profile`
- `connection_state`

## GET `/api/actions`

返回动作列表：

```json
{
  "items": []
}
```

## GET `/api/chat/debug`

返回聊天链和 Hook 链的调试信息，包括：

- `profile`
- `config_path`
- `gateway_urls`
- `relay`
- `hook`
- `log_path`

## GET `/api/runtime/refresh`

重新探测当前 OpenClaw 运行目标，并刷新：

- `config_path`
- `profile`
- `gateway_urls`
- `auth_mode`
- `hook`

这个接口适合在你已经重启 OpenClaw gateway 后，让 Guard 立刻重新判断当前 Hook 状态。

## POST `/api/chat/send`

请求体：

```json
{
  "message": "请删除 /Users/dynooob/secret.txt"
}
```

作用：

- 发送用户请求
- 触发动作推断
- 经过检测引擎和 action gate
- 返回更新后的消息流与动作结果

低风险消息会继续转发到 OpenClaw gateway。高风险消息会先进入待审批，不会直接继续。

## POST `/api/chat/new`

开启一个新的对话会话。

## POST `/api/chat/poll`

轮询当前聊天动作是否已收到 OpenClaw 回复。

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

如果动作来自运行时 Hook，这个接口会直接唤醒等待中的 `before_tool_call`，让原工具调用继续执行。

## POST `/api/actions/reject`

请求体：

```json
{
  "action_id": "xxxx"
}
```

如果动作来自运行时 Hook，这个接口会让原工具调用收到 `block` 结果。

## POST `/api/hook/before-tool-call`

OpenClaw Guard 本地插件内部使用的同步审批接口。

用途：

- 接收 OpenClaw 的 `before_tool_call`
- 生成动作记录
- 执行 `allow / ask / block / escalate`
- 等待 UI 里的批准或拒绝

## POST `/api/hook/after-tool-call`

OpenClaw Guard 本地插件内部使用的结果回写接口。

用途：

- 接收 OpenClaw 的 `after_tool_call`
- 把动作状态改成 `executed` 或 `failed`
- 写入审计与日志

## POST `/api/audit/export`

导出审计数据到 `exports/`。

## 错误返回

接口失败时会返回：

```json
{
  "error": "message_empty",
  "error_code": "message_empty",
  "message": "消息内容不能为空。"
}
```
