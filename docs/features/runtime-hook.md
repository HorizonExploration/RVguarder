# 运行时 Hook 拦截

## 这页讲什么

这一页说明龙虾卫士如何在**不修改 OpenClaw 源码**的前提下，把高风险工具调用真正拦在执行前，以及如何实现 OpenClaw 原生审批与 Guard Dashboard 之间的双向状态同步。

## 核心机制

龙虾卫士不会去改 OpenClaw 内部逻辑，而是利用 OpenClaw 自带的插件能力：

- 生成一个本地插件包（`runtime/openclaw-guard-plugin/`）
- 写入 `plugins.load.paths` 和 `plugins.entries`
- 在插件里注册（使用官方 `api.on()` API）：
  - `before_tool_call` — 工具调用拦截主钩子
  - `after_tool_call` — 执行结果回写
  - `before_prompt_build` — 意图预警（非阻塞）
  - `openclaw_guard.hook_status` — Gateway 健康检查

### API 说明

插件使用 OpenClaw 官方 `api.on()` API 注册钩子（非已废弃的 `api.registerHook()`）：

```javascript
// 正确用法（当前实现）
api.on("before_tool_call", async (event, hookCtx) => {
  // ...
});
```

## 实际链路

```text
OpenClaw 进入工具调用
  -> api.on("before_tool_call")
  -> 调用 Guard 本地 API (/api/hook/before-tool-call)
  -> Guard 转成行为事件
  -> 风险判定
  -> allow / ask (require_approval) / block / escalate
  -> require_approval 时 OpenClaw 挂起 agent，展示审批卡片
  -> 用户在 OpenClaw 原生 UI 或 Guard Dashboard 批准
  -> 双端同步：onResolution 推送 / Gateway 远程调用
  -> 批准后继续原工具调用
  -> after_tool_call 回写执行结果
```

## requireApproval 返回格式

插件返回的 `requireApproval` 对象遵循 OpenClaw 官方 `BeforeToolCallResult` 类型：

```javascript
{
  requireApproval: {
    pluginId: "openclaw-guard-hook",      // 插件标识
    title: "龙虾卫士安全审批",              // 审批卡片标题
    description: "拦截动作：write_file",    // 审批卡片描述
    severity: "warning",                    // "info" | "warning" | "critical"
    timeoutMs: 300000,                      // 5 分钟超时
    timeoutBehavior: "deny",                // 超时后自动拒绝（不设为 allow）
    onResolution: async (decision) => {     // 审批决策回调
      // decision: "allow-once" | "allow-always" | "deny" | "timeout" | "cancelled"
      await postJson(`${guardUrl}/api/hook/resolve-approval`, {
        actionId: result.action_record.action_id,
        decision: decision,
      });
    },
  }
}
```

### fail-closed 模式

当 Guard 后端不可达时，根据 `failClosed` 配置决定行为：

- **failClosed = true**（默认）：返回 `{ block: true, blockReason: "Guard backend unreachable..." }`，工具调用被硬阻块
- **failClosed = false**：返回 `undefined`，工具调用绕过审批继续执行

## 双端同步机制

系统使用双向同步确保 OpenClaw 原生审批与 Guard Dashboard 状态一致：

### Dashboard → OpenClaw

用户在 Guard Dashboard 点击「确认继续」或「拒绝」时：

1. 后端更新 `action_service` 中动作状态
2. 异步调用 `resolve_plugin_approval(target, plugin_id, run_id, decision)` 通过 `openclaw gateway call` 通知 OpenClaw
3. Gateway 方法：优先 `approvals.resolve`，回退 `plugin.resolveApproval`
4. OpenClaw 原生审批卡片同步更新状态，agent 继续执行

### OpenClaw 原生 → Dashboard

用户在 OpenClaw 原生审批 UI 中批准/拒绝时：

1. 插件 `onResolution` 回调触发，POST `/api/hook/resolve-approval`
2. 后端 `resolve_hook_approval` 处理：字段名兼容 `actionId`/`action_id`，决策值兼容 `allow-once`/`allow_once`
3. Guard Dashboard 通过轮询自动获取最新状态

## 首次启用

第一次在某个 OpenClaw 环境里启用龙虾卫士时，会自动生成：

- `runtime/openclaw-guard-plugin/` — 插件包（含 `package.json`、`openclaw.plugin.json`、`index.js`）
- `runtime/hook-bridge.json` — 鉴权 token 和 Guard 地址

并把插件路径和配置写进当前 `openclaw.json`。

插件包结构：

```
runtime/openclaw-guard-plugin/
├── package.json           # npm 包描述（openclaw.extensions）
├── openclaw.plugin.json   # 插件清单（activation.onStartup: true）
└── index.js               # 插件入口（api.on 注册钩子）
```

完成后需要按真实启动方式重启一次 OpenClaw gateway：

```bash
cd <openclaw-source-root>
npm run openclaw gateway
```

否则插件虽然已经写进配置，但还不会加载到运行时。

## 当前会被拦住的典型动作

- 删除工作区外文件
- 删除敏感目录
- 写入工作区外文件
- 修改 `openclaw.json`
- 执行高危命令
- 外联和 webhook

## UI 里会看到什么

### OpenClaw 原生审批卡片

工具调用被拦截时，OpenClaw 直接在界面上弹出审批卡片，显示动作名称和风险等级，用户可「允许一次」「始终允许」「拒绝」。

### Guard Dashboard

- 动作页出现 `pending_approval`
- 批准后动作变为 `approved -> executing`，同时 OpenClaw 卡片同步更新
- 工具执行结束后回写 `executed` 或 `failed`
- 如果用户拒绝，动作保持 `rejected`，原工具不会继续

## 当前边界

- 当前拦的是经过 OpenClaw `before_tool_call` 的工具路径。
- 如果某个内部行为没有走这个 Hook，就还不在这条链里。
- 运行时 Hook 已经是真正执行前拦截，OpenClaw agent 会通过 `requireApproval` 挂起执行线程，等待用户决策。
- 插件使用 `api.on()` API（非已废弃的 `api.registerHook()`），需要 OpenClaw Plugin SDK >= 2026.4.0。

## 对照官方资料

- [OpenClaw Plugin Hooks 官方文档](https://github.com/openclaw/openclaw/blob/main/docs/plugins/hooks.md)
- [OpenClaw Hooks](https://docs.openclaw.ai/automation/hooks)
- [OpenClaw Session Management](https://docs.openclaw.ai/concepts/session)
