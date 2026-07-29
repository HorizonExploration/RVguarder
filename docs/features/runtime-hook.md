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

### 电路熔断器（Circuit Breaker）

Guard 后端可能因维护、故障或网络隔离而不可达。为了避免「后端停服 → 全盘封锁 OpenClaw」，插件内置三层降级保护：

1. **优雅期（Grace Period）**：首次检测到后端不可达时，进入 30 秒优雅期。优雅期内返回 `{ block: true }` 硬阻块。
2. **熔断打开（Circuit OPEN）**：优雅期结束后，若连续失败 ≥ 3 次，熔断器进入 **OPEN**（fail-open）状态。此时所有工具调用绕过审批直接执行，不再封锁 OpenClaw。
3. **熔断闭合（Circuit CLOSED）**：后端恢复后，健康检查连续成功 ≥ 2 次，熔断器自动闭合，恢复 fail-closed 审批模式。

行为总结：

| 后端状态 | 熔断器状态 | 行为 | 含义 |
|----------|-----------|------|------|
| 正常 | CLOSED | 返回 requireApproval / block / allow | 正常审批 |
| 刚断开（< 30s） | CLOSED（优雅期） | 返回 block | 短时故障硬阻块 |
| 断开（> 30s，≥ 3 次失败） | OPEN | 返回 undefined（放行） | 后端停服不封锁 OpenClaw |
| 恢复（≥ 2 次健康检查成功） | CLOSED | 返回 requireApproval / block / allow | 恢复正常审批 |

通过 `pluginConfig` 可配置：

```javascript
pluginConfig = {
  failClosed: true,                    // false: 后端不可达时直接放行（不进入优雅期）
  failThreshold: 3,                    // 连续失败次数阈值
  recoveryThreshold: 2,                // 恢复成功次数阈值
  failClosedGracePeriodMs: 30000,      // 优雅期毫秒数
}
```

> **注意**：`failClosed: false` 时，后端不可达会直接放行所有工具调用（跳过优雅期和熔断），适用于不希望任何锁定的场景。

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

---

## 附：RV 模式

### 什么是 RV 模式

RV（Runtime Verification，运行时验证）模式是龙虾卫士的一项可选高级安全能力。开启后，系统会在常规规则引擎之外，额外运行一套**办公场景 FSM 监视器**，通过滑动窗口分析工具调用的行为序列，识别链式风险。

### RV 模式能做什么

| 场景 | 检测内容 | 判定 |
|------|---------|------|
| 邮件外发 + 敏感内容 | 外部收件人 + 含敏感信息 | block |
| 邮件群发 / AI 草稿 | 群发或 AI 内容未审阅 | ask |
| 日报外发 + 内部来源 | 内部日报发到外部 | block |
| 搜索文件 → 删除 | 先搜索高价值路径后删除 | block |
| 关闭审计 → 改配置 | 先关审计后改配置 | block |
| 下载附件 → 外传 | 下载后外发或发邮件 | escalate |
| 读取凭据 → 网络连接 | 读敏感凭据后外联 | escalate |
| 批量删除累积 | 10 次以上 ask / 50 次以上 block | ask / block |
| 数据库查询后导出 | 查敏感表后导出 | escalate |
| 批量上传到外部 | 大批量文件发往外网 | escalate |
| 共享链接权限变更 | 改为公开或移除密码 | ask |

### 开启/关闭 RV 模式

在龙虾卫士 Dashboard 右上角，点击 **RV 模式** 开关按钮：

- **开启**（绿色高亮）：Dashboard 显示安全执行链路 Trace 时间线和 RV 引擎状态面板
- **关闭**（灰色）：恢复标准视图，隐藏 Trace 和 RV 详情

切换实时生效，状态持久化到浏览器本地存储。

### RV 模式激活后的 UI 变化

| 区域 | 常规模式 | RV 模式 |
|------|----------|---------|
| Dashboard | 概览、统计、待审批、最近动作 | 额外显示 Trace 时间线 + RV 引擎状态面板 |
| 动作卡片 | 风险标签、原因 | 额外显示 RV 判定徽章 |
| 引擎状态 | 不可见 | 显示监视器数量、窗口大小、快照 |

### RV 后端 API

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/rv/status` | GET | 返回 RV 引擎当前状态（监视器数、窗口大小、窗口快照） |
| `/api/rv/toggle` | POST | 切换 RV 模式（`{"enabled": true/false}`） |
| `/api/summary` | GET | 返回的 `rv` 字段包含当前模式和引擎摘要 |
