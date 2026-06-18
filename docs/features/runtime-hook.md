# 运行时 Hook 拦截

## 这页讲什么

这一页说明龙虾卫士如何在**不修改 OpenClaw 源码**的前提下，把高风险工具调用真正拦在执行前。

## 核心机制

龙虾卫士不会去改 OpenClaw 内部逻辑，而是利用 OpenClaw 自带的插件能力：

- 生成一个本地插件包
- 写入 `plugins.load.paths`
- 在插件里注册：
  - `before_tool_call`
  - `after_tool_call`
  - `openclaw_guard.hook_status`

这样一来，OpenClaw 在真正执行工具前，会先进入 Guard 的同步审批桥。

## 实际链路

```text
OpenClaw 进入工具调用
  -> before_tool_call
  -> 调用 Guard 本地 API
  -> Guard 转成行为事件
  -> 风险判定
  -> allow / ask / block / escalate
  -> ask / escalate 时等待用户批准
  -> 批准后继续原工具调用
  -> after_tool_call 回写执行结果
```

## 首次启用

第一次在某个 OpenClaw 环境里启用龙虾卫士时，会自动生成：

- `runtime/openclaw-guard-plugin/`
- `runtime/hook-bridge.json`

并把插件路径和配置写进当前 `openclaw.json`。

完成后需要按真实启动方式重启一次 OpenClaw gateway：

```bash
cd /Users/dynooob/Projects/OpenClaw/OpenClaw_Origin/openclaw
npm run openclaw gateway
```

否则插件虽然已经写进配置，但还没有进入运行时。

## 当前会被拦住的典型动作

- 删除工作区外文件
- 删除敏感目录
- 写入工作区外文件
- 修改 `openclaw.json`
- 执行高危命令
- 外联和 webhook

## UI 里会看到什么

- 动作页出现 `pending_approval`
- 批准后动作变为 `approved -> executing`
- 工具执行结束后回写 `executed` 或 `failed`
- 如果用户拒绝，动作保持 `rejected`，原工具不会继续

## 当前边界

- 当前拦的是经过 OpenClaw `before_tool_call` 的工具路径。
- 如果某个内部行为没有走这个 Hook，就还不在这条链里。
- 运行时 Hook 已经是真正执行前拦截，不再只是聊天层意图提示。

## 对照官方资料

- [OpenClaw Hooks](https://docs.openclaw.ai/automation/hooks)
- [OpenClaw Session Management](https://docs.openclaw.ai/concepts/session)
