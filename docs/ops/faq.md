# FAQ

## 1. 启动后页面打不开

先确认：

- 进程是否已启动
- 端口是否被占用
- 本机是否允许绑定 `127.0.0.1`

建议先运行：

```bash
openclaw-guard run --once --no-browser
```

## 2. 为什么首页不是一堆安全报表

这是有意设计的。普通用户应该先完成对话和任务操作，复杂安全信息应收纳在设置页。

## 3. 为什么危险动作没有直接执行

因为 Openclaw Guard 的设计原则就是“高风险动作先确认，再执行”。

## 4. 为什么我明明启动了 Guard，工具还是没被拦住

最常见原因是：Hook 插件已经写进 `openclaw.json`，但 OpenClaw gateway 还没有按你平时的方式重新启动。

第一次启用运行时 Hook 后，请执行：

```bash
cd /Users/dynooob/Projects/OpenClaw/OpenClaw_Origin/openclaw
npm run openclaw gateway
```

如果设置页里已经显示“最近有真实 Hook 活动”，说明插件链其实已经进过执行流；这时更值得检查的是 gateway RPC 是否还能直接响应，以及当前模型/提供方是否本身报错。

## 5. 为什么 OpenClaw 只弹一个审批，但 Guard 里出现多个待确认动作

Guard Dashboard 不是第二个审批中心。`before_prompt_build` 只做非阻塞预检查，不应创建待审批动作；真正需要用户决定的动作只来自 `before_tool_call`，并由 OpenClaw 原生审批卡片处理。

如果旧的临时插件路径残留在 `plugins.load.paths`，或 OpenClaw 审批回调超时，Dashboard 可能短暂保留历史待确认项。重新启动 Guard 会清理不存在的 `/tmp/.../runtime/openclaw-guard-plugin` 路径；超过 6 分钟没有回调的 Hook 审批会自动标记为 `approval_timeout`。请查看动作的 `sync_state`，不要把 `timeout` 当成规则阻断。

## 6. 为什么长命令会报 `description must not have more than 512 characters`

这是 OpenClaw 审批参数校验错误，不是命令本身的风险判定。当前插件已在发送审批卡片前限制标题和说明长度（说明最多 240 字符），完整详情仍保留在 Guard 审计记录中。若仍看到旧错误，请确认 gateway 已加载最新的 `runtime/openclaw-guard-plugin/index.js` 并重启一次 gateway。

## 7. 为什么读取会话/记忆仍被要求审批

当前版本只对 OpenClaw 原生的 `sessions_*`、`session_status`、`memory_*`、`agents_list` 和 `get_goal` 做低风险只读建模，并继续审计。Shell/exec 读取仍必须落在 workspace 或受管项目内；`sessions_send`、`sessions_spawn`、计划/目标写入等能力不属于只读白名单，会继续审批。

## 8. 可以修改 OpenClaw 源码吗

不可以。当前项目严格遵守非侵入原则。

## 9. 为什么看到 ptrace / eBPF 不可用

在非 Linux 或未开启相关能力的环境下，这是正常现象。当前默认主链仍可通过 Hook Bridge 与事件摄入工作。

## 10. 可以直接给基层人员用吗

可以先用 `normal` 模式。它就是为普通用户准备的简洁入口。

## 11. 启动时报缺少 fastapi/uvicorn

FastAPI 是唯一运行入口。请安装项目依赖：

```bash
pip install -e .
```

安装后重新执行 `openclaw-guard run`；不会自动回退到 `legacy_web`。

## 12. 页面显示“未连接”，或接口返回 HTML 而不是 JSON

先用 curl 验证后端是否在正确返回 JSON：

```bash
curl -i "http://127.0.0.1:8780/api/health?ts=1"
curl -i "http://127.0.0.1:8780/api/summary?ts=1"
```

正常情况下应该返回 `Content-Type: application/json`，并能被 `jq` 解析。
