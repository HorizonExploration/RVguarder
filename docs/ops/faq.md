# FAQ

## 1. 启动后页面打不开

先确认：

- 进程是否已启动
- 端口是否被占用
- 本机是否允许绑定 `127.0.0.1`

建议先运行：

```bash
python -m openclaw_guard.main normal --once --no-browser
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

## 5. 可以修改 OpenClaw 源码吗

不可以。当前项目严格遵守非侵入原则。

## 6. 为什么看到 ptrace / eBPF 不可用

在非 Linux 或未开启相关能力的环境下，这是正常现象。当前默认主链仍可通过 Hook Bridge 与事件摄入工作。

## 7. 可以直接给基层人员用吗

可以先用 `normal` 模式。它就是为普通用户准备的简洁入口。
