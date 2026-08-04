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

## 5. 可以修改 OpenClaw 源码吗

不可以。当前项目严格遵守非侵入原则。

## 6. 为什么看到 ptrace / eBPF 不可用

在非 Linux 或未开启相关能力的环境下，这是正常现象。当前默认主链仍可通过 Hook Bridge 与事件摄入工作。

## 7. 可以直接给基层人员用吗

可以先用 `normal` 模式。它就是为普通用户准备的简洁入口。

## 8. `--fastapi` 启动时报缺少 fastapi/uvicorn

FastAPI 模式是并行实现的可选传输层。若你希望启用它，请先安装依赖：

```bash
pip install fastapi uvicorn[standard]
```

如果你追求最小依赖与最快冷启动，可以先使用默认的 legacy 模式（不加 `--fastapi`）。

## 9. 页面显示“未连接”，或接口返回 HTML 而不是 JSON

先用 curl 验证后端是否在正确返回 JSON：

```bash
curl -i "http://127.0.0.1:8780/api/health?ts=1"
curl -i "http://127.0.0.1:8780/api/summary?ts=1"
```

正常情况下应该返回 `Content-Type: application/json`，并能被 `jq` 解析。
