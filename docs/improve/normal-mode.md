# 使用指南

本文件说明 OpenClaw Guard 插件的“开启即用”使用方式。**不再区分 normal / launch / chat / interactive 等多模式**，启动后只会有一个统一的本地工作台。

## 它解决什么问题

在“让 OpenClaw 自动完成任务”这一类使用场景下，Guard 作为安全插件提供：

- 危险操作执行前的明确确认
- 对话仍然走 OpenClaw 原生页面，不在 Guard 内重复实现
- 动作级审计、基线扫描和拦截链路状态

## 启动命令

```bash
openclaw-guard run
```

带参数：

```bash
openclaw-guard run --no-browser    # 启动但不开浏览器
openclaw-guard run --port 8780     # 指定端口
openclaw-guard run --config PATH   # 指定 OpenClaw 配置文件
```

## 启动后会发生什么

`openclaw-guard run` 启动后自动完成：

1. 发现本机 OpenClaw 的配置路径、工作区和日志目录
2. 准备 `runtime/`、`output/`、`exports/` 等目录
3. 如果还没有基线结果，会自动补一次基线扫描
4. 生成/同步 `runtime/openclaw-guard-plugin/`，并把本地插件路径写入 `openclaw.json`
5. 启动本地 Web 工作台
6. 默认尝试打开浏览器

## 首次启用 Hook 需要做什么

如果这是第一次在当前 OpenClaw 环境里启用 Guard 的运行时 Hook，Guard 会把本地插件路径写进 `openclaw.json`。
这一步完成后，需要按你的真实启动方式重启一次 OpenClaw gateway，Hook 才会真正进入运行时。

如果你的 OpenClaw 是在源码目录里通过 npm 启动的，推荐命令：

```bash
cd /path/to/openclaw
npm run openclaw gateway
```

重启后，你就可以在 Guard 的“待确认动作”页里看到真正的“执行前审批”效果：删除、写入、配置修改、危险命令和外联请求都会先被拦住。

## 维护子命令

```bash
openclaw-guard install-hook         # 把本地 Hook 插件路径写入 OpenClaw 配置
openclaw-guard uninstall-hook       # 还原 OpenClaw 配置
openclaw-guard baseline             # 手动跑一次基线扫描并打印
openclaw-guard export-audit PATH    # 导出审计 JSONL
openclaw-guard doctor               # 打印运行链路健康状况
```

## 工作台入口

启动后默认进入 `/` 首页，结构是：

- 顶部：当前 Guard 状态（运行/插件/连接）
- 主体：一键跳回 OpenClaw 继续对话
- 侧栏：待确认动作 / 审计 / 基线 / 设置

对话视图不再出现在 Guard 内，请回到 OpenClaw 原生页面进行对话。

## 与 OpenClaw 的关系

- 对话、消息、会话上下文完全由 OpenClaw 自己处理
- Guard 只在 OpenClaw 准备调用工具时拿到请求，做风险判定
- Guard 的审计只记“动作级”事件，不镜像 OpenClaw 的对话历史

## 主要输出目录

- `output/reports/`：基线扫描报告
- `output/audit/`：SQLite 审计库与 JSONL 备份
- `output/exports/`：取证导出文件
- `runtime/`：界面初始状态、最近基线结果、前端构建产物
- `runtime/openclaw-guard-plugin/`：自动生成的 OpenClaw 本地 Hook 插件
- `runtime/hook-bridge.json`：Hook 本地鉴权令牌和桥接状态

## 对照官方资料

- [OpenClaw Control UI](https://docs.openclaw.ai/control-ui)
- [OpenClaw Session Management](https://docs.openclaw.ai/concepts/session)
- [OpenClaw Hooks](https://docs.openclaw.ai/automation/hooks)
