# Openclaw-RVGuarder / 龙虾卫士

Openclaw-RVGuarder（龙虾卫士）是一个面向 OpenClaw 的非侵入式安全增强客户端与本地控制面。

项目目标是在**不修改 OpenClaw 源码**的前提下，为 OpenClaw 增加更清晰的安全交互、更可控的执行前审批、更完整的基线扫描与审计能力，并通过 **RV（运行时验证）引擎** 实现全链路行为模式监控。

![Python](https://img.shields.io/badge/Python-3.13%2B-3776AB?logo=python&logoColor=white)
![OpenClaw](https://img.shields.io/badge/OpenClaw-External%20Guard-111827)
![Hook](https://img.shields.io/badge/Runtime%20Hook-api.on-0F766E)
![Status](https://img.shields.io/badge/Status-v0.2.1-F59E0B)

## 核心特性

- **非侵入式接入**：全面对齐官方 Plugin SDK 规范，使用 `api.on()` 接入 `before_tool_call` 拦截。
- **物理审批拦截**：通过 `requireApproval` 实现工具执行前的真正挂起，支持双端状态同步。
- **RV 运行时验证**：引入基于滑动窗口的行为模式检测，识别「搜索 -> 读取 -> 外发」等链式风险。
- **语义增强**：集成 DeepSeek LLM 对工具调用进行语义分析，消除关键词匹配的局限性。
- **基线与审计**：提供全量配置扫描与 SQLite + JSONL 双写审计链。

## 项目结构

```text
OpenClaw-RVGuarder/
├── openclaw_guard/         # 核心后端代码
│   ├── api/                # HTTP 接口处理器
│   ├── core/               # 核心业务逻辑 (Action, Audit, Baseline)
│   ├── engine/             # 安全引擎 (Detection, RV, Semantic, Whitelist)
│   ├── integrations/       # OpenClaw 适配器与 Hook 运行时
│   ├── storage/            # 数据持久化层
│   ├── manager.py          # 业务编排主入口
│   └── web.py              # Web 服务定义
├── frontend/               # 前端独立工程 (Vite + JS SPA)
├── runtime/                # 运行时数据与生成的 Hook 插件
├── docs/                   # 项目文档与 VuePress 文档站
├── policies/               # 安全策略规则定义
└── tests/                  # 单元测试与回归测试
```

## 快速开始

```bash
# 1. 安装依赖
pip install -e .

# 2. 启动服务
openclaw-guard run
```

该命令会：

- 自动发现 OpenClaw 配置
- 准备 `runtime/`、`output/`、`exports/` 等目录
- 自动补齐一份基线扫描结果
- 生成/同步 Hook 插件并写入 OpenClaw 配置
- 启动本地 Web 工作台
- 默认尝试打开浏览器

### 4. 仅做自检

```bash
openclaw-guard run --once --no-browser
```

## 常用命令

```bash
openclaw-guard run                  # 启动主服务
openclaw-guard run --no-browser     # 启动但不开浏览器
openclaw-guard doctor               # 打印运行链路健康状况
openclaw-guard baseline             # 运行基线扫描
openclaw-guard export-audit /path/audit.json  # 导出审计 JSONL
openclaw-guard install-hook         # 把 Hook 插件路径写入 OpenClaw 配置
openclaw-guard uninstall-hook       # 移除 Hook 插件路径
```

## 前端能力

当前 Guard 工作台支持以下主要功能：

- OpenClaw 连接状态与当前模型/Agent 展示
- 待确认动作审批（确认继续 / 拒绝）
- 动作历史分页浏览（按状态筛选）
- 运行时 Hook 状态检查
- 基线扫描与整改建议查看
- 审计导出

> 对话功能回归 OpenClaw 原生页面，Guard 不再提供内置对话 UI。

## 输出目录

运行过程中，Guard 会生成以下内容：

### 基线扫描输出

- `output/reports/compliance-report.json`
- `output/reports/compliance-report.html`
- `output/reports/compliance-report.pdf`
- `output/fixes/baseline-remediation.sh`

### 审计与导出

- `output/audit/audit.db`
- `output/audit/audit.jsonl`
- `exports/audit-export.json`
- `exports/audit-export.csv`

### 运行时数据

- `runtime/ui/`
- `runtime/guard.log`
- `runtime/controlled-actions.json`
- `runtime/latest-baseline.json`
- `runtime/openclaw-guard-plugin/`

## 文档站

本项目附带完整 VuePress 文档站，位于 `docs/`。

本地预览：

```bash
cd docs
npm install
npm run docs:dev
```

构建静态站点：

```bash
cd docs
npm run docs:build
```

## 部署方式

### 本地部署

```bash
pip install -e .
openclaw-guard run
```

## 与 OpenClaw 的集成说明

Openclaw Guard 遵循“非侵入式”原则：

- 不修改 OpenClaw 源码
- 不替换系统库
- 不要求改动 OpenClaw 官方前端代码

它主要通过以下方式与 OpenClaw 交互：

- OpenClaw Gateway RPC
- OpenClaw `sessions.patch` / `chat.send` / `chat.history` / `agent.wait`
- OpenClaw 原生 Hook
- 本地运行时插件桥

如果 Guard 已写入 Hook 插件但仍未生效，通常需要按你的实际启动方式重启 OpenClaw Gateway。

例如：

```bash
cd /path/to/openclaw
npm run openclaw gateway
```

## 测试

运行完整测试：

```bash
python -m unittest discover -s tests -v
```

## FAQ

### 1. Guard 会修改 OpenClaw 源码吗？

不会。Openclaw Guard 设计上遵循非侵入式原则，不修改 OpenClaw 官方源码文件。当前集成方式主要依赖：

- Gateway RPC
- OpenClaw 原生 Hook
- 本地运行时插件桥
- Guard 自己的前端与本地 HTTP 服务

### 2. 为什么 Guard 已启动，但仍提示运行时不可达？

通常有以下几种原因：

- OpenClaw Gateway 尚未启动
- Gateway 已启动，但当前鉴权信息与 Guard 读取到的配置不一致
- Hook 插件已经写入配置，但当前运行中的 Gateway 进程还没有重启加载它
- 本机回环地址、局域网绑定方式或端口暴露状态与当前配置不一致

建议优先检查：

- `openclaw.json` 中的 `gateway` 配置
- Guard 设置页中的运行时调试信息
- `runtime/guard.log`

### 3. 为什么模型切换后，实际回复模型和界面显示不一致？

当前版本已经优先使用 OpenClaw 会话中的真实 `session key` 和 canonical model 标识来切模型，并在切换后回读会话模型确认结果。如果仍然不一致，通常说明：

- 当前运行中的 OpenClaw 会话不是 Guard 正在控制的那一个
- Gateway 返回的是旧会话状态
- 当前 provider 已限流或不可用，OpenClaw 在运行时做了降级或回退

### 4. 危险动作什么时候会被拦截？

当前重点覆盖这些动作：

- 删除文件
- 写入文件
- 修改配置
- 外联请求
- 渠道发送
- 技能执行
- OpenClaw 工具层 Hook 进入的高风险工具调用

其中高风险动作会先进入审批，不会直接继续执行。

### 5. 普通用户应该怎么启动？

推荐直接使用：

```bash
python -m openclaw_guard.main normal
```

这个模式会自动准备运行目录、补一份基线扫描结果，并打开更简洁的前端界面。

## 已知边界

当前版本已经能完成真实对话、模型切换、Hook 接入、动作审批、基线扫描与审计导出，但仍有这些边界：

- `ptrace` / `eBPF` 目前主要是能力探测与接口预留，主执行链依赖 OpenClaw 原生 Hook
- 某些不走当前 Guard Hook 拦截链的内部运行路径，仍需要继续补充覆盖
- 运行时链路依赖 OpenClaw Gateway 的实际可达性与鉴权配置
- 前端仍在持续优化中，当前版本已支持局部 patch、增量消息刷新和轻量状态轮询，但还会继续打磨

## 参考资料

- [OpenClaw 官方网站](https://openclaw.ai/)
- [OpenClaw Control UI 文档](https://docs.openclaw.ai/control-ui)
- [OpenClaw Sessions 文档](https://docs.openclaw.ai/concepts/session)
- [OpenClaw Hooks 文档](https://docs.openclaw.ai/automation/hooks)

## 许可证

本项目采用 Apache-2.0 开源协议。
