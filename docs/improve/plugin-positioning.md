# OpenClaw Guard 作为使用场景的安全插件

本文件说明 `OpenClaw-RVGuarder` 的本质定位：它不是 OpenClaw 的替代品，也不是通用管理台，而是 **OpenClaw 的一种使用场景下的安全插件**。

## 1. 面向的具体使用场景

Guard 主要面向下面这一类使用场景：

> 用户希望让 OpenClaw 自动完成任务，包括删除、写入、修改配置、调用外部网络、推送渠道消息、运行技能等。

这一类场景共同特征是：

- OpenClaw 会主动产生“高风险动作”
- 这些动作一旦被错误执行，会直接影响本机文件、配置、网络出口和外部渠道
- 用户需要的是“OpenClaw 仍然能跑”，而不是“为了安全把 OpenClaw 关掉”

## 2. 插件承担的职责

在上述场景中，Guard 作为安全插件承担以下职责：

- **执行前拦截**：在 OpenClaw 真正调用工具前先拿到请求，做风险判定
- **审批放行**：高风险动作需要用户在前端明确确认后才继续执行
- **基线扫描**：扫描当前 OpenClaw 部署是否处于安全状态，输出报告
- **审计留痕**：把每一次动作判定、审批结果、执行结果写入审计链
- **可视化与排查**：把拦截链、待审批动作、最近审计等集中到一个本地 Web 前端

## 3. 不属于本插件的职责

为了让定位清晰，必须明确以下事情 **不是** Guard 的职责：

- 不负责 OpenClaw 的模型选择和对话体验
- 不替代 OpenClaw 的官方前端
- 不维护 OpenClaw 自己的会话与上下文
- 不做跨用户、跨设备的统一策略分发
- 不替代组织级 IAM / SSO / 审计平台

## 4. 与 OpenClaw 的集成边界

Guard 通过以下三种外部接口接入 OpenClaw，**不侵入 OpenClaw 内部**：

1. OpenClaw Gateway RPC：`chat.send` / `chat.history` / `agent.wait` / `sessions.patch`
2. OpenClaw 运行时 Hook 插件：Guard 写入一个本地插件，由 OpenClaw 加载并回调 Guard
3. 本地 HTTP API：Guard 提供 `127.0.0.1:8780` 内部 API 供 Hook 插件和前端调用

这种集成方式的两个直接好处：

- OpenClaw 升级时，Guard 不需要同步修改
- Guard 不在线时，OpenClaw 仍可继续工作，只是失去了“执行前审批”这一层保护

## 5. 插件的部署形态

Guard 作为 Python 包独立分发，常见部署形态：

- 本地直接 `python -m openclaw_guard.main normal`
- Docker 容器中作为 OpenClaw 的 Sidecar
- Kubernetes Pod 内的 Sidecar 容器

部署形态不影响 OpenClaw 主体，只是决定 Hook 插件和 OpenClaw 之间的网络可达性。

## 6. 与同类项目的边界

Guard 与下面这类项目不重叠：

- OpenClaw 官方前端与控制台
- 通用 LLM 代理网关
- 组织级审计 / SIEM 平台
- 反病毒 / 主机入侵检测系统

Guard 做的事情更收敛：**只关心 OpenClaw 自动化场景下的高风险动作与审计**，其他安全能力不在本插件范围之内。

## 7. 本节与其他文档的关系

- 项目全景分析中的“项目定位”一节已经按本文件的口径改写
- 项目结构清单、清理与优化记录等不再重复定义“它是什么”，只描述结构与改动
- README 与 `docs/README.md` 仍然以“OpenClaw 增强客户端”口径做高层描述，可与本文件配合使用
