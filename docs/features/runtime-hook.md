# 运行时 Hook 拦截

## 这页讲什么

这一页说明龙虾卫士如何在**不修改 OpenClaw 源码**的前提下，把高风险工具调用真正拦在执行前，以及如何把 OpenClaw 原生审批结果及时同步到 Guard Dashboard。

权限知识库、语义命中和双作用域 RV 的系统级结果见[权限知识库与 RV 运行时架构结果](../architecture/permission-kb-runtime-architecture.md)。

## 核心机制

龙虾卫士不会去改 OpenClaw 内部逻辑，而是利用 OpenClaw 自带的插件能力：

- 生成一个本地插件包（`runtime/openclaw-guard-plugin/`）
- 写入 `plugins.load.paths` 和 `plugins.entries`
- 在插件里注册（使用官方 `api.on()` API 注册 4 个钩子）：
  - `before_tool_call` — 工具调用拦截主钩子（透传 `toolKind`、`toolInputKind`、`derivedPaths`）
  - `after_tool_call` — 执行结果回写
  - `gateway_start` — gateway 启动时初始化健康检查定时器
  - `gateway_stop` — gateway 停止时清理健康检查定时器
- 额外通过 `api.registerGatewayMethod()` 注册：
  - `openclaw_guard.hook_status` — Gateway 健康检查方法

只有 `before_tool_call` 进入动作生命周期并可能返回 `requireApproval`；这样 OpenClaw
原生审批卡片是唯一审批入口。

### 授权策略与审批所有权

PMKB 在 Hook 前生成 Authorization Trace 和只读 `policy_decision` 证据。三级路由为
`auto_allow_audit`、`openclaw_approval`、`block`；任何 hard-block
优先级都不能被 Hook 降级。`principal`、`agent_id` 和 `capability_lineage` 必须一致才
允许跨 session 关联，未知身份、未知工具或能力缺失只能进入 OpenClaw 审批；Guard 不会发起额外澄清回合。

对于需要确认的动作，OpenClaw 原生审批卡片是唯一审批（唯一审批）入口。Guard Dashboard
只读显示 `effect`、`match_status`、`missing_features`、`requested_delta`、
`excessive_permissions`、`combo_violations`、`policy_version` 和 timing；Guard 不提供
第二个批准按钮，也不绕过 OpenClaw 的 `requireApproval`。版本化策略 bundle 校验失败、
硬风险漏检或 principal-state merge anomaly 时，禁用新版本并 rollback 到 previous
catalog，保留所有 audit records。

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
  -> 显式工具 profile / 参数动作分类 / Authorization Trace
  -> PMKB 规则、最小权限与危险组合判定
  -> RV 预判（临时回放有效窗口，行为/权限/主体监视器均不持久化）
  -> allow / ask (require_approval) / block
  -> require_approval 时 OpenClaw 挂起 agent，展示审批卡片
  -> 用户只在 OpenClaw 原生 UI 批准或拒绝
  -> Guard 通过 onResolution 回调写入状态并发布 SSE 事件
  -> 批准后继续原工具调用
  -> 仅同一 runId + toolCallId + session/agent 上下文的 after_tool_call 成功后，才提交 RV 状态、主体权限证据并回写执行结果；缺失回调仅在超过 30 秒孤儿阈值后标记 unknown
```

## requireApproval 返回格式

插件返回的 `requireApproval` 对象遵循 OpenClaw 官方 `BeforeToolCallResult` 类型：

```javascript
{
  requireApproval: {
    pluginId: "openclaw-guard-hook",      // 插件标识
    title: "需要确认：修改项目文件",        // 中文审批卡片标题
    description: "要做什么：修改项目文件。目标：managed_project。风险：需确认。", // 仅放决策摘要
    severity: "warning",                    // "info" | "warning" | "critical"
    allowedDecisions: ["allow-once", "allow-always", "deny"],
    timeoutMs: 300000,                      // 5 分钟超时
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

Guard 会同时返回 `user_summary`、`approval`、`allowed_decisions`、`policy_version` 和
`technical_reason`：OpenClaw 卡片只展示“要做什么 / 目标 / 风险”等关键摘要，规则编号、命令
参数和内部原因留在 Guard 详情中。
`technical_reason` 不应直接作为用户提示。

`allow-always` 不是全局放行。Guard 仅对确定性解析的低风险工作区命令开放，并将工具、完整
规范化参数、工作目录和 agent/principal 组合成 fingerprint，默认保存 30 天；参数或目录变化
会重新审批，高危、网络、特权或敏感目标（`.env`、`.git`、凭据、密钥、私钥等）不提供该决定。
请求必须带有已验证的 agent/principal，并通过 Guard 的 Hook token 鉴权上下文；HTTP Hook 会把鉴权 token
转换为服务端绑定标识，避免跨安装实例复用授权；未知工具只有在参数严格收敛为 `command` 与工作目录时
才可进入该精确授权范围，额外参数一律回到单次审批。

### 个人办公场景的低风险分级

以下条件同时满足时，项目内日常读取不创建审批卡片，但仍写入审计：

- 命令由确定性分析器识别为只读（支持复合 `cd && git/rg/find/cat/ls` 等命令）；
- 目标位于 OpenClaw workspace、源码目录或 Guard 受管项目目录；
- 没有重定向、命令替换、网络、提权、删除、写入或 `find -exec`；
- 文件读取属于 `public/internal`，没有凭据或秘密标签。

项目外读取、项目写入、外联、浏览器交互、发送、删除、提权、复合工具越权参数和未知工具仍进入 OpenClaw 原生审批或硬阻断。
范围使用 `workspace / managed_project / outside / external / unknown` 五级模型，不再把所有
非 workspace 目标直接视为恶意。

### 后端静默透传与恢复（Circuit Breaker）

Guard 后端可能因维护、故障或网络隔离而不可达。此时插件以 OpenClaw 可用性为先：所有 Agent 的工具调用都由 OpenClaw 自身规则继续处理，Guard 不提供保护。

1. **健康状态**：正常请求由 Guard 返回 `allow`、`requireApproval` 或 `block`。
2. **传输故障**：连接拒绝或超时时，当前与后续 `before_tool_call` 对所有工具返回 `undefined`；`after_tool_call` 和既有审批的 Guard 同步不再等待后端。写入与执行也不例外。
3. **恢复**：后台健康检查成功后重新启用 Guard。启动时一次成功即可启用；失联后需连续两次成功。静默期间错过的阻断和审计不会重放。
4. **有响应的错误**：后端明确返回 HTTP 401/4xx/5xx 不等同于传输失联，仍按分级错误策略处理；遗留 `failClosed: true` 只在此类错误时可全量阻断。

行为总结：

| 后端状态 | 桥接状态 | 行为 | 含义 |
|----------|-----------|------|------|
| 启动尚未确认健康 | silent | 所有工具透传 | Guard 防护暂停 |
| 传输不可达 | silent | 所有工具透传，无同步回调 | Guard 防护暂停 |
| HTTP 错误有响应 | active + backendResponseError | 低影响透传，高影响阻断；遗留 `failClosed=true` 可全量阻断 | 后端异常，不是静默 |
| 恢复（≥ 2 次连续健康检查成功） | active | 返回 requireApproval / block / allow | 恢复正常审批 |

通过 `pluginConfig` 可配置：

```javascript
pluginConfig = {
  failClosed: false,                   // 旧兼容项：仅对有响应的 HTTP 错误生效，传输故障一律透传
  failThreshold: 3,                    // 已弃用：传输故障立即透传
  recoveryThreshold: 2,                // 恢复成功次数阈值
  failClosedGracePeriodMs: 30000,      // 已弃用：无传输故障阻断优雅期
}
```

> **系统默认**：首次写入 `openclaw.json` 时仍为兼容保留 `failClosed: false`。传输故障时即使旧配置为 `true`，所有工具也静默透传。后端从可用状态突然断开时，首个失败调用可能等待一次决策超时（默认 2 秒），后续调用不再同步请求。生产环境应监控 `hook_status` 的 `state`、`backendResponseError` 和 `circuitOpen`；只有 `state=active` 且无响应错误时才可认为 Guard 防护正常。

## 审批结果同步机制

Hook 动作只有 OpenClaw 原生审批入口；Guard Dashboard 不显示批准/拒绝按钮，只展示风险证据和同步状态。

### OpenClaw 原生 → Guard Dashboard

用户在 OpenClaw 原生审批 UI 中批准/拒绝时：

1. 插件 `onResolution` 回调触发，POST `/api/hook/resolve-approval`
2. 后端 `resolve_hook_approval` 处理：字段名兼容 `actionId`/`action_id`，决策值兼容 `allow-once`/`allow_once`
3. 后端幂等更新并持久化最终 `decision_state`、`sync_state` 和审计记录
4. 发布 `action.resolved` SSE 事件，前端按 `action_id` 增量刷新；超时收拢发布 `action.timeout`，前端同样增量刷新
5. SSE 断线时通过 `GET /api/actions/{action_id}` 和轻量 summary 对账

### 本次同步与误拦截修复

审批所有权仍只有 OpenClaw 原生 UI，但 Guard 对 OpenClaw 自带工具做了显式分类，避免把控制面读取误判为普通命令或文件操作：

| OpenClaw 工具组 | 典型工具 | PMKB 权限族 | 默认行为 |
|---|---|---|---|
| filesystem | `read`、`write`、`edit`、`apply_patch` | `file.read` / `file.write` | 受管只读可审计，其余审批 |
| runtime | `exec`、`process`、`terminal`、`code_execution` | `process.execute` | 审批或硬阻断 |
| web / browser | `web_search`、`x_search`、`web_fetch`、`browser` | `network.egress` / `browser.interact` | 外联与交互审批 |
| session | `sessions_*`、`session_status`、`conversations_*` | `session.read` / `session.send` / `conversation.*` | 同主体只读可审计，跨会话审批 |
| memory | `memory_search`、`memory_get` | `memory.read` | 满足边界时自动放行并审计 |
| messaging | `message` | `message.send` | 发送、编辑、删除审批 |
| automation | `cron`、`gateway` | `automation.modify` / `gateway.modify` | 保持审批 |
| agents / planning | `agents_list`、`get_goal`、`progress_card`、`update_plan`、`create_goal`、`update_goal` | `agents.read` / `goal.*` / `plan.write` | 读取可审计，写入审批 |
| human input / credentials | `ask_user`、`secrets` | `user.interaction` / `credential.read` | 凭据访问审批 |
| nodes / UI | `nodes`、`computer`、`canvas`、`screen`、`dashboard` | `node.control` / `computer.control` / `ui.*` | 控制类审批，观察类受边界约束 |

`sessions_send`、`sessions_spawn` 等跨代理/跨会话写入能力不会继承只读信任，仍按写入风险处理。Shell/exec 的读取仍需满足工作区边界和只读分析条件，不能因为“读取”字样而自动放行。
原生只读信任还会检查参数：出现外部 URL、绝对/父级路径，或指向不同 session/主体的目标时，会退出原生低风险 profile，回到普通审批/阻断路径。

为兼容 OpenClaw `plugin.approval.request` 的描述字段限制，插件会在发送前将审批标题限制为 80 字符、用户说明限制为 512 字符，并保留省略号；完整规则编号、Trace 和技术原因只写入 Guard 审计详情。命令预览默认脱敏，不把 token、密码或私密 payload 发送到审批渠道。

Guard 还会在查询或处理新 Hook 前收拢超过 6 分钟未回调的 `pending_approval` 动作，标记为 `approval_timeout`，避免 OpenClaw 已结束而 Dashboard 永久显示待确认。同步状态 `timeout` 表示审批回调未在窗口内返回，不等同于安全规则 `block`。

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

### 临时项目与配置隔离

Guard 的测试夹具或短期任务可能在系统临时目录生成插件包。此类插件目录具有明确的生命周期，不能注册到用户级 `openclaw.json`，否则临时目录被删除后，OpenClaw 会在启动前因 `plugins.load.paths` 中存在不存在的路径而拒绝加载，Guard 也无法通过启动流程自动修复它。

运行时安装逻辑现在会跳过“临时插件目录 + 外部 OpenClaw 配置”这一组合，仅允许正式项目目录更新用户级配置；项目内配置仍可正常写入。若历史版本已经留下失效路径，请先移除该路径，然后刷新 OpenClaw 持久化插件索引并校验配置：

```bash
openclaw plugins registry --refresh
openclaw config validate
```

`registry --refresh` 用于同步 OpenClaw 的已安装插件诊断缓存；仅修改 JSON 文件而不刷新索引时，旧的 `plugin path not found` 诊断可能仍会被启动检查使用。

## 当前会被拦住的典型动作

- 删除工作区外文件
- 删除敏感目录
- 写入工作区外文件
- 修改 `openclaw.json`
- 执行高危命令
- 外联和 webhook

## UI 里会看到什么

### OpenClaw 原生审批卡片

工具调用被拦截时，OpenClaw 直接在界面上弹出审批卡片，显示动作意图、目标和风险等级；符合条件时用户可「允许一次」「始终允许此命令」或「拒绝」。

### Guard Dashboard

- 动作页出现 `pending_approval`
- OpenClaw 回调收到批准后，动作变为 `approved -> executing`；Guard 不执行二次审批
- 动作详情按“摘要 / 命令与参数 / 规则与权限依据 / RV / 运行时审计”分区折叠，命令默认脱敏并可复制
- 设置页可查看精确授权的作用范围、有效期并撤销
- 工具执行结束后回写 `executed` 或 `failed`
- 收到 OpenClaw 拒绝回调后，动作保持 `rejected`，原工具不会继续

## 当前边界

- 当前拦的是经过 OpenClaw `before_tool_call` 的工具路径。
- 如果某个内部行为没有走这个 Hook，就还不在这条链里。
- 运行时 Hook 已经是真正执行前拦截，OpenClaw agent 会通过 `requireApproval` 挂起执行线程，等待用户决策。
- 插件使用 `api.on()` API（非已废弃的 `api.registerHook()`），需要 OpenClaw Plugin SDK >= 2026.4.0。

## 对照官方资料

- [OpenClaw 工具总览](https://docs.openclaw.ai/tools)
- [OpenClaw 工具配置与分组](https://docs.openclaw.ai/gateway/config-tools)
- [OpenClaw Plugin Hooks 官方文档](https://docs.openclaw.ai/plugins/hooks)

---

## 附：RV 模式

### 什么是 RV 模式

RV（Runtime Verification，运行时验证）模式是龙虾卫士的一项可选高级安全能力。开启后，系统会在常规规则引擎之外，运行由 **ChainRule DSL 编译生成的办公场景监视器**，通过滑动窗口分析工具调用的行为序列，识别链式风险。

### RV 模式能做什么

| 场景 | 检测内容 | 判定 |
|------|---------|------|
| 邮件外发 + 敏感内容 | 外部收件人 + 含敏感信息 | block |
| 邮件群发 / AI 草稿 | 群发或 AI 内容未审阅 | ask |
| 日报外发 + 内部来源 | 内部日报发到外部 | block |
| 搜索文件 → 删除 | 先搜索高价值路径后删除 | block |
| 关闭审计 → 改配置 | 先关审计后改配置 | block |
| 下载附件 → 外传 | 下载后外发或发邮件 | ask / block |
| 读取凭据 → 网络连接 | 读敏感凭据后外联 | ask / block |
| 批量删除累积 | 10 次以上 ask / 50 次以上 block | ask / block |
| 数据库查询后导出 | 查敏感表后导出 | ask / block |
| 批量上传到外部 | 大批量文件发往外网 | ask / block |
| 共享链接权限变更 | 改为公开或移除密码 | ask |

### 开启/关闭 RV 模式

在龙虾卫士 Dashboard 右上角，点击 **RV 模式** 开关按钮：

- **开启**（绿色高亮）：Dashboard 显示安全执行链路 Trace 时间线和 RV 引擎状态面板
- **关闭**（灰色）：恢复标准视图，隐藏 Trace 和 RV 详情

切换实时生效，采用**双持久化**：后端通过 `/api/rv/toggle` 把 `rv_mode` / `rv_rule_mode` 写入 `preferences.json`，前端通过 localStorage 键 `openclaw-guard-rv-mode` 保存 UI 开关状态。

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
