# OpenClaw 审批交接与误拦截优化结果报告

> **核对日期：** 2026-08-30  
> **范围：** OpenClaw 原生 Hook、审批交接、PMKB 原生工具映射、session RV、插件配置与定向回归  
> **原则：** OpenClaw 原生页面保留唯一审批权；Guard 负责语义风险判定、证据和及时同步
>
> **历史快照说明（2026-09-09）：** 本文保留修复前后的现场证据和当时的 `revise`/会话累计风险语境；
> 当前生产实现已移除这些路径，公开决策仅为 `allow`、`ask`、`block`，以[项目理解与当前记忆](../../architecture/project-memory.md)
> 和[三态控制面与 RV 提交边界](../../architecture/three-state-rv-runtime-plan-2026-09-03.md)为准。

## 1. 结论

本次问题不是单一规则“太严格”，而是三类链路问题叠加：

1. OpenClaw 原生工具没有被显式建模，`memory_search`、会话读取等控制面操作被当成普通文件/命令调用，导致缺少路径、scope 或 Agent 身份时进入审批；
2. session 达到 critical 后，旧的通用升权逻辑会把后续安全 `allow/read` 改写为 `revise`，形成风险持续累积、最后什么都不放行的体验；
3. 插件把完整技术说明直接放进 OpenClaw `plugin.approval.request` 的用户字段，长命令触发 schema 长度错误，审批卡片根本无法创建。

此外，临时测试生成的插件路径可能残留在 `openclaw.json`，以及 OpenClaw 已超时但 Guard 未收到回调的动作可能长期停留在 `pending_approval`，分别造成重复加载和“孤儿待确认”表象。

修复后，安全边界保持不变：高风险写入、外联、凭据/令牌读取、跨代理发送和未知命令不会因为本次优化而自动放行；只有明确的 OpenClaw 原生低风险读取减少误报并保留审计。

## 2. 现场证据与根因

### 2.1 最近一次任务

分析对象：

`/home/yosoro126/.openclaw/agents/main/sessions/e233e9a8-c49d-4a52-99e2-57a2e4ceab38.jsonl`

该任务包含 65 次工具调用：`exec` 48、`read` 8、`write` 3、计划/会话/记忆类调用若干。Guard 记录的决策为：`revise` 45、`escalate` 10、`ask` 8、`allow` 1、`block` 1；其中 9 次执行失败，5 次失败原因为 OpenClaw 审批说明字段超过 schema 上限。

这说明“命令越长越容易被拦”并不是有效安全语义，而是审批交接参数错误；同时，`read` 和 OpenClaw 控制面调用被 session 累计升权覆盖，放大了误报。

### 2.2 现场配置

修复前 `plugins.load.paths` 存在不存在的 `/tmp/.../runtime/openclaw-guard-plugin` 路径。当前配置已经清理为一个真实项目插件路径：

```text
/home/yosoro126/OpenClaw-RVGuarder/runtime/openclaw-guard-plugin
```

路径去重和清理逻辑只删除不存在的临时 Guard 路径，保留其他插件和历史实验目录。

## 3. 已实施的代码改造

### 3.1 OpenClaw 原生工具显式映射

`tool_hook_bridge.py` 新增显式 profile，并将 `tool_group`、`tool_origin`、`permission_family`、`risk_class` 写入 BehaviorEvent：

| 工具 | 权限族 | 风险 | 处理 |
|---|---|---|---|
| `sessions_history`、`sessions_list`、`session_status` | `session.read` | low | PMKB 自动放行并审计 |
| `memory_search`、`memory_get` | `memory.read` | low | PMKB 自动放行并审计 |
| `agents_list` | `agents.read` | low | PMKB 自动放行并审计 |
| `get_goal` | `goal.read` | low | PMKB 自动放行并审计 |
| `update_plan`、`create_goal`、`update_goal` | `plan.write` / `goal.write` | medium | 保持 OpenClaw 审批 |

`sessions_send`、`sessions_spawn` 没有继承只读 profile。原生只读 profile 还会检查参数：外部 URL、绝对/父级路径、跨 session 或跨主体目标会退出低风险信任并回到审批/阻断路径。Shell/exec 读取仍需 workspace/managed_project 边界、只读命令分析和低敏感数据条件。

PMKB 的源码和打包副本同步更新：操作目录加入原生权限族，规则加入 `OC-SESSION-READ`、`OC-MEMORY-READ`、`OC-GOAL-READ`、`OC-AGENTS-READ`，TraceCompiler 为无路径的原生低风险调用生成 `openclaw:<tool>` 控制面资源，避免 `required_trace.scope` 缺口造成假审批。

### 3.2 session RV 只对当前危险调用升权

`_apply_session_escalation` 保留 session 的累计风险和 `revision_hint`，但只在当前 action 已是 `ask` 或 `revise` 时改写为 `revise`。当前 action 若已是 `block`，继续保持 block；当前明确安全的 `allow/read` 不再因为历史 critical 状态被改写为审批。

### 3.3 OpenClaw 审批字段边界

生成插件和当前运行时插件均加入统一长度约束：

- 标题最多 80 字符；
- 用户说明最多 240 字符；
- block reason 同样限长；
- 完整规则编号、Trace、组合风险和技术原因留在 Guard 审计详情。

因此长命令仍可按风险进入审批，但不会因 `description` 超长而在 OpenClaw schema 层被误拒。

### 3.4 审批同步和生命周期收拢

- `before_prompt_build` 只产生非阻塞审计，不创建审批动作；
- OpenClaw `onResolution` 是唯一决策来源，Guard Dashboard 只读同步；
- pending Hook 审批超过 6 分钟无回调时标记为 `approval_timeout`、`sync_state=timeout`，不再永久显示待确认；
- `memory_search` / `memory_get` 索引未配置、metadata 缺失等错误归类为 `capability_error`，与安全 block 分开展示；
- `_ensure_plugin_config` 清理不存在的临时 Guard 插件路径并去重。

## 4. 验证方案与结果

遵循本次“只测关注链路”的要求，未重复运行与 OpenClaw 交接无关的全部实验和外部依赖测试。定向命令覆盖：

```bash
pytest -q \
  tests/test_hook_runtime.py \
  tests/test_tool_hook_bridge.py \
  tests/test_openclaw_native_policy.py \
  tests/test_pipeline.py \
  tests/test_approval_sync.py \
  tests/test_review_blockers.py \
  tests/test_policy_docs.py \
  tests/test_policy_pipeline.py \
  tests/test_authorization_trace.py \
  tests/test_permission_diff.py \
  tests/test_permission_risk_graph.py \
  tests/test_permission_rv_compiler.py \
  tests/test_principal_capability_rv.py \
  tests/test_principal_rv_hook_integration.py
```

核心交接回归与 PMKB/服务补充回归合计结果：**192 passed，4 subtests passed，42.57s**。
其中核心 OpenClaw 交接集合覆盖上方列出的插件配置、原生工具、Hook 流水线、审批同步和权限/RV 测试；补充集合增加了 policy catalog、PMKB baseline、services、daily policy 和 legacy migration 回归。

额外通过：

- `python3 -m compileall -q openclaw_guard`
- 六份 PMKB 源码/打包 JSON `python -m json.tool` 校验
- `node --check runtime/openclaw-guard-plugin/index.js`
- 生成插件 Node 运行时长说明边界测试
- 前端 Dashboard `action.timeout` SSE 事件订阅契约测试
- `git diff --check`
- `cd frontend && npm run build`（Vite 构建通过）
- `cd docs && npm run docs:build`（VuePress 渲染 36 页通过）

将同一会话的 65 个 ToolCall 以临时 Guard 服务做离线 smoke replay 时，3 个已知 OpenClaw 原生只读调用（`sessions_history`、`memory_search`、`sessions_list`）均得到 `allow`，子集放行率为 **100%**。其余调用因历史 JSONL 不包含完整执行上下文，不能据此宣称人工审批量已下降；正式下降比例需在重启 gateway 后采集新的真实任务前后对照数据。

改造前全量基线保留为：**513 passed、18 skipped、4 subtests passed**。本次没有把定向回归结果冒充全量回归。

## 5. 启用注意事项

当前运行中的 OpenClaw gateway 若在改造前已经加载插件，不会自动热加载新的 JavaScript。请在下一次实际验证前按平时方式重启 OpenClaw gateway，使其重新加载：

```bash
cd <openclaw-source-root>
npm run openclaw gateway
```

重启后重点验证三组行为：

1. `memory_search`、`sessions_history` 等原生只读调用应执行并审计，不产生 Guard 二次审批；
2. 很长的 `exec` 或写入说明应显示 OpenClaw 原生审批卡片，不再出现 `description must not have more than 512 characters`；
3. `sessions_send`、跨范围写入、外联和高危命令仍应审批或阻断。

## 6. 未改变的边界

- 没有修改 OpenClaw 源码；
- 没有把 Guard Dashboard 恢复为第二审批入口；
- 没有将一次 `allow-once` 变成永久白名单；
- 没有把所有 Shell/exec 读取设成全局可信；
- 没有删除历史实验产物或旧规则兼容记录。

下一步应使用一次新的真实 OpenClaw 任务采集 before/after 指标（native read auto-allow precision、unknown rate、审批量、schema error、timeout count），再决定是否扩大低风险规则覆盖范围。
