# 高危动作审批链

## 核心原则

RVguarder 的价值不在“执行后解释”，而在“执行前决策”。

当前动作链：

```text
用户请求
  -> 事件推断 / 事件摄入
  -> 语义归一化 / Authorization Trace
  -> PMKB 单步规则 + 最小权限 + 危险组合判断
  -> RV 规约 overlay（PMKB 后、controller 前，升权不降权）
  -> 白名单校验
  -> 生成动作记录
  -> allow / ask / block
  -> ask 进入 OpenClaw 原生待审批；内部 escalate 统一映射为 ask
  -> 批准后才执行
```

接入 OpenClaw 原生 Hook 后，运行时工具链路已经变成：

```text
OpenClaw 准备调用工具
  -> before_tool_call
  -> Guard 同步判定
  -> block / pending_approval / allow
  -> OpenClaw 原生审批卡片完成唯一用户决策
  -> Guard 只读同步 resolution 后继续原始工具调用
  -> after_tool_call 回写 executed / failed
```

## PMKB 权限决策证据

每次 `before_tool_call` 都从 `policies/permissions/` 加载已校验的版本化 bundle。语义层先
填充 action、resource、scope、data、context、principal 和 trusted identity，随后按
`matched`、`partial`、`unknown`、`conflict` 返回匹配状态。PMKB 再计算：

- 当前权限与申请权限的 `requested_delta`、冗余权限和超出最小权限的部分；
- 显式 `implies` 闭包后的 least-privilege 范围；
- 互斥、聚合和毒性权限组合的 `combo_violations`。

最终 effect 只允许向更高风险合并：`auto_allow_audit`、
`openclaw_approval`、`block`。响应会携带 `policy_version`、`missing_features`、
`risk_score`、`risk_reasons` 和 timing，供 Guard 页面解释和审计；Guard 页面不创建第二个
审批按钮，需确认时只返回 OpenClaw 原生 `requireApproval`。

## 支持的动作类型（9 种）

- `chat_message`
- `command_exec`
- `file_delete`
- `file_write`
- `config_modify`
- `network_egress`
- `channel_send`
- `skill_run`
- `unknown`（兜底：来自外部原始 payload 的未识别类型）

## 决策结果

- `allow`：直接继续
- `ask`：等待审批
- `block`：直接阻断
- `escalate`：内部 RV 升权信号，最终映射为 OpenClaw `requireApproval`
- `revise`：历史兼容字段，不作为当前审批动作或前端按钮
RV 自动机内部的 `escalate` 只在公开控制面折叠为 `ask`，不创建第二种审批或重试回合。

## 动作状态机

- `proposed`
- `pending_approval`
- `approved`
- `rejected`
- `blocked`
- `executing`
- `executed`
- `failed`
- `allow`（兼容值：auto-allow 路径设置的运行时状态）

## 当前规则示例

- `rm -rf`：默认 `block`
- 工作区外删除：默认 `ask`
- 修改关键配置：默认 `ask` 或 `block`
- 危险外联：`ask`
- 高危 skill：至少 `ask`

## 当前已经接上的执行前拦截

- OpenClaw 原生 `before_tool_call`
- 删除类工具调用
- 写入类工具调用
- 配置修改类工具调用
- 命令执行类工具调用
- 网络外联类工具调用

## 当前边界

- 目前拦的是会经过 OpenClaw `before_tool_call` 的工具路径。
- 首次安装本地 Hook 插件后，需要重启一次 gateway 才会生效。
- `ptrace` / `eBPF` 仍然是能力探测与后续扩展方向，不影响当前这条执行前拦截主链。
