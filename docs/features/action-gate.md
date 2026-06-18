# 高危动作审批链

## 核心原则

Openclaw Guard 的价值不在“执行后解释”，而在“执行前决策”。

当前动作链：

```text
用户请求
  -> 事件推断 / 事件摄入
  -> 风险规则判断
  -> 白名单校验
  -> 生成动作记录
  -> allow / ask / block / escalate
  -> ask / escalate 进入待审批
  -> 批准后才执行
```

接入 OpenClaw 原生 Hook 后，运行时工具链路已经变成：

```text
OpenClaw 准备调用工具
  -> before_tool_call
  -> Guard 同步判定
  -> block / pending_approval / allow
  -> 用户批准后继续原始工具调用
  -> after_tool_call 回写 executed / failed
```

## 支持的动作类型

- `command_exec`
- `file_delete`
- `file_write`
- `config_modify`
- `network_egress`
- `channel_send`
- `skill_run`

## 决策结果

- `allow`：直接继续
- `ask`：等待审批
- `block`：直接阻断
- `escalate`：需要更高等级确认

## 动作状态机

- `proposed`
- `pending_approval`
- `approved`
- `rejected`
- `blocked`
- `executing`
- `executed`
- `failed`

## 当前规则示例

- `rm -rf`：默认 `block`
- 工作区外删除：默认 `ask`
- 修改关键配置：默认 `ask` 或 `block`
- 危险外联：`ask` / `escalate`
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
