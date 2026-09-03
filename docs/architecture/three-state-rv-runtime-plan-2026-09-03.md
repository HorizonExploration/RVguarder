# 三态控制面与 RV 提交边界

> 更新日期：2026-09-03
> 状态：核心实现已完成；完整回归以本次合并前 CI 输出为准。

## 目标与边界

本次收敛解决三类实际问题：重复审批、未执行调用污染风险窗口，以及累计分数把正常
Agent 工作逐步推向极端风险。生产控制面只保留 `allow`、`ask`、`block`：`ask` 只映射为
一次 OpenClaw 原生 `requireApproval`，Guard 页面只展示同步状态，不提供第二个批准入口。

不再提供 `revise`、自动重规划或“要求 Agent 解释后重试”。它们会增加调用轮次、延迟和
token 消耗，却不改变 OpenClaw 的实际工具授权。

## 运行时链路

```text
before_tool_call
  → 明确工具模型 / PMKB 单步决策
  → RV preview：已提交窗口 + 当前候选的纯回放
  → allow | ask | block

after_tool_call（仅无错误且未被拒绝/阻断）
  → RV evaluate：提交本次 trace，并从有效窗口重放自动机
  → 提交主体权限关系证据并持久化状态
```

因此待审批、被拒绝、阻断和执行失败的调用均不会形成跨步攻击链证据。窗口按 session
隔离，受固定长度和 TTL 限制；每次提交和摘要都由有效窗口重建行为自动机，因此窗口过期、
显式 `release_session` 或重置会真实降低状态，不会保留旧 FSM 终态。
风险升级仅来自 RV 自动机对已执行序列的可复现判定；自动机内部的 `escalate` 在出口统一
折叠成 `ask`，不扩大公开动作集合。

## 规则与建模

- PMKB 是单步权限匹配、权限闭包和关系/组合校验的唯一权威。
- 已认证的 `(principal_id, agent_id, capability_lineage)` 仅在工具成功后保存跨 session 的
  权限关系证据；缺少身份时仅禁用该关联判断，不把普通低风险操作自动升级。
- 工具桥接只使用显式 OpenClaw profile 和其声明的结构化字段。未建模工具、或低风险 profile
  出现越权参数时，均保留 `action_type=unknown` 与 `risk_class=unknown`，通过一次保守审批处理，
  不从自由文本伪造命令、文件或网络动作。
- 旧 ConstraintEngine、会话累计分数和 revision hint 已删除。历史实验产物仍保留在
  `testlab/`，不进入生产链路。

## 性能约束与验证

热路径不调用额外 LLM；每个受保护工具最多一次本地 Guard 同步请求。RV preview 是内存内
回放，行为/权限/主体监视器均按当前输入重建，并有小规模性能冒烟阈值（平均小于 50ms）；默认本地 Hook 判定预算为 2 秒。重点回归覆盖：三态公开契约、未知工具
建模、生成插件不注册 prompt 预检查、preview 不提交窗口，以及成功 after callback 才持久化
RV 状态、过期窗口自动机降维，以及主体证据仅在成功 callback 后提交。

## 后续工作

1. 以历史 LEGACY 记录和 PMKB native 规则逐条离线回放，确认效果与证据一致后删除
   `policy/legacy.py` 兼容层。
2. 将 OpenClaw 真机审批回调延迟、超时和失败原因汇总为脱敏指标；不回写第二套审批状态机。
3. 为前端补充最小组件/E2E 测试，覆盖 OpenClaw 唯一审批提示和 RV 已提交窗口展示。
