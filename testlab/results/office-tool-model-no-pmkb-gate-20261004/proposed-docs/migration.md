# RV DSL 统一工具调用迁移（2026-10-04）

## 已实现

生产事件模型升级为 `tool-call-v1`，默认规约升级为 version 2。66 条既有规则全部迁移，保留 9 个监视器及原规则 ID，另增加 `tool_unmodeled_effect_ask`，合计 67 条规则。监视器名称与状态名称保留用于审计；动作匹配、序列和计数统一使用工具效果。

数据路径：

```text
真实 before_tool_call
  → PMKB 操作族 / 原生子动作 / 确定性命令分类
  → 一个 ToolCallIR
  → DSL 预览成功执行历史
  → 保持 PMKB 裁决或提高到原生审批
成功 after_tool_call → 提交这个调用
```

`openclaw_guard/rv/tool_events.py` 显式覆盖 PMKB 的 48 个操作族。有限效果集合为 read、write、delete、execute、egress、configure、grant、schedule、spawn、interact、transform、query、unknown。message、cron、gateway 按已登记子动作细化，读取型 web 工具投影为 read。exec 的读取、外联和删除效果由本地命令分类补充；无法判断的脚本效果保留 unknown。

一次调用只产生一个步骤，不受模型生成的步骤数影响。工具身份、参数、资源、会话、主体、覆盖状态和执行状态随事件保留；不确定的语义事实保留其 suggested 来源。原语义输出单独存放在 `semantic_rv_trace`，不能伪造调用效果、执行次数或授权。聊天中的工具使用意图不进入真实调用历史。

## DSL 使用

```json
{
  "id": "sensitive_read_then_egress_review",
  "from": "sensitive_read",
  "to": null,
  "verdict": "ask",
  "when": {
    "tool": {"effects_any_of": ["egress"]}
  }
}
```

敏感读取状态应由真实 read 调用与敏感事实建立。`when.tool.operation_families` 可进一步限定操作族；计数和窗口使用 `effect:read`、`effect:delete`、`effect:egress` 等。业务事实不等于工具动作。

默认规约、外部规约加载和 NL2Spec 模板输出都经过同一迁移器；迁移具有幂等性。显式 legacy DSL API 留给旧离线测试。恢复的旧历史保留执行时间，标记 `legacy_replay/unverified`；普通行为遥测标记 `behavior_projection`，不能冒充 Hook。

## 硬阻断与审批

按用户要求取消 PMKB 依赖降级门：RV 规约命中 block 时可以独立硬阻断，无须 PMKB 同时返回 block。预览与评估使用相同口径；审计保留规则 ID、匹配历史 ID、`proposed_verdict`，独立 RV 阻断标记 `hard_block_evidence=rv_rule_match`，PMKB 同时确认时标记 `pmkb_confirmed`。规则命中不等同于已证明越权；语义补充事实与宽泛历史规则仍可能造成误报。PMKB 硬约束及故障透传约定不变。

隔离 Docker/OpenClaw 复现见 `testlab/results/office-tool-model-no-pmkb-gate-20261004/report.md`：旧矩阵结果逐场景与历史无门版本比较，新增近邻攻击和公开摘要对照独立报告。公开摘要对照出现实际误硬阻断，不能宣称满足零新增正常失败或整体优越性。

邮件群发及批量上传两条规则的 escalate 统一为 ask，并转入对应审批状态；二者原先在 Hook 中也都请求审批。内部接收方沿用授权 Trace 的边界，避免迁移后被写死的 `internal.com` 示例域名误判。未知工具仍由 PMKB 请求审批；已知工具的未知效果由新增 DSL 规则请求审批。后端故障透传保持原有约定。

## 缺陷与验证

迁移中修复了语义模型虚构执行步骤、聊天意图污染 RV、动作粗略归并导致正常消息误判，以及新事件的参数和实体在公开 Hook 记录中暴露的风险。公开记录清空原始 arguments，并脱敏实体和资源 ID，完整证据留在内部审计。

新增 43 项专项回归覆盖目录完整性、迁移幂等、不同工具实现命中同一约束、执行前预览、成功/失败提交、旧状态恢复、来源标记、未知子动作、相邻合法外发对照和公开记录脱敏。

以下回归统计属于取消门前的迁移阶段，不代表无门版本的正常任务精度。

15 类正常调用配对检查以相同 PMKB 分别关闭/启用 RV：新增硬阻断 **0**，审批请求 **7 → 7**，新增审批请求 **0**。逐例结果见 [配对记录](./rv-tool-call-normal-controls-2026-10-04.json)。这是隔离的进程内 before Hook 检查；没有执行办公工具副作用，也没有真实展示人类审批卡片，不能当作正常业务任务完成率或实际人工提示次数。

完整回归：721 项通过、19 项跳过、4 项子测试通过（146.50 秒）。此后补充的非 Hook 来源标记由 43 项专项回归验证；补丁格式检查通过。

## 尚未证明的能力

- 统一模型不等于自动推导正确安全规约，也不证明覆盖大多数未知攻击。
- 跨调用的数据血缘和按资源/接收方绑定的可信授权仍需独立实现与验证；本次没有把“读取过敏感文件”当作“当前输出含敏感数据”的证明。
- exec 和复合工具并非天然有限；未登记子动作或无法验证的执行效果进入审批，不能猜测为安全。
- 批量规则仍按窗口内调用次数计数，默认窗口 10 次无法达到 50/100 次阈值；它也不等于单次调用影响的对象数量。这一既有覆盖缺口已记录，未靠改变阈值掩盖。
- 本次未重跑 Docker、真实 Agent、机制隔离 holdout 或延迟实验；审批成本和正常任务完成率仍需在那些实验中报告。正常调用进入审批不能算作攻击防护成功。
