# 当前语义理解与 Trace 合同

> **状态：现行实现（2026-09-03）**
>
> 本页只描述当前生产链路。旧的语义设计、提示词样例和未落地方案保留在
> `docs/archive/semantic/method-legacy-design.md`，不应作为接口依据。

## 目标

把 OpenClaw 的工具调用和可选的用户意图，转换为可审计、可匹配、可回放的
`AuthorizationTrace`。语义层服务于 PMKB 单步判定和 RV 跨调用验证；它不直接
批准动作，也不绕过 OpenClaw 原生审批。

## 当前流水线

```text
BehaviorEvent
  → SemanticEnhancer.evaluate()
  → semantic + rv_trace
  → TraceCompiler
  → AuthorizationPolicyEngine
  → RuntimeVerificationEngine.preview
  → GuardController（allow / ask / block）
  → after_tool_call 成功后 RuntimeVerificationEngine.evaluate
  → 审计与主体证据提交
```

实现位置：

- `openclaw_guard/engine/semantic_enhancer.py`：本地规则化分析、可选 LLM 分析和硬性工具名校验；
- `openclaw_guard/policy/trace.py`：把 `rv_trace` 编译为 `AuthorizationTrace`；
- `openclaw_guard/policy/evaluator.py`：覆盖状态、候选规则和单步效果；
- `openclaw_guard/policy/engine.py`：合并权限闭包/差分、危险组合和最终策略证据；
- `openclaw_guard/engine/pipeline.py`：在 Hook 热路径中编排上述步骤。

## 输出字段

`semantic` 是面向解释和匹配的结构化对象，至少包含场景、意图、实体、约束、
标签和置信度。`rv_trace` 是面向自动机的步骤列表；每一步应带
`step_id`、`event`、`props`，并尽可能携带资源、数据、主体和上下文字段。
`TraceCompiler` 最终生成的 `AuthorizationTrace` 包含：

- 主体：`principal`、`agent_id`、`session_id`、`capability_lineage`；
- 操作：canonical `operation.family` / `tool_id` 及参数；
- 资源与数据：`resource.scope`、资源 ID、数据分类和数量；
- 覆盖证据：`complete`、`partial`、`unknown`、`conflict`，以及缺失特征、命中规则和冲突；
- 来源：`provenance`、置信度和原始 trace 步骤。

## 判定与降级边界

1. 配置 `DEEPSEEK_API_KEY` 时，每个配置工具调用（包括空意图和未知 Hook）只发送一次
   结构化、脱敏的语义请求，预算为 1.5 秒且不重试；超时、网络错误、非法 JSON 或 schema
   不合规都自动回退本地确定性规则，并在 `semantic_audit` 记录尝试结果。
2. LLM 只能返回受控 `SemanticMatchIR`：canonical operation candidate 和有限 security facts，
   标记为 `suggested`；原始 payload、完整命令、凭据、cookie、Bearer、邮箱、路径和 URL
   敏感值不会出进程。工具名、命令和范围事实由本地校验覆盖模型输出。
3. `complete` 才表示所需字段齐全；`partial`、`unknown` 或 `conflict` 不得因为相似度
   被静默放行。它们由 PMKB 映射为 OpenClaw 审批或阻断，Guard 不发起澄清重试。
4. 生产插件不注册 `before_prompt_build`；真正的审批只发生在 `before_tool_call`，由
   OpenClaw 原生页面完成。
5. 语义层不保存长期授权。跨 session 的风险和能力 lineage 由 RV/主体状态层维护，只有
   成功执行的工具调用才会提交状态。

PMKB 的内部 effect 枚举为 `auto_allow_audit`、
`openclaw_approval` 和 `block`；最终 Hook 响应再映射为 OpenClaw 的 `allow`、
`requireApproval` 或 `block`。

## 最小回归入口

```bash
python -m pytest -q tests/test_semantic_enhancer.py tests/test_authorization_trace.py \
  tests/test_pmkb_native_rules.py tests/test_pipeline.py
```

完整验证以 `python -m pytest -q`、前端构建和 VuePress 构建为准。

## 办公场景与 P0 规则

当前 `personal-office` 基线使用 versioned PMKB bundle。`EX-10` 覆盖 Feishu/IM
群发，`EX-19` 覆盖 `data.query` 后导出，`EX-27` 覆盖批量文件传输；这些规则的
`hard-block`、审批和正反例向量以办公场景矩阵及策略包为准。bundle 校验失败时
必须 rollback 到 previous catalog，并保留 audit records。

### 18.1 Authorization Trace

以下是与 API/回归测试一致的最小证据样例（字段可继续扩展，但不得省略覆盖状态）：

```json
{"trace_id":"trace-demo","match_status":"matched","policy_version":"1.2.0","selected_rule_ids":["EX-10"],"missing_features":[],"requested_delta":[],"redundant_permissions":[],"excessive_permissions":[]}
```
