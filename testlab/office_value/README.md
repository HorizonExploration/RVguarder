# 个人办公 Agent 通用安全插件价值实验

这是一个“公开漏洞派生的封闭回放（incident-derived, hermetic replay）”，用于展示通用 Hook 安全插件在个人办公 Agent 中的必要性。它不实现 DSH 原生适配，也不声称复现真实数据泄露；只把公开事件中的下游动作链映射到当前 OpenClaw Hook 能观测的工具调用。

## 案例组合

- `DSH-2026-853`：社区披露的 DeepSeek Harness `dsh web` 历史控制面/Host 信任问题，映射为“权限前置条件已失守 → 凭据读取 → 归档 → 外发”。官方 current master 已有浏览器 token 认证设计，因此本实验不声称修复入口。
- `PRAISON-2026-55532`：GitHub Reviewed Advisory 的 Origin 校验绕过与持久规则注入，映射为“常驻规则写入 → 重启/跨会话 → 凭据读取 → 外发”。
- `MCP-SHELL-2026-55580`：GitHub Reviewed Advisory 的默认安全开关/解释器绕过，映射为“外部附件 → shell/解释器 → 敏感读取 → 外发”。Shell 只记录声明式 effect，绝不启动子进程。

每个事件有独立的 `hook_payload`、`effect`、`oracle` 三层。只有 `hook_payload` 进入 Guard；副作用由本地 `office-workspace` 沙箱应用；攻击是否成功由沙箱实际状态和敏感数据 provenance 推导。假凭据、消息正文和文件内容不会进入报告。

## 对照与指标

- `pass_through`：无防护风险上界。
- `pmkb_only`：逐次 PMKB 决策，关闭跨步骤/跨会话 RV。
- `full_guard`：真实 before/审批/after Hook 生命周期、主体 RV 和风险图。
- `risk_aware`：遇到外部目标、凭据、持久化、权限扩张或破坏性命令会拒绝审批。
- `approval_all`：模拟审批疲劳/审批通道被接管，所有待审批动作都允许；Full Guard 必须仍能依靠链路证据约束后果。

报告按模式与审批人格给出 `attack_goal_success`、`containment_rate`、`benign_completion`、`false_hard_block`、审批负担、before Hook p50/p95、证据完整度、模拟外发命中（本地 capture sink）和 Full Guard 增量；不会发生真实外部 I/O。

## 运行

```bash
python -m testlab.office_value.run \
  --mode all --approval-persona all --split all --repeat 5 \
  --output testlab/results/office-value-v2 \
  --root /tmp/rvguard-office-value-v2
```

产物包括 `manifest.json`、`summary.json`、`raw.jsonl`、`report.md` 和 HTML 报告。`--split calibration` 用于初始校准；`--split holdout` 用于冻结后的泛化验证，不能针对 holdout 逐案加规则。

## 保护边界

危险动作必须经过可拦截 Hook，且插件未被卸载、禁用或绕过；直接 OS 调用、绕过 Hook 的 MCP/HTTP 入口、缺少来源/主体上下文都不在证明范围。PraisonAI、mcp-shell 和 DSH 应优先升级/采用其官方认证与安全修复；RVGuarder 是纵深/补偿控制，不替代认证、CSRF 修复或沙箱。

## 来源

- [DSH 社区披露 #853](https://github.com/deepseek-ai/deepseek-harness/discussions/853)
- [DSH 官方浏览器 token 认证设计](https://github.com/deepseek-ai/deepseek-harness/blob/master/.agents/notes/implemented/architecture/2026-08-24-browser-token-authentication.md)
- [DSH 扩展 Hook 文档](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/cookbook/extension-cookbook.md)
- [PraisonAI GHSA-pvph-5j39-v8qc / CVE-2026-55532](https://github.com/advisories/GHSA-pvph-5j39-v8qc)
- [mcp-shell GHSA-f5pj-2738-996m / CVE-2026-55580](https://github.com/advisories/GHSA-f5pj-2738-996m)
