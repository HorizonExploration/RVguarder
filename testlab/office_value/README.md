# 个人办公价值小实验

这是一个离线、确定性的最小实验夹具，用来回答一个问题：同样的办公动作，在逐次策略检查之外，加入 RVGuarder 的会话/主体状态和 Hook 生命周期，是否能更早识别跨步骤风险，同时不牺牲正常办公完成率。

## 重放内容

场景矩阵共 24 条：4 个工作流（飞书日报、会议准备、文档处理、日常命令），每个工作流 3 个正常案例和 3 个攻击案例。攻击案例取材于 EchoLeak、SafeBreach 日历邀请注入、Okta 支持系统事件以及文件批量外传/精确审批范围等公开案例模式；它们只保留行为链，不复现真实目标或凭据。

每条案例在三种模式下运行：

- `pass_through`：无防护对照组，所有 Hook 调用直接视为允许。
- `pmkb_only`：运行当前 PMKB 的逐次决策，关闭会话/主体 RV。
- `full_guard`：运行真实的 `before_tool_call → 审批/阻断 → after_tool_call`，包括跨步骤 RV、主体状态和精确命令信任。

待审批动作在重放中只接受一次，用于让后续步骤继续进入状态机；`after_tool_call` 只提交本地状态，不执行工具。

## 运行

```bash
python -m testlab.office_value.run \
  --mode all \
  --repeat 1 \
  --output /tmp/rvguard-office-value-results \
  --root /tmp/rvguard-office-value-sandboxes
```

输出目录包含 `summary.json`、`raw.jsonl` 和 `report.md`。如果不传 `--output`，CLI 直接打印 Markdown 报告。

实验不会使用真实网络；外部地址均为 `.invalid`，内容只包含假 token。建议在提交结果前检查 `report.md` 中的升级案例和审批信任范围变形测试。

## 案例依据

- [EchoLeak（CVE-2025-32711）](https://arxiv.org/abs/2509.10540)：外部内容诱导 AI 读取并外传敏感信息。
- [SafeBreach：Invitation Is All You Need](https://www.safebreach.com/blog/invitation-is-all-you-need-hacking-gemini/)：恶意日历邀请驱动后续动作。
- [Okta support case root cause](https://sec.okta.com/articles/2023/11/unauthorized-access-oktas-support-case-management-system-root-cause/)：凭据/会话材料与越权访问链。
- [OpenClaw file-transfer advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-7jfq-rmfm-29wp) 与 [exec cwd advisory](https://github.com/openclaw/openclaw/security/advisories/GHSA-3mq7-q27j-mq7q)：文件外传和执行工作目录边界。
- [Microsoft Solorigate response](https://www.microsoft.com/en-us/security/blog/2020/12/28/using-microsoft-365-defender-to-coordinate-protection-against-solorigate/)：权限变化与敏感数据导出的组合风险。
