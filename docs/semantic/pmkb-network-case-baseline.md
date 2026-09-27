# PMKB 网络案例基础知识库

当前随项目发布的权限知识库版本为 **1.2.0**。它不是脱离运行时的案例笔记，而是直接由以下链路加载和执行的结构化基线：

```text
policies/permissions/*.json
  → PolicyBundle.load()
  → TraceCompiler（工具名 → canonical operation）
  → PolicyEvaluator（规则与覆盖状态）
  → PermissionClosure / PermissionDiff / RiskGraph
  → Hook 决策与 OpenClaw 原生审批
```

源码运行时读取 `policies/permissions/`；打包安装时读取
`openclaw_guard/policy/data/permissions/`。两份数据必须保持一致。

## 基础操作与默认处置

| 操作族 | 常见工具/别名 | 基线处置 | 主要证据或理由 |
|---|---|---|---|
| `directory.read` | `directory.lookup` | 自动放行并审计 | 工作区目录查询，要求资源已解析 |
| `table.read` | Feishu Sheets/Bitable read | 自动放行并审计 | 工作区内低影响读取 |
| `document.write` | Docs/Wiki/Drive write | OpenClaw 审批 | 产生持久化副作用 |
| `file.write` | `file.write` | 工作区或工作区外均进入 OpenClaw 审批 | 工作区边界由独立 Trace 约束；工作区外写入增加边界复核 |
| `data.export` | `table.export` | 普通导出审批；敏感/秘密数据阻断 | 防止数据外发 |
| `network.egress` | `network.request` | OpenClaw 审批 | 目的地、范围和数据分类需可审计 |
| `secret.read` / `credential.read` | — | OpenClaw 审批 | 凭据是令牌盗取和后续持久化的高价值目标 |
| `process.execute` | — | 默认 OpenClaw 审批；受管范围内确定性只读命令自动放行并审计 | 终端被入侵后可借合法身份执行命令；只读例外受命令分类器和作用域共同约束 |
| `file.read` | `read`, `cat`, `grep`, `ls` | 受管目录内自动放行并审计；其他范围审批 | 只读命令不应因路径存在而误判为写入 |
| `session.token.read` | `session.cookie.read`, `oauth.token.read` | 阻断 | 直接读取会话令牌可绕过再次认证 |
| `identity.permission.grant` | `role.assign`, `oauth.scope.grant` | OpenClaw 审批 | 权限/应用 scope 变更必须复核 |
| `identity.auth.modify` | `mfa.method.add`, `oauth.credential.add` | OpenClaw 审批 | MFA、设备或应用凭据变更可能形成持久化 |
| `audit.modify` | `audit.disable`, `logging.modify` | OpenClaw 审批 | 保留独立审计，防止检测盲区 |

## 危险组合

`relations/p0-combinations.json` 增加了四类可被 `RiskGraph` 直接消费的组合：

- `credential.read + network.egress + external_target`：阻断凭据读取后的外传；
- `session.token.read + network.egress + external_target`：阻断令牌读取后的外传；
- `identity.permission.grant + data.export + external_recipient + sensitive_data`：阻断“新增权限后立即敏感导出”；
- `identity.auth.modify + audit.modify`：要求审批，避免身份控制和审计同时被削弱。

这些组合不会替代 RV。单步规则先生成 `PolicyDecision`，随后由权限闭包、最小权限差分和跨 session RV 继续升权；任何 hard-block 只能保持或升为更严格处置。

## 案例来源与知识提炼

- [Okta：Support Case Management System incident](https://sec.okta.com/articles/2023/11/unauthorized-access-oktas-support-case-management-system-root-cause/)：服务账号凭据暴露、HAR 文件中的会话令牌被滥用，以及日志事件覆盖缺口。
- [Microsoft：Token tactics](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)：令牌重放、Pass-the-Cookie、MFA 方法/设备变更和外部共享路径。
- [Microsoft：Solorigate response](https://www.microsoft.com/en-us/security/blog/2020/12/28/using-microsoft-365-defender-to-coordinate-protection-against-solorigate/)：OAuth 应用或服务主体被增加凭据/权限后访问邮件和敏感数据。
- [Google Cloud：OAuth token mitigation](https://docs.cloud.google.com/architecture/bps-for-mitigating-gcloud-oauth-tokens)：本地可读令牌、长期 refresh token、终端入侵后的命令执行与撤销策略。
- [CISA：communications infrastructure hardening](https://www.cisa.gov/resources-tools/resources/enhanced-visibility-and-hardening-guidance-communications-infrastructure)：RBAC、最小权限、会话时长和持续账号监控。

案例只用于确定默认风险边界和测试向量；不会自动把单次用户批准转换为永久安全规则。用户化调整应在上层以有范围、有期限、可撤销的审批偏好实现，并且不能降低上述阻断规则。

## 验证与更新

```bash
python -m pytest -q tests/test_pmkb_network_baseline.py tests/test_policy_catalog.py tests/test_policy_vectors.py
```

新增或修改条目时必须同时更新源码目录和打包目录，并为每条规则提供 `source`、`positive_examples`、`negative_examples` 与测试向量。发布前运行完整回归、wheel 安装验证和文档构建。
