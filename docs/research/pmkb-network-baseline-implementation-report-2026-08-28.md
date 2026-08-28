# PMKB 网络案例基础知识库升级结果报告

**日期**：2026-08-28  
**范围**：基础知识库内容扩充与运行时链路接入  
**版本**：PMKB `1.1.0`

## 1. 目标与边界

本次工作将公开网络安全案例提炼为可直接被 Guard 运行时加载的权限知识，不新增数据库表、不改变 OpenClaw 审批所有权，也不把用户一次批准转换成永久规则。用户化调整仍应作为后续有范围、有期限、可撤销的策略叠加层实现。

## 2. 已完成内容

### 2.1 操作分类

在现有办公操作族基础上增加：

- `session.token.read`：会话令牌、Cookie、OAuth token 读取；
- `identity.permission.grant`：角色、OAuth scope、应用权限授予；
- `identity.auth.modify`：MFA 方法、设备或应用认证凭据修改；
- `audit.modify`：审计关闭、日志配置修改。

### 2.2 基线处置规则

新增规则覆盖目录/表读取、文档写入、数据导出、日历/会议/审批、事件订阅、网络出口、配置修改、秘密/凭据读取、进程执行、文件写入、会话令牌读取、权限授予和审计修改。

处置原则如下：

| 类型 | 默认结果 |
|---|---|
| 工作区目录/表读取且资源已解析 | `auto_allow_audit` |
| 写入、导出、网络出口、身份/权限/审计修改 | `openclaw_approval` |
| 敏感/秘密数据导出 | `block` |
| 会话令牌读取 | `block` |

资源、主体或目的缺失时，规则仍会保留 `partial`/缺失字段证据，不能静默放行。

### 2.3 危险权限组合

新增 `RiskGraph` 可直接执行的组合：

1. `credential.read + network.egress + external_target` → 阻断；
2. `session.token.read + network.egress + external_target` → 阻断；
3. `identity.permission.grant + data.export + external_recipient + sensitive_data` → 阻断；
4. `identity.auth.modify + audit.modify` → OpenClaw 审批。

### 2.4 测试与证据

新增 20 条 P1 基线规则、20 个对应 Trace 和 21 个测试向量（其中保留既有 `EX-27` 的批量传输向量），并保留源码目录与打包目录的同版本/同内容断言。新增测试覆盖工具映射、Trace 编译、PolicyEvaluator 规则选择、RiskGraph 组合检测和 AuthorizationPolicyEngine 最终处置。

同时修正了一个会影响既有工具链的误判：`read`、`cat`、`grep`、`ls` 等只读工具不再因携带文件路径而被桥接层推断为 `file_write`，统一标记为 `file_read`，避免被写入持久化组合规则错误升权。工作区外的真实写入则通过独立的 `P1-FILE-WRITE-OUTSIDE` Trace 保持人工审批，而不是静默放行。

## 3. 案例提炼依据

- [Okta Support Case Management System incident](https://sec.okta.com/articles/2023/11/unauthorized-access-oktas-support-case-management-system-root-cause/)：服务账号凭据暴露、HAR 会话令牌泄露、日志覆盖缺口；
- [Microsoft Token tactics](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)：令牌重放、Pass-the-Cookie、MFA/设备变更和外部共享；
- [Microsoft Solorigate response](https://www.microsoft.com/en-us/security/blog/2020/12/28/using-microsoft-365-defender-to-coordinate-protection-against-solorigate/)：OAuth 应用/服务主体权限和凭据被增加后访问敏感邮件数据；
- [Google Cloud OAuth token mitigation](https://docs.cloud.google.com/architecture/bps-for-mitigating-gcloud-oauth-tokens)：本地可读令牌、长期 refresh token、终端入侵后的命令执行及撤销；
- [CISA communications infrastructure hardening](https://www.cisa.gov/resources-tools/resources/enhanced-visibility-and-hardening-guidance-communications-infrastructure)：RBAC、最小权限、会话时长和持续监控。

## 4. 接入方式

运行源码时，`AuthorizationPolicyEngine` 通过 `PolicyBundle.load()` 读取 `policies/permissions/`；打包安装后读取 `openclaw_guard/policy/data/permissions/`。两份目录已通过 JSON parity 校验。

典型链路为：

```text
OpenClaw before_tool_call
  → TraceCompiler（tool/alias → canonical operation）
  → PolicyEvaluator（规则、覆盖和风险分数）
  → PermissionClosure / PermissionDiff / RiskGraph
  → OpenClaw 原生审批或 block
```

验证命令：

```bash
python -m pytest -q
cd docs && npm run docs:build
python -m pip wheel . --no-deps --no-build-isolation
```

提交前验证结果：`472 passed, 18 skipped, 4 subtests passed`（包含本次新增 PMKB 与只读工具回归）；VuePress 成功渲染 36 页；wheel `openclaw_guard-0.3.0-py3-none-any.whl` 构建成功，并确认包含 `openclaw_guard/policy/data/permissions/rules/p0-office.json`。源码/打包知识库 JSON parity 校验通过。历史基线为 `469 passed, 18 skipped, 4 subtests passed`。

## 5. 后续建议

1. 基础规则立即保持 enforced；新规则、批量发布或扩大自动放行范围先做离线规则/攻击向量回放，再进行最多 20 条相关事件的有限样本校验，观察命中率、未知率、人工审批量和高风险召回率；
2. 再实现用户策略叠加层，限定为主体/Agent/资源范围、TTL 和可撤销的审批偏好；
3. 任何用户偏好都不能降低 PMKB `block`、最小权限越界或危险组合的安全下限。
