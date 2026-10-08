# M1 受控宿主授权基础

## 当前状态

已实现本机 `authorization issue/query/revoke`，授权限定有限工具操作目录 `OPERATION_EFFECTS`。不向 Agent 注册签发工具，也没有 HTTP 授权写接口。现已接入[认证Hook参数引用证据](hook-resource-reference.md)，尚未接入授权裁决，因此不能宣称已减少审批或修复公开摘要误阻断。

每条授权绑定：独立任务、可信主体、Agent、session 或宿主 run、命名空间与规范资源 ID、真实内容 SHA-256、操作、精确接收方、期限及撤销状态。签发重新读取真实资源，不接受外部资源描述、附件文本或 `raw_user_intent` 作为签发证明。

后续 Hook 接入必须从认证上下文与宿主记录解析任务。`resolve_task_binding` 不接受工具自报 task ID；若同一上下文对应多个任务，返回不确定。多功能工具还须校验实际子动作/效果，不能以操作族授权整个工具。

## 宿主命令示例

以下命令在可信宿主执行；路径是示例，应换为隔离实例的真实路径。所有 Agent 可写工作区都必须声明。授权存储目录必须在这些工作区之外，现有目录权限应为 `0700`。

```sh
python -m openclaw_guard.main authorization \
  --state-dir /srv/rvguard-q5/host-authority \
  --agent-workspace /srv/rvguard-q5/workspace \
  issue --namespace office --resource-root /srv/rvguard-q5/workspace \
  --resource summary.txt --task-id task-001 \
  --principal-id hook:AUTHENTICATED_BINDING --agent-id agent-001 \
  --session-id isolated-session-001 --run-id isolated-run-001 \
  --operation network.egress --recipient colleague@example.test \
  --ttl-seconds 1800
```

查询/撤销沿用上面的全局存储和工作区参数，分别调用 `query --grant-id ID`、`revoke --grant-id ID`。签发命令不启动 Guard manager，也不修改 Gateway。

## 存储边界与未完成项

- 存储检查拒绝工作区内目录、符号链接、非宿主所有或组/其他用户可访问目录；数据库使用私有权限。此检查依赖工作区声明完整且准确。
- Docker 必须不挂载授权目录，并限制 Agent 的宿主执行路径。POSIX 私有权限不能防止拥有同一宿主 UID 和任意宿主执行能力的 Agent；尚待真实 Docker 验证。
- 匹配内部重新执行受控宿主观察，拒绝陈旧描述及同名换内容、未经验证的复制或资源命名空间替换。复制、打包、摘要变换尚未实现可信血缘。
- 资源读取后的执行竞态尚待通过执行时版本核验或不可变快照解决。
- 后续授权接入不能降低 PMKB 硬约束，不能恢复压制 RV 独立阻断的全局门。
- M1 必须取得公开摘要完成和攻击无敏感外发的真实收据后才能验收；当前测试不能代替该实验。

## 已执行验证

授权测试25项通过并经独立复验；全量回归在增加最后两项任务解析测试前执行，777通过、20跳过、4个subtests通过。两项任务解析测试及后来增加的陈旧/伪造资源描述测试，均包含在随后通过的25项授权回归中。独立复核发现的AUTH-001已修复并记录于[m1-defects.json](m1-defects.json)。

M0冻结文件全部匹配；`rv_rules.json` SHA-256保持 `496daa04a0bd532d9f99eaaa6293e1f52505dc5f9b098cc94f0af40bb5c255a7`，与上轮独立阻断实验的manifest一致。未改历史结果、旧DSL、日常Gateway或AGENTS.md。

授权记录是有限工具调用的可信上下文，不新增Agent工具事件，不让语义模型生成虚构调用；本轮未修改`tool-call-v1`、操作目录或DSL规则。
