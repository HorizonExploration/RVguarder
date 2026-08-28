# 旧规则迁移矩阵 / Legacy Rule Migration Matrix

> **状态 / Status：** 现状盘点，尚未授权删除旧规则 / inventory only; no legacy rule is approved for removal
> **核对日期 / Verified:** 2026-08-28

## 结论 / Conclusion

`DetectionEngine.builtin_rules()` 中的 47 条规则**尚未迁移完成**：正式迁移完成数为 **0 / 47**。这里的“完成”要求旧 ID 到新 ID 的一对一映射、处置级别等价或更严格、正反例回放、Hook 集成回归以及旧实现删除；当前均未建立。

PMKB 1.1.0 和 ConstraintEngine 覆盖的是权限族或增强谓词，存在语义重叠，但不是替代证明。例如 PMKB 的 `process.execute` 默认审批不能替代 `CMD-001` 的 `rm -rf` 硬阻断；`config.modify` 审批不能替代 `CFG-002` 的关闭鉴权阻断。因此不能以“看起来类似”为理由删规则。

## 分类 / Classification

| 旧规则组 / Legacy group | 数量 | 当前归属 / Current owner | PMKB 状态 / PMKB status | 可删除？ / Removable? |
| --- | ---: | --- | --- | --- |
| `CMD-001`–`CMD-010` | 10 | Detection；其中 4 条有 Constraint 增强镜像 | 仅 `process.execute` 泛化审批，缺少命令语义 | 否 / No |
| `FILE-001`–`FILE-010` | 10 | Detection；2 条有 Constraint 镜像 | 仅覆盖 file write 范围，缺少删除/凭据/批量语义 | 否 / No |
| `NET-001`–`NET-006` | 6 | Detection；2 条有 Constraint 镜像 | `network.egress` 和毒性组合部分覆盖，缺目的地细节 | 否 / No |
| `API-001`–`API-004` | 4 | Detection | `message.send` 部分重叠，缺 API 管理/渠道语义 | 否 / No |
| `SKL-001`–`SKL-006` | 6 | Detection；`SKL-005` 有 Constraint 镜像 | PMKB 未建立 skill 能力模型 | 否 / No |
| `CFG-001`–`CFG-005` | 5 | Detection；`CFG-002` 有 Constraint 镜像 | `config.modify`/`audit.modify` 部分重叠，缺精确谓词 | 否 / No |
| `GEN-001`–`GEN-006` | 6 | Detection | PMKB coverage gap 与 scope 有部分作用，缺未解析/批量标签语义 | 否 / No |

ConstraintEngine 中的 10 条同 ID 规则（`CMD-001`–`004`、`FILE-001`–`002`、`NET-001`、`NET-005`、`CFG-002`、`SKL-005`）不是可删重复代码：它们依赖 IR 实体、敏感度和置信度约束，与 Detection 的纯标签快速阻断形成两层防线。若未来统一，应该迁移至 PMKB operation guard，而非先删其中任一层。

## 已迁移的非 47 规则 / Migrated Rules Outside the 47

`SEM-OFFICE-001`（外部敏感邮件）与 `SEM-OFFICE-002`（内部日报外发）已由行为 DSL/FSM 的 MailMonitor、ReportMonitor 承担。这两条属于 `_office_decision` 的单独办公场景规则，**不计入**上述 47 条 `builtin_rules()`。

## 删除门槛 / Deletion Gate

某一旧规则只有同时满足以下条件才可删除：

1. PMKB 数据中存在可追溯的 `legacy_rule_ids` 映射；
2. `PolicyEvaluator + PermissionAutomatonCompiler` 的 effect 不弱于旧决策；
3. 规则的正例、反例、未知字段、Hook payload 回放全部通过；
4. PMKB 与 RV 生成监视器都有 source ID、版本、回滚信息；
5. 删除旧实现后全量回归与攻击用例保持通过。

建议迁移顺序 / Recommended order：先迁 `NET-001/005`、`CFG-002/005`、`FILE-007/009` 等已具备 operation 与权限语义的规则；随后扩展 PMKB 的 command、skill、delete 与 batch 操作模型；最后再迁通用未解析兜底规则。每完成一组再删除该组旧实现，而不是一次性删除 47 条。
