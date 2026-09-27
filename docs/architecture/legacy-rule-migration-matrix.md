# 旧规则迁移矩阵 / Legacy Rule Migration Matrix

> **状态 / Status：** PMKB 逐条回放完成；生产 DetectionEngine 已删除 / PMKB replay complete; production DetectionEngine removed
> **核对日期 / Verified:** 2026-09-20

## 结论 / Conclusion

47 条历史单步规则已迁移到 PMKB native owner，映射保存在 `migrations/legacy-1.1.json`，并由 94 个正反例向量和 47 个 trace 做回放验证。生产路径不再生成或召回 `LEGACY-*` 规则；ConstraintEngine 与 `policy/legacy.py` 已删除。

旧代码的**退役迁移**为 **47 / 47**。`tests/test_native_policy_migration.py` 对每个 owner 回放 positive/near-miss 向量，要求处置级别等价或更严格。

PMKB 1.2.0 的 native predicates 以 operation/resource/scope/facts 表达历史边界；迁移文件只证明来源与回放覆盖，不能作为第二套在线规则来源。

## 已完成的 PMKB 原生化增量 / Native predicate increment

本轮已把 3 个边界清晰的高频条件从标签表达转换为 PMKB 字段谓词：

| 原历史语义 | PMKB 原生规则 | 依据字段 | 处置 |
| --- | --- | --- | --- |
| `CMD-001` 类递归强删 | `NATIVE-PROCESS-DESTRUCTIVE` | `operation.arguments.command_safety=destructive` | block |
| `CMD-004` 类提权命令 | `NATIVE-PROCESS-PRIVILEGED` | `operation.arguments.command_safety=privileged` | OpenClaw approval |
| `NET-005` 类敏感外传 | `NATIVE-NETWORK-SECRET-EXTERNAL` | `scope=external` + `classification=secret` | block |

47 条迁移记录保留用于逐条 replay、审计和回滚；新增规则不得依赖历史标签字段，也不得恢复独立检测引擎。

## 分类 / Classification

| 旧规则组 / Legacy group | 数量 | 当前归属 / Current owner | PMKB 状态 / PMKB status | 可删除？ / Removable? |
| --- | ---: | --- | --- | --- |
| `CMD-001`–`CMD-010` | 10 | PMKB native owner + migration replay | operation + facts | 已完成 |
| `FILE-001`–`FILE-010` | 10 | PMKB native owner + migration replay | operation + facts | 已完成 |
| `NET-001`–`NET-006` | 6 | PMKB native owner/RiskGraph + migration replay | operation + facts + risk graph | 已完成 |
| `API-001`–`API-004` | 4 | PMKB native owner + migration replay | operation + facts | 已完成 |
| `SKL-001`–`SKL-006` | 6 | PMKB native owner + migration replay | operation + facts | 已完成 |
| `CFG-001`–`CFG-005` | 5 | PMKB native owner/RiskGraph + migration replay | operation + facts + relations | 已完成 |
| `GEN-001`–`GEN-006` | 6 | PMKB native owner + migration replay | operation + facts | 已完成 |

47 条迁移记录保留 action、标签和来源 ID，供回放、审计和回滚使用；它们不会进入生产候选集。
后续新增规则应优先使用主体、资源、范围和权限谓词。

## 已迁移的非 47 规则 / Migrated Rules Outside the 47

`SEM-OFFICE-001`（外部敏感邮件）与 `SEM-OFFICE-002`（内部日报外发）由行为 DSL 生成监视器承担。这两条不计入上述 47 条冻结 LEGACY 记录。

## 删除门槛 / Deletion Gate

某一旧规则只有同时满足以下条件才可删除：

1. PMKB 数据中存在可追溯的 `legacy_rule_ids` 映射；
2. `PolicyEvaluator + PermissionAutomatonCompiler` 的 effect 不弱于旧决策；
3. 规则的正例、反例、未知字段、Hook payload 回放全部通过；
4. PMKB 与 RV 生成监视器都有 source ID、版本、回滚信息；
5. 删除旧实现后全量回归与攻击用例保持通过。

后续治理：新增规则优先写入 PMKB 原生操作/资源/范围/主体谓词；若必须引入兼容标签规则，须先添加回放向量并通过本页的删除门槛，禁止恢复独立 DetectionEngine。
