# 旧规则迁移矩阵 / Legacy Rule Migration Matrix

> **状态 / Status：** PMKB 逐条回放完成；生产 DetectionEngine 已删除 / PMKB replay complete; production DetectionEngine removed
> **核对日期 / Verified:** 2026-09-02

## 结论 / Conclusion

47 条历史单步规则已完成**兼容迁移**：ConstraintEngine 为 `47 / 47`，PMKB bundle 为 `47 / 47`。每条 PMKB 兼容记录为 `LEGACY-<old-id>`，带 `legacy_rule_ids`、原 action type 和原语义标签；每条 ConstraintRule 由冻结的 `policy/legacy.py` 元数据生成。

旧代码的**退役迁移**为 **47 / 47**。`tests/test_legacy_policy_migration.py` 对每个 action type 和标签集合回放 PMKB，要求处置级别等价或更严格；通过后已删除生产 `DetectionEngine` 实现。

PMKB 1.1.0 和 ConstraintEngine 覆盖的是权限族或增强谓词，存在语义重叠，但不是替代证明。例如 PMKB 的 `process.execute` 默认审批不能替代 `CMD-001` 的 `rm -rf` 硬阻断；`config.modify` 审批不能替代 `CFG-002` 的关闭鉴权阻断。因此不能以“看起来类似”为理由删规则。

## 分类 / Classification

| 旧规则组 / Legacy group | 数量 | 当前归属 / Current owner | PMKB 状态 / PMKB status | 可删除？ / Removable? |
| --- | ---: | --- | --- | --- |
| `CMD-001`–`CMD-010` | 10 | Constraint + `LEGACY-*` PMKB | action + labels | 是 / Yes |
| `FILE-001`–`FILE-010` | 10 | Constraint + `LEGACY-*` PMKB | action + labels | 是 / Yes |
| `NET-001`–`NET-006` | 6 | Constraint + `LEGACY-*` PMKB | action + labels + 现有风险图 | 是 / Yes |
| `API-001`–`API-004` | 4 | Constraint + `LEGACY-*` PMKB | action + labels | 是 / Yes |
| `SKL-001`–`SKL-006` | 6 | Constraint + `LEGACY-*` PMKB | action + labels | 是 / Yes |
| `CFG-001`–`CFG-005` | 5 | Constraint + `LEGACY-*` PMKB | action + labels + 现有权限规则 | 是 / Yes |
| `GEN-001`–`GEN-006` | 6 | Constraint + `LEGACY-*` PMKB | action + labels | 是 / Yes |

ConstraintEngine 由所有 47 条冻结 LEGACY 元数据动态生成同 ID 规则，避免再维护一份只覆盖 10 条的手写镜像。兼容记录仍依赖 action 与标签；后续新增规则应优先使用主体、资源、范围和权限谓词，不再新增 DetectionEngine 类型实现。

## 已迁移的非 47 规则 / Migrated Rules Outside the 47

`SEM-OFFICE-001`（外部敏感邮件）与 `SEM-OFFICE-002`（内部日报外发）由行为 DSL/FSM 的 MailMonitor、ReportMonitor 承担。这两条不计入上述 47 条冻结 LEGACY 记录。

## 删除门槛 / Deletion Gate

某一旧规则只有同时满足以下条件才可删除：

1. PMKB 数据中存在可追溯的 `legacy_rule_ids` 映射；
2. `PolicyEvaluator + PermissionAutomatonCompiler` 的 effect 不弱于旧决策；
3. 规则的正例、反例、未知字段、Hook payload 回放全部通过；
4. PMKB 与 RV 生成监视器都有 source ID、版本、回滚信息；
5. 删除旧实现后全量回归与攻击用例保持通过。

后续治理：新增规则优先写入 PMKB 原生操作/资源/范围/主体谓词；若必须引入兼容标签规则，须先添加回放向量并通过本页的删除门槛，禁止恢复独立 DetectionEngine。
