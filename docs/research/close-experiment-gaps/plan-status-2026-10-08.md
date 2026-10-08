# 计划核对与清理结果（2026-10-08）

## 当前里程碑

| 里程碑 | 状态 | 证据与剩余事项 |
| --- | --- | --- |
| M0 问题台账与冻结 | 已完成、已复核 | 台账、映射与判据保留 |
| M1 可信授权 | 已完成阶段验收 | [独立复核](m1-stage-independent-review.json)，覆盖指定原生资源与办公工具路径 |
| M2 脚本与跨会话 | 已完成阶段验收 | [独立复核](m2-stage-independent-review-v1.json)，四个强化场景在目标副作用前阻断 |
| M3 新冻结评估 | 主矩阵和自主层运行完成；整体 Q5 未通过 | [holdout](m3-holdout-analysis-v1.json)：防止8/15、正常15/15完成；正常提示增量16>5、callback p95增量381.349>50ms。完整SDK边界与部分原生消融尚缺 |
| M4 候选交付 | 候选工程验证完成；当前源码尚未完整重新打包验收 | [v3 wheel交付](m4-final-wheel-delivery-v3.json)、[SDK安装v8](m4-native-install-v8/acceptance.json)；持久化优化发生于v3包之后，本轮ATLAS使用当前源码后端与v3 JS归档 |
| M5 文档与清理 | 本次缓存清理、索引与状态更新完成；文档整体验收仍有待项 | 删除清单及恢复方式见[清理记录](cleanup-2026-10-08.json)；清单未完成项继续保留 |
| M6 正式发布 | 未通过 | `release_qualified=false`；最终独立磁盘证据复核及发布授权尚未完成 |

原全量回归1065通过、18跳过、4子测试通过，属于持久化优化之前的源码。该优化之后的67项定向回归与原生ATLAS校准不能代替当前全量回归或正式发布验收。本次未重跑实验。

## ATLAS 补充实验

[答辩报告](atlas-plugin-report-v1.md)、[最终配对](atlas-plugin-aligned-analysis-v1.json)、[完整性检查](atlas-plugin-integrity-v1.json)：HTTP资料外发与恶意技能凭据外发两组，B0/P+S均外发成功，Full由历史RV独立阻断；合法对照均完成、合计新增2次提示。

消息外发和新增脚本删除的既有校准结果也保留。所有案例仍是已揭示的固定工具调用校准，不并入历史holdout分母。恶意技能内部凭据读取和打包已经发生，只证明后续外发被阻止。

## 尚需完成

1. 权限关系完整原生消融：关闭策略图、关系监视器和主体图参与路径，分别验证。
2. 有效的持续审批信任写入与复用原生验收；没有eligible事件的样本不能证明该组件无作用。
3. 完整SDK工具调度边界计时；当前callback与本地profile数据不能判定该门通过。
4. 修复已揭盲的inline Python删除、未授权未来任务登记等覆盖缺口，贯通精确可信授权以减少正常提示。按[升级顺序](optimization-v2.md)先做定向验证。
5. 当前源码收敛后的候选重新构建、必要回归、完整性与部署复验；最终独立复核后再判断发布门。

M1/M2的通过与M3整体未通过分别成立。保留RV独立block、有限工具调用建模、可信授权边界及故障完全透传契约。

## 本次清理

删除466个可再生成文件，文件逻辑大小共7,883,413字节（约7.52 MiB）：`build/`、`.pytest_cache/`、项目Python `__pycache__/`、`docs/.vuepress/.temp/`和文档构建输出`docs/.vuepress/dist/`。

每个删除文件都未受Git跟踪，清理前记录SHA-256及恢复方式。构建副本通过重新构建恢复，Python/pytest缓存自动再生成，文档运行`cd docs && npm run docs:build`恢复。未删除源码、前端交付资源、运行中的状态数据或用户输出。

旧候选、旧结果和失败批次仍由阶段验收及哈希索引引用，保留原位置。默认67条规约、AGENTS.md以及主实验、ATLAS、v3候选验收的关键证据摘要均在清理后核验一致。文档死链检查另存为[m5-local-link-check-2026-10-08.json](m5-local-link-check-2026-10-08.json)。

### 提交前补充清理（同日）

在上述缓存清理之后追加一轮提交前清理，明细见[清理记录](cleanup-2026-10-08.json)的 `commit_prep_deletions_2026-10-08`：

- 历史报告：删除 `testlab/results/` 中 2026-07-29 RV A/B/C 五件早期对比产物，并同步更新 [`testlab/results/README.md`](../../../testlab/results/README.md) 索引；`testlab/实验结果/` 因被 9 处现行文档引用并声明为历史证据，按要求保留。
- 无引用一次性脚本：删除 `scripts/` 下 9 个无任何引用的脚本。
- 过时中间产物：删除无引用且被后续版本取代的迭代/草稿（`atlas-cases-v1`、`m3-inputs-draft-v1..v4`、`m5-local-link-check-v1..v7`、`m3-native-mapping-v1..v6`、`m3-native-trust-calibration-v2`、`m4-native-install-v1..v4/v7`），保留最新版与被引用版本。
- 可再生成缓存：`build/`、`.pytest_cache/`、项目内 `__pycache__/`、`openclaw_guard.egg-info/`、`docs/.vuepress/.temp/`；`dist/` 候选包因被安装验收证据引用而保留。
- 分层约定与载荷清理：`docs/research/close-experiment-gaps/` 的逐次运行原始载荷已从工作树删除——14 个 `raw/` 目录（53.5 MB）与 36 个 `*-raw.json`/`raw.json`/`progress.json`/`api-calls.json`/`recording.json`/`m1-calibration-native-*.json`/`m2-native-cross-session-probe-v1.json`（3.13 MB），并移除随后变空的 4 个目录；本目录由约 64 MB 降至 5.5 MB，提交体积不变。[`.gitignore`](.gitignore) 规则保留以防再生后误入库，载荷需重跑相应脚本再生。`m1-causal-r2-*.json` 因被 [`m1-native-decision-progress.md`](m1-native-decision-progress.md) 链接而保留在工作树，但仍按约定不入库。
