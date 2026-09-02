# v0.7.0-dev 工程统一与现状报告

> **核对日期：** 2026-09-02  
> **项目版本：** `v0.7.0-dev`（包元数据 `0.7.0.dev0`）  
> **PMKB 版本：** `1.1.0`

## 结论

项目的 OpenClaw Hook、PMKB、RV、审计和只读 Dashboard 同步链已具备可运行主链。此次收敛将生产 HTTP 入口固定为 FastAPI，并以 PMKB 取代旧 `DetectionEngine` 的运行时裁决；47 条历史规则保留为可审计的 `LEGACY-*` PMKB 兼容记录，不再保留第二个单步规则引擎。

飞书页面 `Ev60wSV5Vijv97k6riBcu44OnEh` 在当前受限环境无法读取，因此本报告仅依据仓库中同步的 PMKB、测试、8 月 30 日 AgentDojo 结果和代码变更核对；发布前应由有飞书访问权限的维护者复核页面内容与本报告的一致性。

## 当前主链

```text
OpenClaw before_tool_call
  → Hook Bridge / BehaviorEvent
  → SemanticEnhancer + TraceCompiler
  → AuthorizationPolicyEngine（PMKB 1.1.0 + LEGACY compatibility records）
  → Constraint/RV/session-principal risk overlays（只升权）
  → GuardController
  → OpenClaw 原生审批 / block / allow
  → onResolution + SSE + 审计
```

Guard 页面不拥有审批权。`before_prompt_build` 仅记录预检查，不能产生待审批动作；真正的审批只来自 `before_tool_call`，由 OpenClaw 原生审批页响应。

## 本次统一项

| 项目 | 统一后的事实 | 验证门禁 |
| --- | --- | --- |
| 版本 | 包 `0.7.0.dev0`、展示/文档 `v0.7.0-dev`、PMKB `1.1.0` | 版本与 bundle 一致性测试 |
| HTTP | FastAPI + Uvicorn 是唯一启动入口；`legacy_web.py` 冻结 | CLI selector 测试、HTTP/前端构建 |
| 单步策略 | PMKB 原生规则与 `LEGACY-*` 共同评估 | 47 条逐条回放、Hook 回归 |
| 历史代码 | `DetectionEngine` 从生产模块删除；`policy/legacy.py` 只含冻结回放元数据 | 无生产导入检查、全量回归 |
| 评测证据 | 8 月 30 日 AgentDojo manifest、metrics、trace、report 入库 | 结果目录与 testlab 文档引用 |

## 已知问题与后续优先级

1. `ConstraintEngine` 仍从同一冻结 LEGACY 元数据生成升权规则。它不会形成第二个 allow 路径，但应继续把高频标签条件重构为 PMKB 的资源、范围、主体与权限谓词，逐步减少兼容规则比例。
2. AgentDojo 证据包含成功与失败运行。带 `error.json`、没有 metrics 的运行只能说明环境/配额失败，不能用作安全效果结论；正式对比只能引用具备 manifest、metrics、raw episodes 和 report 的完整批次。
3. OpenClaw 的审批状态仍依赖 Gateway 的 `onResolution` 回调与 SSE/增量对账。网络断开、Gateway 未重启或回调超时会使 Dashboard 延迟，但不会把 Dashboard 重新变成审批中心。
4. `.env` 当前含真实访问凭据，必须留在本地并轮换已暴露的密钥；它不属于本次提交内容。
5. `legacy_web.py` 作为历史文件仍可被直接手工导入。发布流程应只调用 `openclaw-guard run`，并在后续大版本考虑将冻结文件移至文档归档。

## 本轮文档与仓库清查（2026-09-02）

- 已将 README、现状分析、PMKB 架构、质量保障、RV 技术报告和研究简报中的旧入口、旧 PMKB 计数和 DetectionEngine 现状描述改为当前事实或明确标注为历史快照。
- 已删除无生产/测试引用的一次性 `scripts/append_feishu_comparison.py`；该脚本含本地 OpenClaw 配置读取、固定飞书文档 token 和过时架构文案，不属于历史实验或评测证据。
- `docs/archive/`、`testlab/` 历史实验脚本、AgentDojo 原始结果与报告、LEGACY 回放元数据均保留；它们不得作为当前生产模块清理。
- 已清理 Python `__pycache__` 和 VuePress `.temp` 生成目录；运行中的 `runtime/guard.log` 未删除。
- 未发现其他可在不改变生产行为的前提下删除的 tracked 模块。`collectors` 探测桩、`legacy_web.py` 和单独的基线训练脚本仍由架构/实验文档引用，暂不删除。
- 代码静态清查已移除 `services.py`/`web/app.py` 的重复类型检查导入、`policy/trace.py` 的未使用类型导入、基线脚本无效 f-string，以及命令安全分析中的无效果空分支；包级 `__init__.py` 星号重导出属于兼容 API，保留不删。

## 发布判定

提交前必须通过：策略/LEGACY 回放、Hook 同步回归、完整 Python 测试、前端生产构建、VuePress 构建及 `git diff --check`。通过后，本次变更可作为 `v0.7.0-dev` 的工程统一基线；不在未经明确授权的情况下推送远端。
