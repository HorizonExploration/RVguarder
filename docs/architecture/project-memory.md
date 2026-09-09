# 项目理解与当前记忆

> **核对日期**：2026-09-09（文档清查后复核）
> **核对基准**：当前工作树（PMKB 网络案例基础知识库 `1.1.0`）
> **合并后全量回归（2026-09-03）**：`python -m pytest -q` → **506 passed / 18 skipped / 4 subtests passed**。

本文档是后续维护项目时的“当前事实源”。历史方案、阶段性审计报告和旧版本说明仍然保留，但如果它们与本文档或当前代码冲突，应以当前代码和本文档为准。

本次权限知识库与运行时验证升级的系统级结果见[权限知识库与 RV 运行时架构结果](./permission-kb-runtime-architecture.md)；本文档负责维护全项目事实摘要，避免重复复制策略细节。

## 1. 项目定位

OpenClaw-RVGuarder（龙虾卫士）是面向 OpenClaw 的非侵入式运行时安全控制面。它通过 OpenClaw Plugin SDK 的 Hook，在不修改 OpenClaw 源码的前提下，对工具调用执行：

1. 执行前语义分析与规则检测；
2. 跨调用运行时验证（RV）；
3. 内部风险结果经合并后映射为 `allow` / `ask` / `block`；RV 内部 `escalate` 只作为升权信号，不创建第二审批源；
4. OpenClaw 原生页面是 Hook 审批唯一入口，Guard Dashboard 通过 resolution/SSE 只读同步状态；
5. 执行后审计、哈希链校验和基线扫描。

核心安全取舍是“先决策后执行、可取证、非侵入、故障可降级”。Hook 后端不可达时，插件电路熔断器会进入 fail-open，以避免 Guard 停服阻塞 OpenClaw；这意味着生产部署必须配套健康检查和熔断告警。

## 2. 当前主链

```text
OpenClaw before_tool_call
  → Hook Bridge / BehaviorEvent
  → SemanticEnhancer（DeepSeek LLM 或本地规则降级）
  → TraceCompiler / PMKB PolicyEvaluator（Authorization Trace、最小权限、RiskGraph）
  → AuthorizationPolicyEngine（PMKB 原生规则 + LEGACY 回放兼容记录）
  → RuntimeVerificationEngine.preview（已提交窗口的纯回放）
  → PrincipalSecurityState.evaluate（已提交主体证据的只读校验）
  → GuardController
  → requireApproval / block / allow
  → after_tool_call 成功后提交 RV trace 与主体权限证据，再审计
```

聊天入口和 Hook 入口共用 `openclaw_guard/engine/pipeline.py`。RV 使用 `session_id`（缺失时回退 `_default`）隔离滑动窗口；每次由 TTL 内的窗口快照重建自动机，避免跨会话污染与过期状态残留。

## 3. 代码边界

| 区域 | 当前职责 |
|---|---|
| `openclaw_guard/engine/` | 语义增强、命令安全事实、控制决策、白名单、热路径编排 |
| `openclaw_guard/policy/` | PMKB bundle、TraceCompiler、规则评估、权限闭包/差分、RiskGraph |
| `openclaw_guard/rv/` | ToolCallIR、ChainRule DSL、RV 引擎、基线自动机 |
| `openclaw_guard/spec/` | NL2Spec、规约校验、正反例 trace、主体权限证据状态 |
| `openclaw_guard/core/` | 动作、审计、基线等业务服务 |
| `openclaw_guard/integrations/` | OpenClaw 发现、Hook 生成、载荷转换、Gateway 适配 |
| `openclaw_guard/storage/` | SQLite/PostgreSQL/可选 SQLAlchemy 存储与审计哈希链 |
| `openclaw_guard/web/` | FastAPI 路由，唯一 HTTP 入口 |
| `frontend/` | Vite + Preact + Zustand 工作台 |
| `testlab/` | AgentDojo 与 RV 必要性/鲁棒性/干扰实验 |
| `docs/` | VuePress 文档站、架构报告、研究记录和测试设计 |

## 4. 已落地能力

- v0.3.0 架构重构：Pydantic v2、GuardServices + pipeline、Preact、可选 SQLAlchemyStore、ChainRule 规约驱动 RV；HTTP 服务已在 v0.7.0-dev 收敛为 FastAPI 单入口。
- RV：ToolCallIR、基线自动机、实体/时间/计数参数化、NL2Spec + 反例校验；ConstraintEngine、累计会话分数与 revise 干预已从生产路径删除。
- 运行时默认 `dsl` 规则模式；设置 `OPENCLAW_RV_RULE_MODE=fsm` 可回退到六个手写 FSM 监视器。
- 规则检测、Hook 审批、resolution 幂等同步、审计双写、基线扫描和前端 RV 状态面板均有现行代码与测试覆盖。
- PMKB 网络案例基线 `1.1.0` 已直接接入 `PolicyBundle → TraceCompiler → PolicyEvaluator → RiskGraph` 链路；源码目录与打包目录保持同版本、同内容，并为关键操作保留来源、Trace 和正反例向量。
- OpenClaw 官方 runtime、filesystem、web、browser、sessions、memory、messaging、automation、agents、human-input、credentials、nodes 和 UI 工具通过显式 profile 建模；低风险 profile 必须满足结构化参数边界才继承只读信任。未知工具或越权参数固定为 `unknown` 并一次审批，不通过自由文本猜测动作类型。
- Hook 透传 `toolKind`、`toolInputKind`、`derivedPaths`；after 回调只有在 `runId + toolCallId + session/agent/tool` 上下文一致且动作未终态时才能提交执行、principal 和 RV 状态，重复回调会被拒绝。
- Hook 审批文案在发送给 OpenClaw 前限制为标题 80、说明 240 字符；超过 6 分钟未回调的审批会标记为 `approval_timeout`，避免长命令 schema 失败和 Dashboard 孤儿动作。
- 审批回调由 OpenClaw 单一审批中心拥有；Guard 只读同步。回调在写入动作状态后再发布 `action.resolved`，摘要提供 `sync.approval` 聚合指标（最近 128 个延迟样本），前端摘要哈希会响应同步序号变化。
- PMKB 已新增 `NATIVE-PROCESS-DESTRUCTIVE`、`NATIVE-PROCESS-PRIVILEGED`、`NATIVE-NETWORK-SECRET-EXTERNAL` 三条字段谓词规则；47 条 `LEGACY-*` 继续作为历史回放证据，尚未删除。
- 2026-09-03 已完成原生工具、RV 窗口重放、主体成功提交的定向回归；合并后全量回归为 **506 passed / 18 skipped / 4 subtests passed**；未运行大规模 AgentDojo。

## 5. 当前边界与待办

这些不是“已完成能力”，维护时不要把它们写成完成状态：

- 代码包版本为 `0.7.0.dev0`（展示为 `v0.7.0-dev`），PMKB bundle 为 `1.1.0`（47 个 canonical operations）；二者分别标识产品构建与策略数据版本。
- FastAPI 是唯一启动入口；旧版 stdlib HTTP 实现已从生产包移除，历史源文件保留在 Git 归档中。
- 47 条历史单步规则已形成 `LEGACY-<old-id>` PMKB 记录并通过逐条回放门禁；DetectionEngine 已从生产路径删除，冻结元数据仅用于审计和历史评测。
- 基线 DFA 只有在设置 `OPENCLAW_RV_BASELINE_DFA_PATH` 或显式传入路径时才加载，默认不做基线偏离检测。
- collectors 下的 ptrace/eBPF 仍是 capability 探测桩；不要把它们描述成已落地的系统级采集器。
- NL2Spec 的当前实现以模板/关键词和确定性 ChainRule 合成为主，LLM 生成接口仍属于可选扩展路径。
- 前端自动化测试、文档站 CI、审计归档轮转和熔断告警仍在路线图中；主体级 RV 状态持久化已落地，但仍需长期稳定性和跨版本迁移验证。

## 6. 维护规则

1. 先看本文件、`docs/architecture/index.md`、`docs/ops/roadmap.md`，再看现行研究文档；历史材料统一在 `docs/archive/`，`testlab/` 仅作为历史实验与证据，不是运行时依赖。
2. 修改 Hook 合约、RV 判定顺序、默认模式或版本号时，同时更新 API/架构/部署文档和测试基线。
3. 报告测试数量必须注明运行日期和命令；历史报告中的旧计数是快照，当前回归基线为 **506 passed / 18 skipped / 4 subtests passed**（2026-09-03）。
4. 运行时是否处于 fail-open 不能从静态文档推断，必须通过进程、健康接口和插件状态现场检查。
5. 文档与前端构建验证命令分别为 `cd docs && npm run docs:build`、`cd frontend && npm run build`；当前复核均已通过（2026-09-09）。
