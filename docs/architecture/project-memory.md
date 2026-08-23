# 项目理解与当前记忆

> **核对日期**：2026-08-23  
> **核对基准**：仓库当前 HEAD `114502e`（`feat(release,rv,frontend,docs,build): 发布v0.6.0正式版，落地RV全阶段功能`）  
> **测试基线**：`python -m pytest -q` → **345 passed / 18 skipped / 0 failed**（363 个用例被收集）

本文档是后续维护项目时的“当前事实源”。历史方案、阶段性审计报告和旧版本说明仍然保留，但如果它们与本文档或当前代码冲突，应以当前代码和本文档为准。

## 1. 项目定位

OpenClaw-RVGuarder（龙虾卫士）是面向 OpenClaw 的非侵入式运行时安全控制面。它通过 OpenClaw Plugin SDK 的 Hook，在不修改 OpenClaw 源码的前提下，对工具调用执行：

1. 执行前语义分析与规则检测；
2. 跨调用运行时验证（RV）；
3. `allow` / `ask` / `escalate` / `block` / `revise` 决策；
4. OpenClaw 原生审批与 Guard Dashboard 双向同步；
5. 执行后审计、哈希链校验和基线扫描。

核心安全取舍是“先决策后执行、可取证、非侵入、故障可降级”。Hook 后端不可达时，插件电路熔断器会进入 fail-open，以避免 Guard 停服阻塞 OpenClaw；这意味着生产部署必须配套健康检查和熔断告警。

## 2. 当前主链

```text
OpenClaw before_tool_call
  → Hook Bridge / BehaviorEvent
  → SemanticEnhancer（DeepSeek LLM 或本地规则降级）
  → DetectionEngine（47 条单步规则 + 办公场景策略）
  → ConstraintEngine（可配置，升权不降权）
  → RuntimeVerificationEngine（默认 ChainRule DSL，FSM 回退）
  → SessionSafetyState（会话累计风险、escalate/revise）
  → GuardController
  → requireApproval / block / allow
  → after_tool_call 审计
```

聊天入口和 Hook 入口共用 `openclaw_guard/engine/pipeline.py`。RV 使用 `session_id`（缺失时回退 `_default`）隔离滑动窗口和监视器实例，避免不同 Agent 会话互相污染。

## 3. 代码边界

| 区域 | 当前职责 |
|---|---|
| `openclaw_guard/engine/` | 语义增强、单步检测、控制决策、白名单、热路径编排 |
| `openclaw_guard/rv/` | ToolCallIR、约束推理、ChainRule DSL、RV 引擎、基线自动机 |
| `openclaw_guard/spec/` | NL2Spec、规约校验、正反例 trace、会话安全状态 |
| `openclaw_guard/core/` | 动作、审计、基线等业务服务 |
| `openclaw_guard/integrations/` | OpenClaw 发现、Hook 生成、载荷转换、Gateway 适配 |
| `openclaw_guard/storage/` | SQLite/PostgreSQL/可选 SQLAlchemy 存储与审计哈希链 |
| `openclaw_guard/web/` | FastAPI 路由；`legacy_web.py` 仍是默认兼容入口 |
| `frontend/` | Vite + Preact + Zustand 工作台 |
| `testlab/` | AgentDojo 与 RV 必要性/鲁棒性/干扰实验 |
| `docs/` | VuePress 文档站、架构报告、研究记录和测试设计 |

## 4. 已落地能力

- v0.3.0 架构重构：FastAPI 可选层、Pydantic v2、GuardServices + pipeline、Preact、可选 SQLAlchemyStore、ChainRule 规约驱动 RV。
- RV 阶段 A–F：ToolCallIR、五类约束与置信度门控、基线自动机、实体/时间/计数参数化、NL2Spec + 反例校验、revise 干预与会话升级。
- 运行时默认 `dsl` 规则模式；设置 `OPENCLAW_RV_RULE_MODE=fsm` 可回退到六个手写 FSM 监视器。
- 规则检测、Hook 审批、审计双写、基线扫描和前端 RV 状态面板均有现行代码与测试覆盖。

## 5. 当前边界与待办

这些不是“已完成能力”，维护时不要把它们写成完成状态：

- `pyproject.toml` 与 `openclaw_guard.__version__` 仍为 `0.3.0`，而发布提交和文档产品版本为 `v0.6.0`；这是版本元数据未统一的问题。
- 默认 HTTP 入口仍是 `legacy_web.py`，FastAPI 需要 `--fastapi`；双轨路由存在维护和行为漂移成本。
- 约束引擎与 47 条检测规则仍是并行判定链，尚未完成全部规则迁移为统一 ConstraintRule 数据源。
- 基线 DFA 只有在设置 `OPENCLAW_RV_BASELINE_DFA_PATH` 或显式传入路径时才加载，默认不做基线偏离检测。
- collectors 下的 ptrace/eBPF 仍是 capability 探测桩；不要把它们描述成已落地的系统级采集器。
- NL2Spec 的当前实现以模板/关键词和确定性 ChainRule 合成为主，LLM 生成接口仍属于可选扩展路径。
- 前端自动化测试、文档站 CI、审计归档轮转、熔断告警和 RV 状态持久化仍在路线图中。

## 6. 维护规则

1. 先看本文件、`docs/architecture/project-status-analysis.md`、`docs/ops/roadmap.md`，再看历史研究文档。
2. 修改 Hook 合约、RV 判定顺序、默认模式或版本号时，同时更新 API/架构/部署文档和测试基线。
3. 报告测试数量必须注明运行日期和命令；历史报告中的 331/340/344 是历史快照，不应覆盖当前 345/18 基线。
4. 运行时是否处于 fail-open 不能从静态文档推断，必须通过进程、健康接口和插件状态现场检查。

