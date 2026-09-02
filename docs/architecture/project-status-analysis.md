# OpenClaw-RVGuarder 项目现状分析报告

> **版本**：v0.7.0-dev（含 PMKB 1.1.0、RV 阶段 A–F 和 OpenClaw 单一审批契约）
> **分析日期**：2026-08-30（OpenClaw 交接与误拦截修复后复核）
> **分析基准**：当前工作树；精确提交号以 Git 为准
> **改造前全量基线（2026-08-30）**：`python -m pytest -q` → **513 passed / 18 skipped / 4 subtests passed**；本次变更只运行关键链路定向回归。
> **状态更新（2026-09-02）：** 本文保留 2026-08-30 的问题快照；当前实现、版本和验证结论以 [v0.7.0-dev 工程统一报告](./v070-engineering-unification-report-2026-09-02.md) 为准。

---

## 一、执行摘要

OpenClaw-RVGuarder（龙虾卫士）是一个面向 OpenClaw 的非侵入式运行时安全保护系统。当前项目已跨过 v0.3.0 的四阶段架构重构（HTTP 层替换、Pydantic 迁移、Manager 拆分懒加载、Preact 前端迁移），并在此基础上完成 RV 层拆分（`engine/` → `rv/` + `spec/`）与规约驱动能力（阶段 A–F）的落地。

项目整体处于**核心链路可用、治理能力持续完善**阶段。本快照中的双轨 HTTP、生产 DetectionEngine 和旧规则双源问题已经在 2026-09-02 工程统一中解决；仍有效的问题主要是前端测试门禁、真实 OpenClaw 同步证据、约束规则原生化、生产存储集成和采集器能力边界。当前事实与维护口径见 [项目理解与当前记忆](./project-memory.md)。

本次升级的可核对结果集中在[权限知识库与 RV 运行时架构结果](./permission-kb-runtime-architecture.md)：PMKB `1.1.0` 已进入 `before_tool_call` 热路径，当前基线为 28 个 canonical operations、32 条 authored 规则、47 条 `LEGACY-<old-id>` 兼容规则（bundle 共 79 条规则）、29 条最小权限 Trace、9 条权限关系和 29 个回归向量；生产 DetectionEngine 已退役，LEGACY 仅用于兼容回放。

> **阅读说明：** 第 4–6 节保留 2026-08-30 的问题快照，便于追踪改造前后差异。快照中的 B-1（双轨 HTTP）、C-1（规则双源）和 C-5（重复低风险命令逻辑）已解决；其余仍有效的风险以本节开头列出的工程统一报告为准。

---

## 二、项目概览

| 项 | 状态 |
|---|---|
| 产品定位 | OpenClaw 非侵入式安全护栏（执行前审批 + 语义分析 + 运行时验证 + 审计） |
| 后端 | Python 3.13+ / Pydantic v2 / FastAPI（唯一入口）/ transitions FSM |
| 前端 | Vite 6 + Preact 10 + Zustand 5 + preact-router |
| 存储 | SQLite（开发）/ PostgreSQL + Redis（生产，可选依赖） |
| 测试 | Python 全量回归；最新数量以 `project-memory.md` 与 CI 输出为准 |
| 当前 git | 当前工作树（PMKB 1.1.0 文档与规则基线） |

**后端模块布局**（`openclaw_guard/`）：

| 子包 | 职责 | 状态 |
|---|---|---|
| `engine/` | 单步检测、语义增强、控制决策、白名单、流水线编排 | 活跃 |
| `rv/` | RV 运行时验证（FSM、约束推理、IR、基线自动机） | 本次拆分后新增 |
| `spec/` | 规约生成/校验/会话状态（NL2Spec、SpecValidator、SessionSafetyState） | 本次拆分后新增 |
| `web/` | FastAPI HTTP 层（7 个路由模块） | 唯一生产入口 |
| `legacy_web.py` | stdlib HTTP 兼容层 | 冻结历史文件，不参与启动 |
| `api/` | HTTP handler 桥接层（被 web/ 与 legacy_web 共用） | 保留 |
| `core/` | ActionService / AuditService / BaselineService | 活跃 |
| `integrations/` | OpenClaw 适配、Hook 运行时、发现、载荷转换 | 活跃 |
| `storage/` | DBStoreInterface ABC → SQLite/PostgreSQL、审计哈希链 | 活跃 |
| `collectors/` | Ptrace/eBPF/HookBridge 采集器 | 仅 capability 探测桩 |

---

## 三、已完成开发成果

### 3.1 架构重构（v0.3.0 四阶段，已提交）

1. **阶段一：HTTP 层替换** — FastAPI 应用工厂 + 依赖注入 + 统一异常处理；旧版 `legacy_web.py` 后续冻结为历史参考。
2. **阶段二：Pydantic 模型迁移** — `models.py` 全部 10 个数据类迁移至 Pydantic v2，`to_dict()` 保留兼容别名。
3. **阶段三：Manager 拆分 + 懒加载** — `GuardServices` 容器 + `LazyProxy` 惰性加载 + `pipeline.py` 流水线模块，核心组件延迟初始化优化启动。
4. **阶段四：前端 Preact 迁移** — 17 源文件、5 页面、10 组件、Zustand 状态管理，替换 Vanilla JS。

### 3.2 RV 层拆分、规约驱动与 PMKB 能力（已落地）

5. **RV 层拆分** — `engine/` 下 RV 相关 13 个文件迁移至 `rv/`（运行时验证）与 `spec/`（规约），与在线检测解耦。
6. **阶段 A：ToolCallIR** — `rv/ir.py` 结构化中间表示（Entity/Constraint/ToolCallIR），语义层 `rv_trace` 透传 entities/constraints/confidence。
7. **阶段 B：约束推理引擎** — `rv/constraints.py`，接入 pipeline `_apply_constraint_engine`，支持 `OPENCLAW_RV_CONSTRAINT_MODE` 开关。
8. **阶段 C：基线自动机** — `rv/baseline_learner.py` + `rv/baseline_monitor.py` + `rv/trace_abstractor.py`。
9. **阶段 D：RV 参数化原语** — entity 匹配、时间间隔、state_counter、quantifier/bind_vars。
10. **阶段 E：NL2Spec 生成** — `spec/nl2spec_generator.py` + `spec/spec_validator.py` + 正反例 trace 库（`eval_traces.py`）。
11. **阶段 F：会话安全状态** — `spec/session_state.py`，接入 pipeline `_apply_session_escalation`，per-session 累计风险升级。
12. **PMKB 1.1.0** — 网络案例基础规则通过 `PolicyBundle → TraceCompiler → PolicyEvaluator → PermissionClosure/Diff → RiskGraph` 接入运行时；基础规则立即生效，新规则使用离线回放和有限事件样本验证；主体级 RV 状态按受控键持久化并跨 session 聚合。

### 3.3 核心安全能力

- **47 条单步检测规则**（CMD/FILE/NET/API/SKL/CFG/GEN 七类）+ 6 个 FSM 跨步监视器。
- **双层防线**：PMKB 单步策略（含 LEGACY 回放记录）+ RV 引擎（跨步有状态，<5ms）。
- **SHA-256 审计哈希链**，SQLite + JSONL 双写。
- **白名单 Trie 前缀树**，O(n) 匹配效率。
- **OpenClaw 原生审批 + Guard 只读同步**（`requireApproval` + `onResolution` + SSE/增量查询）。
- **权限知识库与组合风险**：Authorization Trace、最小权限闭包/差分、危险权限组合图和主体跨 session 风险累计。
- **基线安全扫描**（配置/端口/用户/依赖），JSON/HTML/PDF 输出。

---

## 四、问题清单（按三大维度）

> 严重等级定义：
> - **Critical（严重）**：阻塞核心功能、存在安全风险、可能导致数据错误
> - **High（高）**：重要功能缺陷、性能严重不达标、重大技术债务
> - **Medium（中）**：影响开发效率、潜在风险、渐进迁移未完成
> - **Low（低）**：小瑕疵、优化项、文档滞后

---

### 4.1 前端技术实现

| # | 问题 | 具体表现 | 影响范围 | 严重等级 |
|---|---|---|---|---|
| F-1 | **首屏 JS 资源超标** | 当前构建产物 `runtime/ui/assets/index-C6by2uZY.js` 约 54 KB（未压缩），仍高于项目约束「前端首屏 JS ≤ 20 KB gzip」；需在构建门禁中持续复测 | 首屏加载速度、性能指标达成 | **High** |
| F-2 | **前端无自动化测试** | 21 个测试文件全部为后端 Python；前端 `store.js`（乐观更新、哈希去重）、`api.js`（错误处理）、5 个页面组件零单测/E2E | 前端回归保障缺失，重构风险高 | **Medium** |
| F-3 | **前端构建流程依赖手工操作** | `ui.py:build_ui()` 仅复制已存在的 `runtime/ui/` 构建产物，不触发 Vite 构建；前端源码修改后需手动 `npm run build`，否则运行时服务旧资源 | 部署一致性、CI 自动化 | **Medium** |
| F-4 | ~~**API 层静默吞错**~~ ✅ 已解决 | `api.js` 统一抛出错误并由 `apiErrorMessage()` 展示 `detail/message/error` | ~~Low~~ 已闭环 |

---

### 4.2 后端服务支撑

| # | 问题 | 具体表现 | 影响范围 | 严重等级 |
|---|---|---|---|---|
| B-1 | **双轨 HTTP 层并存，维护成本高** | `main.py` 默认 `legacy_web.py`（stdlib `ThreadingHTTPServer`），`--fastapi` 切换 `web/` 包；两套路由表需人工同步，端点逻辑重复 | 长期维护、行为一致性、新端点双份实现 | **High** |
| B-2 | **legacy_web 路由表重复注册** | `legacy_web.py` 中 `/api/audit/export` 同时出现在 GET（第 175 行）与 POST（第 190 行）映射，均指向 `api.audit_export` | 路由语义混乱（虽功能正常） | **Low** |
| B-3 | **FastAPI 关闭 OpenAPI 文档** | `web/app.py` 设 `docs_url=None, redoc_url=None, openapi_url=None` | 无法自动生成 API 文档，前端/第三方对接需手查源码 | **Low** |
| B-4 | **生产存储路径未充分验证** | PostgreSQL/Redis 为可选依赖（`psycopg2-binary`/`sqlalchemy`/`redis`），`PostgreSQLStore` 仅靠 `test_sqlalchemy_store.py` 覆盖，Redis 缓存路径无集成测试 | 生产环境稳定性 | **Medium** |
| B-5 | **`requires-python >= 3.13` 可能过严** | `pyproject.toml` 声明 Python ≥3.13，但 `__pycache__` 中同时存在 3.11 与 3.13 字节码，历史环境用过 3.11 | 部署兼容性 | **Low** |

---

### 4.3 核心应用功能

| # | 问题 | 具体表现 | 影响范围 | 严重等级 |
|---|---|---|---|---|
| C-1 | ~~检测规则双源并存~~ ✅ 已解决 | `builtin_rules()` 现通过 `match_labels` 承载匹配逻辑，`_semantic_predicates()` 已删除，`evaluate()` 直接遍历规则 | 规则治理 | ~~High~~ 已闭环 |
| C-2 | **约束引擎与 lambda 规则并存（迁移未完成）** | `_apply_constraint_engine`（阶段 B）与 detection 的 47 条 lambda 规则并行，约束引擎仅做升权不降权；两套判定逻辑最终一致性靠人工保证 | 规则一致性、长期维护 | **Medium** |
| C-3 | **LLM 语义增强默认降级本地规则** | `DetectionEngine.__init__` 传 `SemanticEnhancer(api_key="")` → `_llm_enabled=False`；pipeline 主实例才读 `.env`。无 `DEEPSEEK_API_KEY` 时 7 维度标签体系实际退化为本地启发式 | 语义准确度、标签覆盖度 | **Medium** |
| C-4 | **collectors 采集器为探测桩** | `collectors/` 三件套（ptrace/ebpf/hook_bridge）仅 capability 探测 stub，但 `config.py` 中 `enable_ptrace=True`/`enable_ebpf=True` 配置项存在且默认开启 | 行为采集能力未落地，配置项形同虚设 | **Medium** |
| C-5 | ~~`_is_low_risk_command` 重复定义~~ ✅ 已解决 | `detection.py` 中的重复定义已删除，仅保留 `semantic_enhancer.py` 的真实实现 | 代码整洁度 | ~~Low~~ 已闭环 |
| C-6 | **BaselineMonitor 默认不加载 DFA** | 需显式配置 `OPENCLAW_RV_BASELINE_DFA_PATH` 才加载基线自动机，默认引擎不加载 | 基线异常检测能力默认关闭 | **Low** |
| C-7 | **NL2Spec LLM 生成未落地** | `nl2spec_generator.py` 的 `use_llm=True` 仅预留接口，当前「自然语言 → 规约」只有模板关键词匹配 | 自然语言策略自动生成能力 | **Low** |
| C-8 | **LLM 默认模型名需核验** | `semantic_enhancer.py` 硬编码 `_DEFAULT_LLM_MODEL = "deepseek-v4-flash"`，需确认该模型在 DeepSeek API 的有效性 | LLM 模式可用性 | **Low** |

---

## 五、待推进开发任务（按优先级）

### P0 — 立即处理（影响正确性与安全）

| 任务 | 关联问题 | 状态 |
|---|---|---|
| 收敛检测规则单一数据源 | C-1 | ✅ 已完成（`match_labels` + 删除 `_semantic_predicates()`） |
| 清理 `_is_low_risk_command` 死代码 | C-5 | ✅ 已完成（删除 `detection.py` 重复定义） |

### P1 — 短期（1–2 个迭代）

| 任务 | 关联问题 | 目标 |
|---|---|---|
| 前端资源体积优化 | F-1 | 分析 61 KB JS 构成，tree-shaking / 按需加载 / 移除未用依赖，压到 20 KB gzip 内 |
| 前端测试补充 | F-2 | 为 `store.js`/`api.js` 补 Vitest 单测，关键页面补 Playwright E2E |
| 约束引擎渐进替换 lambda 规则 | C-2 | 将 47 条 lambda 规则逐条迁移为 `ConstraintRule`，完成阶段 B 收尾 |
| 双轨 HTTP 收敛 | B-1 | 默认切 FastAPI，废弃或冻结 `legacy_web.py`，消除双轨维护成本 |

### P2 — 中期（规划内）

| 任务 | 关联问题 | 目标 |
|---|---|---|
| collectors 真实采集落地 | C-4 | 实现 HookBridge 至少一个真实采集器，或删除 `enable_ptrace/enable_ebpf` 虚设配置 |
| LLM 语义增强启用策略 | C-3 | 明确 LLM 模式开关与降级策略，文档化无 key 时的行为预期 |
| 生产存储路径集成测试 | B-4 | PostgreSQL/Redis 路径补集成测试，覆盖自动切换逻辑 |
| 前端构建自动化 | F-3 | 集成到 CI（`npm run build` 前置），或运行时校验构建产物版本 |

### P3 — 长期（优化）

| 任务 | 关联问题 | 目标 |
|---|---|---|
| NL2Spec LLM 生成落地 | C-7 | 接入 LLM 将自然语言策略直接生成规约 |
| BaselineMonitor 默认策略 | C-6 | 评估默认加载 DFA 的误报率，制定启用策略 |
| OpenAPI 文档恢复 | B-3 | 评估 `docs_url` 与 SPA catch-all 冲突的解决方案 |

---

## 六、风险矩阵

| 风险 | 概率 | 影响 | 缓解措施 |
|---|---|---|---|
| 规则双源导致漏检/误检 | 中 | 高 | 优先执行 P0 收敛规则数据源 |
| 前端资源超标拖慢首屏 | 高 | 中 | 优先执行 P1 体积优化 |
| 双轨 HTTP 行为漂移 | 中 | 中 | 收敛默认到 FastAPI，冻结 legacy |
| LLM 依赖降级导致语义能力打折 | 高 | 中 | 明确降级策略与文档 |
| collectors 虚设配置误导用户 | 低 | 中 | 落地真实采集或移除配置 |

---

## 七、结论

项目已完成 v0.3.0 的架构现代化改造，并成功落地 RV 层拆分、规约驱动能力（阶段 A–F）与 PMKB 1.1.0 基础规则，具备可运行的检测、审批、审计、基线扫描和跨 session 风险链路。当前主要风险集中在**规则治理的单一数据源收敛**、**前端资源体积与测试缺口**、**双轨 HTTP 的维护成本**三大方向。

建议按 P0 → P1 → P2 → P3 顺序推进，优先消除规则双源与死代码，再补前端工程化与双轨收敛，最后完善采集器与 LLM 能力，使项目从「架构转型后期」稳步进入「能力完善期」。

---

*本报告于 2026-08-30 复核，后于 2026-09-02 增加状态说明；改造前全量回归为 **513 passed / 18 skipped / 4 subtests passed**，当前全量回归为 **545 passed / 18 skipped / 4 subtests passed**。历史问题快照保留原日期和语境，Hook 审批职责和同步链路的最新事实以 `frontend-handoff-redesign-report.md` 与 `runtime-hook.md` 为准。*
