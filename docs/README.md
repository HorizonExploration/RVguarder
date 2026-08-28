---
home: true
title: OpenClaw-RVGuarder
heroText: OpenClaw-RVGuarder / 龙虾卫士
tagline: Non-intrusive runtime security protection for OpenClaw
actions:
  - text: 快速开始
    link: /deployment/local.html
    type: primary
  - text: 运行时 Hook 拦截
    link: /features/runtime-hook.html
    type: secondary

features:
  - title: 🛡️ 原生审批拦截
    details: 基于 OpenClaw 官方 `api.on("before_tool_call")` API，工具执行前挂起 agent，通过 `requireApproval` 实现物理拦截。不再有「先执行后审批」的尴尬。
  - title: 🔄 审批结果同步
    details: OpenClaw 原生审批卡片是唯一 Hook 审批入口，Guard Dashboard 通过 `onResolution`、SSE 和增量查询及时同步结果。
  - title: ⚡ 电路熔断降级
    details: 后端不可达时自动进入熔断 fail-open 模式，所有工具调用自动放行。后端恢复后自动闭合。再不担心「停服即封锁」。
  - title: 🧠 语义理解增强
    details: DeepSeek LLM 驱动的语义分析引擎，理解自然语言约束而非简单关键词匹配。7 维度 50+ 标签，双模式运行（LLM / 本地规则）。
  - title: 🧩 权限知识库 PMKB
    details: 版本化操作目录、Authorization Trace、最小权限闭包/差分和危险权限组合图，直接参与 before_tool_call 决策并输出可解释证据。
  - title: 📊 运行时验证 RV
    details: 滑动窗口 + FSM 监视器，检测「搜索→删除→外发」等链式攻击模式。覆盖邮件、日报、群发、数据导出等办公场景。
  - title: 🖥️ 统一工作台
    details: 动作审批、Trace 时间线、安全规则、基线扫描、RV 状态面板 — 一个前端界面全部搞定。

---

<div class="custom-card-grid">
  <div class="custom-card">
    <h3>🎯 适合谁用</h3>
    <p>高安全终端、内网环境、AI 实训场景，以及希望在不侵入 OpenClaw 的前提下增加安全管控的团队与个人。</p>
    <p><em>For teams who want OpenClaw safety without touching a single line of its source.</em></p>
  </div>
  <div class="custom-card">
    <h3>🧱 架构概览</h3>
    <p>插件层 (api.on) → 语义/Authorization Trace → PMKB 权限策略 → session/principal RV → 决策层 (requireApproval/block) → Guard 状态同步 (onResolution + SSE)</p>
    <p><em>Plugin hooks → Semantic/Trace → PMKB policy → session/principal RV → Decision → Read-only Guard sync</em></p>
  </div>
  <div class="custom-card">
    <h3>📦 当前状态</h3>
    <p>v0.7.0-dev — PMKB 权限模型、最小权限与跨 session RV 已落地，Hook 仍由 OpenClaw 单一审批并通过 SSE 同步。PMKB 1.1.0 基础规则立即参与运行时决策；新规则采用离线回放与有限事件样本校验，个人模式可用显式确认或小样本证据启用偏好。</p>
    <p><em>v0.7.0-dev — PMKB authorization modeling, least privilege, and cross-session RV are implemented. OpenClaw remains the single Hook approval owner with SSE synchronization. PMKB 1.1.0 baseline rules are enforced immediately; new rules use offline replay and bounded event-sample validation, while personal mode can use explicit confirmation or small-sample evidence.</em></p>
  </div>
</div>

---

## 本次升级结果 · Current Upgrade Result

本次升级的现行事实以[权限知识库与 RV 运行时架构结果](./architecture/permission-kb-runtime-architecture.html)为准：

- PMKB `1.1.0` 已接入 `before_tool_call` 主链，当前基线包含 22 个操作、25 条持久化规则、47 条 `LEGACY-<old-id>` 兼容规则、23 条最小权限 Trace、9 条权限关系和 27 个回归向量。
- PMKB 规则与权限组合关系同时编译为 RV 权限监视器；规则按 session 隔离、关系按可信主体/Agent/授权谱系隔离，详见 [RV 权限自动机架构](./architecture/rv-permission-automata.html)。
- 语义层先将输入规范化为 Authorization Trace，再进行覆盖感知规则命中；`unknown`、`partial`、`conflict` 不会被模糊匹配直接放行。
- 权限闭包/差分和 RiskGraph 在单步规则之后运行，检查超出业务最小权限、互斥权限和危险聚合组合。
- RV 保留 session-local 行为窗口，并增加以主体、agent 和能力血缘为键的 principal-global 跨 session 状态；审批仍只由 OpenClaw 原生审批中心完成。
- 当前文档中的“目标指标”与“实测指标”分开记录；47 条历史规则已完成兼容迁移但旧 DetectionEngine 尚未退役，也没有自动学习写入生产规则。

配套材料：[PMKB 网络案例基线](./semantic/pmkb-network-case-baseline.html)、[实现结果报告](./research/pmkb-network-baseline-implementation-report-2026-08-28.html)、[路线图](./ops/roadmap.html)。

---

## 项目定位 · Project Positioning

**中文**

OpenClaw-RVGuarder（龙虾卫士）是一个面向 OpenClaw 的非侵入式安全增强客户端与本地控制面。我们不做替代品，做的是**安全补位**。

v0.7.0-dev 在 v0.6.0 六阶段架构与 RV 阶段 A–F 的基础上，增加版本化 PMKB 权限模型：Authorization Trace、覆盖感知匹配、最小权限闭包/差分、危险权限组合图、主体能力跨 session RV，以及 OpenClaw 单一审批契约。PMKB 1.1.0 基础规则直接参与运行时决策；新规则使用离线回放与有限事件样本验证，指标用于晋级和回滚而非阻塞基础规则；详见 [路线图](./ops/roadmap.html)。

**English**

OpenClaw-RVGuarder ("Lobster Guard") is a non-invasive security enhancement client and local control plane for OpenClaw. We don't replace OpenClaw — we **backfill the safety gap**.

v0.7.0-dev builds on the v0.6.0 six-phase refactor and RV phases A–F with a versioned PMKB authorization model: Authorization Traces, coverage-aware matching, least-privilege closure/diff, toxic permission-combination graphs, principal capability RV across sessions, and an OpenClaw single-approval contract. PMKB 1.1.0 baseline rules are enforced immediately; new rules use offline replay and bounded event-sample validation, with evidence used for promotion and rollback rather than blocking the baseline. See the [roadmap](./ops/roadmap.html).

## 核心特性 · Core Features

| 特性 | 说明 | Highlights |
|------|------|------------|
| **原生钩子拦截** | `api.on("before_tool_call")`，工具执行前物理挂起 | Official hook API, physically pauses agent before tool execution |
| **审批结果同步** | OpenClaw 负责 Hook 审批，Guard 只读同步与审计 | OpenClaw owns Hook approval; Guard provides read-only sync and audit |
| **电路熔断器** | 自动熔断 fail-open，不封锁 OpenClaw | Circuit breaker — graceful degradation, never block when backend is down |
| **语义理解** | DeepSeek LLM + 7 维度标签体系 | Understands natural language intent, 50+ labels across 7 dimensions |
| **运行时验证 RV** | 滑动窗口 + 规约驱动（默认 ChainRule DSL，FSM 为回退模式）检测链式攻击 | Sliding window + spec-driven monitors (ChainRule DSL default, FSM fallback) for chain-attack detection |
| **基线扫描** | 配置/端口/用户/依赖 全量安全扫描 | Full security scan: config, ports, users, dependencies |
| **审计导出** | SQLite + JSONL 双写，哈希链防篡改 | Dual-write audit trail with hash chain integrity |
| **规则引擎** | 语义优先模式，办公场景策略 | Semantic-first decision, office scenario policies |

## 技术栈 · Tech Stack

```
Backend:   Python 3.13+ · legacy HTTP(默认) · FastAPI(可选) · DeepSeek API · SQLite · SQLAlchemy(可选) · transitions(FSM) · RV 规约驱动(ChainRule DSL) · DB_STORE_MODE / OPENCLAW_RV_RULE_MODE
Frontend:  Preact · Vite · Zustand · 单页 SPA · SSE + 增量轮询降级
Plugin:    JavaScript · OpenClaw Plugin SDK (api.on) · registerGatewayMethod
Core:      Runtime Verification (RV) · 滑动窗口 · 规约驱动 ChainRule DSL(默认) + FSM 回退 · 白名单 Trie 树
Safety:    Circuit Breaker · requireApproval · fail-open/fail-closed
```

## 快速开始 · Quick Start

```bash
# 1. 安装
pip install -e .

# 2. 启动
openclaw-guard run

# 3. 浏览器打开 http://localhost:8780
# 4. 发送一条消息，体验工具拦截 → 审批 → 放行全链路
```

要求 OpenClaw Plugin SDK >= 2026.4.0（已内置于 OpenClaw >= 2026.4.0 版本中）。

## 文档导航 · Documentation

| 章节 | 内容 | Section |
|------|------|---------|
| 🚀 [本地部署](/deployment/local.html) | 安装与首次启动 | Installation & first run |
| 🛡️ [运行时 Hook 拦截](/features/runtime-hook.html) | 插件机制与审批结果同步详解 | Hook mechanism & approval-result sync |
| ⚙️ [动作审批链](/features/action-gate.html) | 决策流程与规则引擎 | Decision pipeline & rule engine |
| 🌐 [HTTP 接口清单](/api/http.html) | 所有后端 API 文档 | Complete API reference |
| 🏗️ [架构总览](/architecture/overview.html) | 分层设计与代码映射 | Architecture & code map |
| 🧭 [架构文档索引](/architecture/index.html) | 当前架构阅读顺序与历史归档规则 | Architecture index & archive policy |
| 🔬 [RV 层技术报告](/architecture/rv-engine-report.html) | 运行时验证：规约 DSL、FSM、约束引擎、基线自动机 | RV layer tech report |
| ✅ [RV 落地审计报告](/architecture/nl-automata-rv-landing-report.html) | 阶段 A–F 落地核验与整改闭环 | RV landing audit report |
| 📊 [项目现状分析](/architecture/project-status-analysis.html) | 三类系统性问题与推进顺序 | Project status analysis |
| 📋 [基线扫描](/features/baseline.html) | 安全扫描与报告 | Security scanning & reports |
| 📝 [审计](/features/audit.html) | 审计链与导出 | Audit trail & export |
| 🧠 [语义增强方案](/semantic/method.html) | 语义理解架构设计 | Semantic enhancement design |
| 🧩 [语义与 PMKB 索引](/semantic/index.html) | 办公场景、语义方法和知识库入口 | Semantic and PMKB index |
| 📚 [PMKB 网络案例基线](/semantic/pmkb-network-case-baseline.html) | 可直接接入运行时链路的案例型权限知识库 | Case-derived permission baseline wired into the runtime |
| 🧾 [PMKB 升级结果报告](/research/pmkb-network-baseline-implementation-report-2026-08-28.html) | 本次案例型知识库接入、测试与边界 | PMKB baseline integration, tests, and boundaries |
| 🔬 [研究与规划索引](/research/index.html) | 权限模型、PMKB 和 RV 研究入口 | Research and planning index |
| 🧪 [测试设计索引](/test-design/index.html) | 当前验证设计与执行命令 | Test design and commands |
| 🧭 [项目理解与当前记忆](/architecture/project-memory.html) | 当前代码边界、已落地能力、已知边界与维护规则 | Current project facts and maintenance memory |
| 🩺 [运维 FAQ](/ops/faq.html) | 常见问题 | Frequently asked questions |
| 🗺️ [路线图](/ops/roadmap.html) | 开发计划 | Development roadmap |
