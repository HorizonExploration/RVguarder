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
  - title: 🔄 双端状态同步
    details: OpenClaw 原生审批卡片 ↔ Guard Dashboard 双向同步。任一端确认，两端同时更新。`onResolution` 回调 + Gateway 远程调用实时流转。
  - title: ⚡ 电路熔断降级
    details: 后端不可达时自动进入熔断 fail-open 模式，所有工具调用自动放行。后端恢复后自动闭合。再不担心「停服即封锁」。
  - title: 🧠 语义理解增强
    details: DeepSeek LLM 驱动的语义分析引擎，理解自然语言约束而非简单关键词匹配。7 维度 50+ 标签，双模式运行（LLM / 本地规则）。
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
    <p>插件层 (api.on) → 桥接层 (HTTP POST) → 检测层 (规则+语义+RV) → 决策层 (requireApproval/block) → 同步层 (onResolution + Gateway call)</p>
    <p><em>Plugin hooks → Bridge API → Detection (Rule+Semantic+RV) → Decision (requireApproval/Block) → Sync (Bidirectional)</em></p>
  </div>
  <div class="custom-card">
    <h3>📦 当前状态</h3>
    <p>v0.2.1 — 钩子 API 已全面迁移至官方 `api.on()`，requireApproval 对齐官方规范，双端同步链路已闭环，RV 引擎 6 个监视器已上线，熔断器已落地。</p>
    <p><em>v0.2.1 — Hook API on official `api.on()`, requireApproval compliant, bidirectional sync live, 6 RV monitors active, circuit breaker deployed.</em></p>
  </div>
</div>

---

## 项目定位 · Project Positioning

**中文**

OpenClaw-RVGuarder（龙虾卫士）是一个面向 OpenClaw 的非侵入式安全增强客户端与本地控制面。我们不做替代品，做的是**安全补位**。

v0.2.1 是一次彻底的**纠偏**——全面对齐官方 Plugin SDK 规范，用 `api.on()` 替代已废弃的 `registerHook`，`requireApproval` 遵循 `BeforeToolCallResult` 类型，双端同步通过 `onResolution` 回调 + Gateway 远程调用的双向 Push 机制实现实时流转。新增的 RV 引擎和电路熔断器分别解决了链式攻击检测和服务降级两大核心问题。

**English**

OpenClaw-RVGuarder ("Lobster Guard") is a non-invasive security enhancement client and local control plane for OpenClaw. We don't replace OpenClaw — we **backfill the safety gap**.

v0.2.1 is a **full course correction** — aligned with the official Plugin SDK spec, using `api.on()` instead of deprecated `registerHook`, typed `requireApproval` per `BeforeToolCallResult`, bidirectional push sync via `onResolution` + Gateway calls, and the new RV engine with circuit breaker for graceful degradation.

## 核心特性 · Core Features

| 特性 | 说明 | Highlights |
|------|------|------------|
| **原生钩子拦截** | `api.on("before_tool_call")`，工具执行前物理挂起 | Official hook API, physically pauses agent before tool execution |
| **双端审批同步** | Guard ↔ OpenClaw 实时双向同步 | Bidirectional sync — approve from either side, both update instantly |
| **电路熔断器** | 自动熔断 fail-open，不封锁 OpenClaw | Circuit breaker — graceful degradation, never block when backend is down |
| **语义理解** | DeepSeek LLM + 7 维度标签体系 | Understands natural language intent, 50+ labels across 7 dimensions |
| **运行时验证 RV** | 滑动窗口 + FSM 监视器检测链式攻击 | Sliding window + FSM monitors for chain-attack detection |
| **基线扫描** | 配置/端口/用户/依赖 全量安全扫描 | Full security scan: config, ports, users, dependencies |
| **审计导出** | SQLite + JSONL 双写，哈希链防篡改 | Dual-write audit trail with hash chain integrity |
| **规则引擎** | 语义优先模式，办公场景策略 | Semantic-first decision, office scenario policies |

## 技术栈 · Tech Stack

```
Backend:   Python 3.13+ · HTTP 内建服务 · DeepSeek API · SQLite · transitions(FSM)
Frontend:  Vanilla JS · 单页 SPA · 1.5s 轮询刷新
Plugin:    JavaScript · OpenClaw Plugin SDK (api.on) · registerGatewayMethod
Core:      Runtime Verification (RV) · 滑动窗口 · FSM 监视器 · 白名单 Trie 树
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
| 🛡️ [运行时 Hook 拦截](/features/runtime-hook.html) | 插件机制与双端同步详解 | Hook mechanism & bidirectional sync |
| ⚙️ [动作审批链](/features/action-gate.html) | 决策流程与规则引擎 | Decision pipeline & rule engine |
| 🌐 [HTTP 接口清单](/api/http.html) | 所有后端 API 文档 | Complete API reference |
| 🏗️ [架构总览](/architecture/overview.html) | 分层设计与代码映射 | Architecture & code map |
| 📋 [基线扫描](/features/baseline.html) | 安全扫描与报告 | Security scanning & reports |
| 📝 [审计](/features/audit.html) | 审计链与导出 | Audit trail & export |
| 🧠 [语义增强方案](/semantic/method.html) | 语义理解架构设计 | Semantic enhancement design |
| 🩺 [运维 FAQ](/ops/faq.html) | 常见问题 | Frequently asked questions |
| 🗺️ [路线图](/ops/roadmap.html) | 开发计划 | Development roadmap |
