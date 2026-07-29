---
home: true
title: OpenClaw-RVGuarder
heroText: OpenClaw-RVGuarder / 龙虾卫士
tagline: Refined. Rebuilt. Ready.
actions:
  - text: 快速开始
    link: /guide/quick-start.html
    type: primary
  - text: 运行时 Hook 拦截
    link: /features/runtime-hook.html
    type: secondary

features:
  - title: 🛡️ 原生审批拦截
    details: 基于 OpenClaw 官方 `api.on("before_tool_call")` API，工具执行前挂起 agent，通过 requireApproval 实现物理拦截。不再有「先执行后审批」的尴尬。
  - title: 🔄 双端状态同步
    details: OpenClaw 原生审批卡片 ↔ RVGuarder Dashboard 双向同步。任一端确认，两端同时更新。审批结果通过 onResolution 回调 + Gateway 远程调用实时流转。
  - title: ⚡ 零侵入接入
    details: 不改 OpenClaw 一行源码。通过本地插件、Gateway 调用、行为事件桥接完成安全增强。安装即用，卸载无损。
  - title: 🧠 语义理解增强
    details: DeepSeek LLM 驱动的语义分析引擎，理解「删除昨天的实验报告」这样的自然语言约束，而非简单的关键词匹配。
  - title: 🩺 基线扫描与审计
    details: 配置、端口、用户、日志、依赖全量扫描。SQLite + JSONL 双写审计链，支持 JSON/CSV 导出，满足合规取证需求。
  - title: 🖥️ 统一工作台
    details: 动作审批、实时 Trace、安全规则、技能管理、RV 运行时验证 — 一个前端界面全部搞定。
---

<div class="custom-card-grid">
  <div class="custom-card">
    <h3>🎯 适合谁用</h3>
    <p>高安全终端、内网环境、AI 实训场景，以及希望在不侵入 OpenClaw 的前提下增加安全管控的团队与个人。</p>
    <p><em>For teams who want OpenClaw safety without touching a single line of its source.</em></p>
  </div>
  <div class="custom-card">
    <h3>🧱 架构概览</h3>
    <p>插件层 (api.on) → 桥接层 (HTTP POST) → 检测层 (规则+语义+RV) → 决策层 (approve/block) → 同步层 (onResolution + Gateway call)</p>
    <p><em>Plugin hooks → Bridge API → Detection (Rule+Semantic+RV) → Decision (Approve/Block) → Sync (Bidirectional)</em></p>
  </div>
  <div class="custom-card">
    <h3>📦 当前状态</h3>
    <p>v0.2.1 — 钩子 API 已全面迁移至官方 `api.on()`，requireApproval 对齐官方规范，双端同步链路已闭环。</p>
    <p><em>v0.2.1 — Hook API migrated to official `api.on()`, requireApproval aligned with SDK spec, bidirectional sync is live.</em></p>
  </div>
</div>

---

## 项目定位 · Project Positioning

**中文**

OpenClaw-RVGuarder（龙虾卫士）是一个面向 OpenClaw 的非侵入式安全增强客户端与本地控制面。我们不做替代品，做的是**安全补位**。

过去的路走了不少弯路：`api.registerHook()` 废弃了才知道、`threading.Event().wait()` 阻塞了 HTTP 才知道、`allowedDecisions` 是非标字段才知道。v0.2.1 是一次彻底的**纠偏**——全面对齐官方 Plugin SDK 规范，用 `api.on()` 替代已废弃的 `registerHook`，`requireApproval` 遵循 `BeforeToolCallResult` 类型，双端同步不再依赖轮询和阻塞等待，而是通过 `onResolution` 回调 + Gateway 远程调用的双向 Push 机制实现实时流转。

**English**

OpenClaw-RVGuarder ("Lobster Guard") is a non-invasive security enhancement client and local control plane for OpenClaw. We don't replace OpenClaw — we **backfill the safety gap**.

The path here has been full of detours: finding out `api.registerHook()` was deprecated the hard way, discovering `threading.Event().wait()` blocks HTTP the hard way, realizing `allowedDecisions` was non-standard the hard way. v0.2.1 is a **full course correction** — aligned with the official Plugin SDK spec, using `api.on()` instead of deprecated `registerHook`, typed `requireApproval` per `BeforeToolCallResult`, and a real bidirectional push mechanism via `onResolution` callback + Gateway remote calls. No more polling, no more blocking waits.

## 核心特性 · Core Features

| 特性 | 说明 | Highlights |
|------|------|------------|
| **原生钩子拦截** | `api.on("before_tool_call")` 官方 API，工具执行前物理挂起 | Official hook API, physically pauses agent before tool execution |
| **双端审批同步** | RVGuarder ↔ OpenClaw 实时双向同步 | Bidirectional sync — approve from either side, both update instantly |
| **语义理解** | DeepSeek LLM 理解自然语言约束，而非关键词匹配 | Understands natural language intent, not keyword patterns |
| **运行时验证 RV** | 窗口滑动检测，识别 tool-use 行为模式异常 | Sliding window anomaly detection on tool-use patterns |
| **基线扫描** | 配置/端口/用户/依赖 全量安全扫描 | Full security scan: config, ports, users, dependencies |
| **审计导出** | SQLite + JSONL 双写，JSON/CSV 导出 | Dual-write audit trail, JSON/CSV export |
| **规则引擎** | 47+ 内置规则 + 语义增强规则 | 47+ built-in rules + semantic-enriched policies |
| **双语言界面** | 前端全中文，技术与文档中英双版 | Chinese-first UI, bilingual technical docs |

## 技术栈 · Tech Stack

```
Backend:   Python 3.13+ · HTTP 内建服务 (http.server) · DeepSeek API · SQLite
Frontend:  Vanilla JS · 单页 SPA · 1.5s 轮询刷新
Plugin:    JavaScript · OpenClaw Plugin SDK (api.on) · registerGatewayMethod
Adapter:   openclaw gateway call CLI 子进程 · approvals.resolve
Core:      Runtime Verification (RV) · 滑动窗口检测 · 白名单 Trie 树
```

## 快速开始 · Quick Start

```bash
# 1. 安装
pip install openclaw-rvguarder

# 2. 启动（自动探测 OpenClaw 配置）
python -m openclaw_guard.main normal

# 3. 浏览器打开 http://localhost:8780
# 4. 发送一条消息，体验工具拦截 → 审批 → 放行全链路
```

要求 OpenClaw Plugin SDK >= 2026.4.0（已内置于 OpenClaw >= 2026.4.0 版本中）。

## 文档导航 · Documentation

| 章节 | 内容 | Section |
|------|------|---------|
| 🚀 [快速开始](/guide/quick-start.html) | 安装与首次启动 | Installation & first run |
| 🛡️ [运行时 Hook 拦截](/features/runtime-hook.html) | 插件机制与双端同步详解 | Hook mechanism & bidirectional sync |
| ⚙️ [动作审批链](/features/action-gate.html) | 决策流程与规则引擎 | Decision pipeline & rule engine |
| 🌐 [HTTP 接口清单](/api/http.html) | 所有后端 API 文档 | Complete API reference |
| 🏗️ [架构总览](/architecture/overview.html) | 分层设计与代码映射 | Architecture & code map |
| 📋 [基线扫描](/features/baseline.html) | 安全扫描与报告 | Security scanning & reports |
| 📝 [审计](/features/audit.html) | 审计链与导出 | Audit trail & export |
| 🩺 [运维 FAQ](/ops/faq.html) | 常见问题 | Frequently asked questions |
| 🗺️ [路线图](/ops/roadmap.html) | 开发计划 | Development roadmap |

---

::: tip 旧瓶新酒
项目结构没变，但每一层的实现都重构过了。如果你是从 v0.1.0 升级上来的，建议通读[运行时 Hook 拦截](/features/runtime-hook.html)和 [CHANGELOG](https://github.com/OpenClaw-RVGuarder/CHANGELOG.md) 了解全部变更。

*Same bottle, new vintage. If you're upgrading from v0.1.x, read the [runtime hook docs](/features/runtime-hook.html) and [CHANGELOG](https://github.com/OpenClaw-RVGuarder/CHANGELOG.md) for full migration notes.*
:::
