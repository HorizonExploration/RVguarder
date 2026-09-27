# 权限建模与端到端架构图 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 生成与当前 RVguarder 实现一致的四张权限主线架构图，并提供给 OpenClaw 继续优化汇报的整合简报。

**Architecture:** 使用 Mermaid 源图嵌入现有 VuePress 架构文档。图稿只引用当前模块、PMKB 数据合同、RV 监视器和 OpenClaw 单一审批边界；单独的简报文件作为跨助手交接材料。

**Tech Stack:** Markdown、Mermaid、VuePress。

**Spec:** `docs/superpowers/specs/2026-08-31-architecture-diagrams-design.md`

## Global Constraints

- 不修改业务代码和运行时策略。
- 不删除历史实验产物。
- Mermaid 是唯一图稿源格式；不新增外部依赖。
- 明确标注 AgentDojo 首轮实验无效、待重跑。

---

### Task 1: 编写四图架构文档

**Files:**
- Create: `docs/architecture/permission-modeling-diagrams.md`
- Modify: `docs/architecture/index.md`
- Modify: `docs/.vuepress/config.ts`

- [x] **Step 1: 添加总体架构、权限建模、PMKB 和端到端 Mermaid 图**
- [x] **Step 2: 添加每张图的讲解要点和实现状态说明**
- [x] **Step 3: 将图稿加入架构索引与 VuePress sidebar**

### Task 2: 编写 OpenClaw 整合简报

**Files:**
- Create: `docs/research/openclaw-architecture-brief-2026-08-31.md`
- Modify: `docs/research/index.md`

- [x] **Step 1: 提供四图入口与可直接复用的汇报主线**
- [x] **Step 2: 汇总已实现、兼容过渡、待重跑和下一步验证边界**
- [x] **Step 3: 加入给 OpenClaw 的整合指令模板**

### Task 3: 验证文档

**Files:**
- Test: VuePress docs build and `git diff --check`

- [x] **Step 1: 运行 `npm run docs:build`**
- [x] **Step 2: 运行 `git diff --check`**
- [x] **Step 3: 检查新增文档未引入失效相对链接**
