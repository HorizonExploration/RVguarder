---
home: true
title: Openclaw Guard 文档
heroText: Openclaw Guard / 龙虾卫士
tagline: 面向 OpenClaw 的非侵入式安全增强客户端与本地控制面，统一提供对话、执行前审批、基线扫描、审计导出与运行时调试能力。
actions:
  - text: 立即开始
    link: /guide/quick-start.html
    type: primary
  - text: 了解简洁模式
    link: /guide/normal-mode.html
    type: secondary

features:
  - title: 一键进入工作台
    details: 使用 normal 模式即可启动，自动探测 OpenClaw、准备运行目录、补齐基线结果并打开本地 Web 工作台。
  - title: 先审批再执行
    details: 删除、写入、配置修改、危险命令和外联动作会在 OpenClaw 真正调用工具前先被 Guard 拦住，再等待确认。
  - title: 对话、安全、审计集中在一个界面
    details: 普通用户可以在同一个前端里完成对话、风险确认、模型切换、日志查看、基线扫描和审计导出。
  - title: 非侵入接入 OpenClaw
    details: 不修改 OpenClaw 源码，不替换系统库，通过本地插件、Hook Bridge、Gateway 调用与能力探测实现增强。
---

<div class="custom-card-grid">
  <div class="custom-card">
    <h3>适合谁用</h3>
    <p>高安全终端、内网环境、实训场景，以及希望保留 OpenClaw 原始代码结构的团队与个人。</p>
  </div>
  <div class="custom-card">
    <h3>核心收益</h3>
    <p>让用户在一个工作台里直接完成对话、任务申请和风险确认，并把危险动作拦在真正执行之前。</p>
  </div>
  <div class="custom-card">
    <h3>当前模式</h3>
    <p>推荐优先使用 normal 模式；开发、运维或策略调试再使用完整模式。</p>
  </div>
</div>

## 项目定位

Openclaw Guard（龙虾卫士）是一个面向 OpenClaw 的非侵入式安全增强客户端与本地控制面。项目目标不是替换 OpenClaw，而是在**不修改 OpenClaw 源码**的前提下，为 OpenClaw 增加更清晰的安全交互、更可控的执行前审批、更完整的基线扫描与审计能力，并把这些能力集中到一个可直接使用的前端工作台中。

当前版本已经接入 OpenClaw 原生 `before_tool_call` / `after_tool_call` Hook，能够把删除、写入、配置修改、危险命令和外联请求挡在真正执行前。

## 核心特性

- **非侵入式接入 OpenClaw**
  - 不修改 OpenClaw 源码
  - 通过 OpenClaw 原生 Hook、Gateway 调用、本地插件桥与 Guard Web 前端完成联动
- **对话式工作台**
  - 从 Guard 前端直接与 OpenClaw 对话
  - 支持模型切换、会话重置、状态检测、运行时调试
- **执行前风险控制**
  - 删除、写入、配置修改、危险命令、外联、渠道发送、技能执行等动作会先经过 Guard 决策
  - 支持 `allow / ask / block / escalate`
  - 高风险动作需要明确确认后才继续执行
- **基线扫描与风险展示**
  - 扫描 OpenClaw 配置、运行用户、网络暴露、日志、依赖与 Hook 状态
  - 输出 JSON / HTML / PDF 报告与整改脚本
  - 前端提供动态扫描界面、检查项详情和整改建议
- **审计与导出**
  - SQLite + JSONL 双写审计
  - 支持 JSON / CSV 导出
  - 适配本地取证与后续集成
- **普通用户模式**
  - 提供 `normal` 一键启动入口
  - 默认打开更简洁的操作界面

## 你可以从这里开始

- [快速开始](/guide/quick-start.html)
- [normal 简洁模式](/guide/normal-mode.html)
- [分层架构总览](/architecture/overview.html)
- [高风险动作审批链](/features/action-gate.html)
- [运行时 Hook 拦截](/features/runtime-hook.html)
- [HTTP 接口清单](/api/http.html)

::: tip 推荐路径
第一次部署建议直接走“安装 -> `python -m openclaw_guard.main normal` -> 浏览器打开本地页面 -> 发送一个测试任务”。
:::
