# OpenClaw Guard / 龙虾卫士 项目介绍

## 1. 项目概述

**OpenClaw Guard**（中文名：**龙虾卫士**）是一个专为 **OpenClaw** 设计的非侵入式安全增强客户端与本地控制面。

在追求 AI 自动化能力的同时，安全与可控性变得至关重要。OpenClaw Guard 的目标不是替换 OpenClaw，而是在**不修改 OpenClaw 源码**的前提下，为 OpenClaw 增加更清晰的安全交互、更可控的执行前审批、更完整的基线扫描与审计能力，并把这些能力集中到一个可直接使用的前端工作台中。

它非常适合以下场景：
*   高安全终端或内网环境中的 OpenClaw 部署。
*   需要对危险动作（如文件删除、配置修改、外联请求等）做“先审批、再执行”的本地防护。
*   需要对 OpenClaw 配置、运行状态、基线风险和审计日志进行集中管理。
*   需要保留 OpenClaw 原有工程结构，不希望修改官方源码的用户。

---

## 2. 核心特性

*   **非侵入式接入 OpenClaw**
    *   不修改 OpenClaw 源码。
    *   通过 OpenClaw 原生 Hook、Gateway 调用、本地插件桥与 Guard Web 前端完成联动。
*   **对话式工作台**
    *   从 Guard 前端直接与 OpenClaw 对话。
    *   支持模型切换、会话重置、状态检测、运行时调试。
*   **执行前风险控制**
    *   删除、写入、配置修改、危险命令、外联、渠道发送、技能执行等动作会先经过 Guard 决策。
    *   支持 `allow / ask / block / escalate` 四种策略。
    *   高风险动作需要明确确认后才继续执行。
*   **基线扫描与风险展示**
    *   扫描 OpenClaw 配置、运行用户、网络暴露、日志、依赖与 Hook 状态。
    *   输出 JSON / HTML / PDF 报告与整改脚本。
    *   前端提供动态扫描界面、检查项详情和整改建议。
*   **审计与导出**
    *   SQLite + JSONL 双写审计。
    *   支持 JSON / CSV 导出。
    *   适配本地取证与后续集成。
*   **普通用户模式**
    *   提供 `normal` 一键启动入口。
    *   默认打开更简洁的操作界面。

---

## 3. 工作原理

Openclaw Guard 的核心链路可以概括为：

1.  Guard 自动发现本机 OpenClaw 配置、工作区、日志目录与 Gateway 状态。
2.  Guard 将本地 Hook 插件写入 OpenClaw 配置，并通过 OpenClaw 官方插件机制接入 `before_tool_call` / `after_tool_call`。
3.  用户从 Guard 前端发起对话或操作。
4.  OpenClaw 在真正调用工具前，先把请求交给 Guard 判定。
5.  Guard 根据规则、白名单、上下文与风险等级给出 `allow / ask / block / escalate`。
6.  若需要审批，前端会展示待确认动作；用户明确确认后，OpenClaw 才会继续执行。
7.  执行结果、日志和审计记录会统一写回 Guard。

---

## 4. 项目结构

```text
OpenClaw-Guard/
├── openclaw_guard/         # 核心后端代码
│   ├── baseline.py         # 基线扫描与报告生成
│   ├── behavior.py         # 行为事件采集与整理
│   ├── control.py          # 审批与执行决策
│   ├── detection.py        # 规则引擎与风险判定
│   ├── discovery.py        # OpenClaw 环境发现
│   ├── hook_runtime.py     # OpenClaw Hook 插件写入与检查
│   ├── manager.py          # 统一编排层
│   ├── openclaw_adapter.py # OpenClaw Gateway / Session / Chat 适配
│   ├── ui.py               # 前端静态资源生成
│   ├── web.py              # 本地 HTTP 服务与 API
│   ├── whitelist.py        # 白名单匹配
│   └── collectors/         # 运行时行为采集器 (ptrace, eBPF, hook bridge)
├── docs/                   # VuePress 文档站
├── pics/                   # README / 文档截图
├── tests/                  # 自动化测试
├── scripts/                # 安装与卸载脚本
├── docker/                 # Docker 部署文件
└── k8s/                    # Kubernetes / Sidecar 示例
```

---

## 5. 快速开始

### 1. 环境要求

*   Python 3.13+
*   Node.js 与 npm
*   已可正常运行的 OpenClaw

### 2. 安装

```bash
cd OpenClaw-Guard
bash scripts/install.sh
source .venv/bin/activate
```

### 3. 一键启动普通模式

```bash
python -m openclaw_guard.main normal
```

该命令会：
*   自动发现 OpenClaw 配置。
*   准备 `runtime/`、`output/`、`exports/` 等目录。
*   自动补齐一份基线扫描结果。
*   启动本地 Web 服务。
*   打开简洁模式界面。

### 4. 启动完整模式

```bash
python -m openclaw_guard.main launch
```

### 5. 仅做自检

```bash
python -m openclaw_guard.main normal --once --no-browser
```

---

## 6. 常用命令

### 启动普通模式

```bash
python -m openclaw_guard.main normal
```

### 启动完整模式

```bash
python -m openclaw_guard.main launch --no-browser
```

### 运行基线扫描

```bash
python -m openclaw_guard.main baseline --config-path ~/.openclaw/openclaw.json
```

### 导出审计数据

```bash
python -m openclaw_guard.main export-audit
```

### 摄入一条行为事件

```bash
python -m openclaw_guard.main action --event-file examples/dangerous-delete.json
```

---

## 7. 前端能力

当前前端已经支持以下主要功能：

*   聊天与会话管理。
*   OpenClaw 连接状态检测。
*   当前模型与 Agent 状态展示。
*   模型切换。
*   新建会话。
*   待确认动作审批。
*   动作分页浏览。
*   技能管理。
*   渠道管理。
*   运行时 Hook 状态检查。
*   基线扫描与整改建议查看。
*   审计导出。
*   运行时调试信息与日志查看。

目标是让普通用户尽量不需要直接去改配置文件、翻日志目录或手动调用命令行接口。

---

## 8. 输出目录

运行过程中，Guard 会生成以下内容：

### 基线扫描输出

*   `output/reports/compliance-report.json`
*   `output/reports/compliance-report.html`
*   `output/reports/compliance-report.pdf`
*   `output/fixes/baseline-remediation.sh`

### 审计与导出

*   `output/audit/audit.db`
*   `output/audit/audit.jsonl`
*   `exports/audit-export.json`
*   `exports/audit-export.csv`

### 运行时数据

*   `runtime/ui/`
*   `runtime/guard.log`
*   `runtime/controlled-actions.json`
*   `runtime/latest-baseline.json`
*   `runtime/openclaw-guard-plugin/`

---

## 9. 部署方式

### 本地部署

直接使用 Python 启动：

```bash
python -m openclaw_guard.main normal
```

### Docker

参考：
*   `docker/Dockerfile`

### Kubernetes / Sidecar

参考：
*   `k8s/openclaw-guard-sidecar.yaml`

---

## 10. 与 OpenClaw 的集成说明

Openclaw Guard 遵循"非侵入式"原则：

*   不修改 OpenClaw 源码。
*   不替换系统库。
*   不要求改动 OpenClaw 官方前端代码。

它主要通过以下方式与 OpenClaw 交互：

*   OpenClaw Gateway RPC。
*   OpenClaw `sessions.patch` / `chat.send` / `chat.history` / `agent.wait`。
*   OpenClaw 原生 Hook。
*   本地运行时插件桥。

如果 Guard 已写入 Hook 插件但仍未生效，通常需要按你的实际启动方式重启 OpenClaw Gateway。

---

## 11. 测试

运行完整测试：

```bash
python -m unittest discover -s tests -v
```

---

## 12. 许可证

本项目采用 Apache-2.0 开源协议。
