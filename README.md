# RVguarder / 龙虾卫士

> 面向 OpenClaw 的非侵入式运行时安全保护系统
> 
> *Non-intrusive runtime security protection for OpenClaw*

![Python](https://img.shields.io/badge/Python-3.13%2B-3776AB?logo=python&logoColor=white)
![OpenClaw](https://img.shields.io/badge/OpenClaw-Plugin%20SDK-111827)
![Hook](https://img.shields.io/badge/Hook-before__tool__call-0F766E)
![PMKB](https://img.shields.io/badge/PMKB-1.1.0-2563EB)
![RV](https://img.shields.io/badge/RV-ChainRule%20DSL-7C3AED)
![Status](https://img.shields.io/badge/Status-v0.7.0--dev-0F766E)

---

## 项目简介 · Introduction

RVguarder（龙虾卫士）是一个面向 [OpenClaw](https://openclaw.ai/) 的**非侵入式安全增强插件和本地控制面**。它在**不修改 OpenClaw 一行源码**的前提下，通过官方 Plugin SDK 钩子和本地策略服务，为 AI Agent 增加语义理解、版本化权限知识库（PMKB）、执行前审批、运行时行为验证和全链路审计能力。

**核心设计原则**：

- **非侵入** — 不改 OpenClaw 源码，通过插件桥接完成安全增强
- **先决策后执行** — 高风险操作必须通过审批才能真正执行
- **证据驱动** — 每次工具调用先归一化为 Authorization Trace，再由 PMKB 和 RV 给出可解释证据
- **可取证** — 全链路审计，支持 SQLite/JSONL 双写与导出
- **静默透传** — Guard 后端不可达时插件对所有 Agent 工具调用透传（包括写入、执行）；后端恢复后重新启用防护

---

## 核心特性 · Core Features

| 特性 | 说明 | Status |
|------|------|--------|
| **原生钩子拦截** | `api.on("before_tool_call")` 官方 API，工具执行前物理挂起 Agent | ✅ |
| **requireApproval 挂起** | 返回 BeforeToolCallResult 类型，Agent 线程真正挂起等待审批 | ✅ |
| **审批结果同步** | OpenClaw 原生审批卡片唯一决策，Guard Dashboard SSE 只读同步 | ✅ |
| **后端静默透传** | 后端传输不可达时所有工具透传，Guard 保护与审计回传暂停；后端恢复后重启防护 | ✅ |
| **语义理解增强** | DeepSeek LLM 驱动语义分析，7 维度 50+ 标签，理解自然语言意图 | ✅ |
| **PMKB 权限建模** | PMKB 1.1.0：47 个操作、35 条原生规则 + 47 条兼容规则、29 条 Trace、9 个危险组合关系；校验最小权限和权限聚合风险 | ✅ |
| **运行时验证 RV** | 滑动窗口 + ChainRule DSL 生成监视器，检测链式攻击模式（搜索→删除→外发） | ✅ |
| **跨 session 主体验证** | session-local 链路与 principal-global 能力状态分离，持久化主体级 RV 状态 | ✅ |
| **基线安全扫描** | 配置、端口、用户、依赖全量扫描，输出 JSON/HTML/PDF 报告 | ✅ |
| **审计链** | SQLite + JSONL 双写，哈希链防篡改，支持 JSON/CSV 导出 | ✅ |
| **Web 工作台** | 轻量 SPA 前端，集成动作状态、Trace 可视化、RV 状态面板 | ✅ |

---

## 架构总览 · Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Dashboard (前端 SPA)                    │
│         概览 · 动作状态 · 安全规则 · 基线扫描 · RV 面板      │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTP REST API
┌──────────────────────▼──────────────────────────────────┐
│               Guard Bridge (Python 后端)                  │
│  ┌─────────┐ ┌──────────┐ ┌────────┐ ┌──────────────┐  │
│  │ 语义/Trace│ │ PMKB策略 │ │ RV 引擎 │ │ 决策/审计    │  │
│  │ Semantic│ │ Policy   │ │ DSL+   │ │ Controller   │  │
│  │ +Trace  │ │ +Graph   │ │ DSL    │ │ +Evidence    │  │
│  └─────────┘ └──────────┘ └────────┘ └──────────────┘  │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTP POST (before_tool_call)
┌──────────────────────▼──────────────────────────────────┐
│             OpenClaw Plugin Hook (JavaScript)            │
│  api.on("before_tool_call") → requireApproval            │
│  api.on("after_tool_call")  → audit logging              │
│  Circuit Breaker · Health Check · onResolution callback  │
└──────────────────────┬──────────────────────────────────┘
                       │ Plugin SDK
┌──────────────────────▼──────────────────────────────────┐
│                   OpenClaw Gateway                        │
│           Agent 运行 · 工具调用 · 原生审批 UI              │
└─────────────────────────────────────────────────────────┘
```

### 拦截链路

```
OpenClaw 准备调用工具
  → api.on("before_tool_call") 触发
  → 插件 POST Guard 后端 /api/hook/before-tool-call
  → Guard: 语义分析 → Authorization Trace → PMKB 规则/权限组合 → RV 验证 → 决策
  → 返回 requireApproval | block | allow
  → requireApproval 时 Agent 挂起，弹出审批卡片
  → OpenClaw 原生审批 → onResolution 回调 → Guard SSE 只读同步
  → Agent 继续或终止工具调用
  → after_tool_call 回写审计
```

审批所有权只有一个：OpenClaw 原生审批卡片。Guard Dashboard 只读展示 PMKB/RV 证据，
通过 `onResolution`、SSE 和增量对账及时更新状态，不再创建第二个审批源。完整的当前实现
和边界见[权限知识库与 RV 运行时架构结果](docs/architecture/permission-kb-runtime-architecture.md)。

---

## 快速开始 · Quick Start

### 环境要求

- Python 3.13+
- OpenClaw (已安装并运行)
- Node.js (可选，前端开发)

### 安装

```bash
pip install -e .
```

### 启动

```bash
openclaw-guard run
```

启动后自动完成：发现 OpenClaw 配置 → 准备运行时目录 → 补齐基线扫描 → 生成 Hook 插件并注入配置 → 启动 Web 工作台。

浏览器访问 `http://localhost:8780` 即可进入 Dashboard。

### 常用命令

```bash
openclaw-guard run                    # 启动服务
openclaw-guard run --no-browser       # 启动但不打开浏览器
openclaw-guard run --once             # 一次性自检（不启动长期服务）
openclaw-guard baseline               # 运行基线扫描
openclaw-guard doctor                 # 打印链路健康状况
openclaw-guard export-audit --output ./audit.json  # 导出审计数据
openclaw-guard install-hook           # 手动注入 Hook 插件
openclaw-guard uninstall-hook         # 移除 Hook 插件
```

---

## 后端结构 · Backend Structure

```
openclaw_guard/
├── api/                  # HTTP API 处理器（由 FastAPI 路由调用）
│   ├── __init__.py        # 路由注册与导出
│   └── _handlers.py       # 各 API 端点实现
├── web/                  # 唯一 FastAPI HTTP 层
│   ├── app.py            # create_app() 工厂 + launch_web() 入口
│   ├── dependencies.py   # 依赖注入 + Hook 鉴权
│   ├── errors.py         # GuardError + 统一异常处理
│   └── routes/           # 路由模块（health, baseline, audit, rv, actions, hook, static）
├── core/                 # 核心业务逻辑
│   ├── action_service.py  # 动作生命周期服务
│   ├── audit_service.py   # 审计查询服务
│   └── baseline_service.py# 基线扫描服务
├── engine/               # 语义、命令事实与热路径编排
│   ├── behavior.py        # 行为事件建模
│   ├── control.py         # 决策与控制
│   ├── semantic_enhancer.py     # 语义分析增强
│   └── whitelist.py       # 白名单匹配引擎
├── policy/                # PMKB、Authorization Trace 与权限关系运行时
│   ├── catalog.py         # 版本化策略包加载/校验（PolicyBundle）
│   ├── legacy.py          # 冻结 LEGACY 回放元数据（非运行时引擎）
│   ├── trace.py           # TraceCompiler 与语义覆盖计算
│   ├── evaluator.py       # 单步规则匹配与风险评分
│   ├── permission_diff.py # 最小权限闭包/差分
│   └── risk_graph.py      # 危险权限组合图
├── rv/                   # 运行时验证（ChainRule DSL-only）
│   ├── runtime_verification.py  # RV 引擎 + session 滑动窗口
│   └── rv_dsl.py          # ChainRule 规约与监视器编译
├── integrations/         # OpenClaw 集成层
│   ├── discovery.py       # 环境发现
│   ├── hook_runtime.py    # Hook 插件生成与管理
│   ├── openclaw_adapter.py# Gateway 状态探测适配
│   └── tool_hook_bridge.py# 工具事件桥接
├── storage/              # 数据持久化
│   ├── audit_store.py     # 审计存储 + 哈希链
│   └── db_store.py        # 数据库底层
├── collectors/           # 运行时采集器
│   ├── ebpf_adapter.py    # eBPF 接口（预留）
│   ├── hook_bridge.py     # Hook 桥接采集
│   └── ptrace_adapter.py  # ptrace 接口（预留）
├── main.py               # CLI 入口（唯一 FastAPI 服务）
├── manager.py            # 业务编排
├── ui.py                 # 前端资源管理
├── config.py             # 配置与上下文
└── models.py             # Pydantic v2 数据模型
```

### 前端工程

```
frontend/
├── index.html            # 入口 HTML
├── vite.config.js        # Vite 构建配置
├── package.json          # 依赖
└── src/
    ├── main.jsx          # Preact 入口
    ├── App.jsx           # 根组件 + Router
    ├── store.js          # Zustand 状态
    ├── api.js            # API 请求层
    ├── i18n.js           # 国际化
    ├── components/       # 10 个 UI 组件
    ├── pages/            # 5 个页面
    └── styles.css        # 样式
```

前端为独立 Preact 工程，构建产物输出到 `runtime/ui/` 由后端静态托管。

研究代码与当前可运行的封闭办公回放位于 [`testlab/office_value/`](testlab/office_value/README.md)；`testlab/results/` 和 `testlab/实验结果/` 保存历史证据。现行文档从 [`docs/README.md`](docs/README.md) 进入，阶段性方案与旧设计集中在 [`docs/archive/`](docs/archive/README.md)。

---

## 运行时插件 · Hook Plugin

Guard 通过生成一个标准的 OpenClaw 插件注入拦截逻辑：

```
runtime/openclaw-guard-plugin/
├── package.json           # npm 包描述 (openclaw.extensions)
├── openclaw.plugin.json   # 插件清单 (activation.onStartup: true)
└── index.js               # 插件入口
```

插件注册的钩子：

| 钩子 | 类型 | 用途 |
|------|------|------|
| `before_tool_call` | 同步拦截 | 物理挂起工具调用，返回 requireApproval |
| `after_tool_call` | 异步审计 | 回写执行结果、耗时、错误 |
| `gateway_start` | 生命周期 | 初始化熔断器与健康检查 |
| `gateway_stop` | 生命周期 | 清理健康检查定时器 |

插件内置**电路熔断器**：
- 后端不可达 → 所有工具（包括写入和执行）透传，Guard 保护与审计回传暂停
- 后端恢复 → 健康检查通过后恢复正常策略
- 遗留 `failClosed=true` 不覆盖传输故障透传；后端明确返回 HTTP 错误时仍可按原配置全量阻断
- 后端从可用状态突然断开时，首个失败调用可能等待一次有界超时（默认 2 秒），后续调用不再同步等待

---

## 权限知识库与权限建模 · PMKB

PMKB（Permission Model Knowledge Base）不是离线说明，而是随每次 `before_tool_call` 参与决策的
可直接接入策略包。当前基线位于 `policies/permissions/`，由 schema、operation catalog、
office rules、least-privilege traces、permission relations 和 test vectors 组成：

| 数据 | 当前基线 | 运行时用途 |
|------|----------|------------|
| operations | 47 | 将工具/动作归一化为 canonical operation |
| rules | 35（另有 47 条 LEGACY 兼容记录） | 单步规则、风险等级、效果和 required trace |
| traces | 29 | 描述主体在办公场景的最小必要权限范围 |
| relations | 9 | 互斥、聚合和毒性权限组合 |
| vectors | 29 | 规则、Trace、组合和回退路径回归样例 |

处理顺序是：

```text
原始工具调用
  → SemanticEnhancer（entities / labels / classification / purpose / confidence）
  → TraceCompiler（action、resource、scope、data、context、principal、identity）
  → PolicyEvaluator（matched / partial / unknown / conflict）
  → PermissionClosure + PermissionDiff + RiskGraph
  → effect：auto_allow_audit / openclaw_approval / block
```

未知操作、缺失主体或缺失关键 Trace 特征不会因为模糊相似度而自动放行；结果会携带
`match_status`、`missing_features`、`requested_delta`、`excessive_permissions`、
`combo_violations`、`policy_version` 等证据。当前 PMKB 是办公个人场景的可用基线；47 条历史
单步规则已保留为 `LEGACY-<old-id>` 兼容记录并进入 PMKB 统一评估链路；生产 DetectionEngine 已退役，冻结元数据仅用于逐条回放与历史评测。
PMKB 不会自动从用户行为学习写入生产规则。

OpenClaw 原生 runtime、filesystem、web、browser、sessions、memory、messaging、automation、
agents、human-input、nodes 和 UI 工具均有显式 profile。只有参数边界明确且属于当前主体的
低风险读取才会自动放行审计；跨 session 读取、外联、浏览器交互、发送/生成子代理、计划和
网关修改等能力仍需要 OpenClaw 审批。未知工具或已知工具的越权参数保持 `unknown`，不会被
自由文本推断为危险动作，也不会静默放行。
插件发送审批卡片前将标题限制为 80 字符、说明限制为 512 字符，弹窗突出“要做什么”；完整
命令和技术证据在 Guard 页面按分区展示并默认脱敏。低风险精确命令支持默认 30 天可撤销的
`allow-always`，仅对已验证主体的非敏感、严格收敛命令生效，不改变 PMKB hard-block 优先级。

详见：[PMKB 网络案例基线](docs/semantic/pmkb-network-case-baseline.md)、[升级结果报告](docs/research/pmkb-network-baseline-implementation-report-2026-08-28.md)。

## RV 运行时验证 · Runtime Verification

RV 在 PMKB 单步效果之上验证行为序列。运行时唯一使用 ChainRule DSL；历史
`OPENCLAW_RV_RULE_MODE=fsm` 输入仅归一化为 DSL，不会加载旧监视器。当前有两个状态作用域：session-local 用于当前会话窗口，
principal-global 用 `(principal_id, agent_id, capability_lineage)` 聚合跨 session 能力，
状态保存于 `runtime/rv-state.json` 并受 TTL/有界状态约束。

典型滑动窗口链路：

```
工具调用链（按时间顺序）
  s1: file_read  /tmp/data.xlsx                    ← 读取外部附件
  s2: file_read  → 含 contains_secret              ← 读取到敏感数据
  s3: file_search → 搜索通讯录                      ← 正常操作
  s4: file_write → 合并数据到新文件                  ← 敏感数据被写入
  s5: network_egress → external_target              ← 数据外传

ChainRule DSL 监视器触发:
  检测到 "不可信来源 → 读取敏感数据 → 外传到外部目标" 链路
  → 判定: BLOCK（自动阻断，级别高于单步规则 ASK）
```

### 内置监视器

| 监视器 | 场景 | 判定 |
|--------|------|------|
| MailMonitor | 邮件外发 + 敏感内容 | block |
| ReportMonitor | 日报外发 + 内部来源 | block |
| SecurityChainMonitor | 搜索→删除 / 关审计→改配置 / 下载→外传 | ask/block |
| BroadcastMonitor | 消息群发/广播 | ask/block |
| DataExportMonitor | 数据库查询后导出 | ask/block |
| BatchFileMonitor | 文件批量操作 | ask/block |

---

## 语义理解与规则命中 · Semantic Understanding & Matching

`SemanticEnhancer` 对每个工具调用进行语义分析，产出结构化标签和实体；`TraceCompiler`
再把它们转换为 PMKB 可匹配的 Authorization Trace，策略引擎和 RV 都消费同一份规范化结果：

**标签体系（7 维度）**：
- 基础标签：action_type, scenario, scope_class（workspace / managed_project / outside / external / unknown）
- 确定性操作标签：command_readonly；复合只读命令在受管范围内可自动放行并审计
- 命令标签：command_rm_rf, command_sudo, command_pipe_curl_sh
- 路径标签：path_system_root, path_sensitive_creds, path_high_value
- 网络标签：network_http, network_webhook, network_secret_payload
- 配置标签：config_auth_disable, config_audit_disable
- 渠道/技能标签：channel_external_send, skill_system_admin
- 办公场景标签：mail_send, report_send, external_recipient, contains_secret

支持双模式运行：
- **LLM 模式**（配置 `DEEPSEEK_API_KEY` 后启用）
- **本地规则化模式**（默认，延迟 < 1ms）

匹配评分由 action（0.40）、completeness（0.25）、specificity（0.20）和 provenance（0.15）
组成；`unknown` / `conflict` 永远不会自动放行。这个分层是当前减少“全部进入人工审批”的关键控制点，
后续以离线回放和有限事件样本调优阈值，而不是直接削弱未知路径的安全兜底。

---

## 测试 · Testing

```bash
python -m pytest -q
```

本轮全量回归（2026-09-15）：`412 passed / 19 skipped / 4 subtests passed`；Chromium 与 Firefox Playwright 冒烟均为 `5 passed`（Firefox 在清除代理变量、单 worker 的独立环境复跑）。

测试覆盖：

| 测试文件 | 覆盖内容 |
|----------|----------|
| `test_policy_decision_adapter.py` / `test_policy_evaluator.py` | PMKB 策略决策与兼容记录回放 |
| `test_semantic_enhancer.py` | 语义增强器输出结构 |
| `test_pmkb_network_baseline.py` / `test_policy_pipeline.py` / `test_policy_docs.py` | PMKB 规则、Trace、权限闭包/差分、文档合同 |
| `test_principal_capability_rv.py` / `test_principal_rv_hook_integration.py` | 主体级跨 session RV、TTL 和状态持久化 |
| `test_runtime_verification.py` | RV 引擎、窗口、TTL、会话隔离与状态重置 |
| `test_rv_dsl.py` / `test_rv_dsl_ext.py` | ChainRule DSL 编译、序列和参数化监视器 |
| `test_baseline.py` | 基线扫描 |
| `test_web_cli.py` | CLI 命令路由 |
| `test_frontend_rv_contract.py` | 前端 ←→ 后端 RV 接口契约 |
| `test_rv_frontend_integration.py` | 前端 RV 集成 |

---

## 文档站点 · Documentation Site

项目附带完整 VuePress 文档站（位于 `docs/`）：

```bash
cd docs
npm install
npm run docs:dev     # 本地预览
npm run docs:build   # 构建静态站点
```

文档目录：

| 路径 | 内容 |
|------|------|
| `features/runtime-hook.md` | 运行时 Hook 拦截详解 |
| `features/action-gate.md` | 高危动作审批链 |
| `features/audit.md` | 审计与取证 |
| `features/baseline.md` | 基线扫描与合规检测 |
| `architecture/overview.md` | 架构总览与代码映射 |
| `architecture/permission-kb-runtime-architecture.md` | 本次 PMKB、语义命中、权限建模与 RV 升级结果 |
| `api/http.md` | HTTP 接口清单 |
| `semantic/method.md` | 语义理解增强方案 |
| `semantic/pmkb-network-case-baseline.md` | 可直接运行的案例型权限知识库基线 |
| `deployment/local.md` | 本地部署 |
| `ops/faq.md` | 常见问题 |
| `test-design/openclaw-guard-test-design.md` | 测试设计方案 |

---

## 许可证 · License

Apache-2.0
