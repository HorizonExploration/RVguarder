# 项目结构清单（已更新 2026-07-08）

## 1. 目录分层总览

```text
OpenClaw-RVGuarder/
├── openclaw_guard/                 # 核心 Python 包
│   ├── __init__.py                 # 包元数据
│   ├── main.py                     # CLI 入口 (run + 维护子命令)
│   ├── manager.py                  # 协调层（委托 core services）
│   ├── web.py                      # HTTP 路由装配层
│   ├── ui.py                       # 嵌入式前端（概览/审批/扫描）
│   ├── models.py                   # 公共数据模型（dataclass）
│   ├── config.py                   # 路径/配置/目标模型
│   ├── utils.py                    # 通用工具函数
│   ├── baseline.py                 # 基线扫描与报告生成
│   ├── conversation.py             # 对话辅助逻辑（内部使用）
│   │
│   ├── api/                        # HTTP API 边界层
│   │   ├── __init__.py             # Re-export 15 个路由函数
│   │   └── _handlers.py            # 路由处理函数实现
│   │
│   ├── core/                       # 核心业务服务
│   │   ├── __init__.py
│   │   ├── action_service.py       # 动作拦截/决策/审批/拒绝
│   │   ├── baseline_service.py     # 基线扫描触发与缓存
│   │   └── audit_service.py        # 审计查询、导出、校验
│   │
│   ├── integrations/               # 外部依赖适配器
│   │   ├── __init__.py
│   │   ├── openclaw_adapter.py     # Gateway/Chat/Session RPC
│   │   ├── discovery.py            # OpenClaw 环境发现
│   │   ├── detection.py            # 风险规则引擎
│   │   ├── behavior.py             # 行为事件摄入
│   │   ├── whitelist.py            # 白名单策略
│   │   ├── control.py              # 决策落地与状态控制
│   │   ├── hook_runtime.py         # 运行时 Hook 插件生成
│   │   └── tool_hook_bridge.py     # Hook 事件标准化
│   │
│   ├── storage/                    # 持久化层
│   │   ├── __init__.py
│   │   ├── audit_store.py          # 审计存储统一入口
│   │   └── db_store.py             # SQLite/PostgreSQL/Redis 抽象
│   │
│   └── collectors/                 # 运行时采集能力适配器
│       ├── __init__.py
│       ├── ptrace_adapter.py
│       ├── ebpf_adapter.py
│       └── hook_bridge.py
│
├── runtime/                        # 运行产物（gitignore）
│   ├── openclaw-guard-plugin/      # 自动生成的 OpenClaw Hook 插件
│   ├── hook-bridge.json
│   ├── controlled-actions.json
│   └── ui/                         # 编译后的前端静态文件
│
├── output/                         # 报告与审计导出
│   ├── reports/
│   ├── audit/
│   └── exports/
│
├── tests/                          # 自动化测试
│   ├── test_baseline.py
│   ├── test_detection.py
│   ├── test_web_cli.py
│   └── test_whitelist_audit.py
│
├── docs/                           # VuePress 文档站
│   ├── README.md
│   ├── .vuepress/ config.ts
│   ├── guide/                      # 使用指南
│   ├── improve/                    # 项目梳理与重构方案
│   ├── architecture/               # 架构说明
│   ├── features/                   # 功能说明
│   ├── deployment/                 # 部署文档
│   ├── api/                        # API 文档
│   ├── ops/                        # 运维文档
│   └── Sematic/                    # 研究笔记（保留）
│
├── frontend/                       # 前端独立工程
│   ├── index.html                  # 入口 HTML
│   ├── package.json                # 依赖与脚本
│   ├── vite.config.js              # Vite 构建配置
│   └── src/
│       ├── app.js                  # 主逻辑
│       └── styles.css              # 样式
│
├── testlab/                        # 研究实验区（保留）
│
├── pyproject.toml                  # Python 项目元信息
├── README.md
├── LICENSE
└── .gitignore
```

## 2. 核心模块职责

### 2.1 根目录（10 个 .py）

| 文件 | 职责 | 依赖 |
|------|------|------|
| `main.py` | CLI 入口：`run` / `doctor` / `baseline` / `export-audit` / `install-hook` / `uninstall-hook` | manager, web |
| `manager.py` | 协调层：汇总所有 service，对外暴露统一 API | core/*, integrations/*, storage/* |
| `web.py` | HTTP 路由装配：GET/POST 路由表映射到 api 函数 | api |
| `ui.py` | 嵌入式前端生成：概览/动作审批/基线扫描 3 视图 | — (纯静态) |
| `models.py` | 数据模型：ControlledAction, BehaviorEvent, DetectionDecision 等 | — |
| `config.py` | 配置模型：AppContext, AppPaths, OpenClawTarget, GuardSettings | — |
| `utils.py` | 工具函数：JSON 读写、CSV、PDF、时间、加密 | — |
| `baseline.py` | BaselineScanner：基线扫描与 ComplianceReport 生成 | integrations/discovery |
| `conversation.py` | 对话辅助函数：消息构建、回复生成（内部使用） | utils |

### 2.2 api/ 子包

| 文件 | 职责 |
|------|------|
| `_handlers.py` | 15 个 HTTP 路由处理函数（health/summary/actions/baseline/audit/hook_bridge） |
| `__init__.py` | 统一 re-export，供 `from openclaw_guard import api` 使用 |

### 2.3 core/ 子包 — 业务核心

| 文件 | 类 | 职责 |
|------|------|------|
| `action_service.py` | `ActionService` | 动作持久化、查询、摄入、审批、拒绝 |
| `baseline_service.py` | `BaselineService` | 基线扫描触发、缓存、最近结果查询 |
| `audit_service.py` | `AuditService` | 审计追加、查询、导出 JSON/CSV、完整性校验 |

### 2.4 integrations/ 子包 — 外部依赖

| 文件 | 职责 |
|------|------|
| `openclaw_adapter.py` | OpenClaw Gateway RPC 封装（chat/session/health/model） |
| `discovery.py` | 本机 OpenClaw 安装发现、端口探测、资产收集 |
| `detection.py` | DetectionEngine：风险规则匹配与决策 |
| `behavior.py` | BehaviorCollectorManager：行为事件摄入与分类 |
| `whitelist.py` | WhitelistEngine：白名单策略精细判定 |
| `control.py` | GuardController：决策落地与动作状态控制 |
| `hook_runtime.py` | 运行时 Hook 插件生成与 openclaw.json 写入 |
| `tool_hook_bridge.py` | Hook 事件标准化（before/after tool call） |

### 2.5 storage/ 子包 — 持久化

| 文件 | 职责 |
|------|------|
| `audit_store.py` | `AuditStore`：审计记录追加/查询/导出/校验，委托 db_store |
| `db_store.py` | `DBStoreInterface` + PostgreSQL/SQLite 双实现 |

## 3. 重构前后对比

| 指标 | 重构前 | 重构后 | 变化 |
|------|--------|--------|------|
| 根目录 .py 文件 | 21 个 | 10 个 | **-52%** |
| 子包数量 | 2 (core/, collectors/) | 5 (+api/, +integrations/, +storage/) | **+3** |
| 子包总文件 | 6 个 | 22 个 | 模块均归位子包 |
| 前端视图 | 4（含对话 UI） | 3（概览/审批/扫描） | 对话已移除 |
| CLI 入口 | 5 个独立命令 | 1 主入口 + 5 维护子命令 | 统一化 |
| 审计范围 | 对话级 + 动作级 | 仅动作级 | 专注化 |

## 4. 关键依赖关系

```text
main.py ──→ manager.py ──→ core/{action,baseline,audit}_service
                          ├── integrations/{discovery,detection,whitelist,...}
                          └── storage/{audit_store,db_store}

web.py ──→ api/__init__.py ──→ api/_handlers.py ──→ manager.py

ui.py ──→ (纯静态 HTML/CSS/JS，通过 HTTP 调 api/_handlers)
```
