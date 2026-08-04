# 架构分析报告

> 版本：v0.2.1（分析基线）→ v0.3.0（当前） | 日期：2026-07-30（分析）/ 2026-08-01（更新） | 作者：架构评审组

---

## 1. 概述

OpenClaw-RVGuarder（龙虾卫士）是一个面向 OpenClaw AI Agent 的**非侵入式运行时安全保护系统**。本文档以 v0.2.1 为分析基线，并同步标注 v0.3.0 的落地结果与仍待完成的阶段性目标。

---

## 2. 技术栈全景

### 2.1 当前技术栈

| 层次 | 技术选型 | 版本 | 状态 |
|------|---------|------|------|
| 编程语言 | Python | ≥3.13 | **确认** |
| HTTP 服务 | legacy：`http.server.ThreadingHTTPServer`（标准库） | 内置 | ✅ 默认运行 |
| HTTP 服务（可选） | FastAPI + uvicorn | 可选依赖 | ✅ 并行实现（未安装依赖时自动降级） |
| 异步模型 | 同步（threading per request） | — | ⚠️ 有瓶颈 |
| 序列化/验证 | Pydantic v2（`BaseModel`） | — | ✅ 已迁移（`to_dict()` 保留兼容别名） |
| 数据库 | SQLite（开发）/ PostgreSQL（生产预留） | — | ✅ 设计良好 |
| 审计存储 | JSONL 双写 + SHA-256 哈希链 | — | ✅ |
| 语义分析 | DeepSeek API / 本地规则降级 | — | ✅ |
| FSM 状态机 | `transitions` 库 | — | ✅ |
| 前端 | Preact SPA（Vite 构建） | — | ✅ |
| JS 运行时插件 | OpenClaw Plugin SDK (`api.on()`) | — | ✅ |
| 容器化 | Docker Compose（生产） | — | ⚠️ 未充分使用 |

### 2.2 依赖清单（核心 Python 包）

```text
- transitions      # FSM 状态机（rv_monitors 核心依赖）
- python-dotenv    # .env 加载
- requests         # DeepSeek API 客户端
- psycopg2-binary  # PostgreSQL（预留）
- redis            # 缓存（预留）
```

**总外部依赖仅 5 个**，极其轻量。这对重构有利 — 引入新框架时依赖冲突风险低。

---

## 3. 模块架构分析

### 3.1 模块依赖关系

```
main.py (CLI 入口)
    │
    ├── legacy_web.py (默认 HTTP 服务 · ThreadingHTTPServer)
    │       └── api/ (_handlers · 路由处理器，仅做 HTTP 边界)
    │
    ├── web/ (可选 FastAPI 传输层 · 并行实现)
    │       └── routes/*（API 路由 + 静态 SPA 托管）
    │
    ├── services.py (业务编排 · GuardServices 容器 + LazyProxy)
    │       └── engine/pipeline.py（热路径流水线：ingest/before/after）
    │
    ├── engine/ (安全检测核心)
    │       ├── behavior.py (行为采集)
    │       ├── semantic_enhancer.py (语义增强)
    │       ├── detection.py (规则引擎)
    │       ├── runtime_verification.py (RV 引擎)
    │       ├── rv_monitors.py (手写 FSM 监视器 · 规约驱动未落地)
    │       ├── control.py (决策控制)
    │       └── whitelist.py (白名单匹配)
    │
    ├── core/ (业务服务)
    │       ├── action_service.py (动作审批)
    │       ├── audit_service.py (审计服务)
    │       └── baseline_service.py (基线扫描)
    │
    ├── integrations/ (OpenClaw 集成)
    │       ├── discovery.py (环境发现)
    │       ├── hook_runtime.py (JS 插件生成)
    │       ├── tool_hook_bridge.py (工具桥接)
    │       └── openclaw_adapter.py (Gateway 适配)
    │
    ├── storage/ (数据持久化)
    │       ├── db_store.py (DB 抽象：SQLite/Postgres)
    │       └── audit_store.py (审计存储)
    │
    └── manager.py（兼容层：用于旧导入路径与测试打补丁）
```

### 3.2 依赖关系类型分析

| 关系 | 类型 | 说明 |
|------|------|------|
| `main` → `manager` | 强依赖（组合） | `build_manager()` 工厂函数，入口唯一 |
| `services` → `legacy_web/web` | 强依赖（组合） | `launch_web()` 启动 HTTP 服务（legacy 或 FastAPI） |
| `services` → `engine/*` | 强依赖（组合） | 热路径组件初始化 + 冷路径 LazyProxy |
| `services` → `core/*` | 强依赖（组合） | 业务服务聚合（Action/Audit/Baseline） |
| `engine/*` 内部 | 弱耦合（独立） | 各引擎通过 `evaluate()` 接口通信，不互相引用 |
| `api/*` → `services` | 强依赖（委托） | API 处理器直接调用 GuardServices 实例 |
| `storage/*` → 外部 | 弱依赖（接口） | 通过 `DBStoreInterface` 抽象层隔离 |

**关键发现（v0.3.0 已缓解）**：编排中枢从 `manager.py` 转移到 `services.py`（GuardServices + pipeline），`manager.py` 降级为兼容层。上帝对象风险已显著降低，但服务容器仍是扩展的主要入口，需要持续控制依赖方向与初始化成本。

---

## 4. 数据流分析

### 4.1 核心流水线

```
用户输入 / Hook 调用
    │
    ▼
[1] BehaviorCollectorManager.ingest()        → BehaviorEvent
    │                                          (Pydantic model → dict)
    ▼
[2] SemanticEnhancer.evaluate()              → semantic + rv_trace
    ├─ LLM API 模式（DeepSeek，~500ms）
    └─ 本地规则降级（<1ms）
    │
    ▼
[3] DetectionEngine.evaluate()               → DetectionDecision
    ├─ Office policies（5 条，语义优先）
    ├─ Semantic predicates（47 条规则）
    └─ Fallback 兜底
    │
    ▼
[4] RuntimeVerificationEngine.evaluate()     → RV 判定（可覆盖 decision）
    ├─ MailMonitor / ReportMonitor / SecurityChainMonitor
    ├─ BroadcastMonitor / DataExportMonitor / BatchFileMonitor
    └─ WindowManager（滑动窗口 10 步，TTL 300s）
    │
    ▼
[5] GuardController.decide()                 → ControlledAction
    ├─ WhitelistEngine（Trie / Radix Tree）
    └─ 设置状态：proposed / pending_approval / blocked
    │
    ▼
[6] ActionService 持久化                    → JSON 双缓冲
    │
    ▼
[7] AuditStore 审计记录                      → SHA-256 哈希链 + JSONL 双写
    │
    ▼
[8] Hook 返回 / UI 展示 / 审批等待
    └─ 审批通过 → 执行 / 拒绝 → 结束
```

### 4.2 数据流瓶颈

| 阶段 | 延迟 | 瓶颈 | 影响 |
|------|------|------|------|
| [1] 行为采集 | <1ms | 无（纯内存转换） | — |
| [2] 语义增强 | 0.5ms~500ms | LLM API 调用（可选） | 首次调用延迟 |
| [3] 规则检测 | <5ms | 47 条规则遍历 | 可接受 |
| [4] RV 验证 | <2ms | 6 个 FSM 顺序判定 | 可接受 |
| [5] 决策控制 | <1ms | 白名单 Trie 匹配 | — |
| [6] 持久化 | <10ms | JSON 读写 | 高频调用时累积 |
| [7] 审计 | <5ms | 哈希链计算 + 双写 | 可接受 |

**总体延迟**：LLM 模式下约 500ms，本地模式下约 20ms。Hook 桥接接受决策超时为 180s（可配），当前性能足够。

---

## 5. 技术痛点分析

### 5.1 P0 — 严重（必须解决）

| # | 痛点 | 位置 | 影响 | 说明 |
|---|------|------|------|------|
| A1 | **手动 HTTP 路由管理** | `legacy_web.py` | 维护性 | ✅ FastAPI `web/` 并行实现已落地；legacy 仍保留作默认/回退 |
| A2 | **无请求验证** | legacy API | 安全性 | ✅ FastAPI 路由已具备请求体校验；legacy 路由仍为手工解析（迁移期保留） |
| A3 | **手动序列化** | 全部 model | 维护性 | ✅ Pydantic v2 替代 `@dataclass`，`to_dict()` 保留为兼容别名 |
| A4 | **无自动 API 文档** | 全部 | 效率 | 前端对接时需手动阅读 `_handlers.py` 函数签名才能知道 API 格式。无人能快速了解所有端点 |
| A5 | **Manager 上帝对象** | `services.py` / `manager.py` | 扩展性 | ✅ GuardServices + pipeline 已承担主要编排；`manager.py` 保留兼容层（不再作为新代码入口） |

### 5.2 P1 — 重要（建议解决）

| # | 痛点 | 位置 | 影响 | 说明 |
|---|------|------|------|------|
| B1 | **同步阻塞** | `legacy_web.py` | 并发 | `ThreadingHTTPServer` 每个请求一个线程。OpenClaw 可能同时发送多个 `before_tool_call` 请求，线程池膨胀无上限 |
| B2 | **JSON 文件作为主存储** | `action_service.py` | 可靠性 | 使用 JSON 文件存储动作列表（`_load()`/`_save_all()`），最大 1000 条。非事务性，并发写可能导致数据丢失 |
| B3 | **硬编码路由路径** | `legacy_web.py` + `api/_handlers.py` | 维护性 | legacy 路由表与处理器分离，新增端点需手动同步；FastAPI 已缓解该问题（声明式路由） |
| B4 | **错误处理不规范** | 全项目 | 可靠性 | 异常时返回 `(error_dict, 500)`，无统一异常处理中间件。调试信息可能泄漏到响应中 |
| B5 | **ORM 未使用** | `db_store.py` | 维护性 | `SQLiteStore` 使用原生 SQL 查询字符串拼接，无类型安全。表结构变更需手动迁移 |

### 5.3 P2 — 轻微（可暂缓）

| # | 痛点 | 位置 | 影响 | 说明 |
|---|------|------|------|------|
| C1 | **日志/监控缺失** | 全项目 | 运维 | 无结构化日志，无 metrics 暴露 |
| C2 | **配置分散** | 多文件 | 维护性 | 配置散落在 `.env`、`runtime/guard-config.json`、`pyproject.toml` |
| C3 | **前端无 TS** | `frontend/` | 维护性 | 已迁移到 Preact，但仍为 JavaScript（无 TS 类型约束） |
| C4 | **测试覆盖率不足** | `tests/` | 质量 | 虽有测试文件，但缺乏集成测试覆盖完整流水线 |

---

## 6. 扩展性瓶颈分析

### 6.1 当前性能极限

| 维度 | 当前测量 | 瓶颈原因 |
|------|---------|---------|
| 启动时间 | **3-5 秒**（实测） | `build_manager()` 同步执行 discovery + baseline + hook |
| 并发请求 | ~50 req/s | `ThreadingHTTPServer` 同步阻塞 |
| 动作存储 | 1000 条 | `action_service.py` MAX_ACTIONS_SIZE 硬限制 |
| 规则数量 | 47 条 | 硬编码谓词，无动态规则加载 |
| 监视器数量 | 6 个 | 手写 FSM 类，无规约驱动生成 |
| 会话隔离 | 内存 | RV 引擎 per-session WindowManager 在内存中，重启丢失 |
| 审计写入 | ~1000 tx/s | JSONL 双写 + SHA-256 |
| Python 模块加载 | **< 100ms**（全部模块） | 实测验证，不是瓶颈 |

### 6.2 启动速度根因分析

```
openclaw-guard run 启动时序（实测）:

t=0ms     Python 解释器启动 + 模块导入
t=100ms   模块加载完成（全部 engine/core/integrations 等）  ✅ 不是瓶颈
t=100ms   build_manager() 开始
t=200ms   discover_openclaw() — socket 探测 + 文件扫描   ❌ 可延迟
t=500ms   reset_db_store() — 建表 + 连接池                    ✅ 可接受
t=700ms   ensure_baseline() — 全量基线扫描                   ❌ 首次使用时再做
t=2-5s    ensure_runtime_hook_plugin() — 生成 JS + node --check ❌ 后台线程
t=3-6s    服务就绪                                            ❌ 目标 ≤ 2s
```

**结论**：启动慢不是代码执行慢，是**不该在启动时做的事**在启动时做了。Python 自身性能足够。

### 6.3 未来扩展需求预测

| 需求 | 时间预期 | 对架构的影响 |
|------|---------|-------------|
| 更多办公场景规则（100+） | 短期 | 规则引擎需支持动态加载 |
| 多用户/多租户 | 中期 | 需引入认证/授权体系 |
| 规则热更新 | 中期 | 需规则存储位于 DB 而非内存硬编码 |
| 分布式部署 | 长期 | 需状态外移（Redis/PostgreSQL） |
| API 开放给第三方 | 长期 | 需完整的 API 文档 + 鉴权 |

---

## 7. 核心设计优势

在指出问题的同时，需确认哪些设计应该保留：

| 优势 | 位置 | 保留原因 |
|------|------|---------|
| `DBStoreInterface` 抽象层 | `storage/` | 良好的接口隔离，PostgreSQL 扩展点已预留 |
| `SemanticEnhancer` 双模式 | `engine/` | LLM/本地规则自动切换，fail-open 设计 |
| `RuntimeVerificationEngine` 隔离 | `engine/` | per-session WindowManager，天然会话隔离 |
| 审计哈希链 | `storage/` | SHA-256 防篡改，取证合规 |
| 决策追踪链 | `detection.py` | 每一步决策记录完整的 trace path |
| Hook 插件熔断器 | `runtime/` | 后端不可达时自动 fail-open |
| `BaseMonitor` 抽象基类 | `rv_monitors.py` | 良好的多态设计，可扩展新监视器 |

---

## 8. 总结

### 8.1 必须保留的架构特性

1. **分层检测架构**：语义层 → 规则层 → RV 层 → 决策层，这一流水线设计合理
2. **接口抽象**：`DBStoreInterface` 和 `BaseMonitor` 是正确的设计方向
3. **fail-safe 理念**：熔断器、fail-open、语义降级，安全领域核心设计原则
4. **全链路追踪**：每个决策步骤记录 trace，可审计可调试

### 8.2 必须解决的核心问题

1. **HTTP 框架缺失**：手动路由 + 手动序列化 + 无验证 — 这是当前最大的技术债务
2. **Manager 上帝对象**：阻碍组件独立测试和扩展
3. **JSON 文件存储**：并发安全性和可靠性不足
4. **规则硬编码**：无法动态加载和热更新

### 8.3 OpenClaw 合约边界（需对照官方文档验证）

涉及 OpenClaw Plugin SDK 的代码可以优化改动，但必须遵守以下验证流程：

1. **文档对照**：每次改动前，先查阅 OpenClaw 官方文档确认 API 合约
2. **合约测试**：改完后运行合约测试，验证响应格式与 JS 插件预期一致
3. **PR 审查**：在 PR 描述中附上对应的官方文档链接和章节

| 合约项 | 位置 | 保护措施 |
|--------|------|---------|
| `runtime/openclaw-guard-plugin/` | JS 插件层 | 合约测试 + 文档对照 |
| `/api/hook/*` 端点响应格式 | 后端 API | FastAPI Pydantic 模型约束 + 合约测试 |
| `registerGatewayMethod(...)` | JS 插件 | 文档对照 + 自动生成模板由 `hook_runtime.py` 维护 |
| `hook_runtime.py` 的 JS 模板 | 后端 | 模板引擎维护，改模板时对照 SDK 文档 |

### 8.4 选型方向

HTTP 框架替代 `BaseHTTPRequestHandler` 是重构的核心目标。详见 [framework-evaluation.md](./framework-evaluation.md)。
