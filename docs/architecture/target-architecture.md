# 重构后目标架构设计

> 版本：v1.0 (重构目标) | 日期：2026-08-01 | 作者：架构评审组

---

## 1. 目标架构总览

### 1.1 层次架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLI（main.py）                           │
│             openclaw-guard run / baseline / doctor              │
└───────────────────────────┬─────────────────────────────────────┘
                            │ 依赖注入
┌───────────────────────────▼─────────────────────────────────────┐
│                   Service Container                              │
│            GuardServices (替代 Manager 上帝对象)                  │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐        │
│  │Detection│Semantic│  RV   │Whitelist│Control│Behavior│       │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘        │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐                │
│  │Action│Audit│Baseline│Adaptr│Discover│                        │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘                │
└───────────────────────────┬─────────────────────────────────────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
┌─────────────▼──┐ ┌────────▼────────┐ ┌─▼──────────────┐
│  FastAPI Web  │ │   Pipeline      │ │   Storage       │
│   Layer       │ │   (编排层)      │ │   (持久化)      │
├───────────────┤ ├────────────────┤ ├────────────────┤
│ Routes:       │ │ ingest_event() │ │ DBStoreInterface│
│ /api/health   │ │ before_tool()  │ │ ├─ SQLiteStore  │
│ /api/hook/**  │ │ after_tool()   │ │ ├─ PostgreSQL   │
│ /api/actions  │ │                │ │ └─ AuditStore   │
│ /api/audit/** │ │ 复用现有逻辑    │ │    (哈希链)     │
│ /api/rv/**    │ │ (engine/core)  │ │                 │
│ /api/baseline │ │                │ │                 │
│ 静态文件 SPA  │ │                │ │                 │
└───────────────┘ └────────────────┘ └────────────────┘
```

### 1.2 OpenClaw SDK 合约边界（重构时需对照官方文档验证）

以下内容涉及 OpenClaw Plugin SDK 合约。**可以优化改动，但必须逐项对照 [OpenClaw 官方文档](https://openclaw.ai/docs) 验证**，确保字段名、类型、行为与 SDK 要求一致。建议在 PR 审查中加入"OpenClaw 合约合规"检查项。

| 合约项 | 位置 | 官方文档依据 |
|--------|------|-------------|
| `runtime/openclaw-guard-plugin/index.js` | JS 插件入口 | `api.on()`, `before_tool_call`, `requireApproval` 类型 |
| `runtime/openclaw-guard-plugin/openclaw.plugin.json` | 插件清单 | `activation.onStartup`, `openclaw.extensions` |
| `runtime/openclaw-guard-plugin/package.json` | npm 包描述 | `openclaw.extensions` 声明 |
| `POST /api/hook/before-tool-call` 响应格式 | 后端 API | JS 插件解析 `{ action, title, message, ... }` |
| `POST /api/hook/resolve-approval` 请求/响应格式 | 后端 API | JS 插件 `onResolution` 回调 |
| `registerGatewayMethod(STATUS_METHOD, ...)` | JS 插件 | Gateway 插件状态检测 |
| `api.on("before_tool_call")` 的 `requireApproval` 返回值 | JS 插件 | `allowedDecisions`, `timeoutMs`, `onResolution` |
| `x-openclaw-guard-token` 鉴权 header | 后端 API | JS 插件认证协议 |

**合约保护手段**：
- **合约测试**：每个 Hook API 端点有专门的测试用例验证响应格式符合 JS 插件预期（见 [quality-assurance.md](./quality-assurance.md#32-合约测试contract-testing)）
- **文档对照**：改动 JS 插件或 Hook API 时，必须在 PR 描述中附上对应的官方文档链接和章节
- **版本兼容**：OpenClaw SDK 版本升级时，先查阅 changelog 确认 API 变更，再适配

### 1.3 架构约束（按优先级排列）

| 优先级 | 约束 | 指标 | 违反代价 |
|--------|------|------|---------|
| **P0** | **启动速度** | `openclaw-guard run` → 服务就绪 ≤ 2秒 | 严重影响开发体验和插件可用性 |
| **P0** | **热路径延迟** | `before_tool_call` 完整链路 ≤ 50ms（本地模式） | 直接影响 OpenClaw Agent 响应速度 |
| **P0** | **摘要接口速度** | `GET /api/summary` ≤ 10ms | 首页加载体验 |
| **P1** | **冷路径延迟** | 基线扫描、审计导出等 ≤ 5秒 | 可用但不关键 |
| **P1** | **前端首屏加载** | SPA 首屏 JS ≤ 20KB gzip | Dashboard 使用体验 |
| **P2** | **并发吞吐** | `before_tool_call` ≥ 100 req/s | 极端场景 |

### 1.4 设计原则

1. **轻量优先**：一切设计以低延迟为首要目标，不做无谓的抽象
2. **懒加载**：所有非关键路径组件在启动时不初始化，首次使用时再创建
3. **依赖倒置**：高层模块（Web/Pipeline）不依赖低层模块，都依赖抽象接口
4. **单一职责**：每个模块只有一个变更理由，API 路由不做业务逻辑
5. **显式依赖**：所有组件通过构造器注入依赖，不隐式创建

---

## 2. 目录结构（实际实现 · v0.6.0）

> 以下目录结构已按 v0.6.0 当前实现对齐：`services.py` 为扁平单文件、编排层内嵌 `engine/pipeline.py`、RV 规约采用 `rv_dsl.py` + `rv_rules.json`，并新增 `rv/` 与 `spec/` 的阶段 A–F 能力；SQLAlchemyStore 内嵌于 `db_store.py`，`api/` 与 `manager.py` 保留为兼容层。

```
openclaw_guard/
├── main.py                    # CLI 入口（argparse + 启动，--fastapi 切换 HTTP 层）
├── config.py                  # 配置定义（读取 DB_STORE_MODE / OPENCLAW_RV_RULE_MODE）
├── models.py                  # Pydantic 数据模型
│
├── web/                       # FastAPI 层（可选，--fastapi 启用）
│   ├── __init__.py            # app = FastAPI() + 全局中间件（关闭 OpenAPI docs）
│   ├── app.py                 # create_app() 工厂函数
│   ├── dependencies.py        # FastAPI 依赖注入
│   ├── errors.py              # 统一异常处理
│   └── routes/                # 路由模块
│       ├── __init__.py
│       ├── health.py          # GET /api/health
│       ├── hook.py            # POST /api/hook/{before,after,resolve}
│       ├── actions.py         # 动作审批 CRUD
│       ├── audit.py           # 审计查询/导出
│       ├── rv.py              # RV 状态/开关
│       ├── baseline.py        # 基线扫描
│       └── static.py          # 前端 SPA 静态文件
│
├── services.py                # GuardServices 服务容器 + build_services()（扁平单文件）
│
├── legacy_web.py              # stdlib http.server 实现（默认 HTTP 层，FastAPI 缺失时回退）
│
├── engine/                    # 安全检测引擎
│   ├── __init__.py
│   ├── behavior.py            # 行为事件建模
│   ├── control.py             # 决策控制
│   ├── detection.py           # 规则引擎
│   ├── whitelist.py           # 白名单
│   ├── semantic_enhancer.py   # 语义增强
│   ├── pipeline.py            # 编排层（ingest / before / after 流水线，从 manager 拆分）
│   ├── runtime_verification.py  # RV 引擎 + 滑动窗口（per-session 隔离 + 状态序列化）
│   ├── rv_dsl.py              # ChainRule 声明式规约 DSL（compile_monitors 编译监视器）
│   ├── rv_rules.json          # 声明式规约数据
│   └── rv_monitors.py         # 手写 FSM 监视器（保留为规约关闭时的回退模式）
│
├── core/                      # 核心业务服务
│   ├── __init__.py
│   ├── action_service.py
│   ├── audit_service.py
│   └── baseline_service.py
│
├── integrations/              # OpenClaw 集成
│   ├── __init__.py
│   ├── discovery.py
│   ├── hook_runtime.py
│   ├── tool_hook_bridge.py
│   └── openclaw_adapter.py
│
├── storage/                   # 数据持久化
│   ├── __init__.py
│   ├── db_store.py            # DBStore 接口族：SQLiteStore / PostgreSQLStore / SQLAlchemyStore
│   └── audit_store.py
│
├── api/                       # 保留：HTTP 处理函数边界层（legacy_web 与 web/routes 共用）
├── manager.py                 # 向后兼容层（OpenclawGuardManager 子类化 GuardServices）
└── utils.py                   # LazyProxy 懒加载代理等工具
```

---

## 3. 前后端交互规范

### 3.1 API 设计原则

```
Method: RESTful (GET/POST/PUT/DELETE)
Base URL: http://localhost:8780
Content-Type: application/json
Auth Header: x-openclaw-guard-token
```

### 3.2 响应格式统一

```python
# 成功响应
{
    "ok": true,
    "data": { ... },
    "meta": {
        "request_id": "uuid",
        "timestamp": 1722000000.123,
    }
}

# 错误响应
{
    "ok": false,
    "error": {
        "code": "ACTION_NOT_FOUND",
        "message": "Action with id xxx not found",
        "detail": { ... }  // 可选，调试信息
    },
    "meta": {
        "request_id": "uuid",
        "timestamp": 1722000000.123,
    }
}
```

### 3.3 分页规范

```python
# 查询列表响应
{
    "ok": true,
    "data": [ ... ],
    "pagination": {
        "page": 1,
        "page_size": 20,
        "total": 156,
        "total_pages": 8
    }
}

# 请求参数
GET /api/actions?page=1&page_size=20&status=pending_approval
```

### 3.4 错误码清单

| Code | HTTP Status | 含义 |
|------|------------|------|
| `INVALID_TOKEN` | 403 | 鉴权失败 |
| `VALIDATION_ERROR` | 422 | 请求体验证失败 |
| `ACTION_NOT_FOUND` | 404 | 指定的动作不存在 |
| `INVALID_DECISION` | 400 | 无效的审批决策 |
| `PIPELINE_ERROR` | 500 | 内部流水线错误 |
| `RATE_LIMITED` | 429 | 请求频率超限 |

---

## 4. 依赖注入方案

### 4.1 FastAPI Dependencies

```python
# web/dependencies.py

from fastapi import Request, HTTPException, Header

async def get_services(request: Request) -> GuardServices:
    """从 app.state 获取服务容器"""
    return request.app.state.services

async def verify_token(
    token: str = Header(None, alias="x-openclaw-guard-token"),
    services: GuardServices = Depends(get_services),
) -> None:
    """验证 Hook 鉴权 Token"""
    if token != services.config.GUARD_TOKEN:
        raise HTTPException(status_code=403, detail="invalid token")
```

### 4.2 路由中使用

```python
@router.post("/hook/before-tool-call", response_model=BeforeToolCallResponse)
async def before_tool_call(
    req: BeforeToolCallRequest,
    services: GuardServices = Depends(get_services),
    _: None = Depends(verify_token),  # 钩子路由自动鉴权
):
    # 使用 asyncio.to_thread 将同步业务逻辑放入线程池，避免阻塞事件循环
    import asyncio
    result = await asyncio.to_thread(services.pipeline.handle_before_tool_call, req)
    return result
```

---

## 5. 懒加载初始化策略（P0 关键）

### 5.1 问题背景

当前 `build_manager()` 在启动时同步执行：
1. `discover_openclaw()` — socket 探测 + 文件扫描（~500ms）
2. `reset_db_store()` — 建表 + 连接池初始化
3. `ensure_baseline()` — 全量基线扫描（~2-5s）
4. `ensure_runtime_hook_plugin()` — 生成 JS 插件 + `node --check`（~200ms）

**目标**：启动时只创建热路径必需组件，其余延迟加载。

### 5.2 LazyProxy 实现

```python
# services/lazy.py

import importlib
from typing import Any, Generic, TypeVar

T = TypeVar("T")

class LazyProxy(Generic[T]):
    """懒加载代理：首次访问属性时才真正创建对象"""
    
    def __init__(self, module_path: str, class_name: str, *args, **kwargs):
        self._module_path = module_path
        self._class_name = class_name
        self._args = args
        self._kwargs = kwargs
        self._instance: T | None = None
    
    def _get(self) -> T:
        if self._instance is None:
            module = importlib.import_module(self._module_path)
            cls = getattr(module, self._class_name)
            self._instance = cls(*self._args, **self._kwargs)
        return self._instance
    
    def __getattr__(self, name: str) -> Any:
        return getattr(self._get(), name)
```

### 5.3 启动时序（目标）

```
t=0ms     import openclaw_guard.web           (Python 模块加载)
t=50ms    create_app() → FastAPI()            (框架初始化)
t=100ms   app.state.services = build(minimal)  (只创建热路径组件)
t=150ms   uvicorn.run() 开始监听              (服务就绪 ✅)
          ↓
          ─── 首次工具调用触发 ───
t=500ms   LazyProxy.rv_engine → 创建 RV 引擎  (按需初始化)
t=600ms   LazyProxy.baseline → 创建 Baseline  (按需初始化)
t=3s      LazyProxy.adapter → discover()      (首次调用 OpenClaw 时探测)
```

### 5.4 组件分类

| 类别 | 组件 | 初始化时机 |
|------|------|-----------|
| **热路径（启动时创建）** | DetectionEngine, SemanticEnhancer, GuardController, WhitelistEngine | 启动时 |
| **懒加载（首次使用时）** | RuntimeVerificationEngine, BaselineService, OpenclawAdapter | 首次访问 |
| **按需触发** | discover_openclaw(), ensure_hook_plugin() | 用户主动操作或后台线程 |

---

## 6. 状态管理方案

### 6.1 服务状态

```python
# app.state.services — FastAPI 应用级状态
# 每次请求通过依赖注入获取，线程安全

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时
    services = build_services(...)
    app.state.services = services
    yield
    # 关闭时
    services.shutdown()
```

### 6.2 会话状态

RV 引擎的 `per-session 窗口` 仍保持在内存中：

```python
# rv/runtime_verification.py
class RuntimeVerificationEngine:
    def __init__(self):
        self._windows: dict[str, WindowManager] = {}
        self._monitors: dict[str, list[BaseMonitor]] = {}
```

大数据量时可通过 `lru_cache` 或 Redis 外移，但不作为当前重构目标。

---

## 7. 前端架构（Preact SPA）

### 7.1 选型理由

| 框架 | 体积 | 选型理由 |
|------|------|---------|
| **Preact** | ~3KB gzip | 兼容 React API，生态丰富，Vite 官方插件，学习成本为零 |
| ~~Vanilla JS~~ | 35k 行 app.js | 历史实现（v0.2.x），已在 v0.3.0 迁移到 Preact |
| ~~Vue~~ | ~16KB | 过于重量级，且与当前技术栈不匹配 |

选择 Preact 的核心原因：
1. **渐进迁移**：可在 Vite 项目中逐步引入 Preact 组件，不需要一次性重写 35k 行
2. **极致轻量**：3KB gzip，满足首屏 JS ≤ 20KB 的约束
3. **React 生态**：可复用 React 仪表盘组件（如 `recharts`、`tanstack-table`）
4. **Vite 集成**：`@preact/preset-vite` 零配置接入

### 7.2 前端目录结构（已落地 · v0.6.0）

```
frontend/
├── index.html                  # 入口 HTML
├── vite.config.js              # Vite 配置 + @preact/preset-vite
├── package.json
├── src/
│   ├── main.jsx                # Preact 入口
│   ├── App.jsx                 # 根组件 + 路由
│   ├── api.js                  # API 请求层（fetch 封装 + 认证头注入，单文件）
│   ├── store.js                # zustand 状态管理（单文件）
│   ├── i18n.js                 # 国际化文案
│   ├── pages/                  # 页面组件
│   │   ├── Dashboard.jsx       # 概览面板
│   │   ├── Actions.jsx         # 动作审批页
│   │   ├── Rules.jsx           # 安全规则页
│   │   ├── Skills.jsx          # 技能页
│   │   └── Settings.jsx        # 设置页
│   ├── components/             # 可复用组件（Layout / ActionCard / RvStatusPanel / TraceTimeline 等）
│   └── styles.css              # 全局样式
```

### 7.3 迁移策略

详见 [refactoring-plan.md §6](./refactoring-plan.md#6-阶段四前端-preact-迁移)，采用渐进式替换：基础设施 → 逐页迁移 → 旧代码清理。

---

## 8. 工程化配置

### 8.1 pyproject.toml 依赖（目标）

```toml
[project]
name = "openclaw-guard"
version = "0.3.0"
requires-python = ">=3.13"

dependencies = [
    "fastapi >=0.115.0",
    "uvicorn[standard] >=0.30.0",
    "pydantic >=2.0",
    "transitions",
    "python-dotenv",
    "requests",
]

[project.optional-dependencies]
postgres = ["psycopg2-binary", "sqlalchemy[asyncio] >=2.0"]
redis = ["redis >=5.0"]
test = ["pytest", "httpx", "pytest-asyncio"]
```

### 8.2 开发工具链

```bash
# 开发环境
pip install -e ".[test]"
pip install ruff mypy pytest

# 运行测试
pytest tests/ -v --cov=openclaw_guard

# 类型检查
mypy openclaw_guard/

# 代码格式化
ruff format openclaw_guard/
```

### 8.3 CI/CD 配置

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - run: pip install -e ".[test]"
      - run: pytest tests/ -v
      - run: mypy openclaw_guard/
```

---

## 9. 新功能开发流程

### 9.1 新增一个 API 端点的标准流程

```text
1. 在 web/models/ 定义请求/响应 Pydantic 模型
2. 在 web/routes/ 创建或修改路由文件
3. 注入 GuardServices 依赖
4. 委托给现有 engine/core 业务逻辑
5. 在 tests/ 添加 FastAPI TestClient 测试
6. 运行 pytest 确认通过
```

### 9.2 新增一个安全规则的标准流程

```text
1. (a) 如果是单步规则 → 在 detection.py 添加语义谓词
   (b) 如果是链式规则 → 在 rv/rv_rules.json 追加 ChainRule
2. 在 rv/rv_rules.json 中追加声明
3. (可选) 如果监视器逻辑特殊 → 实现 BaseMonitor 子类
4. 在 tests/test_rv.py 添加测试用例
```

### 9.3 代码审查清单

- [ ] Pydantic 模型是否使用了正确的字段类型和验证？
- [ ] 路由函数是否只做路由委派，不做业务逻辑？
- [ ] 异常是否通过统一错误处理返回？
- [ ] 是否添加了对应测试？
- [ ] mypy 类型检查是否通过？

---

## 10. 迁移后对比

| 维度 | 重构前 (v0.2.1) | 当前 (v0.6.0) | 重构后 (v1.0) |
|------|-----------------|----------------|---------------|
| Web 框架 | `BaseHTTPRequestHandler` | **legacy_web 默认 + FastAPI 可选（`--fastapi`）** | FastAPI |
| 序列化 | 手动 `to_dict()` | **Pydantic v2（to_dict 别名）** | Pydantic 自动 |
| 请求验证 | 无 | Pydantic schema（FastAPI 层）/ 手动（legacy） | Pydantic schema |
| API 文档 | 无 | 无（web/app.py 关闭 OpenAPI：docs_url/redoc_url/openapi_url） | Swagger + ReDoc 自动生成 |
| 启动速度 | ~3-5秒（同步初始化全部组件） | ~3-5秒（冷路径经 LazyProxy 惰性加载） | ~150ms（懒加载，仅创建热路径） |
| 编排层 | Manager 上帝对象 | **GuardServices 容器 + engine/pipeline.py（manager.py 兼容子类）** | 独立 Pipeline + 依赖注入 + LazyProxy |
| 前端框架 | Vanilla JS（35k 行 app.js） | **Preact SPA（Dashboard/Actions/Rules/Skills/Settings）** | Preact SPA（3KB gzip，组件化） |
| 存储层 | SQLiteStore (原生 SQL) | **SQLiteStore 默认 + SQLAlchemyStore 可选（DB_STORE_MODE=sqlalchemy）** | SQLAlchemy (可选) |
| RV 监视器 | 6 个手写 FSM | **ChainRule DSL 规约驱动（默认）+ FSM 回退** | ChainRule 声明式规约 |
| 并发 | threading (无上限) | threading | uvicorn worker (可配置) |
| 测试 | unittest | unittest | pytest + httpx |
| 类型安全 | 无 | **Pydantic 类型约束** | mypy + Pydantic |
