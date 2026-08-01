# 框架选型评估报告

> 版本：v0.2.1 | 日期：2026-07-30 | 作者：架构评审组

---

## 1. 评估背景

OpenClaw-RVGuarder 当前 HTTP 服务层使用 Python 标准库 `http.server.ThreadingHTTPServer`，存在以下核心问题：
- 手动路由管理（字典映射，增端点改 3 处文件）
- 无请求/响应序列化验证（手动 `json.loads` + 手动构建 dict）
- 无自动 API 文档
- 同步阻塞模型

本次选型目标是寻找替代方案，解决上述问题，同时保持轻量部署和低迁移成本。

---

## 2. 选型需求矩阵

### 2.1 硬性需求（必须满足）

| # | 需求 | 优先级 | 说明 |
|---|------|--------|------|
| R1 | 轻量级 | P0 | 单进程可运行，不依赖外部服务器 |
| R2 | 自动序列化/验证 | P0 | 替代当前手动 `to_dict()` 和 `json.loads()` |
| R3 | 路由系统 | P0 | 替代当前 `_GET_ROUTES`/`_POST_ROUTES` 字典 |
| R4 | 静态文件服务 | P0 | 托管前端 SPA（`/runtime/ui/`） |
| R5 | 低迁移成本 | P0 | 不碰现有业务逻辑层（engine/core/storage） |
| R6 | Python 3.13+ | P0 | 利用最新语言特性 |

### 2.2 期望需求（加分项）

| # | 需求 | 优先级 | 说明 |
|---|------|--------|------|
| R7 | 自动 OpenAPI 文档 | P1 | 对接前端时高效沟通 |
| R8 | 异步支持 | P2 | 未来并发场景预留 |
| R9 | 社区活跃 | P1 | 长期可维护性 |
| R10 | 生态完整 | P1 | 中间件、CORS、错误处理等 |

---

## 3. 候选框架清单

| 框架 | 版本 | Stars | 定位 | 初筛 |
|------|------|-------|------|------|
| **FastAPI** | 0.115.x | ~85k | 异步 REST 框架 | ✅ 通过 |
| **Flask** | 3.1.x | ~70k | 微型 WSGI 框架 | ✅ 通过 |
| **Litestar** | 2.x | ~5k | 异步类 FastAPI | ✅ 通过 |
| Django+DRF | 6.1 | ~111k | 全栈框架 | ❌ 过重 |
| Starlette | 0.45.x | ~11k | ASGI 工具包 | ❌ 非业务框架 |
| Sanic | 24.x | ~18k | 异步框架 | ❌ 生态不足 |

---

## 4. 深度对比

### 4.1 开发效率

| 维度 | FastAPI | Flask | Litestar |
|------|---------|-------|----------|
| 路由定义 | `@app.get()` 装饰器 | `@app.route()` 装饰器 | `@app.get()` 装饰器 |
| 请求解析 | Pydantic 模型自动注入 | 手动 `request.json` | Pydantic + DTO |
| 响应序列化 | 自动 JSON（Pydantic） | 手动 `jsonify()` | 自动 JSON（Pydantic） |
| 请求验证 | 自动（Pydantic v2） | 无内置，需 marshmallow | 自动（Pydantic） |
| 类型安全 | ✅ 原生 | ❌ 需扩展 | ✅ 原生 |
| 自动文档 | ✅ Swagger + ReDoc | ❌ 需 Flask-RESTX | ✅ Swagger |

**FastAPI 胜出**，Pydantic v2 与 Python 3.13 类型系统深度集成，自动验证 + 文档。

### 4.2 性能

| 维度 | FastAPI | Flask | Litestar |
|------|---------|-------|----------|
| 底层 | Starlette（ASGI） | Werkzeug（WSGI） | Starlette（ASGI） |
| 异步 | ✅ 原生 async | ⚠️ 2.0+ 有限支持 | ✅ 原生 async |
| 吞吐量 | ~20k req/s | ~5k req/s | ~20k req/s |
| 延迟 P50 | ~5ms | ~15ms | ~5ms |

**FastAPI / Litestar 同级胜出**。但当前项目为同步 IO，异步优势暂不明显。

### 4.3 静态文件服务

| 场景 | FastAPI | Flask | Litestar |
|------|---------|-------|----------|
| SPA 托管 | `StaticFiles(directory="...")` | `send_from_directory()` | `StaticFiles` |
| 一行代码 | ✅ `app.mount("/", SPAStaticFiles(...))` | ❌ 需手动路由 | ✅ `app.mount(...)` |
| 历史回退 | ✅ 内置 `index.html` fallback | ❌ 需手动实现 | ✅ 内置 |

### 4.4 学习成本

| 维度 | FastAPI | Flask | Litestar |
|------|---------|-------|----------|
| 上手时间 | 2-4 小时 | 1-2 小时 | 4-8 小时 |
| 核心概念 | 依赖注入、Pydantic | 蓝本、上下文 | DTO、依赖注入 |
| 进阶学习 | pytest + httpx | Flask 扩展体系 | Litestar 特有概念 |
| 文档质量 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |

### 4.5 社区与生态

| 维度 | FastAPI | Flask | Litestar |
|------|---------|-------|----------|
| GitHub Stars | ~85k | ~70k | ~5k |
| Stack Overflow 问题 | ~50k+ | ~500k+ | ~500+ |
| 第三方扩展 | 丰富（SQLModel、FastAPI Users） | 极丰富 | 有限 |
| 维护活跃度 | 高 | 高（核心作者参与度下降，由维护团队接手） | 中 |
| 长期前景 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |

### 4.6 与本项目的适配度

| 需求 | FastAPI | Flask | Litestar |
|------|---------|-------|----------|
| R1: 轻量级 | ✅ uvicorn 单进程 | ✅ 单进程 | ✅ uvicorn 单进程 |
| R2: 自动序列化 | ✅ Pydantic 原生 | ❌ 需 marshmallow | ✅ Pydantic |
| R3: 路由系统 | ✅ 装饰器 | ✅ 装饰器 | ✅ 装饰器 |
| R4: 静态文件 | ✅ mount | ✅ send_from | ✅ mount |
| R5: 低迁移成本 | ✅ 只替换 web.py + api/ | ✅ 只替换 web.py + api/ | ✅ 只替换 web.py + api/ |
| R6: Python 3.13 | ✅ | ✅ | ✅ |
| R7: 自动文档 | ✅ 开箱即用 | ❌ 需额外 | ✅ |
| R8: 异步 | ✅ 原生 | ⚠️ 有限 | ✅ 原生 |
| R9: 社区活跃 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| R10: 生态完整 | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |

---

## 5. 推荐排序

```
1st: FastAPI    ★★★★★  强烈推荐（9.5/10）
2nd: Flask      ★★★☆☆  有条件推荐（6.5/10）
3rd: Litestar   ★★★☆☆  有潜力但生态不足（6.0/10）
```

### 5.1 FastAPI 推荐理由

1. **解决核心痛点**：Pydantic 模型替代手动 `to_dict()` 和 `json.loads()`，这是当前最大的技术债务
2. **零业务侵入**：`web.py` + `api/` 是独立层，替换不影响 `engine/`、`core/`、`storage/`
3. **自动 OpenAPI**：免费获得交互式文档，前端对接效率提升 3-5 倍
4. **极轻部署**：`uvicorn app:app` 单命令启动
5. **Python 3.13 完美集成**：Pydantic v2 Rust 内核 + 3.13 类型系统
6. **社区保障**：85k stars，增长最快，长期维护无虞
7. **静态文件一行搞定**：`app.mount("/", SPAStaticFiles(...))` 替代 50 行 `_serve_static()`

### 5.2 Flask 评估

Flask 的极简学习曲线是优势，但缺少原生序列化/验证是硬伤。需要额外集成：
```python
# Flask 需要这些额外扩展才能达到 FastAPI Pydantic 的等效能力
Flask + Flask-Pydantic + marshmallow + flask-cors + Flask-RESTX
```
这些扩展的维护状态参差不齐，长期维护风险高于 FastAPI 的单一技术栈。

### 5.3 Litestar 评估

Litestar 设计理念与 FastAPI 类似（Pydantic + 类型注解），提供更丰富的 DTO 系统。但：
- 社区仅 5k stars，约为 FastAPI 的 1/17
- 第三方扩展稀缺
- 文档虽完整但示例不足
- 长期维护前景不明朗

---

## 6. 迁移成本估算

### 6.1 FastAPI 迁移范围

| 文件 | 操作 | 代码量 | 复杂度 |
|------|------|--------|--------|
| `web.py` | **重写** | 原生 6.4k → FastAPI ~200 行 | ⭐ |
| `api/_handlers.py` | **重写** | 8.3k → 6 个路由模块 ~1k 行 | ⭐⭐ |
| `api/__init__.py` | **删除** | 544 行 → 不必要 | ⭐ |
| `models.py` | **改为 Pydantic** | 定义 + 自动验证 | ⭐⭐ |
| `main.py` | **修改** | 入口整合 uvicorn | ⭐ |
| `manager.py` | **不动** | 业务逻辑不变 | — |
| `engine/*` | **不动** | 检测逻辑不变 | — |
| `core/*` | **不动** | 业务服务不变 | — |
| `storage/*` | **不动** | 数据层不变 | — |

### 6.2 接入 FastAPI 的核心改动示例

**当前代码** (`web.py`):
```python
class GuardHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        handler = _GET_ROUTES.get(self.path)
        if handler:
            result, status = handler(self.server.manager)
            self._send_json(status, dump_response(result))
        else:
            self._serve_static(self.path)
```

**FastAPI 代码** (`api/routes/health.py`):
```python
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api", tags=["health"])

class HealthResponse(BaseModel):
    status: str
    version: str
    uptime: float

@router.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(status="ok", version="0.2.1", uptime=...)
```

---

## 7. OpenClaw SDK 边界约束（改动需对照官方文档）

框架选型必须兼容以下 OpenClaw Plugin SDK 合约约束。这些约束**不是不能改**，而是每次改动前必须对照 [OpenClaw 官方文档](https://openclaw.ai/docs) 验证字段名、类型、行为。

### 7.1 受合约约束的 API 端点

| 端点 | 方法 | 约束 |
|------|------|------|
| `/api/hook/before-tool-call` | POST | 响应 JSON 中必须有 `action` / `title` / `message` / `severity` / `action_record` / `blockReason` 等字段，由 JS 插件的 `postJson` 解析逻辑决定 |
| `/api/hook/after-tool-call` | POST | 接收 `toolName` / `params` / `runId` / `toolCallId` 等字段的 POST body |
| `/api/hook/resolve-approval` | POST | 接收 `actionId` / `decision` 字段 |
| `/api/health` | GET | 健康检查端点，JS 插件熔断器依赖 |

这些端点的**字段名和嵌套结构**不能随意修改。FastAPI 的 Pydantic 模型可以直接约束字段名，确保不偏离 JS 插件预期。

### 7.2 认证协议

所有 `/api/hook/*` 端点必须支持 `x-openclaw-guard-token` header 鉴权。FastAPI 的 `Header()` 依赖注入可以天然支持。

---

## 8. 回退方案

如果 FastAPI 因某种原因不适用（如政策限制不允许 0.x 框架），备用方案：

```text
首选: FastAPI (0.115.x)    — 强烈推荐
备选: Flask 3.1 + Flask-Pydantic + marshmallow  — 功能等效但集成成本高
最终: 继续使用 stdlib 但引入 Pydantic 做序列化 — 不替换 HTTP 层
```

---

## 9. 推荐结论

**选定 FastAPI 为重构目标框架**。理由总结：
1. Pydantic v2 彻底解决当前手动序列化/验证的技术债务
2. 零侵入侵入现有业务逻辑层（engine/core/storage 不动）
3. 自动 OpenAPI 文档是锦上添花的长期收益
4. 社区 85k stars 保证长期可维护性
5. 迁移成本约 2-3 个工作日，收益可覆盖 2 年以上维护周期

> **⚠️ Python 3.13 兼容性提示**：项目目前要求 Python ≥3.13。FastAPI 0.115.x 依赖 Starlette + Pydantic v2，虽然这些库已声明 3.13 支持，但在开始阶段一之前，建议先在 Python 3.13 环境下运行 `pip install fastapi uvicorn && python -c "from fastapi import FastAPI; print('OK')"` 做一次快速烟雾测试，确认所有传递依赖可用。
