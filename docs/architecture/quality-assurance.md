# 质量保障方案

> **核对日期：** 2026-08-28
> **适用版本：** v0.7.0-dev（PMKB 1.1.0、RV 阶段 A–F）
> **文档性质：** 当前测试门禁与目标指标；历史重构过程见 [`archive/architecture/`](../archive/architecture/)。

当前可执行事实以仓库 `tests/`、`frontend/` 和 `docs` 构建输出为准。本方案中的“目标”是尚未完成的工程门禁，不应被误读为已实现能力。

---

## 1. 质量目标

| 维度 | 当前水平 | 重构目标 | 衡量方式 |
|------|---------|---------|---------|
| 启动速度 | 3-5 秒 | ≤ 2 秒 | `time openclaw-guard run` |
| 摘要接口 | > 50ms（聚合全部模块） | ≤ 10ms | ab / wrk 基准测试 |
| 热路径延迟 | ~25ms（本地模式） | ≤ 30ms | 基准测试 |
| API 可用性 | 无定义 | ≥99.9% | 健康检查通过率 |
| 代码覆盖率 | 未知 | ≥75% | pytest-cov |
| 错误处理 | 分散 | 统一规范 | 异常处理覆盖率 |
| 类型安全 | 无 | 100% mypy pass | mypy --strict |
| 前端首屏 | > 50KB JS | ≤ 20KB gzip | Vite 构建分析 |

---

## 2. 测试策略

### 2.1 测试金字塔

```
      ┌──────────┐
      │  E2E      │  ← Playwright（前端 + 完整链路，约 5%）
     ┌┴──────────┴┐
     │ 集成测试    │  ← HTTPX + FastAPI TestClient（API 端点 + 流水线，约 15%）
    ┌┴────────────┴┐
    │  单元测试     │  ← pytest（engine/core/storage，约 80%）
    └──────────────┘
```

### 2.2 测试工具链

```bash
# 单元测试
pytest tests/ -v --cov=openclaw_guard --cov-report=term-missing

# API 集成测试（FastAPI TestClient）
pytest tests/test_api/ -v

# E2E 测试
cd e2e && npx playwright test

# 类型检查
mypy openclaw_guard/ --strict

# 代码格式/质量
ruff check openclaw_guard/
ruff format --check openclaw_guard/
```

### 2.3 测试目录结构（目标）

```
tests/
├── conftest.py                  # pytest fixtures + services 工厂
├── test_engine/
│   ├── test_detection.py        # 规则引擎测试
│   ├── test_semantic.py         # 语义增强测试
│   ├── test_rv.py               # RV 引擎测试
│   ├── test_rv_fsm.py           # FSM 监视器测试
│   └── test_whitelist.py        # 白名单测试
├── test_core/
│   ├── test_action_service.py   # 动作服务测试
│   ├── test_audit_service.py    # 审计服务测试
│   └── test_baseline_service.py # 基线服务测试
├── test_api/
│   ├── test_health.py           # 健康检查端点测试
│   ├── test_hook.py             # Hook 桥接端点测试
│   ├── test_actions.py          # 动作审批端点测试
│   ├── test_audit.py            # 审计端点测试
│   └── test_rv_api.py           # RV 状态端点测试
├── test_storage/
│   ├── test_sqlite_store.py     # SQLite 存储测试
│   └── test_audit_store.py      # 审计存储测试
└── test_integration/
    └── test_before_tool_call.py # 完整流水线集成测试
```

---

## 3. API 测试策略

### 3.1 每个端点需覆盖的测试用例

```python
# 以 before_tool_call 为例

async def test_before_tool_call_allow(client, services):
    """工具调用被允许"""
    response = await client.post("/api/hook/before-tool-call", json={
        "toolName": "read",
        "params": {"path": "/tmp/README.md"},
    }, headers={"x-openclaw-guard-token": "test-token"})
    assert response.status_code == 200
    data = response.json()
    assert data["action"] == "allow"

async def test_before_tool_call_block(client, services):
    """高危命令被阻断"""
    response = await client.post("/api/hook/before-tool-call", json={
        "toolName": "exec",
        "params": {"command": "rm -rf /"},
    }, headers={"x-openclaw-guard-token": "test-token"})
    assert response.status_code == 200
    data = response.json()
    assert data["action"] == "block"

async def test_before_tool_call_no_token(client, services):
    """缺少鉴权 Token 返回 403"""
    response = await client.post("/api/hook/before-tool-call", json={
        "toolName": "read",
        "params": {"path": "/tmp/README.md"},
    })
    assert response.status_code == 403

async def test_before_tool_call_invalid_body(client, services):
    """请求体字段类型错误"""
    response = await client.post("/api/hook/before-tool-call", json={
        "toolName": 123,  # 应为字符串
    }, headers={"x-openclaw-guard-token": "test-token"})
    assert response.status_code == 422
```

### 3.2 合约测试（Contract Testing）

OpenClaw Plugin SDK 定义的 API 合约是红线，必须有专门的测试保障：

```python
async def test_hook_contract_before_tool_call(client, services):
    """验证 /api/hook/before-tool-call 响应格式符合 JS 插件预期"""
    response = await client.post("/api/hook/before-tool-call", json={
        "toolName": "read",
        "params": {"path": "/safe/path"},
    }, headers={"x-openclaw-guard-token": "test-token"})
    assert response.status_code == 200
    data = response.json()
    # JS 插件 postJson 解析依赖以下字段
    assert "action" in data
    assert data["action"] in ("allow", "require_approval", "block")
    if data["action"] == "allow":
        pass  # 无额外要求
    if data["action"] == "require_approval":
        assert "title" in data       # JS 渲染审批卡片标题
        assert "message" in data     # JS 渲染审批卡片描述
        assert "severity" in data    # JS 决定卡片颜色
        assert "action_record" in data  # JS 解析动作记录用于状态同步
    if data["action"] == "block":
        assert "blockReason" in data  # JS 展示阻断理由

async def test_hook_contract_after_tool_call(client, services):
    """验证 /api/hook/after-tool-call 响应格式符合 JS 插件预期"""
    response = await client.post("/api/hook/after-tool-call", json={
        "toolName": "read",
        "params": {"path": "/safe/path"},
        "runId": "test-run-1",
        "toolCallId": "test-call-1",
    }, headers={"x-openclaw-guard-token": "test-token"})
    assert response.status_code == 200
    data = response.json()
    # after-tool-call 返回审计确认
    assert "ok" in data

async def test_hook_contract_resolve_approval(client, services):
    """验证 /api/hook/resolve-approval 请求/响应格式符合 JS 插件 onResolution 预期"""
    response = await client.post("/api/hook/resolve-approval", json={
        "actionId": "test-action-id",
        "decision": "approved",
    }, headers={"x-openclaw-guard-token": "test-token"})
    assert response.status_code == 200
    data = response.json()
    assert "status" in data  # JS 插件解析审批结果状态
```

### 3.3 测试前置条件

```python
# conftest.py

@pytest.fixture
async def services():
    """创建测试用的服务容器（所有组件使用 mock/store）"""
    context = AppContext(...)
    db = SQLiteStore(":memory:")  # 内存数据库
    svc = build_services(context, db)
    yield svc
    svc.shutdown()

@pytest.fixture
async def client(services):
    """FastAPI TestClient"""
    from openclaw_guard.web import create_app
    app = create_app(services)
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

---

## 4. 回归测试策略

### 4.1 重构验证矩阵

每个阶段完成后，运行以下回归测试：

| 阶段 | 单元测试 | API 测试 | E2E 测试 | 手动验证 |
|------|---------|---------|---------|---------|
| 一：HTTP 层 | ✅ | ✅ 23 个端点 | ✅ | curl + 前端 |
| 二：Pydantic | ✅ | ✅ | — | 数据结构校验 |
| 三：Manager | ✅ | ✅ 流水线 | ✅ | 功能一致 |
| 四：前端 | ✅ | ✅ | ✅ | UI 关键路径 |
| 五：存储（SQLAlchemy） | ✅（native/sqlalchemy） | ✅（关键端点） | — | 数据一致性与降级 |
| 六：RV 规约驱动（ChainRule） | ✅（dsl/fsm） | ✅（rv_status/rv_toggle） | ✅（前端联动） | 规则输出对比 |

### 4.2 并行运行验证

新旧系统可并行运行在不同端口，对比响应：

```bash
# 旧系统端口 8780
python -m openclaw_guard.main run --port 8780

# 新系统端口 8781
python -m openclaw_guard.main run --fastapi --port 8781

# 对比脚本
for endpoint in health actions audit rv baseline; do
    old=$(curl -s http://localhost:8780/api/$endpoint | jq .)
    new=$(curl -s http://localhost:8781/api/$endpoint | jq .)
    diff <(echo "$old") <(echo "$new") && echo "✅ $endpoint" || echo "❌ $endpoint"
done
```

---

### 4.3 关键回归用例（已发生）

以下用例来自近期一次真实回归：`/api/*` 请求被 SPA 静态 `index.html` 覆盖，导致前端解析 JSON 失败并表现为“无法连接/未连接”。

```bash
# /api 端点必须返回 JSON（且带 query 也不能失效）
curl -i "http://127.0.0.1:8780/api/health?ts=1"
curl -i "http://127.0.0.1:8780/api/summary?ts=1"

# 断言要点：
# - HTTP 200
# - Content-Type 包含 application/json
# - body 可被 jq 正常解析
```

建议补充到测试套件的最小断言（legacy 与 fastapi 都应覆盖）：

```python
def assert_json_response(resp):
    assert resp.status_code == 200
    assert "application/json" in resp.headers.get("content-type", "")
    resp.json()
```

同时建议固定一个“依赖可选性”门禁：在未安装 fastapi/uvicorn 的环境中，仍可正常运行 legacy 模式并通过测试收集（避免 import-time 失败）。

---

### 4.5 阶段五/六回归用例（新增）

以下用例用于保障“存储层升级（阶段五）”与“RV 规约驱动（阶段六）”的回归门禁，确保默认行为不变、开关可控、矩阵覆盖完整。

#### 4.5.1 存储后端切换（native ↔ sqlalchemy）

目标：验证 `DB_STORE_MODE` / `OPENCLAW_GUARD_DB_STORE_MODE` 对存储实现的选择生效，且默认仍为 native。

- 用例 A：默认（不设置 `DB_STORE_MODE`）启动并可写入审计
  - 断言：服务可启动；产生审计记录；`/api/audit/export` 导出成功
- 用例 B：`DB_STORE_MODE=native` 明确指定 native
  - 断言：后端为 SQLiteStore/PostgreSQLStore 之一（取决于 `DATABASE_URL`）；关键端点输出正常
- 用例 C：`DB_STORE_MODE=sqlalchemy` 且安装了 sqlalchemy
  - 断言：后端为 SQLAlchemyStore；关键端点输出正常
- 用例 D：`DB_STORE_MODE=sqlalchemy` 但未安装 sqlalchemy（降级/报错策略）
  - 断言：默认模式仍可运行；仅在实际启用 sqlalchemy 模式时返回可读错误信息（避免 import-time 崩溃）

对应测试（建议作为门禁最小集合）：

- `tests/test_sqlalchemy_store.py`（SQLAlchemyStore 单测）
- `tests/test_integration_storage_rv_matrix.py`（native/sqlalchemy × RV 模式矩阵）

#### 4.5.2 RV 模式切换与规则模式切换（dsl ↔ fsm）

目标：验证 RV 引擎在“规约驱动（dsl）/手写 FSM（fsm）”之间可切换，且 API 输出兼容、前端联动不回归。

- 用例 A：`OPENCLAW_RV_RULE_MODE=dsl|fsm` 环境变量生效
  - 断言：`/api/rv/status` 的 `engine.rule_mode` 与预期一致
- 用例 B：`/api/rv/toggle` 支持新字段 `rule_mode`
  - 请求：`{"enabled": true, "rule_mode": "dsl"}` 或 `{"enabled": true, "rule_mode": "fsm"}`
  - 断言：返回包含 `rv_mode` 与 `rule_mode`；`/api/rv/status` 同步体现切换结果
- 用例 C：`/api/rv/toggle` 的开关持久化
  - 断言：写入 `preferences.json` 后重启仍生效；summary 中 `rv.mode` 与切换一致
- 用例 D：前端契约不变（UI 能显示状态、切换模式不报错）
  - 断言：前端使用的字段（`ok/mode/engine/window_size/monitor_count` 等）保持存在并符合类型预期

对应测试（建议作为门禁最小集合）：

- `tests/test_rv_dsl.py`（DSL 编译/执行单测）
- `tests/test_rv_fsm.py`（FSM 监视器单测）
- `tests/test_rv_frontend_integration.py`（rv_status/rv_toggle/summary 全流程）
- `tests/test_integration_storage_rv_matrix.py`（切换 `rule_mode` 的 API 断言）

#### 4.6 PMKB、语义命中与权限组合回归（当前门禁）

本次升级增加了“语义输入 → Authorization Trace → PMKB → RV”的专门回归，而不是只断言最终
`allow/block`。最小矩阵如下：

| 层 | 必测断言 | 当前证据 |
|---|---|---|
| bundle | schema、版本、源码/打包目录 parity | `tests/test_policy_catalog.py`、`tests/test_pmkb_network_baseline.py` |
| 语义/Trace | canonical operation、实体、缺失特征和 coverage gap | `tests/test_authorization_trace.py`、`tests/test_pmkb_network_baseline.py` |
| 单步规则 | `matched/partial/unknown/conflict`、评分和风险效果 | `tests/test_policy_evaluator.py` |
| 最小权限 | closure、requested delta、冗余/越界和 scope expansion | `tests/test_permission_diff.py` |
| 组合关系 | 4 类高危组合与 evidence lineage | `tests/test_permission_risk_graph.py` |
| 集成决策 | PMKB 与 Detection/Constraint/RV 只升权合并、OpenClaw 单一审批 | `tests/test_policy_pipeline.py`、`tests/test_principal_rv_hook_integration.py` |
| 跨 session | principal 键、TTL、持久化恢复和 session 隔离 | `tests/test_principal_capability_rv.py` |
| 文档合同 | 当前架构和 README 不回退到旧版本/旧审批口径 | `tests/test_policy_docs.py` |

当前全量基线为 `490 passed / 18 skipped / 4 subtests passed`；覆盖率、人工审批下降比例和命中率目标
仍需用真实事件或离线回放另行测量，不把目标指标写成已经达成的结果。

### 4.4 回退测试

每阶段完成后，必须运行一次全量 pytest 回归，确保无功能退化：

```bash
# 每阶段完成后的标准回归命令
python -m pytest -q 2>&1 | tee phase-N-regression.log

# 与基线（重构前）对比
diff <(grep -E "^(OK|FAILED|ERROR)" baseline-regression.log) \
     <(grep -E "^(OK|FAILED|ERROR)" phase-N-regression.log)
```

新旧 HTTP 层并行运行时（历史策略见 `docs/archive/architecture/refactoring-plan.md §11.2`），还应执行端点对比验证。

---

## 5. 代码质量门禁

### 5.1 CI 门禁清单

| 检查项 | 工具 | 门禁标准 |
|--------|------|---------|
| 单元测试 | pytest | 100% 通过 |
| 代码覆盖率 | pytest-cov | ≥75% |
| 类型检查 | mypy --strict | 0 错误 |
| 代码格式 | ruff format --check | 0 差异 |
| 代码质量 | ruff check | 0 告警 |

### 5.2 CI 配置（参考）

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - run: pip install -e ".[test]"
      - run: ruff check openclaw_guard/
      - run: ruff format --check openclaw_guard/
      - run: mypy openclaw_guard/ --strict
      - run: pytest tests/ -v --cov=openclaw_guard --cov-fail-under=75
```

---

## 6. 性能基准

### 6.1 基准测试

```bash
# 使用 locust 或 wrk
wrk -t4 -c20 -d30s http://localhost:8780/api/health

# 关键指标
# P50 latency < 5ms
# P95 latency < 30ms
# Throughput > 500 req/s
```

**RV 热路径冒烟基准**（`tests/test_perf_smoke.py`，已纳入全量回归）：

| 组件 | 实测延迟（本机） | 冒烟阈值 |
|------|----------------|----------|
| 约束引擎 `evaluate_steps()`（20 步 IR） | 0.07 ms/次 | < 50 ms |
| RV 引擎 `evaluate()`（链式外发 6 步） | 0.08 ms/次 | < 50 ms |
| 会话状态 `record()`（1000 次） | 0.75 ms | < 200 ms |

阈值刻意宽松（10 倍余量）防 CI 抖动误报，超阈值说明明显性能劣化需人工复核。项目硬约束：detection < 1ms、rv < 5ms、摘要接口 ≤ 10ms。

### 6.2 性能回归门禁

CI 中设置性能回归门禁，新代码导致 P95 延迟增加超过 20% 时 CI 失败。

### 6.3 熔断器测试

在集成测试中覆盖熔断器状态转换：

```python
async def test_circuit_breaker_open(client, monkeypatch):
    """后端不可达时熔断器自动打开"""
    monkeypatch.setattr("httpx.AsyncClient.post", lambda *a, **kw: raise_(ConnectionError()))
    for _ in range(4):  # 连续 4 次失败触发熔断
        await client.post("/api/hook/before-tool-call", ...)
    # 熔断后自动放行
    response = await client.post("/api/hook/before-tool-call", ...)
    assert response.json()["action"] == "allow"
```

---

## 7. 监控与可观测性

### 7.1 结构化日志

```python
# 目标日志格式（JSON Lines）
{"level": "INFO", "event": "before_tool_call", "tool": "read",
 "duration_ms": 12.3, "decision": "allow", "request_id": "uuid"}
{"level": "WARN", "event": "circuit_open", "reason": "backend unreachable",
 "consecutive_fails": 3}
```

### 7.2 metrics 暴露（预留）

```
# GET /api/metrics (v1.0 后)
guard_requests_total{endpoint="before_tool_call",decision="block"} 42
guard_rv_verdicts{monitor="MailMonitor",verdict="block"} 7
guard_circuit_breaker_state{state="open"} 0
```
