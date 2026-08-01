# 质量保障方案

> 版本：v0.2.1 | 日期：2026-07-30 | 作者：架构评审组

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
        assert "action_record" in data  # JS 解析动作记录用于双端同步
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
| 四：存储 | ✅ | ✅ | — | 数据一致性 |
| 五：RV 规约 | ✅ | — | — | 规则输出对比 |

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

### 4.3 回退测试

每阶段完成后，必须在旧测试套件（unittest）上运行一次全量回归，确保无功能退化：

```bash
# 每阶段完成后的标准回归命令
python -m unittest discover -s tests -v  2>&1 | tee phase-N-regression.log

# 与基线（重构前）对比
diff <(grep -E "^(OK|FAILED|ERROR)" baseline-regression.log) \
     <(grep -E "^(OK|FAILED|ERROR)" phase-N-regression.log)
```

新旧 HTTP 层并行运行时（见 [refactoring-plan.md §11.2](./refactoring-plan.md#112-并行运行策略)），还应执行端点对比验证。

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
