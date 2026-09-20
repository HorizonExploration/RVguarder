# 架构总览

Openclaw Guard 采用分层、非侵入、模块化设计，核心原则是：**不修改 OpenClaw 源码，不替换系统库，通过外部壳、本地插件和行为代理完成安全增强。**

## 当前分层结构

```text
1. 接入边界
   OpenClaw api.on(before_tool_call / after_tool_call)
   → Hook Bridge / BehaviorEvent
2. 语义理解与 Trace
   SemanticEnhancer
   → action / resource / scope / data / context / principal / identity
   → TraceCompiler / canonical operation
3. 规则知识库与权限模型（PMKB 1.2.0）
   PolicyEvaluator
   → 单步规则、覆盖状态、最小权限 Closure/Diff、RiskGraph 组合关系
4. 运行时验证（RV）
   ChainRule DSL 生成自动机
   → session-local window + principal-global capability state
5. 决策与审批
   PMKB / RV 结果合并（只升权不降权）
   → allow / requireApproval / block
6. 同步与取证
   OpenClaw 原生审批结果 → onResolution → SSE/增量对账 → SQLite/JSONL 审计
```

端到端的当前主链是：

```text
before_tool_call
  → 语义归一化与 Authorization Trace
  → PMKB 覆盖感知匹配
  → 权限闭包/差分与危险组合检查
  → RV preview（执行前纯回放）
  → 决策控制器
  → OpenClaw 唯一审批入口
  → resolution/SSE 只读同步
  → 成功 after_tool_call 提交 RV/主体证据与审计
```

本次升级的完整实现口径、数据文件和测试证据见
[权限知识库与 RV 运行时架构结果](./permission-kb-runtime-architecture.md)。PMKB 的案例规则明细见
[PMKB 网络案例基线](../semantic/pmkb-network-case-baseline.md)。

## 当前代码映射

- `main.py`：CLI 入口（`openclaw-guard run / baseline / doctor`），仅启动 FastAPI HTTP 层
- `services.py`：GuardServices 服务容器 + `build_services()` 工厂（冷路径组件经 LazyProxy 惰性加载）
- `engine/pipeline.py`：编排层（ingest_event / before_tool / after_tool 流水线）
- `integrations/discovery.py`：资产发现、运行环境探测
- `core/baseline_service.py`：基线扫描、报告生成、修复脚本
- `engine/behavior.py`：行为事件摄入
- `engine/whitelist.py`：Trie / Radix Tree 白名单匹配
- `engine/semantic_enhancer.py`：本地/LLM 语义标注，输出 `entities`、`labels`、`classification`、`purpose`、`confidence`
- `policy/`：版本化 PMKB bundle、`TraceCompiler`、规则评估、权限闭包/差分、危险组合图与冻结 LEGACY 回放数据
- `engine/control.py`：动作决策、审批状态流
- `rv/runtime_verification.py`：RV 运行时验证引擎（ChainRule DSL 生成自动机 + 滑动窗口，per-session 隔离）
- `rv/rv_dsl.py` + `rv/rv_rules.json`：ChainRule 声明式规约与编译监视器（唯一生产规则来源）
- `services.py`：主体级 RV 状态、策略引擎和持久化装配；主体键为 `principal_id + agent_id + capability_lineage`
- `core/audit_service.py`：SQLite + JSON 审计与哈希链
- `storage/db_store.py`：DBStore 接口族（SQLiteStore / PostgreSQLStore / SQLAlchemyStore，`DB_STORE_MODE=sqlalchemy` 启用 ORM 存储）
- `manager.py`：向后兼容子类（OpenclawGuardManager 继承 GuardServices，方法委托 `_*_impl`）
- `integrations/hook_runtime.py`：生成并安装 OpenClaw Guard 本地 Hook 插件（使用官方 `api.on()` API）
- `integrations/tool_hook_bridge.py`：把 `before_tool_call` / `after_tool_call` 转成 Guard 行为事件
- `integrations/openclaw_adapter.py`：OpenClaw Gateway 状态探测适配层；Hook 审批结果由原生 `onResolution` 回调同步到 Guard
- `web/` / `ui.py`：本地 Web 工作台 API 与前端资源管理（FastAPI 为唯一入口；`api/` 为共享 HTTP 处理函数边界层）

## 关键设计原则

1. **非侵入**：不改 OpenClaw 原始代码。
2. **先决策，后执行**：高风险动作必须先进入 action gate，工具执行前由 `before_tool_call` 拦截。
3. **可取证**：所有关键动作留痕，并可导出。
4. **可扩展**：规则、白名单、扫描项都可以继续增长。
