# 架构总览

Openclaw Guard 采用分层、非侵入、模块化设计，核心原则是：**不修改 OpenClaw 源码，不替换系统库，通过外部壳、本地插件和行为代理完成安全增强。**

## 分层结构

```text
管理层
  ├─ Web 工作台
  ├─ 报告与导出
  └─ 配置与操作入口

管控层
  ├─ 白名单
  ├─ 审批流
  ├─ allow / ask / block / escalate
  └─ 二次确认

检测层
  ├─ 高危规则引擎
  ├─ 风险分级
  └─ 规则命中追踪

监控层
  ├─ 资产发现
  ├─ 基线扫描
  ├─ 行为采集
  └─ ptrace / eBPF / Hook Bridge / OpenClaw 原生 Hook
```

## 当前代码映射

- `main.py`：CLI 入口（`openclaw-guard run / baseline / doctor`），`--fastapi` flag 切换 HTTP 层（缺失依赖时自动回退 legacy）
- `services.py`：GuardServices 服务容器 + `build_services()` 工厂（冷路径组件经 LazyProxy 惰性加载）
- `engine/pipeline.py`：编排层（ingest_event / before_tool / after_tool 流水线）
- `integrations/discovery.py`：资产发现、运行环境探测
- `core/baseline_service.py`：基线扫描、报告生成、修复脚本
- `engine/behavior.py`：行为事件摄入
- `engine/detection.py`：内置安全规则与检测引擎
- `engine/whitelist.py`：Trie / Radix Tree 白名单匹配
- `engine/control.py`：动作决策、审批状态流
- `rv/runtime_verification.py`：RV 运行时验证引擎（规约驱动 DSL（默认）+ FSM 回退 + 滑动窗口，per-session 隔离，支持状态序列化）
- `rv/rv_dsl.py` + `rv/rv_rules.json`：ChainRule 声明式规约与编译监视器（`OPENCLAW_RV_RULE_MODE=dsl` 为默认模式）
- `rv/rv_monitors.py`：手写 FSM 监视器（规约模式关闭时的回退实现）
- `engine/semantic_enhancer.py`：语义分析与上下文标注 (DeepSeek 驱动)
- `core/audit_service.py`：SQLite + JSON 审计与哈希链
- `storage/db_store.py`：DBStore 接口族（SQLiteStore / PostgreSQLStore / SQLAlchemyStore，`DB_STORE_MODE=sqlalchemy` 启用 ORM 存储）
- `manager.py`：向后兼容子类（OpenclawGuardManager 继承 GuardServices，方法委托 `_*_impl`）
- `integrations/hook_runtime.py`：生成并安装 OpenClaw Guard 本地 Hook 插件（使用官方 `api.on()` API）
- `integrations/tool_hook_bridge.py`：把 `before_tool_call` / `after_tool_call` 转成 Guard 行为事件
- `integrations/openclaw_adapter.py`：Gateway 远程调用适配层（含 `resolve_plugin_approval` 双端同步）
- `web/` / `legacy_web.py` / `ui.py`：本地 Web 工作台 API 与前端资源管理（`--fastapi` 启用 FastAPI 层，默认回退 legacy_web；`api/` 为共享 HTTP 处理函数边界层）

## 关键设计原则

1. **非侵入**：不改 OpenClaw 原始代码。
2. **先决策，后执行**：高风险动作必须先进入 action gate，工具执行前由 `before_tool_call` 拦截。
3. **可取证**：所有关键动作留痕，并可导出。
4. **可扩展**：规则、白名单、扫描项都可以继续增长。
