# OpenClaw-RVGuarder 当前测试设计

> **状态：现行回归合同（2026-09-03）**
>
> 旧版大规模场景设计保留在 `docs/archive/test-design/openclaw-guard-test-design-legacy.md`。
> 可执行事实以仓库 `tests/` 和 CI 命令为准。

## 测试分层

| 层级 | 关注点 | 主要入口 |
| --- | --- | --- |
| 单元 | 语义、命令安全、PMKB、权限差分与自动机 | `tests/test_semantic_enhancer.py`、`test_policy_*.py`、`test_rv*.py`、`test_three_state_control.py` |
| 流水线 | `before_tool_call` / `after_tool_call`、动作状态和审计 | `tests/test_pipeline.py`、`test_hook_runtime.py`、`test_action_service.py` |
| 交接合同 | OpenClaw 原生审批、回调幂等、SSE/序号同步和超时 | `tests/test_approval_sync.py`、`test_openclaw_adapter.py`、`test_frontend_*.py` |
| 兼容回放 | `LEGACY-*` 与 PMKB 判定一致性、版本和 bundle 完整性 | `tests/test_legacy_policy_migration.py`、`test_pmkb_*.py` |
| 实验 | AgentDojo 与历史 RV 必要性/干扰证据 | `testlab/`；不作为每次提交门禁 |

## 当前控制合同

- 外部 Hook 响应只使用 `allow`、`ask`（映射 OpenClaw `requireApproval`）和 `block`。
- 内部 RV 可以产生 `escalate`，但只用于升权，最终仍折叠为 OpenClaw 审批；不创建 Guard 第二审批源。
- 生产插件不注册 `before_prompt_build`；`before_tool_call` 是唯一执行前门禁。
- OpenClaw 是唯一审批中心。Guard 页面通过 action 状态、resolution 回调和 SSE 只读展示；回调重复或乱序必须保持幂等。
- unknown/partial/conflict、缺失主体或越界资源不能静默变成 allow；低风险只读动作可在规则完整时自动放行并审计。

## 必须覆盖的场景

1. 原生工具映射：`sessions_*`、`session_status`、`memory_*`、`agents_list`、`get_goal` 等只读族，
   以及 `sessions_send`、`sessions_spawn`、计划/目标写入等升权族。
2. 危险组合：敏感数据读取后外发、破坏性命令、特权命令、密钥访问后外部网络连接。
3. RV 隔离：同一 session 的链式风险、不同 session 不互相污染，以及主体 lineage 跨 session 的聚合。
4. 交接异常：OpenClaw 审批延迟、重复 resolution、回调不可达、动作超时和历史
   `before_prompt_build` 预检查迁移。
5. 构建与发布：Python 编译、前端 Vite 构建、VuePress 构建、文档本地链接和 diff 空白检查。

## 验证命令

```bash
python -m pytest -q
python -m compileall -q openclaw_guard
git diff --check
cd frontend && npm run build
cd ../docs && npm run docs:build
```

实验重跑需单独审批环境和凭据；默认不运行大规模 AgentDojo，也不把运行时目录、
`.env` 或历史结果作为清理对象。
