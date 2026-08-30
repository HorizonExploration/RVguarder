# 发展路线图 · Roadmap

当前版本：**v0.7.0-dev** — PMKB 权限模型、覆盖感知匹配、最小权限闭包/差分、风险组合图、主体能力跨 session RV 和 OpenClaw 单一审批契约已实现。PMKB `1.1.0` 基础规则立即参与运行时决策；新规则采用离线回放与有限事件样本校验，个人模式不依赖长时间留存记录。

---

## ✅ 已完成 · Completed

| 里程碑 | 版本 | 内容 |
|--------|------|------|
| 语义理解增强 | v0.2.0 | SemanticEnhancer（DeepSeek LLM + 本地规则），7 维度标签体系，检测引擎语义优先模式 |
| 办公场景规则 | v0.2.0 | 5 条办公安全策略（邮件、日报、附件），47+ 语义规则 |
| 原生钩子拦截 | v0.2.1 | `api.on("before_tool_call")`，`requireApproval` 物理挂起，对齐官方 SDK 规范 |
| 审批结果同步 | v0.6.0 | OpenClaw 原生审批唯一入口，`onResolution` 回调 + SSE/增量查询更新 Guard Dashboard |
| 电路熔断器 | v0.2.1 | 优雅期 → 熔断 OPEN（fail-open）→ 恢复 CLOSED 三态自动切换 |
| RV 运行时验证 | v0.2.1 | 6 个 FSM 监视器（Mail/Report/Chain/Broadcast/DataExport/BatchFile），滑动窗口 10 步 |
| 前端 RV 面板 | v0.2.1 | Trace 时间线、RV 状态面板、RV 模式开关 |
| **FastAPI HTTP 层** | **v0.3.0** | `web/` 包替代 stdlib `http.server`，`--fastapi` flag 选择加入，统一异常处理 |
| **Pydantic v2 模型** | **v0.3.0** | models.py 全部迁移至 BaseModel，自动验证 + 序列化，`to_dict()` 兼容别名 |
| **旧版 HTTP 层保留** | **v0.3.0** | `legacy_web.py` 为默认 HTTP 服务，与 FastAPI 双轨并行 |
| **SQLAlchemyStore 可选存储** | **v0.3.0** | `storage/db_store.py` 内嵌 SQLAlchemyStore，`DB_STORE_MODE=sqlalchemy` 启用 ORM 存储 |
| **RV 规约驱动** | **v0.3.0** | ChainRule DSL（`rv/rv_dsl.py` + `rv_rules.json`）编译监视器，默认 dsl 模式，FSM 为回退 |
| **IR 结构化透传** | **v0.4.0** | ToolCallIR（11 字段）+ 语义层实体/约束/置信度透传，约束推理引擎（五类约束 + 加权评分 + 置信度门控），10 条高频规则已迁移（渐进） |
| **基线自动机 + 参数化** | **v0.5.0** | BaselineLearner 偏离检测 + QEA 式 bind_vars + 实体守卫 + 时间原语 + 状态计数器 |
| **NL2Spec + 干预闭环** | **v0.6.0** | Nl2SpecGenerator + SpecValidator 反例验证 + revise 干预 + SessionSafetyState 会话追踪 |
| **PMKB 权限模型与跨 session RV** | **v0.7.0-dev** | PMKB 1.1.0（23 operations / 27 authored rules + 47 compatibility rules / 25 traces / 9 relations）、Authorization Trace、最小权限闭包/差分、RiskGraph、主体级状态持久化和 OpenClaw 单一审批契约 |

---

## 🔜 下一步规划

### P0（当前迭代优先）

- [x] **会话级作用域**（已完成）：RV 引擎按 `session_id` 隔离，不同 Agent 会话使用独立的滑动窗口和 FSM 状态（`rv/runtime_verification.py` `_session_windows`）
- [x] **RV 引擎持久化**：主体/能力状态在 `runtime/rv-state.json` 恢复后再处理新 Hook，窗口状态仍按 session 隔离
- [ ] **熔断器告警**：熔断状态变更时通过 Webhook 或邮件通知运维

### P1（下一阶段）

- [ ] **用户自定义规则**：支持通过 `policies/` 配置结构化安全规则（JSON DSL）
- [ ] **规则受控更新**：支持离线回放、有限事件样本和可回滚的版本晋级（不设置自然日 shadow gate）
- [ ] **日志自动归档与轮转**：防止审计日志无限增长
- [ ] **更细粒度 API 健康检查**：区分后端、Gateway、LLM 三类健康状态

### P2（后续扩展）

- [ ] **VuePress 文档站 CI**：自动构建与部署
- [ ] **暗色模式与多端适配**：前端主题切换
- [ ] **运维策略模板**：更多预设安全策略模板
- [ ] **长期稳定性压测**：72 小时连续运行验证

---

## 已知边界

- 当前拦截范围是经过 `before_tool_call` 的工具路径，内部运行路径仍需补充覆盖
- Hook 插件注入后需要重启 OpenClaw Gateway 才能生效
- RV 的窗口大小（默认 10 步）在不同办公场景下可能需要动态调整
- `feishu_doc`/`feishu_wiki` 等频道工具在 Dashboard（WebChat）环境下不可见

## PMKB 发布门禁、指标与回滚

当前 `1.1.0` 基础 bundle 已直接接入运行时；高风险阻断、普通审批和明确低风险自动放行立即生效。
新规则或用户化偏好先通过离线规则/攻击向量回放，再进行最多 20 条相关事件的有限样本校验；个人模式也可通过一次显式确认立即启用范围受限的偏好。用户偏好不能降低既有安全下限。

以下指标用于新规则晋级、自动放行范围扩大和回滚判断，而不是基础 PMKB 的生效前置条件：

| 指标 | 目标 |
|---|---:|
| complete coverage（P0） | ≥85% |
| unknown rate | ≤10% |
| low-risk auto-allow precision | ≥99% |
| high-risk recall | ≥98% |
| total manual approvals | −40% |
| low-risk approvals | −60% |
| local evaluator P95 | ≤50 ms |

每个 outcome 都要带 `policy_version`、effect、匹配状态、证据字段和 timing；按事件计数进行比较，不设置自然日等待门槛。若发生 hard-risk false negative、bundle validation error 或 principal-state
merge anomaly，立即 disable 新 bundle version，rollback 到 previous catalog，并保留全部
audit records 供调查；修复后重新执行离线回放与有限样本校验。
