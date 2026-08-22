# 发展路线图 · Roadmap

当前版本：**v0.6.0** — FastAPI HTTP 层就绪，Pydantic v2 模型迁移完成，RV 阶段 A–F（IR 结构化 / 约束推理 / 基线自动机 / 参数化原语 / NL2Spec / 干预升级）全部落地。全量测试 344 passed / 18 skipped。

---

## ✅ 已完成 · Completed

| 里程碑 | 版本 | 内容 |
|--------|------|------|
| 语义理解增强 | v0.2.0 | SemanticEnhancer（DeepSeek LLM + 本地规则），7 维度标签体系，检测引擎语义优先模式 |
| 办公场景规则 | v0.2.0 | 5 条办公安全策略（邮件、日报、附件），47+ 语义规则 |
| 原生钩子拦截 | v0.2.1 | `api.on("before_tool_call")`，`requireApproval` 物理挂起，对齐官方 SDK 规范 |
| 双端状态同步 | v0.2.1 | `onResolution` 回调 + Gateway 远程调用，Dashboard ↔ OpenClaw 双向 Push |
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

---

## 🔜 下一步规划

### P0（当前迭代优先）

- [x] **会话级作用域**（已完成）：RV 引擎按 `session_id` 隔离，不同 Agent 会话使用独立的滑动窗口和 FSM 状态（`rv/runtime_verification.py` `_session_windows`）
- [ ] **RV 引擎持久化**：允许跨 Guard 重启保留 RV 窗口状态 —— 引擎已实现 `serialize_state` / `deserialize_state`（`rv/runtime_verification.py`），尚未接线到持久化
- [ ] **熔断器告警**：熔断状态变更时通过 Webhook 或邮件通知运维

### P1（下一阶段）

- [ ] **用户自定义规则**：支持通过 `policies/` 配置结构化安全规则（JSON DSL）
- [ ] **规则灰度更新**：支持规则 A/B 测试和逐步上线
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
