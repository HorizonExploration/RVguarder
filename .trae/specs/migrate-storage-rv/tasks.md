# Tasks
- [x] Task 1: 阶段五（存储层）现状盘点与接口对齐
  - [x] 梳理 `DBStoreInterface` 当前被哪些模块调用、最小必需方法集是什么
  - [x] 明确 SQLAlchemyStore 的覆盖范围（SQLite 优先，Postgres 兼容策略）
  - [x] 明确配置入口（配置项/CLI 参数）与默认行为（不改默认）

- [x] Task 2: 引入 SQLAlchemyStore（可选依赖、可降级）
  - [x] 在 `storage/` 中新增 SQLAlchemyStore，实现与现有抽象一致的读写接口
  - [x] `get_db_store()` 工厂支持选择 sqlalchemy 模式（缺依赖给出可读错误，不 import-time 崩溃）
  - [x] 保持启动策略：连接/迁移不进入热路径（必要时 LazyProxy）

- [x] Task 3: 存储迁移与数据一致性策略
  - [x] 设计并实现最小迁移/初始化策略（表结构创建、版本标识、向后兼容）
  - [x] 补充“旧数据→新后端”的迁移路径（若需要，提供一次性命令或自动迁移开关）

- [x] Task 4: 阶段六（RV）ChainRule DSL 设计与落地
  - [x] 定义 ChainRule/StepRequirement 的最小数据结构（字段、匹配语义、窗口语义）
  - [x] 新增规则文件作为唯一可变入口（默认包含当前 6 个监视器的等价规则）
  - [x] 实现规则编译器：规则 → 可执行监视器（或等价的状态推进器）

- [x] Task 5: RV 引擎集成与回退开关
  - [x] RuntimeVerificationEngine 集成编译后的监视器
  - [x] 提供回退开关（配置/环境变量/运行时 toggle）在“手写 FSM”与“规约驱动”间切换
  - [x] 保持 `/api/rv/status`、`/api/rv/toggle` 的兼容输出

- [x] Task 6: 测试与回归门禁（覆盖阶段五/六）
  - [x] SQLAlchemyStore 单元测试（CRUD、查询、边界条件、缺依赖降级）
  - [x] ChainRule 编译与执行单元测试（确定性、窗口边界、触发/不触发）
  - [x] 端到端/集成测试：关键 API 在两种后端/两种 RV 模式下输出一致或符合预期差异

- [x] Task 7: 文档同步（对齐计划与验收）
  - [x] 更新 `docs/architecture/refactoring-plan.md` 阶段五/六的状态与验收标准
  - [x] 更新 `docs/architecture/quality-assurance.md` 增加阶段五/六回归用例
  - [x] 更新 `docs/api/http.md`（若新增/变更配置入口或行为说明）

# Task Dependencies
- Task 2 depends on Task 1
- Task 3 depends on Task 2
- Task 5 depends on Task 4
- Task 6 depends on Task 2 and Task 5
- Task 7 depends on Task 2 and Task 5
