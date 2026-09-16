# 阶段五/六：存储层 SQLAlchemy 化 + RV 规约驱动 Spec

> **历史规格（已 superseded）：** 本文保留阶段五/六的原始设计与取舍。当前项目采用 FastAPI 单入口、ChainRule DSL-only RV；手写 `rv_monitors.py`、`transitions` 依赖及“双实现并行/可回退”路径已退役，不应据本文重新启用。

## Why
当前 v0.3.0 的存储层仍以原生 SQL（SQLiteStore）为主，表结构演进与复杂查询维护成本高；同时 RV 层仍依赖手写 FSM 监视器，扩展新链式攻击模式需要写代码、不可配置，违背规约驱动目标。

## What Changes
- 引入 **SQLAlchemyStore**（在保留 `DBStoreInterface` 抽象的前提下新增实现），作为阶段五“存储层升级”的主要落地。
- 引入 **ChainRule DSL + 编译器**（从声明式规则自动生成监视器），作为阶段六“RV 规约驱动”的主要落地。
- 在不破坏现有行为的前提下，提供“双实现并行 + 可回退”的迁移路径（默认行为不变，逐步切换）。
- **BREAKING（文档层面）**：文档中“阶段五/六未落地”的状态将转为“进行中/已落地”，并补齐新的验收与回归用例。

## Impact
- Affected specs: 存储抽象（DBStoreInterface）、RV 引擎（RuntimeVerificationEngine / rv_monitors）、质量保障（Contract/Regression）、性能与启动策略（LazyProxy、启动 ≤2s）。
- Affected code:
  - `openclaw_guard/storage/db_store.py`（新增 SQLAlchemyStore 与工厂选择）
  - `openclaw_guard/core/*`（若使用 DBStoreInterface 的查询/写入接口）
  - `openclaw_guard/rv/runtime_verification.py`、`openclaw_guard/engine/rv_monitors.py`（新增规约驱动生成路径并逐步替换手写监视器）
  - `docs/architecture/*`（计划/验收/QA 更新）

## ADDED Requirements

### Requirement: SQLAlchemy 存储后端（Phase 5）
系统 SHALL 提供一个基于 SQLAlchemy 的存储实现，并保持与现有存储抽象一致的行为。

#### Scenario: SQLAlchemy 后端可选启用（默认不变）
- **WHEN** 用户未配置开启 SQLAlchemy
- **THEN** 系统 SHALL 继续使用现有默认存储实现（现有功能与数据不变）

#### Scenario: SQLAlchemy 后端启用成功
- **WHEN** 用户配置开启 SQLAlchemy（例如通过配置项/CLI 参数选择存储模式）
- **THEN** 系统 SHALL 使用 SQLAlchemyStore 完成同等的读写与查询能力
- **AND** 关键端点（`/api/summary`、动作审批、审计导出、基线扫描）行为与数据结构保持兼容

#### Scenario: 缺少 SQLAlchemy 依赖时的降级
- **WHEN** 用户尝试启用 SQLAlchemyStore 但运行环境缺少 SQLAlchemy 依赖
- **THEN** 系统 SHALL 输出可读的错误与安装提示
- **AND** SHALL 不影响 legacy 默认运行（不应因 import-time 失败导致崩溃）

#### Scenario: 性能与启动约束保持
- **WHEN** 系统启动
- **THEN** SQLAlchemyStore 初始化 SHALL 遵循懒加载策略，避免在启动阶段做昂贵的连接/迁移
- **AND** SHALL 不破坏既有性能约束：启动 ≤ 2s、`/api/summary/lite` ≤ 10ms（若存在）或摘要热路径延迟不显著退化

---

### Requirement: RV 规约驱动（Phase 6）
系统 SHALL 提供声明式 ChainRule 规则描述，并从规则自动生成可执行的监视器逻辑，以替代手写 FSM 模板。

#### Scenario: 规则以声明式文件集中维护
- **WHEN** 开发者新增一个链式攻击检测规则
- **THEN** SHALL 仅需在规则文件中添加/修改声明式条目（不新增监视器类代码）

#### Scenario: 规则编译为监视器并参与判定
- **WHEN** RV 引擎接收到事件序列
- **THEN** SHALL 根据编译后的监视器输出 verdict（ok/block/escalate 等）
- **AND** SHALL 保持与当前 RV API（`/api/rv/status`、`/api/rv/toggle`）数据结构兼容

#### Scenario: 与现有 6 个监视器的兼容迁移
- **WHEN** 规约驱动路径开启
- **THEN** 系统 SHALL 能覆盖当前已存在的 6 个监视器的等价规则集
- **AND** SHALL 提供回退开关，使其可随时回退到手写监视器实现

#### Scenario: 规约编译的确定性与可测试性
- **WHEN** 在相同输入 trace 上运行
- **THEN** 规约驱动输出 SHALL 与基线输出一致（或以文档明确的差异为准）
- **AND** SHALL 提供单元测试覆盖：编译结果、状态推进、触发条件、窗口边界

## MODIFIED Requirements

### Requirement: 现有存储抽象（DBStoreInterface）
系统 SHALL 保持 `DBStoreInterface` 作为唯一上层依赖抽象；上层业务代码不应直接依赖某个具体存储实现（SQLiteStore/SQLAlchemyStore）。

### Requirement: RV 引擎初始化策略
系统 SHALL 将 RV 监视器的构建/编译从“类定义散落”改为“规则→编译→实例”的统一路径，并保证编译过程不会阻塞启动热路径（可通过惰性编译或预编译缓存实现）。

## REMOVED Requirements

### Requirement: 手写 FSM 监视器作为唯一扩展方式
**Reason**：扩展成本高、与“规约驱动”目标冲突、易产生同构模板冗余。
**Migration**：保留手写监视器作为回退实现；默认规则集先做到“行为等价”，再逐步下线手写实现入口。 
