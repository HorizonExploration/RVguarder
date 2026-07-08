# 项目全景分析

## 1. 项目定位

`OpenClaw-RVGuarder`（龙虾卫士）作为 **OpenClaw 的一种使用场景下的安全插件** 存在。它不是 OpenClaw 的替代品，也不是一个独立的 OpenClaw 管理台，而是：

> 在用户以“让 OpenClaw 自动执行任务”为使用场景时，作为这一类场景的安全护栏，让 OpenClaw 仍然按原来的方式工作，但高风险动作、危险调用、配置变更和外联请求都先经过 Guard 的判定与审批。

围绕这一类使用场景，Guard 提供以下能力：

- 高风险动作执行前审批
- 运行时 Hook 接入与可视化状态管理
- 基线扫描、审计留痕与导出
- 与该场景配套的本地工作台，用于查看动作、配置、扫描和审计

因此本项目的所有设计都服从以下约束：

- 不修改 OpenClaw 主体源码
- 不替换 OpenClaw 官方前端
- 不强制改变用户原有的 OpenClaw 启动方式
- 当 Guard 没有被激活或链路不可用时，不能让 OpenClaw 出现功能性破坏，只对“高风险动作”这一使用场景生效

从角色上看，它是一个**“场景级安全插件”**：

- 对 OpenClaw 而言：是一个外部插件 + 外部前端
- 对用户而言：是一个针对“让 OpenClaw 自动干活”这一使用场景的安全护栏
- 对开发者而言：是一个可独立打包、单独演进、单独部署的 Python 包

## 2. 技术栈选型

### 2.1 后端

- Python 3.13+
- 标准库为主：`argparse`、`http.server`、`threading`、`sqlite3`、`json`
- 可选数据库依赖：
  - PostgreSQL：`psycopg2`
  - Redis：`redis`

### 2.2 前端

- 无独立前端工程
- 通过 `openclaw_guard/ui.py` 直接生成静态 `HTML + CSS + JS`
- 前端由本地 Python HTTP 服务托管

### 2.3 文档体系

- `docs/` 采用 VuePress 2
- 文档站与运行时 UI 分离
- `docs/guide/` 负责用户向导与本次项目梳理输出

### 2.4 与 OpenClaw 的集成方式

- 通过 Gateway RPC 与会话接口通信
- 通过运行时插件目录注入 Hook 插件
- 通过本地 Web API 承接 Hook 回调
- 通过配置发现逻辑自动识别 `openclaw.json`、工作区、日志路径与模型信息

## 3. 核心业务能力

### 3.1 对话与会话控制

- 直接从 Guard 前端发起对话
- 查询会话历史
- 重置会话
- 切换模型
- 展示当前 Agent、模型与连接状态

核心文件：

- `openclaw_guard/openclaw_adapter.py`
- `openclaw_guard/manager.py`
- `openclaw_guard/web.py`
- `openclaw_guard/ui.py`

### 3.2 风险检测与审批

- 输入或 Hook 事件被标准化为 `BehaviorEvent`
- 规则引擎给出 `allow / ask / block / escalate`
- 白名单在允许范围内可对低风险路径进行豁免
- 动作结果进入状态机并在前端展示

核心文件：

- `openclaw_guard/behavior.py`
- `openclaw_guard/models.py`
- `openclaw_guard/detection.py`
- `openclaw_guard/control.py`
- `openclaw_guard/whitelist.py`

### 3.3 基线扫描与资产发现

- 自动发现 OpenClaw 配置、工作区、日志、网络端口、模型与依赖描述
- 按检查项生成 `BaselineCheck`
- 汇总为 `ComplianceReport`
- 输出 JSON / HTML / PDF / 修复脚本

核心文件：

- `openclaw_guard/discovery.py`
- `openclaw_guard/baseline.py`
- `openclaw_guard/models.py`

### 3.4 审计与证据保留

- 审计记录带哈希链
- SQLite 为默认落地
- PostgreSQL / Redis 为增强后端
- 提供 JSONL 备份与导出能力

核心文件：

- `openclaw_guard/audit_store.py`
- `openclaw_guard/db_store.py`

### 3.5 运行时 Hook 与桥接

- Guard 自动生成本地 Hook 插件目录
- OpenClaw 加载插件后，通过 Hook 回调 Guard 的 `/api/hook/*`
- Guard 再把回调转为标准化行为事件

核心文件：

- `openclaw_guard/hook_runtime.py`
- `openclaw_guard/tool_hook_bridge.py`
- `openclaw_guard/web.py`
- `openclaw_guard/manager.py`

## 4. 运行主链分析

## 4.1 启动链路

1. `openclaw_guard/main.py` 解析 CLI 命令。
2. `build_manager()` 构造 `AppContext`、路径配置和 `OpenClawTarget`。
3. `OpenclawGuardManager` 初始化采集器、规则引擎、白名单、控制器、审计存储和运行时 Hook。
4. `web.py` 启动本地 HTTP 服务并托管 UI。

### 4.2 对话链路

1. 前端调用 `/api/chat/send`。
2. `manager.create_chat_action()` 先对用户请求做风险判定。
3. 如为高风险动作，进入待审批状态。
4. 审批通过后，`openclaw_adapter.py` 调用 OpenClaw Gateway 完成 `chat.send`、`agent.wait`、`chat.history`。
5. 回复写回消息历史与审计存储。

### 4.3 Hook 审批链路

1. OpenClaw 运行时插件在 `hook_runtime.py` 生成。
2. 插件监听当前可用的运行时事件，并把数据发到：
   - `/api/hook/before-tool-call`
   - `/api/hook/after-tool-call`
3. `manager.handle_before_tool_call()` 生成 `BehaviorEvent` 并判定风险。
4. 若需审批，则挂起等待；若允许，则回传放行结果。
5. `manager.handle_after_tool_call()` 写回执行结果与审计。

### 4.4 基线扫描链路

1. `manager.run_baseline()` 刷新 OpenClaw 发现结果。
2. `BaselineScanner.run()` 汇总配置、网络、Hook、日志、依赖、模型等检查。
3. 生成 `ComplianceReport` 并写入 `runtime/` 与 `output/reports/`。

## 5. 模块依赖关系

## 5.1 编排中心

`openclaw_guard/manager.py` 是绝对中心模块，直接依赖：

- 配置与路径：`config.py`
- 发现与基线：`discovery.py`、`baseline.py`
- 风险治理：`behavior.py`、`detection.py`、`control.py`、`whitelist.py`
- OpenClaw 适配：`openclaw_adapter.py`
- Hook 桥接：`hook_runtime.py`、`tool_hook_bridge.py`
- 存储与审计：`audit_store.py`
- Web 接口：被 `web.py` 调用

结论：`manager.py` 同时承担应用服务、协调器和部分领域逻辑，耦合度偏高，是后续拆分的第一优先级。

## 5.2 数据模型层

`models.py` 被以下模块共同依赖：

- `baseline.py`
- `behavior.py`
- `detection.py`
- `control.py`
- `audit_store.py`
- `tool_hook_bridge.py`

结论：`models.py` 是当前项目最稳定的公共边界，保留为共享模型层是合理的。

## 5.3 风险治理层

风险治理链如下：

`behavior.py` -> `detection.py` -> `control.py` -> `manager.py`

补充豁免链：

`whitelist.py` -> `control.py`

结论：这一层分工较清晰，是项目目前最接近“领域层”的部分。

## 5.4 OpenClaw 接入层

OpenClaw 接入相关模块如下：

- `discovery.py`：发现环境与配置
- `openclaw_adapter.py`：调用 Gateway
- `hook_runtime.py`：写入运行时插件
- `tool_hook_bridge.py`：将 Hook 回调映射为标准事件

结论：这一层已经形成比较明确的“适配器”角色，但接口仍散落在多个模块中，后续可归并为 `integrations/openclaw/`。

## 6. 当前结构优点

- 核心功能集中在一个 Python 包中，启动与部署简单
- 运行主链清晰，`main -> manager -> web/adapter/scanner`
- 风险治理模型、规则与动作状态机已经成型
- 文档站与运行时界面分离，便于分别维护
- `testlab/` 已与生产代码隔离，没有直接污染运行入口

## 7. 当前主要问题

### 7.1 文档与实现存在认知偏差

- 部分 README / docs 仍描述旧的 Hook 事件名
- 项目内同时存在“运行时真实链路”和“历史设计说明”，新成员容易混淆

### 7.2 编排层过重

- `manager.py` 聚合了过多职责：
  - 会话编排
  - 动作状态机
  - Hook 状态判断
  - 审计附加
  - 偏好配置
  - 文档输出前置逻辑

### 7.3 包装与发布痕迹不干净

- 存在已生成的 `egg-info` 元数据
- 文档目录存在构建生成文件
- 存在未接入执行链的数据库迁移目录

### 7.4 目录语义不够统一

- `testlab/` 是实验区，命名和生产目录风格差异较大
- `docs/Sematic/` 目录拼写异常，且内容更像研究草稿而非正式文档

## 8. 推荐的后续演进方向

### 8.1 目录分层

建议后续将 `openclaw_guard/` 内部逐步拆分为：

- `application/`
- `domain/`
- `integrations/`
- `presentation/`
- `storage/`

### 8.2 运行接口统一

建议把当前由 `manager.py` 暴露的多类能力收敛到服务对象，例如：

- `ChatService`
- `BaselineService`
- `ActionService`
- `HookService`
- `AuditService`

### 8.3 文档治理

建议把“架构说明”“实验草稿”“运维指引”“用户指南”彻底分层，避免一个概念在多处文档里出现旧版本描述。

## 9. 本次梳理结论

本项目已经具备可运行的最小产品形态，主链路清晰，最有价值的部分是：

- OpenClaw 接入适配
- 审批前风险阻断
- 基线扫描与审计导出

目前最需要持续优化的不是“再加功能”，而是：

- 清理遗留与生成文件
- 收敛文档口径
- 拆分 `manager.py`
- 明确实验区与生产区的边界
