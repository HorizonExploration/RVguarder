# 重排方案：前后端分离 + 只保留核心（修订稿）

> 状态：**已完成实施**（2026-07-08）
> 目标：把项目收敛为"OpenClaw 的使用场景安全插件"，前后端分离，UI 只留最核心功能
> 修订点：
> 1. 保留 `testlab/` 与 `docs/Sematic/`，不再列入删除清单
> 2. 不再分 `normal` / `launch` / `chat` 等多模式
> 3. CLI 收敛为单一主入口，"开启即用"

## 0. 实施完成摘要

已于 2026-07-08 完成核心重构，当前实际结构如下：

### openclaw_guard/ 根目录（10 个 .py）
| 文件 | 用途 | 状态 |
|---|---|---|
| `__init__.py` | 包初始化 | 保留 |
| `main.py` | CLI 入口 (`run` + 维护子命令) | 已收敛 |
| `manager.py` | 协调层（委托 core service） | 已委托 |
| `web.py` | HTTP 路由装配层 | 已拆分 |
| `ui.py` | 嵌入式前端（概览+审批+扫描） | 已裁剪 |
| `models.py` | 数据模型（dataclass） | 保留 |
| `config.py` | 配置（AppContext 等） | 保留 |
| `utils.py` | 工具函数 | 保留 |
| `baseline.py` | 基线扫描器 | 保留 |
| `conversation.py` | 对话辅助 | 保留（内部使用） |

### 子包（4 个，共含 18 个 .py）
| 子包 | 文件 | 内容 |
|---|---|---|
| `api/` | `__init__.py`, `_handlers.py` | 15 个 HTTP 路由处理函数 |
| `core/` | `__init__.py`, `action_service.py`, `baseline_service.py`, `audit_service.py` | 动作/基线/审计核心服务 |
| `integrations/` | `__init__.py` + 8 个适配器模块 | OpenClaw 通信、发现、检测、白名单等 |
| `storage/` | `__init__.py`, `audit_store.py`, `db_store.py` | 审计存储与数据库抽象 |

### 重构前后对比
| 指标 | 重构前 | 重构后 |
|---|---|---|
| 根目录 .py 文件 | 21 个 | 10 个 (-52%) |
| 子包数 | 2 (core/, collectors/) | 5 (api/, core/, integrations/, storage/, collectors/) |
| 子包总文件 | 6 个 | 22 个 |
| CLI 入口 | 5 个命令 | 1 主入口 + 5 维护子命令 |
| 前端 UI | 4 视图（含对话） | 3 视图（概览/审批/扫描） |
| 审计范围 | 对话+动作 | 仅动作级 |

## 1. 设计原则

1. **后端是事实来源**：审计、拦截、审批、基线状态都以 Python 后端为准
2. **前端只做消费**：纯静态资源，通过 HTTP API 拿数据，不直接调用 OpenClaw Gateway
3. **不再做对话 UI**：对话完全回到 OpenClaw 原生页面
4. **审计只到动作级**：不再为对话上下文/消息内容建本地存储
5. **Hook 路径独立**：`runtime/openclaw-guard-plugin/` 只承担"拦截回调"，不嵌业务逻辑
6. **可独立演进**：前后端可以各自版本、单独打包、单独部署
7. **开启即用**：只保留一个主命令 `openclaw-guard run`，启动后自动完成发现、基线、Hook 加载与本地工作台
8. **实验区与笔记区保留**：`testlab/` 与 `docs/Sematic/` 是研究与笔记空间，**不**作为重排对象

## 2. CLI 收敛

### 2.1 旧设计

```text
python -m openclaw_guard.main launch
python -m openclaw_guard.main normal
python -m openclaw_guard.main chat
python -m openclaw_guard.main interactive
python -m openclaw_guard.main baseline
python -m openclaw_guard.main export-audit
```

### 2.2 新设计（单一主入口 + 维护子命令）

主入口：开启即用，启动后直接进入“工作台 + 拦截 + 审批 + 基线 + 审计”。

```text
openclaw-guard run                  # 启动主服务（默认 + 唯一长期运行模式）
openclaw-guard run --no-browser     # 启动但不开浏览器
openclaw-guard run --port 8780      # 指定端口
openclaw-guard run --config PATH    # 指定 OpenClaw 配置文件
```

维护子命令（一次性，不进入长期运行）：

```text
openclaw-guard install-hook         # 把本地 Hook 插件路径写入 OpenClaw 配置
openclaw-guard uninstall-hook       # 还原 OpenClaw 配置
openclaw-guard baseline             # 手动跑一次基线扫描并打印
openclaw-guard export-audit PATH    # 导出审计 JSONL
openclaw-guard doctor               # 打印运行链路健康状况
```

`normal` / `launch` / `chat` / `interactive` 这四个旧子命令**全部移除**。

### 2.3 启动后行为

`openclaw-guard run` 启动后自动完成：

1. 发现本机 OpenClaw 配置、工作区、日志
2. 准备 `runtime/`、`output/`、`exports/` 目录
3. 如果还没有最近基线，自动补一次
4. 生成/同步 `runtime/openclaw-guard-plugin/`，并把路径写入 `openclaw.json`
5. 启动本地工作台
6. 默认尝试打开浏览器

用户不需要决定模式。

## 3. 目标目录结构

```text
OpenClaw-RVGuarder/
├── backend/                       # Python 后端（独立工程）
│   ├── openclaw_guard/
│   │   ├── __init__.py
│   │   ├── main.py                # CLI 入口（单 run + 维护子命令）
│   │   ├── api/                   # HTTP API 层（前后端边界）
│   │   │   ├── __init__.py
│   │   │   ├── actions.py         # 拦截/审批
│   │   │   ├── baseline.py        # 基线
│   │   │   ├── audit.py           # 审计查询/导出
│   │   │   ├── status.py          # 状态
│   │   │   └── hook_bridge.py     # Hook 插件回调
│   │   ├── core/                  # 业务核心
│   │   │   ├── __init__.py
│   │   │   ├── action_service.py  # 动作决策
│   │   │   ├── baseline_service.py
│   │   │   ├── audit_service.py
│   │   │   └── status_service.py
│   │   ├── integrations/          # 外部依赖
│   │   │   ├── __init__.py
│   │   │   ├── openclaw_adapter.py
│   │   │   ├── discovery.py
│   │   │   ├── detection.py
│   │   │   ├── behavior.py
│   │   │   ├── whitelist.py
│   │   │   ├── control.py
│   │   │   ├── hook_runtime.py
│   │   │   └── tool_hook_bridge.py
│   │   ├── storage/               # 存储层
│   │   │   ├── __init__.py
│   │   │   ├── audit_store.py
│   │   │   ├── db_store.py
│   │   │   ├── file_store.py
│   │   │   └── models.py
│   │   ├── web.py                 # 路由装配
│   │   ├── models.py              # 通用 dataclass
│   │   ├── config.py
│   │   ├── paths.py
│   │   └── utils.py
│   ├── pyproject.toml             # 独立 Python 包
│   └── tests/                     # 最小冒烟
│
├── frontend/                      # 纯静态前端
│   ├── index.html                 # 入口：状态 + 跳回 OpenClaw
│   ├── pages/                     # 拦截/审批/审计/设置
│   ├── assets/
│   ├── config.js                  # 指向 backend base URL
│   ├── package.json               # 仅用于本地构建/格式化
│   └── README.md
│
├── runtime/                       # 运行产物（gitignore）
│   ├── openclaw-guard-plugin/     # 自动生成的 Hook 插件
│   ├── hook-bridge.json
│   └── static/                    # 编译后前端，web.py 静态托管
│
├── output/                        # 报告/审计导出
│   ├── reports/
│   ├── audit/
│   └── exports/
│
├── scripts/                       # 维护脚本
│   ├── install-hook.sh
│   ├── uninstall-hook.sh
│   └── export-audit.sh
│
├── tests/                         # 端到端冒烟
│
├── testlab/                       # 研究/实验区（保留，不重排）
│
├── docs/                          # 文档站
│   ├── .vuepress/
│   ├── architecture/
│   ├── guide/
│   ├── improve/
│   └── Sematic/                   # 研究笔记（保留，不重排）
│
├── pyproject.toml                 # 工作区元信息
├── README.md
└── .gitignore
```

## 4. 删除与合并清单

### 4.1 显式保留（不重排）

- `testlab/`：研究/实验区
- `docs/Sematic/`：研究笔记
- `runtime/static/`：保留作为“编译产物目录”，但**内容**会被砍到最小（见 §6）

### 4.2 完全删除

- `openclaw_guard/ui.py`：前端壳不再由 Python 端渲染
- `openclaw_guard/chat.py` 类对话代理（如有）：改为不向外暴露
- `openclaw_guard/web.py` 中 `/api/chat/*` `/api/sessions/*` 等接口：直接去掉
- `openclaw_guard/db_store.py` 中关于“对话/消息/会话”的表与索引
- `openclaw_guard/main.py` 中 `normal` / `launch` / `chat` / `interactive` 子命令
- `runtime/static/` 中对话视图、消息流、模型切换、语言切换、皮肤等组件
- `output/audit/conversations*` 历史产物：清理脚本一并处理
- `docs/Sematic/` **不**删除，仅从本方案的删除清单中移出

### 4.3 合并

- `openclaw_guard/main.py` 命令收敛：
  - 保留：`run` / `install-hook` / `uninstall-hook` / `baseline` / `export-audit` / `doctor`
  - 删除：`normal` / `launch` / `chat` / `interactive`
- `openclaw_guard/manager.py` 的 API 拆分到 `core/*_service.py`
- `openclaw_guard/audit_store.py` 与 `db_store.py` 合并到 `storage/`
- `openclaw_guard/web.py` 中具体路由下沉到 `api/`

### 4.4 改造但保留

- `runtime/openclaw-guard-plugin/index.js`：去掉内部业务逻辑，只转发“拦截事件 → backend /api/hook_bridge”
- `openclaw_guard/hook_runtime.py`：仅负责生成插件模板与 `package.json`，不再承担决策
- `openclaw_guard/discovery.py`：与 OpenClaw 解耦，单独放 `integrations/`
- `openclaw_guard/openclaw_adapter.py`：作为 `integrations/openclaw_adapter.py`，只暴露 RPC
- `openclaw_guard/detection.py` / `behavior.py` / `whitelist.py`：合并为 `integrations/policy_engine.py` 或保持三件，按你倾向二选一

## 5. 前后端边界（HTTP API 草案）

```text
GET  /api/status                       # 运行/插件/连接状态
GET  /api/actions?status=pending       # 待确认动作
POST /api/actions/{id}/approve
POST /api/actions/{id}/reject
GET  /api/actions/{id}                 # 单条动作详情
GET  /api/audit?limit=&cursor=         # 动作级审计查询
GET  /api/audit/export                # 导出 JSONL
POST /api/baseline/run                # 触发基线扫描
GET  /api/baseline/latest             # 读取最近一次结果
POST /api/hook_bridge/event           # Hook 插件回调
```

明确不在前端的 API：

- 不暴露 OpenClaw Gateway RPC
- 不暴露对话历史、消息、会话
- 不暴露模型切换

## 6. 前端只保留的页面

```text
/                    首页：当前 Guard 状态 + 一键跳回 OpenClaw
/pending             待确认动作列表
/actions/:id         单条动作详情
/audit               动作级审计
/baseline            基线报告
/settings            拦截/审批策略
```

## 7. 迁移阶段（按推荐顺序）

1. **CLI 收敛**：把 `main.py` 改为 `run` + 维护子命令，旧的 4 个子命令改为 alias 打印迁移提示 1 个版本后删除
2. **API 边界先行**：在不动 UI 的情况下，把 `web.py` 中所有路由按 `api/*` 拆分，每个路由不超过 20 行
3. **service 拆分**：把 `manager.py` 的方法下沉到 `core/*_service.py`，`web.py` 只做参数校验
4. **storage 收敛**：审计表只保留动作事件，删除对话/会话表与索引
5. **前端瘦身**：从 `runtime/static/` 砍掉对话 UI，只留最小骨架
6. **解耦 runtime 插件**：让 Hook 插件只做“事件转发 + 鉴权”，决策全部在后端
7. **目录重组**：按本文件第 3 节的目录结构整体迁移，迁移完后再删旧文件
8. **回归测试**：跑一次 `chat → trigger risky tool → approve → execute` 完整链路

## 8. 待你确认的项

- [ ] 第 3 节目录结构是否直接落地
- [ ] 第 4.1 节保留项是否完整
- [ ] 第 4.2 节删除清单是否都同意
- [ ] 第 4.3 节合并点是否同意
- [ ] 第 4.4 节中 `detection/behavior/whitelist` 是合并为 `policy_engine` 还是保持三件
- [ ] 第 7 节迁移阶段是否可以按这个顺序推进
- [ ] 是否需要保留旧 CLI 子命令 1 个版本作为过渡（建议否，直接砍）

## 9. 风险与回滚

- **风险点**：审计表结构变更后，历史审计数据需要兼容读取
- **缓解**：保留一次“旧表 → 新表”的迁移脚本，迁移期双写
- **回滚**：在合并前给 `web.py` 与 `manager.py` 留一个 commit，回滚时只需 `git revert`
- **验证**：迁移前后用同一份历史审计数据做“读一致性”比对

## 10. 完成定义

- 后端可以单独 `pip install` 并启动
- 前端可以单独 `pnpm build` 产出 `runtime/static/`
- Hook 插件只做事件转发，决策代码 0 行
- `openclaw-guard run` 启动后即进入工作台，无模式选择
- 一次端到端测试通过：会话在 OpenClaw 内进行，Guard 只负责拦截与审批
