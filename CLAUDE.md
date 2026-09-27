# CLAUDE.md — RVguarder（龙虾卫士）

> 面向 OpenClaw 的非侵入式运行时安全保护系统 | v0.7.0-dev（PMKB 1.2.0）

## 通用执行准则

以下准则适用于本项目中的编码、调试、重构和文档任务；与本文件后续的项目专属约定合并执行。

### 1. 编码前先思考

- 明确陈述假设；不确定时先提出问题。
- 存在多种解释时列出差异，不要静默选择。
- 发现更简单的方案时说明，并在必要时对当前方案提出质疑。
- 信息不完整或存在歧义时暂停，明确说明疑点并请求确认。

### 2. 简单性优先

- 只实现用户请求的内容，不添加推测性功能。
- 单次使用的逻辑不额外抽象。
- 不为未提出的需求增加灵活性或可配置项。
- 不为不可能发生的情况增加复杂错误处理。
- 如果实现明显超出问题规模，重新审视并尽量简化。

### 3. 外科式修改

- 只修改完成当前请求所必需的内容。
- 不顺手改进相邻代码、注释或格式。
- 不重构未损坏且不影响当前任务的代码。
- 遵循现有项目风格，即使个人偏好不同。
- 只清理由本次修改产生的未使用导入、变量或函数；发现既有死代码时只报告，不主动删除。
- 修改的每一行都应能直接追溯到用户请求。

### 4. 目标驱动执行

- 将任务转换为可验证的成功标准。
- 修复问题时先编写能够复现问题的测试，再实现修复。
- 添加校验时覆盖无效输入测试，并确认测试通过。
- 重构前后都执行对应测试。
- 多步骤任务先给出简短计划，并为每一步指定验证方式：

```text
1. [步骤] → 验证：[检查方式]
2. [步骤] → 验证：[检查方式]
3. [步骤] → 验证：[检查方式]
```

这些准则的目标是减少不必要的 diff、避免过度设计，并让澄清问题发生在实现之前，而不是错误发生之后。

## 项目定位

龙虾卫士通过 OpenClaw Plugin SDK 的钩子系统，在不修改 OpenClaw 源码的前提下，为 AI Agent 增加：
- **执行前审批** — `before_tool_call` 拦截 + `requireApproval` 物理挂起
- **语义风险分析** — DeepSeek LLM 驱动的 7 维度 50+ 标签语义标签体系
- **运行时行为验证（RV）** — ChainRule DSL 生成监视器 + 滑动窗口，检测链式攻击模式
- **全链路审计** — SHA-256 哈希链防篡改，SQLite + JSONL 双写
- **基线安全扫描** — 配置/端口/用户/依赖全量扫描，输出 JSON/HTML/PDF

核心设计原则：**非侵入、先决策后执行、可取证、分级故障降级**（低风险只读可审计放行，高影响工具保持阻断；`failClosed=true` 可全量阻断）。

## 技术栈

| 层 | 技术 |
|---|------|
| 后端 | Python 3.13+（FastAPI + Pydantic v2） |
| 前端 | Vite + Preact SPA（组件化，Zustand 状态管理，preact-router） |
| 插件 | Node.js + OpenClaw Plugin SDK `>=2026.4.0`（自动生成） |
| 检测引擎 | PMKB + ChainRule DSL、Trie 前缀树白名单 |
| 语义增强 | DeepSeek API（LLM 模式）或本地启发式规则（本地模式） |
| 存储 | SQLite（开发/测试）、PostgreSQL + Redis（生产），`DBStoreInterface` ABC 抽象 |
| 测试 | Python `unittest` + Playwright E2E |
| 文档 | VuePress 静态站点 |

## 目录结构

```
openclaw_guard/          # Python 后端主包
├── main.py              # CLI 入口（argparse，子命令：run/install-hook/uninstall-hook/baseline/export-audit/doctor）
├── manager.py           # [兼容层] OpenclawGuardManager 子类化 GuardServices，保留旧导入路径与 patch 锚点
├── services.py          # GuardServices 容器 — 核心编排 + 组件懒加载 + 流水线委托（阶段三产物）
├── config.py            # AppContext / AppPaths / GuardSettings 数据类
├── models.py            # 核心数据模型（Pydantic BaseModel v2）
├── ui.py                # 前端静态资源管理
├── baseline.py           # 基线安全扫描器（BaselineScanner）
├── conversation.py       # 对话交互辅助
├── utils.py             # 工具函数：utc_now_iso, sha256_text, append_jsonl, write_json 等
├── engine/              # 安全检测引擎（核心）
│   ├── pipeline.py      # 热路径流水线（ingest / before-tool-call / after-tool-call）
│   ├── semantic_enhancer.py  # SemanticEnhancer — LLM/本地双模，7 维度标签，含工具名幻觉校验
│   ├── control.py       # GuardController — 决策 + 白名单 → 动作状态
│   ├── whitelist.py     # WhitelistEngine — Trie 前缀匹配，含 default_police_whitelist()
│   └── behavior.py      # BehaviorCollectorManager — 行为采集（Ptrace/eBPF/HookBridge 预留桩）
├── rv/                  # 运行时验证引擎（ChainRule DSL、窗口与基线自动机）
│   ├── runtime_verification.py  # RV 引擎 + WindowManager — 滑动窗口、会话隔离、序列匹配
│   ├── rv_dsl.py        # 参数化 RV DSL 原语（entity/时间间隔/quantifier）
│   ├── ir.py            # ToolCallIR 结构化中间表示（阶段 A）
│   ├── baseline_learner.py     # 基线自动机学习（阶段 C）
│   ├── baseline_monitor.py     # 基线自动机监视器（阶段 C）
│   └── trace_abstractor.py     # 轨迹抽象（阶段 C）
└── spec/                # 规约层（拆分自 engine/，阶段 E-F）
    ├── nl2spec_generator.py  # NL2Spec 生成（阶段 E）
    ├── spec_validator.py     # 规约校验 + 正反例 trace
    ├── session_state.py      # PrincipalSecurityState 主体成功证据状态
    └── eval_traces.py        # 正反例 trace 库
├── web/                 # 唯一 FastAPI HTTP 层
│   ├── __init__.py      # 兼容旧导出（launch_web, _error_message）
│   ├── app.py           # create_app() 工厂 + launch_web() 入口
│   ├── dependencies.py  # DI: get_manager, body_payload, require_hook_token
│   ├── errors.py        # GuardError + 统一异常处理器 + _error_message()
│   └── routes/          # 路由模块（health, baseline, audit, rv, actions, hook, static）
├── api/                 # [保留] 路由调用的业务 handler（不是独立 HTTP 服务器）
│   └── _handlers.py     # HTTP API 处理器（20+ 端点）
├── core/                # 业务服务层
│   ├── action_service.py     # ActionService — 动作生命周期 CRUD
│   ├── audit_service.py      # AuditService — 审计追加/查询/导出/完整性校验
│   └── baseline_service.py   # BaselineService — 基线扫描运行/确保
├── integrations/        # OpenClaw 集成层
│   ├── hook_runtime.py       # 插件 JS 生成器
│   ├── tool_hook_bridge.py   # Hook 载荷 → BehaviorEvent 转换器
│   ├── openclaw_adapter.py   # Gateway 状态探测适配
│   └── discovery.py          # 自动发现 OpenClaw 安装
├── storage/             # 数据持久层
│   ├── db_store.py      # DBStoreInterface ABC → PostgreSQLStore / SQLiteStore
│   └── audit_store.py   # AuditStore — SHA-256 哈希链，DB + JSONL 双写
└── collectors/          # 运行时采集器（预留）

frontend/                # SPA 前端（Vite + Preact）
├── src/main.jsx          # Preact 入口
├── src/App.jsx           # 根组件 + preact-router (5 路由)
├── src/store.js          # Zustand 状态管理
├── src/api.js            # fetch 封装 + 后端 API
├── src/i18n.js           # 国际化文本 (T/SCENE_ZH/STATUS_ZH)
├── src/components/       # 10 个可复用 UI 组件
├── src/pages/            # 5 个页面组件
└── src/styles.css        # CSS 自定义属性现代化样式

tests/                   # Python 单元测试（unittest）
e2e/                     # Playwright E2E 测试
testlab/                 # 历史结果与无副作用研究夹具（不含可执行旧评测）
runtime/                 # 运行时产物（自动生成，已 .gitignore）
docs/                    # VuePress 文档站点
```

## 常用命令

### 开发环境

```bash
# 安装 Python 包（开发模式）
pip install -e .

# 构建前端
cd frontend && npm install && npm run build

# 启动 Guard 工作台（FastAPI，http://127.0.0.1:8780）
python -m openclaw_guard.main run

# 仅输出摘要后退出（--once）
python -m openclaw_guard.main run --once

# 自定义端口
python -m openclaw_guard.main run --port 8888
```

### 维护命令

```bash
# 安装 Hook 插件到 OpenClaw 配置
python -m openclaw_guard.main install-hook

# 卸载 Hook 插件
python -m openclaw_guard.main uninstall-hook

# 运行基线扫描
python -m openclaw_guard.main baseline

# 导出审计数据
python -m openclaw_guard.main export-audit --output audit.csv

# 健康检查
python -m openclaw_guard.main doctor
python -m openclaw_guard.main doctor --json
```

### 测试

```bash
# 运行全部回归测试
python -m pytest -q

# 运行单个测试文件
python -m pytest tests/test_policy_decision_adapter.py -q
python -m pytest tests/test_runtime_verification.py tests/test_rv_dsl.py -q

# 运行 E2E 测试
cd e2e && npm install && npm run install:browsers && npm test
```

## 架构约定

### 决策流水线（PMKB + RV）

```
1. PMKB（单步、版本化、可回放）— 79 条原生规则 + 47 条迁移记录（`migrations/legacy-1.1.json`，仅用于 provenance/replay，不进入运行时候选召回）
   └─ 处理：授权 Trace、最小权限和单步硬约束
2. RV 引擎（跨步、有状态、时序）— DSL 生成监视器 + 滑动窗口
   └─ 处理：链式攻击（搜索→删除→外发）、多步累积模式
   └─ RV 判定只升权，不降低 PMKB 裁决
```

### 代码风格

- **Python 3.13+**，使用 `from __future__ import annotations` 延迟求值类型注解
- 所有模块、类、公开函数必须有 docstring（中文描述职责）
- 数据模型使用 **Pydantic v2 BaseModel** 定义在 `models.py`（`to_dict()` 保留为兼容别名）
- 服务层遵循「管理器协调，服务执行」模式：`Manager` 编排流程，`Service` 封装业务
- 检测规则中文注释（规则 ID 英文：`CMD-001`, `FILE-001`, `NET-001` 等）
- 文件顶部用 docstring 声明模块职责边界（如 `policy/engine.py` 与 `rv/runtime_verification.py` 的分工约定）

### 关键模式

- **非侵入式**：不修改 OpenClaw 源码，通过生成的 JS 插件 + HTTP 桥接通信
- **单 HTTP 层**：`web/` FastAPI 是唯一启动入口；旧版 stdlib HTTP 实现已移出生产包，源文件仅在归档/Git 历史中保留
- **分级故障策略**：JS 插件内置，低风险只读在后端不可达时审计放行，高影响工具保持阻断；恢复后回到正常策略
- **审批同步**：OpenClaw 原生审批卡片是唯一决策入口，Guard Dashboard 通过 SSE/增量查询只读同步
- **审计哈希链**：每条记录含 `previous_hash` + `record_hash = SHA-256(prev_hash + payload)`
- **数据库抽象**：`DBStoreInterface` ABC → PostgreSQLStore（生产，含 Redis 缓存）/ SQLiteStore（开发）自动切换
- **白名单 Trie 树**：前缀匹配路径/命令/网络/API/Skill，O(n) 匹配效率
- **RV 会话隔离**：不同 session_id 的行为序列互不干扰

### 环境配置

- `.env` 文件存储 DeepSeek API Key（`DEEPSEEK_API_KEY=...`）
- `runtime/` 目录为运行时生成物，已在 `.gitignore` 中排除
- `output/` 目录为报告/修复脚本/审计导出输出
- `policies/` 目录预留给未来的安全策略文件

## 当前状态

- **版本**: v0.7.0-dev（PMKB 1.2.0 基线已接入）
- **Python 版本要求**: 3.13+
- **许可证**: Apache 2.0
- **作者**: Codex
- **重构进度**: 
  - ✅ 阶段一（HTTP 层收敛） — FastAPI 为默认且唯一入口，旧版实现已移出生产包
  - ✅ 阶段二（Pydantic 模型迁移） — models.py 全部 Pydantic v2
  - ✅ 阶段三（Manager 拆分 + 懒加载） — GuardServices 容器 + LazyProxy + pipeline 模块
  - ✅ 阶段四（前端 Preact 迁移） — 17 源文件，5 页面，10 组件，Zustand 状态管理
  - ✅ RV 层拆分 — engine/ 下 RV 相关拆分为 rv/ + spec/ 子包
  - ✅ 阶段 A（ToolCallIR）/ C（基线自动机）/ D（RV 参数化原语）
  - ✅ 阶段 E（NL2Spec 生成 + 规约校验）；阶段 B/F 的旧在线实现已收敛为 PMKB 原生规则和主体成功证据状态
  - ✅ PMKB 1.2.0 原生规则基线 — 48 个 canonical operations、79 条原生规则、76 条 Trace、9 个危险组合关系、123 个回归向量；直接参与运行时决策，新规则采用离线回放与有限事件样本校验
- **下一步计划**: 见 `CHANGELOG.md`、`docs/architecture/index.md`、`docs/ops/roadmap.md` 和 `docs/research/index.md`

---

*CLAUDE.md 最后更新: 2026-09-15 · DSL-only 与分级故障策略复核*
