# 前端开发说明

本文件说明 OpenClaw Guard 前端的开发、构建与部署方式。

## 架构

```
frontend/                       # 前端源码（独立工程，可单独开发）
├── index.html                  # 入口 HTML
├── package.json                # 依赖与脚本
├── vite.config.js              # Vite 构建配置
├── package-lock.json          # npm 锁文件
└── src/
    ├── main.jsx                # Preact 入口
    ├── App.jsx                 # 路由与页面壳
    ├── api.js                  # 后端 API 访问封装
    ├── store.js                # Zustand 状态管理（含 RV 模式持久化）
    ├── pages/                  # 页面
    ├── components/             # 组件
    └── styles.css              # 全部样式

runtime/ui/                     # 构建产物（后端静态托管目录）
└── assets/...
```

- `frontend/` 是开发工作区，使用 Vite 做开发服务器和构建
- `runtime/ui/` 是构建产物目录，由 Python 后端的 FastAPI `web/` 包静态托管
- 两者**不是**冗余：一个是源码，一个是输出

## 开发流程

### 1. 安装依赖

```bash
cd frontend
npm install
```

### 2. 启动开发服务器

```bash
npm run dev
```

Vite 开发服务器运行在 `localhost:5173`，`/api/*` 请求会自动代理到后端 `127.0.0.1:8780`。

因此你需要先启动后端：

```bash
cd ..
openclaw-guard run --no-browser
```

然后浏览器打开 `localhost:5173` 进行开发调试，支持热更新。

### 3. 构建产出

```bash
npm run build
```

构建后的文件直接输出到 `../runtime/ui/`（由 `vite.config.js` 中 `outDir` 指定）。

### 4. 验证

构建完成后，直接访问后端即可看到最新前端：

```bash
openclaw-guard run
# 浏览器打开 http://127.0.0.1:8780
```

## 可用脚本

| 命令 | 说明 |
|------|------|
| `npm run dev` | 启动 Vite 开发服务器（热更新，代理 /api） |
| `npm run build` | 构建到 `../runtime/ui/` |
| `npm run preview` | 预览构建结果 |

## 技术栈

- **Vite** — 构建工具与开发服务器
- **Preact** — 轻量级组件框架（兼容 React 心智，体积更小）
- **preact-router** — 前端路由
- **Zustand** — 状态管理（含 RV 模式持久化）
- **CSS** — 原生 CSS（无预处理器）

## 页面结构

| 路由/视图 | 说明 |
|-----------|------|
| `dashboard`（`/`） | 首页：连接状态 + 待 OpenClaw 处理动作 + 最近动作 + Hook 状态；最近动作不重复展示待确认项 |
| `actions`（`/actions`） | 动作状态页：按状态筛选 + 分页浏览；Hook 动作只读 |
| `rules`（`/rules`） | 安全规则页：规则列表与管理 |
| `skills`（`/skills`） | 技能配置页：skill 启停与权限 |
| `settings`（`/settings`） | 安全扫描页：基线扫描 + 审计导出 |

共 5 个页面，对应 `App.jsx` 中的 `preact-router` 路由。

## API 依赖

前端通过 HTTP 调用后端以下端点：

| 端点 | 用途 |
|------|------|
| `GET /api/summary?view=compact` | 获取首页轻量摘要 |
| `GET /api/actions/{action_id}` | 获取单动作最新状态 |
| `GET /api/events` | SSE 实时动作事件流 |
| `GET /api/rv/status` | 获取 RV 引擎当前状态 |
| `POST /api/rv/toggle` | 切换 RV 启用状态 |
| `POST /api/actions/approve` | 仅批准非 Hook 本地动作；Hook 返回 409 |
| `POST /api/actions/reject` | 仅拒绝非 Hook 本地动作；Hook 返回 409 |
| `POST /api/actions/clear` | 清空动作历史 |
| `POST /api/actions/ingest` | 接收行为事件 |
| `POST /api/baseline/run` | 触发基线扫描 |
| `POST /api/audit/export` | 导出审计数据 |
| `POST /api/skills/upsert` | 创建/更新 skill 配置 |

## 与后端的边界

- 前端**不**直接调用 OpenClaw Gateway
- Hook 审批只在 OpenClaw 原生页面完成，Guard 前端通过 SSE/增量查询同步结果
- 前端**不**维护对话/消息/会话状态
- 所有业务决策（拦截、审批、基线、审计）由 Python 后端完成
- 前端仅作为展示与操作界面

## Python 侧托管

`openclaw_guard/ui.py` 是一个薄层：启动时确保 `runtime/ui/` 目录存在，并在运行目录缺少 UI 时把仓库内的构建产物复制过去（避免首次启动空白页面）。

```python
def build_ui(target_dir: Path, summary=None) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    if (target_dir / "index.html").exists():
        return
    # 若运行目录缺少 UI，则从仓库内 runtime/ui 复制一份
```

`openclaw_guard/web/routes/static.py`（FastAPI）负责托管 `runtime/ui/` 下的静态文件（`/`、`/assets/*`、前端路由的 SPA fallback）；FastAPI 是唯一 HTTP 入口。
