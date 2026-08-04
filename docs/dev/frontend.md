# 前端开发说明

本文件说明 OpenClaw Guard 前端的开发、构建与部署方式。

## 架构

```
frontend/                       # 前端源码（独立工程，可单独开发）
├── index.html                  # 入口 HTML
├── package.json                # 依赖与脚本
├── vite.config.js              # Vite 构建配置
├── pnpm-lock.yaml              # 锁文件
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
- `runtime/ui/` 是构建产物目录，由 Python 后端的 `legacy_web.py` 或 `web/` 包静态托管
- 两者**不是**冗余：一个是源码，一个是输出

## 开发流程

### 1. 安装依赖

```bash
cd frontend
pnpm install
```

### 2. 启动开发服务器

```bash
pnpm dev
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
pnpm build
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
| `pnpm dev` | 启动 Vite 开发服务器（热更新，代理 /api） |
| `pnpm build` | 构建到 `../runtime/ui/` |
| `pnpm preview` | 预览构建结果 |

## 技术栈

- **Vite** — 构建工具与开发服务器
- **Preact** — 轻量级组件框架（兼容 React 心智，体积更小）
- **preact-router** — 前端路由
- **Zustand** — 状态管理（含 RV 模式持久化）
- **CSS** — 原生 CSS（无预处理器）

## 页面结构

| 路由/视图 | 说明 |
|-----------|------|
| `dashboard` | 首页：连接状态 + "前往 OpenClaw 对话" 入口 + 待确认动作 + 最近动作 + Hook 状态 |
| `actions` | 动作审批页：按状态筛选 + 分页浏览 + 确认继续/拒绝 |
| `settings` | 安全扫描页：基线扫描 + 审计导出 |

## API 依赖

前端通过 HTTP 调用后端以下端点：

| 端点 | 用途 |
|------|------|
| `GET /api/summary` | 获取全量摘要数据 |
| `POST /api/actions/approve` | 批准待确认动作 |
| `POST /api/actions/reject` | 拒绝待确认动作 |
| `POST /api/baseline/run` | 触发基线扫描 |
| `POST /api/audit/export` | 导出审计数据 |

## 与后端的边界

- 前端**不**直接调用 OpenClaw Gateway
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

`openclaw_guard/legacy_web.py`（legacy）和 `openclaw_guard/web/routes/static.py`（FastAPI）负责托管 `runtime/ui/` 下的静态文件（`/`、`/assets/*`、前端路由的 SPA fallback）。
