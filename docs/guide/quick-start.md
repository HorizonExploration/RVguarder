# 快速开始

## 1. 环境要求

- Python 3.13+
- Node.js 与 npm
- 已在本机完成 OpenClaw 初始化，或至少存在 `openclaw.json`
- 本地可执行 `python -m openclaw_guard.main`

## 2. 推荐启动方式

```bash
cd OpenclawGuard
bash scripts/install.sh
source .venv/bin/activate
python -m openclaw_guard.main normal
```

## 3. 启动后会发生什么

- 自动探测本机 OpenClaw 的配置路径、工作区和日志目录
- 自动准备 `runtime/`、`output/`、`exports/` 等目录
- 如果还没有基线结果，会自动补一次基线扫描
- 自动生成 OpenClaw Guard 本地 Hook 插件，并尝试写入 `plugins.load.paths`
- 启动本地 Web 工作台
- 默认尝试打开浏览器

## 4. 首次启用 Hook 需要做什么

如果这是第一次在当前 OpenClaw 环境里启用龙虾卫士的运行时 Hook，Guard 会把本地插件路径写进 `openclaw.json`。  
这一步完成后，需要按你的真实启动方式重启一次 OpenClaw gateway，Hook 才会真正进入运行时。

如果你的 OpenClaw 是在源码目录里通过 npm 启动的，推荐命令：

```bash
cd /path/to/openclaw
npm run openclaw gateway
```

重启后，你就可以在动作页里看到真正的“执行前审批”效果：删除、写入、配置修改、危险命令和外联请求都会先被拦住。

## 5. 开发与运维模式

如果你需要完整页面、更多安全细节和管理入口，可以使用：

```bash
python -m openclaw_guard.main launch
```

## 6. 常见命令

```bash
python -m openclaw_guard.main normal
python -m openclaw_guard.main normal --once --no-browser
python -m openclaw_guard.main baseline --config-path ~/.openclaw-dev/openclaw.json
python -m openclaw_guard.main export-audit
```

## 7. 主要输出目录

- `output/reports/`：基线扫描报告
- `output/audit/`：SQLite 审计库与 JSONL 备份
- `output/fixes/`：自动生成的修复脚本
- `runtime/`：界面初始状态、最近基线结果、前端构建产物
- `runtime/openclaw-guard-plugin/`：自动生成的 OpenClaw 本地 Hook 插件
- `runtime/hook-bridge.json`：Hook 本地鉴权令牌和桥接状态
- `exports/`：取证导出文件

<div class="soft-note">
  <strong>提示：</strong>`normal` 模式适合普通用户。它会把复杂的安全信息收进设置页，首页主要保留对话、待确认动作和关键运行状态。
</div>

## 8. 对照官方资料

- [OpenClaw Control UI](https://docs.openclaw.ai/control-ui)
- [OpenClaw Session Management](https://docs.openclaw.ai/concepts/session)
- [OpenClaw Hooks](https://docs.openclaw.ai/automation/hooks)
