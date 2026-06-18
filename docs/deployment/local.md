# 本地部署

## 推荐流程

```bash
cd /Users/dynooob/Projects/OpenClaw/OpenclawGuard
bash scripts/install.sh
source .venv/bin/activate
python -m openclaw_guard.main normal
```

## 常见模式

### 普通用户

```bash
python -m openclaw_guard.main normal
```

### 管理或测试

```bash
python -m openclaw_guard.main launch
```

### 只做检测

```bash
python -m openclaw_guard.main normal --once --no-browser
```

## 建议目录

- 项目目录：`OpenclawGuard/`
- OpenClaw 配置：`~/.openclaw-dev/openclaw.json` 或 `~/.openclaw/openclaw.json`

## 卸载

```bash
bash scripts/uninstall.sh
```
