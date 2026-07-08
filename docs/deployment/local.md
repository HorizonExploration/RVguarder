# 本地部署

## 推荐流程

```bash
cd OpenClaw-RVGuarder
pip install -e .
openclaw-guard run
```

启动后自动完成：发现 OpenClaw 配置 → 准备目录 → 补齐基线 → 生成 Hook 插件 → 启动工作台。

## 常见用法

### 启动主服务

```bash
openclaw-guard run
```

### 启动但不自动打开浏览器

```bash
openclaw-guard run --no-browser
```

### 仅做一次性自检（不启动长期服务）

```bash
openclaw-guard run --once --no-browser
```

### 运行基线扫描

```bash
openclaw-guard baseline
```

### 导出审计数据

```bash
openclaw-guard export-audit /path/to/audit.json
```

### 检查运行链路健康状况

```bash
openclaw-guard doctor
```

## 建议目录

- 项目目录：`OpenClaw-RVGuarder/`
- OpenClaw 配置：`~/.openclaw/openclaw.json`

## 卸载

由于 Guard 是纯 Python 包，卸载只需：

```bash
openclaw-guard uninstall-hook   # 先移除 OpenClaw 配置中的 Hook 引用
pip uninstall openclaw-guard
```
