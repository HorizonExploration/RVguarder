# 基线扫描与合规检测

## 功能目标

在不修改 OpenClaw 源码的前提下，对运行环境做快速、结构化、可导出的安全基线检查。

## 当前覆盖项

- 配置文件是否存在
- 配置权限是否过宽
- 当前运行用户是否过高
- 是否存在额外开放端口
- 是否能发现依赖描述文件
- 系统基础网络配置是否异常

## 输出内容

- `compliance-report.json`
- `compliance-report.html`
- `compliance-report.pdf`
- `baseline-remediation.sh`

## 使用方式

```bash
python -m openclaw_guard.main baseline --config-path ~/.openclaw-dev/openclaw.json
```

## 风险分级

- `critical`
- `high`
- `medium`
- `low`
- `info`

## 目前仍可继续完善

- 增加依赖清单级别的合规检测
- 增加更细的文件权限与属主检查
- 增加端口来源解释与更低噪音策略
