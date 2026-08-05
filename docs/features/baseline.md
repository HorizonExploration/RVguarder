# 基线扫描与合规检测

## 功能目标

在不修改 OpenClaw 源码的前提下，对运行环境做快速、结构化、可导出的安全基线检查。

## 当前覆盖项

- 配置文件是否存在（BASE-001 / 001A）
- 配置权限位检查（BASE-002 / 002A）
- Gateway 鉴权配置（BASE-002B ~ 002F）
- 当前运行用户是否过高（BASE-003 / 003A）
- 是否存在额外开放端口（BASE-004 / 004A）
- 依赖描述文件检查（BASE-005 / 005A）
- 系统基础网络配置是否异常（BASE-006 / 006A）
- 工作区 / 日志目录（BASE-010 / 010A / 011 / 011A）
- Gateway 健康（BASE-012 / 012A）
- Hook 运行时（BASE-013 / 013A）
- 插件信任策略（BASE-013B / 013C）
- 模型解析（BASE-014 / 014A）

## 输出内容

- `compliance-report.json`
- `compliance-report.html`
- `compliance-report.pdf`
- `baseline-remediation.sh`

## 使用方式

```bash
openclaw-guard baseline
```

## 风险分级

- `critical`
- `high`
- `medium`
- `low`
- `info`

## 已实现与仍规划

已实现：
- 依赖描述检查（BASE-005 / 005A）：能发现 OpenClaw 源码 `package.json` 依赖描述文件
- 配置权限位检查（BASE-002 / 002A）：配置文件权限按最小权限原则校验

仍规划：
- CVE / 许可证级别的依赖清单合规检测
- 端口来源解释与更低噪音策略
- 更细的文件属主检查
