# 模块说明

## 资产发现

负责识别：

- OpenClaw 配置路径
- OpenClaw 根目录
- Workspace / Logs
- 当前 Profile
- 本地常见端口和运行环境基础信息

## 基线扫描

负责检测：

- `openclaw.json` 是否存在
- 配置权限是否过宽
- 运行账户是否过高
- 环境中是否存在额外开放端口
- 是否能定位依赖描述
- 基础系统安全配置是否异常

输出：

- JSON
- HTML
- PDF
- 一键修复脚本

## 行为采集

当前实现以 Hook Bridge、OpenClaw 原生 Hook 与事件摄入为主，并预留：

- `ptrace`
- `eBPF`

## 检测引擎

当前内置 47 条高危规则，覆盖：

- 命令执行
- 删除 / 写入
- 配置修改
- 外联
- API / Channel
- Skill 运行

## 权限管控

通过：

- 白名单
- 风险分级
- `allow / ask / block / escalate`
- 二次确认词

实现对动作的实际前置决策。

其中运行时主链已经接入 OpenClaw 原生：

- `before_tool_call`
- `after_tool_call`

## 审计溯源

采用：

- SQLite
- JSONL 追加备份
- 哈希链校验
- JSON / CSV 导出

## 管理界面

当前提供两种模式：

- `launch`：完整模式
- `normal`：简洁模式
