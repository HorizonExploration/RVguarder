# 架构总览

Openclaw Guard 采用分层、非侵入、模块化设计，核心原则是：**不修改 OpenClaw 源码，不替换系统库，通过外部壳、本地插件和行为代理完成安全增强。**

## 分层结构

```text
管理层
  ├─ Web 工作台
  ├─ 报告与导出
  └─ 配置与操作入口

管控层
  ├─ 白名单
  ├─ 审批流
  ├─ allow / ask / block / escalate
  └─ 二次确认

检测层
  ├─ 高危规则引擎
  ├─ 风险分级
  └─ 规则命中追踪

监控层
  ├─ 资产发现
  ├─ 基线扫描
  ├─ 行为采集
  └─ ptrace / eBPF / Hook Bridge / OpenClaw 原生 Hook
```

## 当前代码映射

- `discovery.py`：资产发现、运行环境探测
- `baseline.py`：基线扫描、报告生成、修复脚本
- `behavior.py`：行为事件摄入
- `detection.py`：47 条高危规则与检测引擎
- `whitelist.py`：Trie / Radix Tree 白名单匹配
- `control.py`：动作决策、审批状态流
- `audit_store.py`：SQLite + JSON 审计与哈希链
- `manager.py`：统一编排与主业务入口
- `hook_runtime.py`：生成并安装 OpenClaw Guard 本地 Hook 插件（使用官方 `api.on()` API）
- `tool_hook_bridge.py`：把 `before_tool_call` / `after_tool_call` 转成 Guard 行为事件
- `openclaw_adapter.py`：Gateway 远程调用适配层（含 `resolve_plugin_approval` 双端同步）
- `web.py` / `ui.py`：本地 Web 工作台

## 关键设计原则

1. **非侵入**：不改 OpenClaw 原始代码。
2. **先决策，后执行**：高风险动作必须先进入 action gate，工具执行前由 `before_tool_call` 拦截。
3. **可取证**：所有关键动作留痕，并可导出。
4. **可扩展**：规则、白名单、扫描项都可以继续增长。
