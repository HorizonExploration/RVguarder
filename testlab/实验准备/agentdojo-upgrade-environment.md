# AgentDojo 升级评测环境

## 目的

AgentDojo 仅用于 `testlab` 的合成环境评测，不加入 OpenClaw-RVGuarder 主包依赖，也不连接真实文件、邮件、银行或 OpenClaw 生产资源。

## 固定版本

| 组件 | 要求 |
|---|---|
| Python | 3.11（独立环境） |
| AgentDojo | `0.1.35` |
| benchmark suite | `v1.2.2` |
| Pydantic | `>=2.7.1` |
| OpenAI SDK | `>=1.59.7` |
| Guard | 项目本地运行实例，默认 `127.0.0.1:8780` |

## 预检

```bash
cd /home/yosoro126/OpenClaw-RVGuarder
python testlab/脚本工具/agentdojo_upgrade_eval.py \
  --preflight \
  --agent-python /home/yosoro126/miniconda3/envs/agentdojo/bin/python
```

预检会输出 Python、AgentDojo、Pydantic 版本和 `ready`。本次修复后的环境为：

```text
Python 3.11.15
agentdojo 0.1.35
pydantic 2.13.5
ready: true
```

Pydantic 已升级到 2.13.5，AgentDojo 官方模块可以正常导入，`pip check` 无 broken requirements。

本次仅修改独立 `agentdojo` 环境；OpenClaw Guard 项目环境未修改。后续若重建环境，仍需保持 `pydantic[email]>=2.9.0,<3`，并重新运行预检。

## DeepSeek 配置

在运行环境中配置以下变量，脚本不会把密钥写入 manifest 或结果：

```bash
export DEEPSEEK_API_KEY='...'
export DEEPSEEK_BASE_URL='https://api.deepseek.com/v1'
export DEEPSEEK_MODEL='deepseek-chat'
```

只发送 AgentDojo 合成任务和工具参数。结果中的 `api_key`、`token`、`password`、`secret`、`credential` 和 `authorization` 字段会被遮罩。

## 运行前提

1. 先通过 `--preflight`。
2. 确认 Guard 已启动并监听指定 URL。
3. CandidateGuard 使用 `/api/hook/before-tool-call`；NoGuard 和 LegacyGuard 不调用该 HTTP 端点。
4. 结果写入带时间戳的 `testlab/results/agentdojo-upgrade/`，不会覆盖历史实验。
