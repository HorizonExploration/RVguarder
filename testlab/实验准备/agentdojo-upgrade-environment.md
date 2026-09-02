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

## OpenAI-compatible 模型配置

在运行环境中配置以下变量，脚本不会把密钥写入 manifest 或结果：

```bash
export DEEPSEEK_API_KEY='...'
export DEEPSEEK_BASE_URL='https://api.deepseek.com/v1'
export DEEPSEEK_MODEL='deepseek-chat'
```

变量名保持 `DEEPSEEK_*` 以兼容现有评测脚本，但它们可以指向任意 OpenAI-compatible 服务。例如 MiniMax：

```bash
DEEPSEEK_API_KEY='你的密钥'
DEEPSEEK_BASE_URL='https://api.minimaxi.com/v1'
DEEPSEEK_MODEL='MiniMax-M2.7-highspeed'
```

推荐把配置放在项目根目录 `.env`，不要把密钥写入命令历史或提交 Git。模型余额和 Token Plan 速率不足会导致 402/429；对应 episode 必须计为无效样本。

只发送 AgentDojo 合成任务和工具参数。结果中的 `api_key`、`token`、`password`、`secret`、`credential` 和 `authorization` 字段会被遮罩。

AgentDojo 0.1.35 会把系统消息序列化为 `developer`，部分 OpenAI-compatible 端点仍要求 `system`；`testlab/agentdojo_upgrade.py` 已在评测边界自动完成角色归一化，不修改 AgentDojo 安装包。Candidate 组还需要 Hook 鉴权 token；若未通过环境变量传入，可从本地运行时状态读取：

```bash
export OPENCLAW_GUARD_HOOK_TOKEN="$(python -c 'import json; print(json.load(open("runtime/hook-bridge.json"))["auth_token"])')"
```

## 运行前提

1. 先通过 `--preflight`。
2. 确认 Guard 已启动并监听指定 URL。
3. CandidateGuard 使用 `/api/hook/before-tool-call`；NoGuard 和 LegacyGuard 不调用该 HTTP 端点。
4. 结果写入带时间戳的 `testlab/results/agentdojo-upgrade/`，不会覆盖历史实验。

## 推荐运行规模

评测脚本默认使用 `--profile demo`：workspace、banking 各 4 个用户任务和 3 个注入任务，保留两类代表攻击和 baseline，共 168 个 episode，适合日常回归与项目汇报。需要更宽覆盖时显式指定 `--profile full`；该 profile 已将原任务矩阵缩减约 60%，每个 Arm 约 1155 个 episode。API 额度有限时优先使用 demo，不要把 401/402/429 失败样本计入安全结论。
