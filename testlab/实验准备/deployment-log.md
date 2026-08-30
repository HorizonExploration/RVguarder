# AgentDojo 部署操作记录

> **历史部署快照（2026-05-31）**：安装记录保留用于追溯。当前环境需以 `agentdojo-upgrade-environment.md` 的 `--preflight` 为准；该记录中的旧环境曾使用 Pydantic 1.10.26，现已在独立环境升级到 Pydantic 2.13.5 并通过预检。

## 1. 部署时间
2026-05-31

## 2. 环境配置
- **操作系统**: Linux (Ubuntu 24.04)
- **Conda 版本**: 26.3.2
- **Python 版本**: 3.11.15 (AgentDojo 专用环境)
- **镜像源**: 清华大学开源软件镜像站 (TUNA)

## 3. 部署步骤记录

### 3.1 创建 Conda 环境
```bash
~/miniconda3/bin/conda create -n agentdojo python=3.11 -y
```
- **结果**: 成功创建 `agentdojo` 环境，安装 Python 3.11.15 及相关基础依赖。

### 3.2 安装 AgentDojo
```bash
~/miniconda3/bin/conda run -n agentdojo pip install -i https://pypi.tuna.tsinghua.edu.cn/simple agentdojo
```
- **结果**: 成功安装 `agentdojo==0.1.35` 及其所有依赖项，包括：
  - `openai>=1.59.7`
  - `anthropic>=0.47.0`
  - `langchain>=0.1.17`
  - `cohere>=5.3.4`
  - `google-genai>=1.15.0`
  - `rich>=13.7.1`
  - 等其他 40+ 个依赖包。

### 3.3 验证安装
```bash
~/miniconda3/bin/conda run -n agentdojo python -m agentdojo.scripts.benchmark --help
```
- **结果**: 命令正常输出帮助信息，确认 AgentDojo 可正常调用。
- **可用模型**: 支持 GPT-4o, Claude 3.5/3.7, Gemini 2.5, Llama 3 等主流大模型。
- **可用攻击类型**: 包括 `direct`, `ignore_previous`, `system_message`, `tool_knowledge`, `dos` 等 17 种攻击策略。
- **可用防御类型**: 包括 `tool_filter`, `transformers_pi_detector`, `spotlighting_with_delimiting`, `repeat_user_prompt` 等。

## 4. 兼容性说明

| 项目 | 说明 |
| :--- | :--- |
| **OpenClaw Guard 环境** | `conda env: openclaw-guard`, Python 3.13 |
| **AgentDojo 环境** | `conda env: agentdojo`, Python 3.11 |
| **隔离方式** | 两个 Conda 环境完全独立，互不干扰 |
| **交互方式（历史）** | 早期脚本曾通过 HTTP API 发送检测请求；当前 CandidateArm 仅在官方 AgentDojo 工具执行前调用 `/api/hook/before-tool-call`，NoGuard/Legacy 不调用该 HTTP 端点。 |

## 5. 注意事项

1. 运行 AgentDojo 实验需要配置相应的 LLM API Key（如 `OPENAI_API_KEY`）。
2. 实验过程中，OpenClaw Guard 必须处于运行状态。
3. 实验日志将默认保存在 `./runs` 目录下，建议自定义 `--logdir` 路径。
