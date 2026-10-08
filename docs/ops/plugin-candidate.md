# 插件测试候选交付

最新工具建模候选位于 `dist/rvguard-atlas-model-candidate-v1/`，包含 OpenClaw Hook插件tgz、后端wheel和`SHA256SUMS`。[新包验收](../research/close-experiment-gaps/atlas-model-package-acceptance-v1.json)核验独立安装、规则数、包内容、历史完整性和可重复构建；尚未对这一新归档完成整套SDK安装验收。原`dist/rvguard-m4-candidate-v3/`及其原生安装证据保留。当前候选是`test-candidate`，`release_qualified=false`。

## 已验证环境

| 项目 | 实测版本 |
| --- | --- |
| OpenClaw | 2026.9.5（ec9c1a1） |
| Node | 24.19.0 |
| Python | 3.13.13 |
| Docker | 29.8.0 |
| 系统 | 本机 Linux/WSL；其他系统和版本未核验 |

实验拓扑是隔离宿主 Gateway、Guard 与模型代理，Agent 工具在仅挂载合成工作区的 Docker 沙箱运行。宿主私有授权库和签名密钥不挂载到工具沙箱。

## 安装与配置

先校验产物；后端安装在独立 Python 环境。以下命令仅用于新建的测试 profile，替换本机路径：

```sh
cd dist/rvguard-atlas-model-candidate-v1
sha256sum -c SHA256SUMS
python -m pip install backend/openclaw_guard-0.7.0.dev0-py3-none-any.whl
openclaw --profile rvguard-dev plugins install ./openclaw-guard-hook.tgz --force --accept-capabilities
openclaw-guard run --project-dir /path/to/test-workspace --config-path /path/to/isolated/openclaw.json --no-browser
```

`--force` 确认安装本地归档，`--accept-capabilities` 确认插件声明的工具钩子与审批能力。先审阅包内 manifest 和源码，再显式确认。

按包内 `guard.config.example.json` 配置 `plugins.entries.openclaw-guard-hook.config`。`guardUrl` 指向后端；`authToken` 从本地后端运行状态取得，只写入私有运行配置。不得把 Token、API key、数据库或工作区放入候选包。重启隔离 Gateway 后检查 Hook 状态。

## 规约与保护边界

新wheel随包默认JSON仍为version 2、67条；默认加载显式追加5条原生请求边界规约，有效72条。可选`openclaw_guard/rv/profiles/atlas-tool-policy-v2.json`是version 3、122条。显式加载旧r4路径仍为109条，不隐式添加。启用方式、精确授权与新增审批的边界见[建模升级报告](../research/close-experiment-gaps/atlas-model-upgrade-v1.md)。72/122条组合均未经新冻结主矩阵评估，不能继承旧Q5成绩。

有限工具调用映射是 RV 建模单位。明确 RV block 独立阻断；任务授权仅豁免确切匹配的授权守卫，不覆盖其他规则。可信授权/内容证据需要相应执行器的受控宿主证明，本轮仅验证指定办公路径，不承诺所有 MCP 自动具备该证明。

## 故障与卸载

后端未启动、失联、超时、HTTP 错误或响应不可解析时，所有工具透传；这段时间没有 Guard 防护保证。恢复由原生插件健康探测处理，不需要修改 Agent。旧v3归档实际SDK安装后已验证allow/ask/block、四类错误透传、连续健康恢复及卸载后Docker写读；新归档尚未重复这项整套验收。

```sh
openclaw --profile rvguard-dev plugins uninstall openclaw-guard-hook --force
```

SDK 会删除安装记录，可能保留 `enabled=false` 的配置条目；以插件未加载和实际工具完成核验卸载。重启测试 Gateway。日常 Gateway 不参与这些命令。

证据入口：[整改执行记录](../research/close-experiment-gaps/README.md)和[本轮缺陷](../research/close-experiment-gaps/m3-m4-defect-followup.md)。

## 可重复构建

先执行 `cd frontend && npm run build`。在仓库根目录新建候选（不要覆盖历史包）：

```sh
python -m openclaw_guard.main build-plugin --output dist/<new-candidate>
SOURCE_DATE_EPOCH=0 python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist/<new-candidate>/backend
```

固定 `SOURCE_DATE_EPOCH` 才能使 wheel ZIP 时间戳一致；未固定时内容相同也可能字节不同。
