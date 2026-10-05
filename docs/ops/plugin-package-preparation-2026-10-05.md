# 插件打包准备与本轮执行记录

## 状态

首个目标为OpenClaw插件，产物为**测试候选包**，未发布、未安装到日常Gateway。完整优化计划见 [实验问题优化计划](../superpowers/plans/2026-10-05-rv-experiment-optimization-plugin.md)。资源关联/可信授权和跨会话缺口尚未修复，公开摘要误阻仍存在。

## 已实施的优化

1. 原生审批解析保留退出码、受限错误码及传输失败类型；不保存原始响应、stdout/stderr或任意错误消息。诊断器容忍畸形字段。首次未准入记录不能视为攻击阻止。
2. 插件增加`startupHealthCheck`配置：开启时注册期间异步探活，覆盖未触发`gateway_start`的路径；定时器复用并清理，工具不等待探活。默认不开启，保留既有静默启动契约；候选包配置示例开启此项。探活前和失联时仍透传。
3. 后端wheel显式包含`rv_rules.json`，避免源码开发可用但安装后规约缺失。
4. 增加`build-plugin`CLI：复用生产JS生成器，不初始化Manager，不读取/嵌入本机Hook令牌，不修改OpenClaw配置。归档确定性，拒绝覆盖已有输出。

RV独立block保留，本轮没有改DSL规约或历史实验成绩。

需要如实澄清随包规约的口径：本次wheel携带的`rv_rules.json`是2026-10-04工具调用迁移后的 **version 2 / 67条规则**（仓库HEAD为 version 1 / 66条），即相对已提交基线确有规则改动（新增`tool_unmodeled_effect_ask`并全面改写状态模型），且该迁移**尚未经过新的冻结安全评估**。因此`verification.json`里的`dsl_rules_modified: false`只表示"本轮未再改动规约"，不可被读作"随包规则与历史基线一致"。重新打包时应将该字段改名为`dsl_rules_modified_in_this_round`，或在旁边直接标注随包规则版本。

## 构建与产物

在仓库根目录执行，输出目录必须尚不存在：

```sh
python -m openclaw_guard.main build-plugin --output dist/rvguarder-candidate
python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist/rvguarder-candidate/backend
```

当前候选：`dist/rvguarder-test-candidate-20261005-r2/`，包含插件tgz、插件目录、配置示例、后端wheel、验证记录与SHA256SUMS。后端运行时仍需安装Python依赖；插件与后端不是一个独立可执行程序。

首版 `dist/rvguarder-test-candidate-20261005/` 不再作为候选：其 `verification.json` 只记录三个专项子集而未跑全量回归，且 `dsl_rules_modified` 字段与随包规则实际版本矛盾。本版已修正并补齐全量回归。

OpenClaw 2026.9.5本机帮助已确认支持本地tgz安装。后续仅在隔离profile执行：

```sh
openclaw --profile rvguard-dev plugins install ./dist/rvguarder-candidate/openclaw-guard-hook.tgz
```

本轮没有实际执行安装。认证令牌应本地配置，不能放进发行包。完整Docker安装、卸载、后端恢复及新冻结安全评估仍是发布前必要步骤；wheel的前端资源交付也需单独核验。

## 验证

- 全量回归：`python -m pytest tests/ -q` → 740 passed、20 skipped、0 failed。修复前，测试内真实调用 `main()` 会执行 `load_dotenv`，把仓库 `.env` 的密钥永久写入同进程 `os.environ`，导致全量为 1 failed（`test_semantic_enhancer` 触发真实 LLM 请求并超时）。已在 `test_plugin_package.py`、`test_web_cli.py` 隔离该调用，并新增 `tests/conftest.py` 在每个测试后还原环境变量。
- 专项子集（首版记录）：106 passed；29 passed、9 skipped（跳过不是通过）；7 passed。三者均已被全量回归覆盖。
- wheel在干净临时目录独立加载：79条PMKB规则、9个行为监视器、67条RV DSL规则（version 2）；确认含RV/策略JSON，排除.env、runtime及实验记录。
- 生成JS通过Node语法检查。归档重复构建字节一致由回归测试验证。
- 验证范围为回归与构建，不是新安全实验；旧holdout8/12的历史结果不能据此称为重新验证。

## 下一步

优先实施计划阶段二：可信资源关联与细粒度授权，修复公开摘要误阻且保留相近未知攻击阻断。随后修复复合调用、跨会话及拦截时机，再做新30场景冻结holdout。达到发布门后再正式封装与发布。
