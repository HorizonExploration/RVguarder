# 测试设计索引

> 测试设计文档描述验证意图和场景；可执行测试以仓库 `tests/` 为准。

## 当前有效

- [OpenClaw-RVGuarder 测试设计方案](./openclaw-guard-test-design.md)：基于个人办公场景矩阵，覆盖 Hook、审批同步、RV、审计、基线和异常边界。

## 运行方式

```bash
python -m pytest -q
cd docs && npm run docs:build
```

历史 RV 与静态检测对比实验仍保留在 `docs/archive/experiments/`，用于复现实验假设和结果，不作为当前回归门禁。
