# Docker 与 Kubernetes

> **规划中 / 未实现（截至 2026-08-05）**：当前仓库不包含任何 `Dockerfile`、`docker/` 或 `k8s/` 目录，也不存在 Kubernetes 清单。本文档仅为规划记录，下文链接均指向尚不存在的文件。

## Docker

规划中：

- `docker/Dockerfile`（文件不存在，尚未实现）

适合（规划目标）：

- 本地容器化验证
- 与 OpenClaw 一起编排
- 便于复制部署环境

## Kubernetes

规划中：

- `k8s/openclaw-guard-sidecar.yaml`（文件不存在，尚未实现）

推荐用作（规划目标）：

- Sidecar 模式
- 与 OpenClaw 容器同 Pod 运行
- 保持非侵入部署结构

## 当前说明

容器化结构尚未实现，正式落地前建议补：

- 容器健康检查
- 资源限制
- 持久化卷说明
- 日志归档策略
- 72 小时稳定性验证记录
