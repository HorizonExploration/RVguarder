# Docker 与 Kubernetes

## Docker

项目已提供：

- [Dockerfile](/Users/dynooob/Projects/OpenClaw/OpenclawGuard/docker/Dockerfile)

适合：

- 本地容器化验证
- 与 OpenClaw 一起编排
- 便于复制部署环境

## Kubernetes

项目已提供：

- [openclaw-guard-sidecar.yaml](/Users/dynooob/Projects/OpenClaw/OpenclawGuard/k8s/openclaw-guard-sidecar.yaml)

推荐用作：

- Sidecar 模式
- 与 OpenClaw 容器同 Pod 运行
- 保持非侵入部署结构

## 当前说明

当前版本已经具备容器化结构，但正式上线前建议补：

- 容器健康检查
- 资源限制
- 持久化卷说明
- 日志归档策略
- 72 小时稳定性验证记录
