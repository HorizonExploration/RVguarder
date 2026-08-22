# 架构文档索引

> 版本：v1.1 | 日期：2026-08-14 | 状态：阶段一~六 ✅ 阶段七 ⏳ ｜ RV 阶段 A–F ✅

---

本文档集全面涵盖 OpenClaw-RVGuarder 从 v0.2.1 到目标 v1.0 的架构分析、框架选型、分阶段实施计划、目标架构设计及质量保障措施。当前已完成前六个阶段（FastAPI HTTP 层、Pydantic 模型迁移、Manager 拆分、Preact 前端、SQLAlchemyStore 可选存储、RV 规约驱动）与 RV 升级阶段 A–F（IR 结构化、约束推理引擎、基线自动机、参数化原语、NL2Spec 生成、干预升级），阶段七（长期优化：CI、typing、metrics）为下一目标。

---

## 文档清单

### 核心文档（现行）

| 文档 | 摘要 | 阅读顺序 |
|------|------|---------|
| [overview.md](./overview.md) | **架构总览**：分层设计（管理层/管控层/检测层/监控层）与决策流 | **1** |
| [rv-engine-report.md](./rv-engine-report.md) | **RV 层技术报告**：规约 DSL、监视器编译、约束引擎、基线自动机、已知边界 | **2** |
| [nl-automata-rv-landing-report.md](./nl-automata-rv-landing-report.md) | **RV 落地审计报告**：阶段 A–F 逐项核验 + 异常整改闭环 | **3** |
| [project-status-analysis.md](./project-status-analysis.md) | **项目现状分析**：前端/后端/核心功能三类问题清单与推进顺序 | **4** |
| [quality-assurance.md](./quality-assurance.md) | **质量保障方案**：测试金字塔、API 测试策略、回归验证矩阵、代码质量门禁、性能基准 | **5** |

### 历史重构文档（阶段一~六，已执行完毕）

| 文档 | 摘要 | 状态 |
|------|------|------|
| [architecture-analysis.md](./architecture-analysis.md) | 架构分析报告：技术栈全景、模块依赖、技术痛点矩阵 | ✅ 已完成（历史参考） |
| [framework-evaluation.md](./framework-evaluation.md) | 框架选型评估：FastAPI vs Flask vs Litestar | ✅ 已完成（历史参考） |
| [refactoring-plan.md](./refactoring-plan.md) | 渐进式重构计划：6 阶段划分与验收标准 | ✅ 已完成（历史参考） |
| [target-architecture.md](./target-architecture.md) | 目标架构设计：目录结构、前后端交互规范 | ✅ 已完成（历史参考） |

---

## 文档健康状态（2026-08-14 体检）

| 文档 | 状态 | 处理建议 |
|------|------|---------|
| `archive/rv-development-plan.md`、`archive/rv-feasibility-report.md`、`archive/rv-engine-comparison-v3.md` | 🗑️ **已删除**（2026-08-14） | transitions FSM 时代文档，已被 `rv-engine-report.md` 取代 |
| `research/nl-automata-rv-upgrade.md` | 🗑️ **已删除**（2026-08-14） | 调研方案 v0.1，已被 `research/nl-automata-rv-upgrade-plan.md` 取代 |
| `comparison/rvguard-vs-guardrail.md` | 🗑️ **已删除**（2026-08-14） | 早期对比，已被 `comparison/rvguard-vs-agent-security-tools.md` 取代 |
| `features/rv-layer-analysis.md` | 🗑️ **已删除**（2026-08-14） | RV 层历史分析，已被 `architecture/rv-engine-report.md` 取代 |
| 其余 `features/`、`deployment/`、`api/`、`semantic/`、`dev/`、`ops/` 文档 | ✅ 现行 | 保持 |

> 上述 6 个文档已删除，`docs/` 内部交叉引用与 `.vuepress/config.ts` 导航均已同步清理，无死链。

---

## 核心结论速览

### 选型决策

**选定 FastAPI**，理由：
- Pydantic v2 彻底解决手动序列化/验证的技术债务
- 零侵入侵入现有业务逻辑层（engine/core/storage 不动）
- 自动 OpenAPI 文档
- 社区 85k stars，长期可维护
- 迁移成本约 2-3 个工作日

### OpenClaw 合约约束（改动需对照官方文档）

| 合约项 | 保护手段 |
|--------|---------|
| `runtime/openclaw-guard-plugin/` JS 插件层 | 合约测试 + 文档对照 |
| `/api/hook/*` 端点响应格式 | Pydantic 模型约束 + 合约测试 |
| `registerGatewayMethod()` 声明 | 文档对照 + PR 审查 |
| `x-openclaw-guard-token` 鉴权 | FastAPI Header 注入 |

### 实施路径

```
阶段一 (2-3天) HTTP 层替换 → FastAPI 路由 + API 端点            ✅
    ↓
阶段二 (1-2天) Pydantic 模型迁移 → 替代手动 to_dict()           ✅
    ↓
阶段三 (3-5天) Manager 拆分 + 懒加载 → 终结上帝对象 + 启动 ≤ 2秒 ✅
    ↓
阶段四 (3-4天) 前端 Preact 迁移 → 组件化 SPA，首屏 ≤ 20KB       ✅
    ↓
阶段五 (2-3天) 存储层升级 → SQLAlchemy 可选                      ✅
    ↓
阶段六 (2-3天) RV 规约驱动 → 声明式 ChainRule 替代手写 FSM      ✅
    ↓
阶段七 (持续)  长期优化 → 异步、监控、CI、结构化日志             ⏳
```

### 总工期

约 25-30 个工作日（含稳定期回归测试 + 文档更新），分 7 个风险隔离阶段，每阶段结束均可正常交付业务。

---

## 相关文档

- `README.md`（仓库根）— 项目说明
- `CLAUDE.md`（仓库根）— 开发协作约定
- [architecture/overview.md](./overview.md) — 当前架构总览
- [ops/roadmap.md](../ops/roadmap.md) — 产品路线图
