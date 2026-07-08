# 项目梳理导航

本目录汇总了针对 `OpenClaw-RVGuarder` 的专项梳理与结构优化结果。

## 目录结构

- [使用指南](./normal-mode.md)
  - "开启即用"的统一使用方式，包含 `openclaw-guard run` 与维护子命令。
- [作为安全插件的定位](./plugin-positioning.md)
  - 明确本项目是"OpenClaw 的一种使用场景下的安全插件"，约束了它该做什么、不该做什么。
- [重排方案：前后端分离 + 只保留核心](./restructure-plan.md)
  - "前后端分离 + 只保留核心"的目录与删减清单，已完成实施。
- [前端开发说明](./frontend.md)
  - 前端独立工程的开发、构建与部署方式。
- [项目全景分析](./project-overview.md)
  - 说明项目定位、技术栈、核心模块职责、依赖关系与运行流程。
- [项目结构清单](./project-structure.md)
  - 以标准化目录树形式说明核心目录、源码文件、配置文件、资源文件及其用途。
- [项目清理与优化记录](./project-cleanup.md)
  - 记录本次已完成的清理动作、发现的问题、保留项和后续结构优化建议。

## 阅读顺序

1. 先看 [使用指南](./normal-mode.md)，了解怎么用。
2. 再看 [作为安全插件的定位](./plugin-positioning.md)，明确本项目的边界。
3. 接着看 [重排方案：前后端分离 + 只保留核心](./restructure-plan.md)，了解重排背景与已完成事项。
4. 看 [前端开发说明](./frontend.md)，了解前端独立开发方式。
5. 然后看 [项目全景分析](./project-overview.md)，建立对业务与运行链路的整体理解。
6. 接着看 [项目结构清单](./project-structure.md)，快速定位目录与文件职责。
7. 最后看 [项目清理与优化记录](./project-cleanup.md)，了解本次具体调整与后续建议。

## 说明

- 本次梳理重点覆盖运行主链 `openclaw_guard/`、前端工程 `frontend/`、文档站 `docs/`、测试 `tests/`、实验区 `testlab/` 与研究笔记区 `docs/Sematic/`。
- 使用指南已按"单一主入口 + 维护子命令"重写，不再区分 normal / launch / chat / interactive 等多模式。
- `testlab/` 与 `docs/Sematic/` 显式保留，不作为重排对象。
- 前端已从 `ui.py` 内嵌字符串独立为 `frontend/` 工程，`pnpm build` 输出到 `runtime/ui/`。
- 输出以"当前有效结构 + 已完成清理 + 后续建议"的方式呈现，避免为了追求形式上的重排而破坏现有运行入口。
