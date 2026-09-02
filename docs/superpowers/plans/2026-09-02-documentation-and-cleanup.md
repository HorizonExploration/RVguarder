# Documentation and Repository Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 使现行文档与 v0.7.0-dev 代码事实一致，并在不删除历史实验与评测证据的前提下清理可确认的生成物和失效描述。

**Architecture:** 以 `docs/architecture/v070-engineering-unification-report-2026-09-02.md`、`docs/architecture/project-memory.md` 和 `docs/ops/roadmap.md` 作为现行事实源；历史方案与实验材料保留在原位置并加快照说明。清理仅限被 `.gitignore` 排除的生成物或经引用扫描确认不属于生产/测试路径的内容。

**Tech Stack:** Markdown/VuePress, Python 3.13+, pytest, Vite, Git.

**Spec:** User request: 更新对应文档，全面清查项目文件，检查过时无用部分并进行缩减；保留历史实验产物。

## Global Constraints

- 不删除 `docs/archive/`、`testlab/` 历史实验、AgentDojo 评测证据或 LEGACY 回放数据。
- 不修改或提交 `.env`；其中的凭据仍需保持本地。
- 不使用 `git reset --hard` 或 `git checkout --`。
- 每项删除先通过生产代码、测试和文档引用扫描确认。
- 文档中的当前版本以 `v0.7.0-dev` / PMKB `1.1.0` 为准。

### Task 1: Establish stale-content inventory

**Files:**
- Inspect: `README.md`, `docs/**/*.md`, `AGENTS.md`, `CLAUDE.md`
- Inspect: `openclaw_guard/`, `tests/`, `frontend/`, `testlab/`

- [x] 搜索旧入口、旧规则计数、旧 DetectionEngine 现状描述，并记录需要更新的现行文档。
- [x] 搜索未被引用的 Python/JS/Markdown 文件；将历史文件与生产候选分开。
- [x] 验证 `.gitignore` 是否覆盖 `__pycache__`、运行时日志、前端构建产物。

### Task 2: Update current documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/README.md`
- Modify: `docs/architecture/project-status-analysis.md`
- Modify: `docs/architecture/permission-kb-runtime-architecture.md`
- Modify: `docs/semantic/method.md`
- Modify: `docs/research/openclaw-architecture-brief-2026-08-31.md`

- [x] 删除或改写仍把 legacy HTTP 描述为默认、把 DetectionEngine 描述为生产组件的现行段落。
- [x] 统一 PMKB 当前统计与测试事实；历史快照保留日期和上下文。
- [x] 明确前端测试缺口、真实 OpenClaw 同步验证缺口、采集器探测桩和 LLM 降级边界。

### Task 3: Safe repository reduction

**Files:**
- Modify: `.gitignore` only if a verified generated path is missing
- Remove: only generated/untracked files confirmed safe by Task 1

- [x] 不删除历史目录；对可安全移除的缓存执行最小清理，不触碰运行日志。
- [x] 删除无引用的一次性飞书写入脚本；未发现其他可安全删除的 tracked production file。

### Task 4: Verify and record

**Files:**
- Modify: `docs/architecture/v070-engineering-unification-report-2026-09-02.md` if findings changed

- [x] 运行 `pytest -q`、`cd frontend && npm run build`、`cd docs && npm run docs:build`。
- [x] 运行 `git diff --check` 和旧事实扫描，确认当前文档只保留明确的历史快照描述。
- [x] 汇总删除/保留清单、验证结果和剩余风险，不修改 `.env`。

### Task 5: Remove confirmed dead code

**Files:**
- Modify: `openclaw_guard/services.py`
- Modify: `openclaw_guard/web/app.py`
- Modify: `openclaw_guard/policy/trace.py`
- Modify: `openclaw_guard/engine/command_safety.py`
- Modify: `scripts/train_baseline.py`

- [x] 删除重复的类型检查导入、未使用类型导入和无占位符 f-string。
- [x] 删除命令安全分析中无效果的空分支；保留抽象接口、兼容方法和异常恢复分支。
- [x] 运行 `pyflakes openclaw_guard scripts`，确认仅剩包级 `__init__.py` 显式重导出提示。
- [x] 运行全量 Python 测试并检查差异格式。
