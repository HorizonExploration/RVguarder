# v0.7.0 Engineering Unification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 将 8 月 30 日修复与评测证据纳入可审计发布口径，并把 FastAPI、PMKB 和 OpenClaw 单一审批链收敛为生产唯一实现。

**Architecture:** 项目版本统一为 `0.7.0-dev`，PMKB 版本统一为 `1.1.0`。FastAPI 是唯一运行入口，`legacy_web.py` 只作为冻结历史文件；PMKB evaluator 负责运行时授权，历史 `LEGACY-*` 规则仅作为离线回放证据和迁移审计数据。

**Tech Stack:** Python 3.13, FastAPI/Uvicorn, Pydantic v2, pytest, Vite/VuePress.

**Spec:** 用户 2026-09-02 的工程统一要求与仓库内 PMKB 1.1.0 迁移记录。

## Global Constraints

- 不提交 `.env` 或任何凭据；历史实验产物保留在 archive/testlab evidence。
- 不删除历史研究、实验结果和兼容记录；仅移除生产运行时旧实现及其失效引用。
- `0.7.0-dev` 是代码包、README/运行文档和运行状态的项目版本；所有 PMKB 数据组件必须为 `1.1.0`。
- FastAPI 缺失时必须显式报错，不得静默回退到 `legacy_web`。
- DetectionEngine 只有在 LEGACY 逐条回放门禁通过后才从生产代码和测试导入中删除。

### Task 1: Version and entry-point contract

**Files:** `pyproject.toml`, `openclaw_guard/__init__.py`, `openclaw_guard/main.py`, `tests/test_web_cli.py`, docs/architecture and ops entry-point docs.

- [x] Add failing tests for package version `0.7.0-dev` and FastAPI as the default selector.
- [x] Remove `--fastapi` mode switch and legacy fallback; make missing FastAPI dependencies an actionable error.
- [x] Update non-archived docs and runtime version response to the same project version.
- [x] Run focused CLI/version tests.

### Task 2: LEGACY replay gate

**Files:** `openclaw_guard/policy/legacy.py`, `openclaw_guard/policy/catalog.py`, `openclaw_guard/rv/constraints.py`, `tests/test_legacy_policy_migration.py`.

- [x] Keep the 47 historical records as frozen metadata outside the runtime evaluator.
- [x] Replay every record against PMKB and assert effect/risk/action equivalence, including the `LEGACY-*` candidate.
- [x] Remove catalog/constraint imports from the retired engine and make the replay test the deletion gate.
- [x] Run migration and policy tests.

### Task 3: PMKB-only runtime decision path

**Files:** `openclaw_guard/policy/engine.py`, `openclaw_guard/engine/pipeline.py`, `openclaw_guard/services.py`, `openclaw_guard/core/action_service.py`, tests.

- [x] Convert `PolicyDecision` into the existing `DetectionDecision` transport shape without changing OpenClaw hook responses.
- [x] Replace runtime `services.detector` calls with PMKB evaluation; retain constraint/RV overlays only where their existing contracts require them.
- [x] Remove `DetectionEngine` construction, imports and metrics from production services.
- [x] Keep replay/evidence tooling on frozen legacy metadata only.
- [x] Run full Python tests plus hook-specific regressions.

### Task 4: Documentation and evidence alignment

**Files:** `README.md`, `AGENTS.md`, `CLAUDE.md`, `docs/**`, `testlab/**` metadata.

- [x] Replace stale default-legacy and dual-track claims in active docs; mark archived documents as historical where needed.
- [x] Link 8-30 evaluation evidence and the replay gate from the research/quality pages.
- [x] Add a current-state/problem/decision report that records Feishu access limitation, known risks, and validation results.
- [x] Build frontend and VuePress docs.

### Task 5: Safe commit and handoff

- [x] Review the complete diff, exclude `.env`, generated secrets, and unrelated files.
- [x] Run `git diff --check`, focused tests, full tests, frontend build and docs build.
- [x] Commit the complete safe change set with a release-oriented message; do not push without an explicit push request.
