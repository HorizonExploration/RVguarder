# Documentation Cleanup Implementation Plan

> **归档状态（2026-08-28）：** 已执行的内部文档清理计划；当前文档结构见 [`docs/archive/README.md`](../../archive/README.md)。

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Align current documentation with the implemented v0.6.0 code, remove invalid local links, and explicitly preserve historical experiment artifacts.

**Architecture:** Keep historical reports and `testlab/` unchanged. Update current-source documents (`docs/README.md`, architecture status/memory/report pages, API/frontend docs) to describe OpenClaw-only Hook approval, SSE synchronization, current test baseline, and the legacy/FastAPI compatibility boundary.

**Tech Stack:** Markdown, VuePress, Python/pytest verification.

**Spec:** User-approved documentation cleanup scope in the conversation.

## Global Constraints

- Do not delete or move `testlab/` historical artifacts.
- Do not install dependencies without user approval.
- Do not change production behavior in this cleanup pass.
- Current test baseline is `349 passed / 18 skipped` from `python -m pytest -q`.
- Historical `CHANGELOG.md` entries retain their wording; only absolute local file URIs are normalized to repository-relative links.

### Task 1: Update current project facts

**Files:**
- Modify: `docs/README.md`
- Modify: `docs/architecture/project-memory.md`
- Modify: `docs/architecture/project-status-analysis.md`

- [x] Replace stale 345/18 baseline with 349/18 and date it.
- [x] Replace dual-sided Hook approval wording with OpenClaw-only approval and Guard read-only synchronization.
- [x] Mark `testlab/` as preserved historical evidence, not runtime code.
- [x] Update stale current-status conclusions without rewriting historical sections.

### Task 2: Fix current architecture/API descriptions

**Files:**
- Modify: `docs/architecture/frontend-handoff-redesign-report.md`
- Modify: `docs/api/http.md`
- Modify: `docs/dev/frontend.md`
- Modify: `docs/features/runtime-hook.md`

- [x] Document `GET /api/actions/{action_id}` and `GET /api/events`.
- [x] Document SSE-first synchronization with polling fallback.
- [x] Document Hook approval rejection from Guard endpoints (`409 hook_approval_owned_by_openclaw`).
- [x] Correct frontend refresh description from full 1.5-second polling to SSE plus compact-summary fallback.

### Task 3: Repair invalid local references

**Files:**
- Modify: `docs/README.md`
- Modify: `docs/deployment/docker-k8s.md`
- Modify: `docs/semantic/office-scenario-matrix.md`
- Modify: `CHANGELOG.md` only where absolute local `file://` links are present (historical wording retained).

- [x] Keep valid site-root VuePress links; normalize repository-facing links where appropriate.
- [x] Remove or replace references to non-existent `docker/`, `k8s/`, and old `openclaw_guard/integrations/detection.py` paths.
- [x] Keep external URLs unchanged.

### Task 4: Verify and report

- [x] Run `python -m pytest -q` → `349 passed, 18 skipped`.
- [x] Run `npm run docs:build` in `docs/` → 32 pages rendered successfully.
- [x] Run a repository-relative Markdown link scan → no broken relative links in project docs.
- [x] Run `git diff --check`; no historical artifact was deleted or moved (one report received link-only repairs).
- [x] Update the current memory/documentation baseline with verification results.
