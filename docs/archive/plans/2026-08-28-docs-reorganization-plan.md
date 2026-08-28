# Documentation Reorganization Implementation Plan

> **归档状态（2026-08-28）：** 本次文档整理的执行记录；整理结果见 [`docs/archive/README.md`](../../archive/README.md)。

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reorganize the project documentation into current, research, semantic, testing, operational, and historical categories while preserving useful experiment records and removing dead navigation/link references.

**Architecture:** Keep implementation-facing documents in their existing topical directories. Move superseded architecture reports, completed research plans, and internal execution artifacts into `docs/archive/` with a manifest and explicit historical labels. Make `project-memory.md`, the current status report, roadmap, PMKB reports, and frontend handoff report the authoritative current set.

**Tech Stack:** Markdown, VuePress, TypeScript navigation configuration, Git path moves, pytest documentation checks, npm documentation build.

**Spec:** User request to classify, refresh, and prune `/home/yosoro126/OpenClaw-RVGuarder/docs` while retaining historical experiment artifacts.

## Global Constraints

- Do not delete historical experiment or research evidence that may be needed for traceability; archive it instead.
- Do not change runtime code or production behavior in this documentation-only pass.
- Current PMKB baseline is immediately enforceable; do not reintroduce a calendar-based shadow gate.
- Active docs must point to current files; no links may target moved or deleted paths.
- The VuePress build must exclude `archive/**` and internal execution plans from the published navigation.

---

### Task 1: Define the active documentation map

**Files:**
- Modify: `docs/architecture/index.md`
- Create: `docs/research/index.md`
- Create: `docs/test-design/index.md`
- Create: `docs/archive/README.md`

- [x] Replace the stale architecture index with an authoritative reading order and current-vs-historical policy.
- [x] Add research and test-design indexes that identify the canonical documents.
- [x] Add an archive manifest explaining why each archived category is retained and which current document supersedes it.

### Task 2: Reclassify superseded documents without data loss

**Files:**
- Move: old architecture reports to `docs/archive/architecture/`
- Move: superseded research notes/plans to `docs/archive/research/`
- Move: internal execution plans/specifications to `docs/archive/plans/` and `docs/archive/specs/`
- Move: historical RV comparison experiment to `docs/archive/experiments/`

- [x] Use Git moves so history remains traceable.
- [x] Add a historical-status banner to moved documents with a link to the current replacement.
- [x] Keep the formal OpenClaw guard test design and current PMKB/RV reports in active sections.

### Task 3: Refresh current facts and links

**Files:**
- Modify: `docs/architecture/project-status-analysis.md`
- Modify: `docs/architecture/quality-assurance.md`
- Modify: `docs/architecture/target-architecture.md`
- Modify: `docs/architecture/project-memory.md`
- Modify: `AGENTS.md`
- Modify: `CLAUDE.md`
- Modify: all active docs with references to moved paths

- [x] Update dates, commit/test baselines, PMKB immediate-enforcement wording, and current known boundaries.
- [x] Replace references to archived paths with current indexes or archive paths.
- [x] Remove claims that historical stages are still pending when the current memory says otherwise.

### Task 4: Align VuePress navigation and publishing rules

**Files:**
- Modify: `docs/.vuepress/config.ts`

- [x] Exclude `archive/**` and `superpowers/**` from page generation.
- [x] Make architecture, research, and test-design sidebars list only active canonical documents.
- [x] Point the research navbar entry to the new research index.

### Task 5: Verify and prune only dead generated artifacts

**Files:**
- No runtime source changes.

- [x] Search for stale path references and calendar-shadow wording.
- [x] Run `python -m pytest -q tests/test_policy_docs.py`.
- [x] Run `npm run docs:build` from `docs/`.
- [x] Run the full test suite and `git diff --check`.
- [x] Remove only generated, ignored documentation build output if it is accidentally tracked; retain all source/history documents.
