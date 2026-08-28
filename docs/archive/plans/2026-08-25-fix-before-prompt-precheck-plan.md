# Fix before_prompt_build Precheck Plan

> **归档状态（2026-08-28）：** 已执行的 Bug 修复计划；现行 Hook 行为见 [`features/runtime-hook.md`](../../features/runtime-hook.md)。

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Prevent the non-blocking `before_prompt_build` precheck from creating phantom Guard approvals while preserving real `before_tool_call` approval and resolution synchronization.

**Architecture:** Keep `before_prompt_build` as a telemetry/precheck path that always returns `allow` and does not enter the pending action lifecycle. Keep `before_tool_call` as the only Hook path that can create `pending_approval` and receive OpenClaw `onResolution`. Remove duplicate dashboard rendering of a pending action from the recent-actions section.

**Tech Stack:** Python pipeline/tests, Preact frontend, JSON runtime action store.

## Global Constraints

- Do not change OpenClaw’s native approval ownership.
- Do not create or expose a Guard approval for `before_prompt_build`.
- Preserve audit visibility for real `before_tool_call` actions.
- Preserve historical action records; do not delete runtime history as part of the code fix.
- Add regression coverage before implementation and run the full test/build suite afterward.

### Task 1: Add failing regression tests

**Files:**
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_approval_sync.py` only if shared assertions are needed

- [x] Add a test asserting `before_prompt_build` returns `allow` and creates no `pending_approval` action.
- [x] Add a test asserting a real `before_tool_call` with an ask decision still creates exactly one `pending_approval` action.
- [x] Run the focused tests and confirm the new precheck assertion fails against the current implementation.

### Task 2: Fix backend precheck lifecycle

**Files:**
- Modify: `openclaw_guard/engine/pipeline.py`
- Modify: `openclaw_guard/integrations/tool_hook_bridge.py` if classification needs a dedicated precheck type

- [x] Skip persistence and `action.created` publication for `before_prompt_build`, or persist it only as a non-pending telemetry record; the minimal behavior is no pending action.
- [x] Keep the real `before_tool_call` branch unchanged for `require_approval`, `onResolution`, and `after_tool_call` reconciliation.
- [x] Prevent `before_prompt_build` from falling through the generic unknown-tool `command_exec` classification where practical.
- [x] Run focused regression tests and the existing Hook approval tests.

### Task 3: Remove duplicate pending presentation

**Files:**
- Modify: `frontend/src/pages/Dashboard.jsx`
- Test: existing frontend build; add a focused UI test only if an existing test harness supports it without installing dependencies

- [x] Exclude `pending_approval` items from the recent-actions list, or deduplicate by `action_id`, so one action renders once on Dashboard.
- [x] Keep the dedicated pending section as the sole current-approval status display.
- [x] Run `npm run build`.

### Task 4: Verify and document

- [x] Run focused tests, then `python -m pytest -q`.
- [x] Run `npm run build` in `frontend/` and `npm run docs:build` in `docs/`.
- [x] Inspect runtime action semantics with a temporary service fixture; do not mutate the user’s running runtime history.
- [x] Update the relevant Hook/frontend documentation if behavior wording is stale.
- [x] Run `git diff --check` and report whether the user’s running process needs a restart to load the generated plugin/code.
