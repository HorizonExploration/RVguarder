# PMKB 1.2 Native Rules and LLM Semantics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace all 47 runtime LEGACY compatibility rules with typed PMKB-native rules and make every configured tool call use one sanitized, best-effort LLM semantic pass without giving the model authorization authority.

**Architecture:** Deterministic tool, command, path, recipient, and scope evidence is merged with a validated `SemanticMatchIR`. The LLM emits only canonical operation candidates and controlled facts; PMKB, PermissionDiff, RiskGraph, and RV remain the deterministic decision owners. A versioned migration manifest retains historical traceability after runtime legacy matching is deleted.

**Tech Stack:** Python 3.13, Pydantic v2, JSON PMKB, pytest, FastAPI/OpenClaw Hook, existing DeepSeek-compatible HTTP endpoint.

**Spec:** Approved conversational design from 2026-09-20; no separate tracked spec file.

## Global Constraints

- PMKB bundle becomes `1.2.0`; package version remains `0.7.0.dev0` / `v0.7.0-dev`.
- No new dependencies and no network access in tests.
- Configured calls attempt exactly one LLM request with a 1.5 second timeout and no retry; failures use local deterministic fallback.
- Raw secrets, credentials, cookies, full file contents, raw payloads, and exact sensitive values never leave the process.
- LLM evidence cannot independently auto-allow or hard-block; OpenClaw remains the sole approval owner.
- Historical experiment results and archived documents remain intact.

## Review Focus

- Empty user intent still receives one semantic attempt using sanitized tool facts.
- Suggested LLM facts cannot become verified through serialization or merge order.
- Conflicting deterministic and LLM evidence becomes approval, never allow.
- All 47 legacy IDs have a native owner and both positive and near-miss vectors.
- Removing legacy matching does not weaken the existing command, file, egress, config, and Skill hard-block boundaries.

---

### Task 1: Typed semantic IR and sanitization

**Files:** Create `openclaw_guard/engine/semantic_models.py`; modify `semantic_enhancer.py`; create `tests/test_semantic_matcher.py`.

- [x] Write failing tests for controlled operation candidates, fact validation, secret redaction, empty-intent LLM attempts, invalid JSON, timeout, and local fallback.
- [x] Run the focused tests and confirm failures are caused by missing v3 interfaces.
- [x] Implement the typed IR, fact registry, sanitizer, validated prompt/response adapter, one-attempt behavior, and audit status.
- [x] Run semantic and Hook bridge tests until green.
- [x] Commit the task.

### Task 2: Authorization Trace evidence and evaluator trust semantics

**Files:** Modify `policy/models.py`, `policy/trace.py`, `policy/evaluator.py`, and focused policy tests.

- [x] Write failing tests for `security_facts`, deterministic precedence, suggested-only allow/block downgrade, conflict approval, priority selection, and partial-default approval.
- [x] Confirm the tests fail on current legacy behavior.
- [x] Implement fact evidence propagation, `rv_steps`, nested `facts.*` matching, trust-aware effects, and priority/specificity selection.
- [x] Run evaluator, trace, permission, and policy pipeline tests until green.
- [ ] Commit the task.

### Task 3: PMKB 1.2 and all 47 native migrations

**Files:** Modify the PMKB loader and data bundle; add native rule/vector/trace/migration JSON files; update package parity tests.

- [x] Write failing catalog and migration tests requiring PMKB 1.2, glob-loaded components, 47 unique native owners, no runtime `LEGACY-*`, and positive/near-miss replay.
- [x] Confirm the current 1.1 bundle fails those requirements.
- [x] Add canonical facts and rules for CMD, FILE, NET, API, SKL, CFG, and GEN groups; add `skill.execute`; add migration manifest and 94 vectors.
- [x] Extend loader validation for multi-file bundles, migration ownership, unique IDs, references, and packaged parity.
- [x] Run catalog, vectors, migration, RiskGraph, RV compiler, and pipeline tests until green.
- [ ] Commit the task.

### Task 4: Remove compatibility paths and consolidate tests

**Files:** Delete `policy/legacy.py` and obsolete test modules; remove AgentDojo runtime branches; redistribute unique long-term assertions.

- [x] Write/adjust tests asserting no legacy or AgentDojo runtime symbols remain and historical assets are untouched.
- [x] Delete dynamic LEGACY rule generation and legacy-label evaluator branches.
- [x] Replace `legacy_steps` with `rv_steps` in current contracts while leaving archived JSON untouched.
- [x] Merge unique assertions, then delete one-time/redundant modules named in the approved plan.
- [x] Run collection and the complete Python suite; confirm the retained suite exercises each behavior once at the appropriate layer.
- [ ] Commit the task.

### Task 5: Documentation, builds, and end-to-end verification

**Files:** Update current architecture, project memory, roadmap, semantic method, migration matrix, test design, README, and changelog.

- [ ] Update all current facts and counts to PMKB 1.2 and document LLM privacy/failure semantics.
- [ ] Build frontend and docs; run link and diff checks.
- [ ] Run complete pytest, compileall, Chromium and Firefox Playwright smoke tests, and runtime plugin syntax/inspection checks.
- [ ] Review the whole branch, fix Critical/Important findings with RED→GREEN tests, and record deferred minors.
- [ ] Commit the verified documentation and fixes.
