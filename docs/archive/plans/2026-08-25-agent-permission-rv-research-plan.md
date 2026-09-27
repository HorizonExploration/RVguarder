# Agent Permission and Runtime Verification Research Plan

> **归档状态（2026-08-28）：** 已执行的内部研究计划；当前研究结论见 [`research/index.md`](../../research/index.md)。

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce an evidence-backed research report and an executable roadmap for strengthening RVguarder’s policy knowledge base, permission-risk model, cross-session runtime verification, and attack-validation program.

**Architecture:** Preserve the current fast deterministic enforcement path and OpenClaw-native approval ownership. Add a canonical permission/policy ontology before the existing `DetectionEngine`/`ConstraintEngine`, evolve `ToolCallIR` into an authorization trace, and extend the current per-session FSM/RV layer with persistent, indexed security state and explicit cross-session invariants. Validate each upgrade with local, non-destructive attack fixtures before changing production enforcement.

**Tech Stack:** Markdown/VuePress, Python 3.13+, Pydantic v2, existing `ToolCallIR`, `ConstraintEngine`, `RuntimeVerificationEngine`, JSON/SQLite stores, pytest/unittest, and local mock tool traces.

**Spec:** `docs/research/agent-permission-rv-research-report-2026-08-25.md`

## Global Constraints

- Do not replace the current OpenClaw-native approval owner or introduce a second approval UI.
- Do not allow an LLM to be the final authorization decision maker; use it only for structured extraction with confidence and abstention.
- Preserve existing rule/FSM compatibility and fail-safe behavior for unknown or uncovered permissions.
- Do not execute destructive attacks against real OpenClaw, external accounts, or user data; all validation fixtures are local mocks.
- Every generated rule must carry provenance, version, test vectors, and an explicit coverage/uncertainty result.
- Cross-session aggregation must key on an authenticated principal/agent identity and capability lineage, not merge unrelated sessions by text similarity.

---

### Task 1: Freeze the evidence baseline

**Files:**
- Read: `openclaw_guard/rv/ir.py`, `openclaw_guard/rv/constraints.py`, `openclaw_guard/rv/runtime_verification.py`, `openclaw_guard/spec/session_state.py`
- Read: `docs/ops/roadmap.md`, `docs/semantic/method.md`, `docs/architecture/project-status-analysis.md`
- Test: existing `tests/test_rv*.py`, `tests/test_semantic_enhancer.py`

- [ ] Record current fields, rule paths, decision semantics, session keys, state serialization, and missing persistence in the report.
- [ ] Establish baseline measurements for rule-hit precision/recall, unknown-action rate, decision latency, and cross-session false-negative cases using deterministic fixtures.
- [ ] Keep this baseline immutable so later experiments can compare against it.

### Task 2: Define the canonical permission and policy model

**Files:**
- Design: `docs/research/agent-permission-rv-research-report-2026-08-25.md`
- Future create: `openclaw_guard/policy/ontology.py`, `openclaw_guard/policy/catalog.py`, `policies/permissions/*.json`
- Future test: `tests/test_permission_ontology.py`

- [ ] Define the authorization tuple: principal, agent, session, tool, operation, resource, data class, context, current grants, requested delta, provenance, and expiry.
- [ ] Define normalized permissions and relationships for the project’s high-frequency tools: read, write, delete, execute, network egress, send, export, credential access, config/audit modification, and skill execution.
- [ ] Define policy effects (`allow`, `ask`, `block`, `revise`) separately from evidence (`matched`, `uncovered`, `ambiguous`, `conflicting`).
- [ ] Define rule metadata: stable ID, owner, version, source, validity window, severity, rationale, test vectors, and rollback status.

### Task 3: Upgrade semantic decomposition and rule coverage

**Files:**
- Future modify: `openclaw_guard/engine/semantic_enhancer.py`, `openclaw_guard/rv/ir.py`, `openclaw_guard/rv/constraints.py`, `openclaw_guard/engine/detection.py`
- Future test: `tests/test_policy_trace_coverage.py`, `tests/test_semantic_paraphrase_matrix.py`

- [ ] Require schema-constrained extraction into canonical authorization events and trace steps.
- [ ] Add provenance and confidence for every extracted field; represent missing/contradictory fields explicitly instead of silently dropping them.
- [ ] Add a coverage pass that maps every trace step to zero or more catalog rules and returns an explainable gap when none match.
- [ ] Keep hard deny/approval predicates deterministic; treat low-confidence or uncovered high-impact operations as `ask`/`revise`, not `allow`.
- [ ] Test paraphrases, negation, scope, recipients, time windows, multi-target requests, and tool-name spoofing.

### Task 4: Add permission-risk and toxic-combination analysis

**Files:**
- Future create: `openclaw_guard/policy/risk_graph.py`, `openclaw_guard/policy/permission_diff.py`
- Future modify: `openclaw_guard/spec/session_state.py`, `openclaw_guard/rv/runtime_verification.py`
- Future test: `tests/test_permission_risk_graph.py`, `tests/test_cross_session_risk.py`

- [ ] Compute effective permissions as the closure of direct grants, role inheritance, relationships, temporary grants, and tool capabilities.
- [ ] Compare current effective set with the requested delta; flag redundancy, privilege expansion, external reachability, sensitive-data reachability, and SoD/toxic combinations.
- [ ] Model high-risk combinations as hyperedges/invariants, not only single-event labels.
- [ ] Store a bounded event-sourced security state per principal/agent/session/resource with TTL, sequence numbers, deduplication, and snapshot recovery.
- [ ] Add cross-session joins only for authenticated identity/capability lineage and preserve separate session-local traces.

### Task 5: Build the controlled attack-validation lab

**Files:**
- Create: `testlab/research/README.md`
- Create: `testlab/research/fixtures.py`, `testlab/research/scenarios.json`
- Test: `tests/test_research_attack_fixtures.py`

- [x] Implement local deterministic trace fixtures; no network, shell, real credentials, or external side effects.
- [x] Include indirect prompt injection, over-broad tool permission, credential-read plus egress, configuration plus audit-disable, semantic paraphrase, and cross-session privilege accumulation scenarios.
- [ ] Record attack success, blocked/asked decision, rule coverage, trace fidelity, false positives, decision latency, and audit evidence.
- [ ] Run the same fixtures against the baseline and upgraded engines and export a comparison table.

### Task 6: Convert findings into phased delivery

**Files:**
- Modify: `docs/ops/roadmap.md`
- Modify: `docs/architecture/index.md`
- Modify: `docs/research/agent-permission-rv-research-report-2026-08-25.md`

- [ ] Phase P0: catalog and trace contract; no external dependency.
- [ ] Phase P1: coverage/evidence reporting and permission-delta risk checks.
- [ ] Phase P2: persistent cross-session state and toxic-combination monitor.
- [ ] Phase P3: offline rule synthesis/validation and red-team regression gate.
- [ ] Define measurable exit criteria and rollback criteria for each phase.

## Verification Checklist

- [ ] Each literature claim links to a primary paper, standard, or official industrial documentation.
- [ ] Every recommendation identifies the exact existing module it changes or leaves untouched.
- [ ] Baseline and upgraded attack fixtures are deterministic and side-effect free.
- [ ] `python -m pytest -q` remains green after each implementation phase.
- [ ] `npm run docs:build` succeeds after report/navigation updates.
