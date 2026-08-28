# Permission Knowledge Base and Modeling Upgrade Implementation Plan

> **归档状态（2026-08-28）：** 已执行的权限知识库实施计划；当前交付状态见 [`research/pmkb-network-baseline-implementation-report-2026-08-28.md`](../../research/pmkb-network-baseline-implementation-report-2026-08-28.md)。

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a versioned personal-office permission knowledge base and deterministic authorization model that reduces false “unmatched → manual approval” outcomes while preserving hard blocking, least privilege, toxic-combination detection, and OpenClaw’s single approval owner.

**Architecture:** Add a local PMKB policy layer beside the existing detector/constraint/RV components. A typed `AuthorizationTrace` is compiled from each Hook event, matched against schema-validated policy records, compared with the principal’s effective permissions, and checked against sparse toxic hyperedges. The existing detector, ConstraintEngine, and session RV remain compatible safety overlays; a unified policy result can only raise a decision’s severity, never lower an existing block or approval.

**Tech Stack:** Python 3.13+, Pydantic v2, stdlib JSON/YAML-compatible data files, existing Python `unittest`/pytest suite, current JSON/SQLite-compatible stores, React/Vite documentation and frontend build tooling.

**Spec:** `docs/archive/specs/2026-08-27-openclaw-rvguarder-five-phase-upgrade-design.md`

## Global Constraints

- OpenClaw is the Hook approval owner; Guard APIs for Hook actions remain read-only synchronization semantics.
- All external Hook input is untrusted; missing, malformed, or uncorrelated fields must be explicitly recorded.
- Existing `DetectionEngine`, `ConstraintEngine`, and RV DSL/FSM remain compatible and available as fallback.
- Deterministic `before_tool_call` decisions must not wait for an LLM, embedding service, or remote policy database.
- Every rule, permission relation, and risk combination carries version, source, positive/negative examples, and rollback state.
- No third-party dependency may be added without user approval.
- Unknown, partial, or conflicting coverage must never silently become a safe allow.
- `match_confidence` describes understanding/coverage; `risk_score` describes security impact. They are separate values.

## File and Interface Map

Create a focused `openclaw_guard/policy/` package:

- `models.py`: typed PMKB records and authorization decision data models.
- `catalog.py`: load and validate versioned ontology, tool mapping, and policy bundles.
- `trace.py`: compile `BehaviorEvent` plus semantic output into `AuthorizationTrace`.
- `evaluator.py`: deterministic candidate retrieval, predicate matching, coverage and confidence.
- `permission_diff.py`: effective-permission closure, requested delta, redundancy and least-privilege checks.
- `risk_graph.py`: sparse `implies`, `conflicts`, `delegates`, `owns`, and `toxic_with` relations.
- `engine.py`: orchestration facade consumed by the existing pipeline.

Create versioned data under `policies/permissions/`:

- `schema/permissions.schema.json`: field names, types and enumerations used by the loader.
- `catalog/operation-catalog.json`: Feishu-inspired business domains mapped to OpenClaw operation families.
- `rules/p0-office.json`: P0 allow, clarify, approval and block policies.
- `relations/p0-combinations.json`: permission implications and toxic hyperedges.
- `traces/p0-office.json`: least-privilege traces for EX-10, EX-19 and EX-27.
- `tests/p0-vectors.json`: positive, negative, boundary and unknown vectors.

Modify only these existing integration points:

- `openclaw_guard/models.py`: add optional serialized policy evidence without breaking old action records.
- `openclaw_guard/engine/pipeline.py`: compile/evaluate policy evidence and apply severity monotonicity.
- `openclaw_guard/services.py`: construct the policy engine from the versioned local bundle.
- `openclaw_guard/spec/session_state.py` and `openclaw_guard/rv/runtime_verification.py`: add principal/capability keyed state only after policy evidence is available.
- `docs/semantic/method.md`, `docs/semantic/office-scenario-matrix.md`, `docs/api/http.md`, `docs/ops/roadmap.md`: document contracts, examples and metrics.

---

### Task 1: Define typed PMKB and Authorization Trace models

**Files:**
- Create: `openclaw_guard/policy/__init__.py`
- Create: `openclaw_guard/policy/models.py`
- Modify: `openclaw_guard/models.py:150-175`
- Test: `tests/test_policy_models.py`
- Create: `tests/policy_factories.py`

**Interfaces:**
- Produces `PrincipalRef`, `OperationRef`, `ResourceRef`, `CapabilityGrant`, `AuthorizationTrace`, `CoverageResult`, `MatchCandidate`, `PolicyDecision` and `PolicyRule`.
- `PolicyDecision.to_dict() -> dict[str, Any]` is embedded in `DetectionDecision.policy_decision` as an optional field, preserving old records when absent.

- [ ] **Step 1: Write failing model tests**

```python
def test_trace_requires_operation_and_preserves_unknown_scope():
    trace = AuthorizationTrace(
        trace_id="h1",
        principal=PrincipalRef(id="agent-1", type="agent", trust="verified"),
        operation=OperationRef(family="document.read", tool_id="docs.read"),
        resource=ResourceRef(type="document", scope="unknown"),
        coverage=CoverageResult(status="partial", missing_features=["resource.id"]),
    )
    assert trace.resource.scope == "unknown"
    assert trace.coverage.status == "partial"

def test_policy_decision_separates_confidence_and_risk():
    decision = PolicyDecision(
        effect="openclaw_approval",
        match_status="matched",
        match_confidence=0.94,
        risk_score=82,
        policy_version="p0.1.0",
    )
    assert decision.match_confidence == 0.94
    assert decision.risk_score == 82
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run: `python -m pytest tests/test_policy_models.py -q`

Expected: FAIL because `openclaw_guard.policy.models` and `DetectionDecision.policy_decision` do not exist.

- [ ] **Step 3: Implement the minimum typed models**

Use `Literal` values from the spec (`complete|partial|unknown|conflict`, `auto_allow_audit|clarify_then_retry|openclaw_approval|block`) and default empty lists/dicts. Set `DetectionDecision.policy_decision: dict[str, Any] | None = None`; do not alter existing required fields or existing `DecisionAction` values.

Add `tests/policy_factories.py` with deterministic factories used by later tests: `permission(family: str, *, scope: str = "unknown", classification: str = "internal") -> PermissionRef`, `grant(family: str, *, scope: str = "unknown") -> CapabilityGrant`, and `make_event(action_type: str, *, target_paths: list[str] | None = None, network_targets: list[str] | None = None) -> BehaviorEvent`. Keep factory defaults free of external I/O.

When later tasks introduce scenario-specific snippets, extend this same factory module with the named helpers before running those task tests: `trace_for_message(...)`, `trace_for_external_secret_egress()`, `trace_for_internal_read()`, `secret_read_trace(session_id: str)`, `external_egress_trace(session_id: str)`, `allow_policy()`, `approval_policy()`, `internal_message_payload()`, `secret_external_egress_payload()`, `unknown_tool_payload()`, `load_p0_vectors()`, and `evaluate_vector(vector)`. Each helper must construct typed local objects or deterministic payload dictionaries and must not call OpenClaw or a network service.

- [ ] **Step 4: Run focused and compatibility tests**

Run: `python -m pytest tests/test_policy_models.py tests/test_ir.py tests/test_pipeline.py -q`

Expected: PASS, with old serialized `DetectionDecision` fixtures loading when `policy_decision` is absent.

- [ ] **Step 5: Commit**

```bash
git add openclaw_guard/policy openclaw_guard/models.py tests/test_policy_models.py
git commit -m "feat: add typed authorization policy models"
```

### Task 2: Add Feishu-inspired operation catalog and versioned P0 policy data

**Files:**
- Create: `openclaw_guard/policy/catalog.py`
- Create: `policies/permissions/schema/permissions.schema.json`
- Create: `policies/permissions/catalog/operation-catalog.json`
- Create: `policies/permissions/rules/p0-office.json`
- Create: `policies/permissions/traces/p0-office.json`
- Create: `policies/permissions/relations/p0-combinations.json`
- Create: `policies/permissions/tests/p0-vectors.json`
- Test: `tests/test_policy_catalog.py`

**Interfaces:**
- `PolicyBundle.load(root: Path) -> PolicyBundle` loads all five files and raises `PolicyBundleError` with the file and field path for malformed data.
- `PolicyBundle.operation_for_tool(tool_id: str, params: dict[str, Any]) -> OperationRef` returns a known operation or `unknown_tool` with `coverage_gap="tool_mapping"`.
- `PolicyBundle.rules_for_operation(family: str) -> list[PolicyRule]` uses exact operation indexes before aliases.
- `PolicyBundle.p0_vectors() -> list[dict[str, Any]]` exposes deterministic test vectors without executing tools.

- [ ] **Step 1: Write failing loader and classification tests**

```python
def test_catalog_maps_feishu_like_domains_to_atomic_operations():
    bundle = PolicyBundle.load(Path("policies/permissions"))
    assert bundle.operation_for_tool("feishu.docs.read", {}).family == "document.read"
    assert bundle.operation_for_tool("feishu.im.send", {}).family == "message.send"
    assert bundle.operation_for_tool("feishu.bitable.export", {}).family == "table.export"

def test_catalog_keeps_unknown_tool_as_explicit_gap():
    operation = PolicyBundle.load(Path("policies/permissions")).operation_for_tool("new.tool", {})
    assert operation.family == "unknown_tool"
    assert operation.gaps == ["tool_mapping"]
```

- [ ] **Step 2: Run tests to verify the loader fails**

Run: `python -m pytest tests/test_policy_catalog.py -q`

Expected: FAIL because the bundle files and loader do not exist.

- [ ] **Step 3: Implement the catalog and data files**

Encode these domains: IM, directory, document/wiki/drive, sheets/bitables, calendar/meeting, workflow/approval, event/network, app/config. Every rule must include `id`, `version`, `effect`, `priority`, `match`, `required_fields`, `negative_conditions`, `obligations`, `source`, and `test_vectors`. Include P0 records for EX-10, EX-19 and EX-27 and the relations `secret.read + network.egress + external_target`, `data.export + external_recipient + sensitive_data`, `config.modify + audit.modify`, `credential.read + process.execute`, `file.write + persistence_location`.

Use only stdlib JSON parsing and explicit schema checks; do not add `jsonschema` or another dependency. Reject duplicate IDs, unknown effects, missing versions, and relation endpoints absent from the catalog.

- [ ] **Step 4: Run catalog tests and vector sanity checks**

Run: `python -m pytest tests/test_policy_catalog.py -q`

Expected: PASS; each P0 vector references a real rule ID and each operation maps to one atomic family.

- [ ] **Step 5: Commit**

```bash
git add openclaw_guard/policy/catalog.py policies/permissions tests/test_policy_catalog.py
git commit -m "feat: add versioned office permission catalog"
```

### Task 3: Compile Hook events into Authorization Trace

**Files:**
- Create: `openclaw_guard/policy/trace.py`
- Modify: `openclaw_guard/rv/ir.py:30-75`
- Modify: `openclaw_guard/engine/pipeline.py:55-105`
- Test: `tests/test_authorization_trace.py`

**Interfaces:**
- `TraceCompiler(bundle: PolicyBundle).compile(event: BehaviorEvent, *, semantic: dict[str, Any], rv_trace: list[dict[str, Any]], source_message: str = "") -> AuthorizationTrace`.
- `TraceCompiler` extracts principal, tool/operation, resource scope, data classification, recipient zone, purpose, provenance, and field confidence without making an allow/block decision.
- `AuthorizationTrace` retains old `ToolCallIR` props/entities/constraints through `legacy_steps` for RV compatibility.

- [ ] **Step 1: Write failing extraction tests**

```python
def test_compile_external_report_send_preserves_negation_and_scope():
    event = make_event(action_type="network_egress", network_targets=["partner.example"])
    trace = TraceCompiler(bundle).compile(
        event,
        semantic={"scenario": "report_send", "labels": ["internal_source"], "purpose": "report_delivery"},
        rv_trace=[],
    )
    assert trace.operation.family == "network.egress"
    assert trace.resource.scope == "external"
    assert trace.context.purpose == "report_delivery"

def test_compile_missing_recipient_is_partial_not_safe():
    event = make_event(action_type="channel_send")
    trace = TraceCompiler(bundle).compile(event, semantic={"scenario": "message_send"}, rv_trace=[])
    assert trace.coverage.status == "partial"
    assert "resource.recipient" in trace.coverage.missing_features
```

- [ ] **Step 2: Run focused tests to verify failure**

Run: `python -m pytest tests/test_authorization_trace.py -q`

Expected: FAIL because `TraceCompiler` and the typed trace fields do not exist.

- [ ] **Step 3: Implement deterministic trace compilation**

Normalize tool aliases before inspecting labels. Parse command parameters with `shlex` or the existing safe command parser; never execute a command. Derive `scope` from the already annotated workspace boundary, `resource` from paths/URLs/recipients, and `data.classification` from explicit metadata plus the highest classification in the trace. Preserve `negated`, `excluded_entities`, `quantity`, and `provenance`. Missing values become explicit `unknown`/`partial` fields.

- [ ] **Step 4: Run tests and verify backward compatibility**

Run: `python -m pytest tests/test_authorization_trace.py tests/test_ir.py tests/test_semantic_enhancer.py -q`

Expected: PASS; old `ToolCallIR` fixtures still validate and trace compilation never changes the original event action type.

- [ ] **Step 5: Commit**

```bash
git add openclaw_guard/policy/trace.py openclaw_guard/rv/ir.py openclaw_guard/engine/pipeline.py tests/test_authorization_trace.py
git commit -m "feat: compile authorization traces from hook events"
```

### Task 4: Implement coverage-aware deterministic policy matching

**Files:**
- Create: `openclaw_guard/policy/evaluator.py`
- Test: `tests/test_policy_evaluator.py`
- Modify: `tests/test_constraints.py` only when a compatibility assertion needs the new evidence field

**Interfaces:**
- `PolicyEvaluator(bundle: PolicyBundle).evaluate(trace: AuthorizationTrace) -> PolicyDecision`.
- `PolicyEvaluator.match_rule(rule: PolicyRule, trace: AuthorizationTrace) -> MatchCandidate`.
- `MatchCandidate.score` is the calibrated pre-deployment score `0.40*action + 0.25*entity_completeness + 0.20*specificity + 0.15*provenance_agreement`.
- Candidate statuses are `matched`, `partial`, `unknown`, `conflict`; missing fields and conflicts are returned, never discarded.

- [ ] **Step 1: Write failing coverage and routing tests**

```python
def test_known_internal_small_message_is_auto_allow_audit():
    trace = trace_for_message(recipient_zone="internal", recipient_count=2, classification="internal", purpose="meeting_notice")
    result = evaluator.evaluate(trace)
    assert result.effect == "auto_allow_audit"
    assert result.match_status == "matched"

def test_external_unknown_recipient_is_approval_with_gap():
    trace = trace_for_message(recipient_zone="unknown", recipient_count=None, classification="internal")
    result = evaluator.evaluate(trace)
    assert result.effect == "openclaw_approval"
    assert "context.recipient_zone" in result.missing_features

def test_conflicting_allow_and_block_rules_choose_block():
    trace = trace_for_message(recipient_zone="external", classification="secret", purpose="report_delivery")
    result = evaluator.evaluate(trace)
    assert result.effect == "block"
    assert result.conflicts == [] or "rule_conflict" in result.conflicts
```

- [ ] **Step 2: Run tests and confirm the evaluator is absent**

Run: `python -m pytest tests/test_policy_evaluator.py -q`

Expected: FAIL because `PolicyEvaluator` is not implemented.

- [ ] **Step 3: Implement exact-first matching and four-level routing**

Build indexes by operation family, resource type, and required field. Apply exact predicates for scope, quantity, classification, recipient zone, purpose, negation and exclusions. Use aliases only for candidate retrieval; aliases cannot by themselves produce `auto_allow_audit`. Select all applicable candidates, retain their IDs, and choose the strongest effect by `block > openclaw_approval > clarify_then_retry > auto_allow_audit`. A partial high-impact trace routes to approval; a partial low-impact trace with at most two missing fields routes to clarification.

- [ ] **Step 4: Run focused and existing rule tests**

Run: `python -m pytest tests/test_policy_evaluator.py tests/test_constraints.py tests/test_detection.py -q`

Expected: PASS; existing detection behavior remains unchanged when no PMKB evidence is attached.

- [ ] **Step 5: Commit**

```bash
git add openclaw_guard/policy/evaluator.py tests/test_policy_evaluator.py
git commit -m "feat: add coverage-aware policy evaluator"
```

### Task 5: Compute effective permissions, requested delta and least-privilege Trace

**Files:**
- Create: `openclaw_guard/policy/permission_diff.py`
- Test: `tests/test_permission_diff.py`

**Interfaces:**
- `PermissionClosure(bundle: PolicyBundle).close(grants: list[CapabilityGrant]) -> frozenset[PermissionRef]`.
- `PermissionDiff.compute(effective: frozenset[PermissionRef], requested: list[PermissionRef], required_trace: list[PermissionRef]) -> PermissionDiffResult`.
- `PermissionDiffResult` contains `requested_delta`, `redundant_permissions`, `excessive_permissions`, `scope_expansions`, `expired_grants`, and `hard_violations`.

- [ ] **Step 1: Write failing closure and diff tests**

```python
def test_read_grant_does_not_imply_export_or_share():
    effective = closure.close([grant("document.read", scope="own")])
    result = PermissionDiff.compute(effective, [permission("document.export", scope="own")], [])
    assert result.requested_delta == [permission("document.export", scope="own")]

def test_requested_permission_already_granted_is_redundant():
    granted = permission("calendar.read", scope="own")
    result = PermissionDiff.compute(frozenset({granted}), [granted], [granted])
    assert result.redundant_permissions == [granted]
    assert result.requested_delta == []

def test_workspace_to_external_scope_is_expansion():
    result = PermissionDiff.compute(
        frozenset({permission("file.read", scope="workspace")}),
        [permission("file.read", scope="external")],
        [permission("file.read", scope="workspace")],
    )
    assert "scope_expansion" in result.hard_violations or result.scope_expansions
```

- [ ] **Step 2: Run tests and verify failure**

Run: `python -m pytest tests/test_permission_diff.py -q`

Expected: FAIL because the closure and diff interfaces do not exist.

- [ ] **Step 3: Implement bounded closure and TTL/revocation handling**

Apply only `implies` relations from the loaded bundle. Include direct grants, inherited roles, active capabilities and delegated capabilities; exclude expired or revoked grants and report them. Compare permissions by operation, resource type, scope, data classification, field scope, purpose and TTL. A broader scope does not satisfy a narrower required trace unless the relation explicitly permits it.

- [ ] **Step 4: Run focused tests and a performance smoke test**

Run: `python -m pytest tests/test_permission_diff.py tests/test_perf_smoke.py -q`

Expected: PASS; closure evaluation for the P0 bundle remains below 10 ms per trace on the local test machine.

- [ ] **Step 5: Commit**

```bash
git add openclaw_guard/policy/permission_diff.py tests/test_permission_diff.py
git commit -m "feat: add permission closure and least privilege diff"
```

### Task 6: Add sparse toxic-combination and relation graph evaluation

**Files:**
- Create: `openclaw_guard/policy/risk_graph.py`
- Test: `tests/test_permission_risk_graph.py`

**Interfaces:**
- `RiskGraph.from_bundle(bundle: PolicyBundle) -> RiskGraph`.
- `RiskGraph.evaluate(*, effective: frozenset[PermissionRef], requested_delta: list[PermissionRef], trace: AuthorizationTrace) -> list[ComboViolation]`.
- `ComboViolation` contains `relation_id`, `permissions`, `conditions`, `severity`, `effect`, and `evidence`.

- [ ] **Step 1: Write failing toxic-combination tests**

```python
def test_secret_read_plus_external_egress_is_hard_block():
    violations = graph.evaluate(
        effective=frozenset({permission("secret.read")}),
        requested_delta=[permission("network.egress", scope="external")],
        trace=trace_for_external_secret_egress(),
    )
    assert {v.relation_id for v in violations} == {"COMBO-SECRET-EGRESS-001"}
    assert violations[0].effect == "block"

def test_unrelated_read_permissions_do_not_trigger_hyperedge():
    violations = graph.evaluate(
        effective=frozenset({permission("document.read"), permission("calendar.read")}),
        requested_delta=[],
        trace=trace_for_internal_read(),
    )
    assert violations == []
```

- [ ] **Step 2: Run tests and verify failure**

Run: `python -m pytest tests/test_permission_risk_graph.py -q`

Expected: FAIL because `RiskGraph` is not implemented.

- [ ] **Step 3: Implement indexed relations and condition predicates**

Index hyperedges by their rarest permission, then verify set inclusion plus conditions for data classification, external target, persistence location, quantity and principal lineage. Do not enumerate the power set of permissions. Apply `conflicts` and `toxic_with` before risk scoring; preserve all matched relation IDs and evidence fields.

- [ ] **Step 4: Run focused and attack fixture tests**

Run: `python -m pytest tests/test_permission_risk_graph.py tests/test_runtime_verification.py -q`

Expected: PASS; existing session monitors continue to receive the original `props` and event sequence.

- [ ] **Step 5: Commit**

```bash
git add openclaw_guard/policy/risk_graph.py tests/test_permission_risk_graph.py
git commit -m "feat: detect toxic permission combinations"
```

### Task 7: Integrate PMKB, permission delta and risk graph into the decision pipeline

**Files:**
- Create: `openclaw_guard/policy/engine.py`
- Modify: `openclaw_guard/services.py:395-420`
- Modify: `openclaw_guard/engine/pipeline.py:71-105,145-225`
- Modify: `openclaw_guard/models.py:159-176`
- Test: `tests/test_policy_pipeline.py`

**Interfaces:**
- `AuthorizationPolicyEngine.evaluate(event: BehaviorEvent, *, source_message: str = "") -> PolicyDecision`.
- `AuthorizationPolicyEngine` composes `TraceCompiler`, `PolicyEvaluator`, `PermissionDiff`, and `RiskGraph` and never invokes an LLM or network service.
- Pipeline helper `_apply_policy_engine(services, event, decision) -> decision` attaches `decision.policy_decision` and raises the existing decision only when PMKB effect is stronger.

- [ ] **Step 1: Write failing integration tests**

```python
def test_p0_internal_message_is_allowed_with_policy_evidence(services):
    result = services.handle_before_tool_call(internal_message_payload())
    assert result["action"] == "allow"
    evidence = result["action_record"]["decision"]["policy_decision"]
    assert evidence["effect"] == "auto_allow_audit"
    assert evidence["policy_version"]

def test_secret_external_egress_cannot_be_downgraded_by_policy_overlay(services):
    result = services.handle_before_tool_call(secret_external_egress_payload())
    assert result["action"] in {"block", "require_approval"}
    assert result["action_record"]["decision"]["policy_decision"]["combo_violations"]

def test_unknown_tool_records_gap_and_does_not_create_silent_allow(services):
    result = services.handle_before_tool_call(unknown_tool_payload())
    evidence = result["action_record"]["decision"]["policy_decision"]
    assert evidence["match_status"] in {"partial", "unknown"}
    assert "tool_mapping" in evidence["missing_features"]
    assert result["action"] != "allow" or evidence["effect"] == "auto_allow_audit"
```

- [ ] **Step 2: Run focused pipeline tests and verify failure**

Run: `python -m pytest tests/test_policy_pipeline.py -q`

Expected: FAIL because the policy engine is not wired into `GuardServices` or the pipeline.

- [ ] **Step 3: Implement composition and monotonic decision overlay**

Construct one `AuthorizationPolicyEngine` in `GuardServices` using `Path("policies/permissions")`. Obtain initial grants from `event.metadata.get("current_permissions", [])`; absent grants mean an empty effective set and are recorded as `grant_source="empty_default"`. In `_annotate_event_context`, compile the trace after semantic enrichment and store it under `event.metadata["authorization_trace"]`. Invoke `_apply_policy_engine` after detection and before existing constraint/RV overlays. Map effects as follows: `block` → block, `openclaw_approval` → at least ask/escalate, `clarify_then_retry` → revise/ask, `auto_allow_audit` → no downgrade. Preserve existing `DetectionEngine` and RV rule IDs and append PMKB evidence to the decision trace.

- [ ] **Step 4: Run all backend regression tests**

Run: `python -m pytest -q`

Expected: PASS with all previous tests green; policy evidence is optional for old non-Hook fixtures.

- [ ] **Step 5: Commit**

```bash
git add openclaw_guard/policy/engine.py openclaw_guard/services.py openclaw_guard/engine/pipeline.py openclaw_guard/models.py tests/test_policy_pipeline.py
git commit -m "feat: integrate authorization policy into hook pipeline"
```

### Task 8: Add principal/capability RV state and evidence-oriented test matrix

**Files:**
- Modify: `openclaw_guard/spec/session_state.py:1-130`
- Modify: `openclaw_guard/rv/runtime_verification.py:1-220`
- Test: `tests/test_principal_capability_rv.py`
- Test: `tests/test_policy_vectors.py`

**Interfaces:**
- `PrincipalSecurityState(principal_id: str, agent_id: str, capability_lineage: tuple[str, ...])` stores effective grants, sensitive-data lineage, revocations, TTL and monotonic sequence.
- `PrincipalSecurityState.record(trace: AuthorizationTrace, decision: PolicyDecision) -> str | None` returns `block`, `openclaw_approval`, or `None` when a cross-session toxic chain is observed.
- `RuntimeVerificationEngine.state_for_principal(principal_id: str, agent_id: str, lineage: tuple[str, ...]) -> PrincipalSecurityState` does not merge states when any identity component differs.

- [ ] **Step 1: Write failing cross-session and P0 vector tests**

```python
def test_same_principal_secret_read_then_external_egress_escalates_across_sessions():
    state = PrincipalSecurityState("u1", "agent1", ("grant1",))
    assert state.record(secret_read_trace(session_id="s1"), allow_policy()) is None
    assert state.record(external_egress_trace(session_id="s2"), approval_policy()) in {"block", "openclaw_approval"}

def test_different_principal_cannot_inherit_sensitive_lineage():
    state_a = PrincipalSecurityState("u1", "agent1", ("grant1",))
    state_b = PrincipalSecurityState("u2", "agent1", ("grant1",))
    state_a.record(secret_read_trace(session_id="s1"), allow_policy())
    assert state_b.record(external_egress_trace(session_id="s2"), approval_policy()) is None

def test_all_p0_vectors_have_expected_effect():
    for vector in load_p0_vectors():
        assert evaluate_vector(vector).effect == vector["expected_effect"]
```

- [ ] **Step 2: Run tests to verify the new state is absent**

Run: `python -m pytest tests/test_principal_capability_rv.py tests/test_policy_vectors.py -q`

Expected: FAIL because principal state and vector runner are not implemented.

- [ ] **Step 3: Implement bounded principal/capability state**

Keep existing per-session windows unchanged. Add a separate keyed map and JSON-compatible snapshot fields for principal, agent and capability lineage, with TTL, revoke and expire events. `goal_id` partitions work but cannot authenticate a merge. Feed only normalized `AuthorizationTrace` events into this state. Treat missing identity or lineage as inconclusive and route to approval/block according to the policy decision; never mark it safe.

- [ ] **Step 4: Run RV and full regression tests**

Run: `python -m pytest tests/test_principal_capability_rv.py tests/test_policy_vectors.py tests/test_runtime_verification.py -q && python -m pytest -q`

Expected: PASS; existing session snapshots remain loadable and cross-session state does not merge different principals.

- [ ] **Step 5: Commit**

```bash
git add openclaw_guard/spec/session_state.py openclaw_guard/rv/runtime_verification.py tests/test_principal_capability_rv.py tests/test_policy_vectors.py
git commit -m "feat: add principal capability runtime verification"
```

### Task 9: Document policy contracts, metrics, rollback and operator workflow

**Files:**
- Modify: `docs/semantic/method.md`
- Modify: `docs/semantic/office-scenario-matrix.md`
- Modify: `docs/api/http.md`
- Modify: `docs/features/runtime-hook.md`
- Modify: `docs/ops/roadmap.md`
- Test: `tests/test_policy_docs.py`

**Interfaces:**
- Documentation examples must use the serialized `policy_decision` shape from Task 1 and the P0 policy IDs from Task 2.
- API docs define read-only Guard evidence fields: `effect`, `match_status`, `missing_features`, `requested_delta`, `excessive_permissions`, `combo_violations`, `policy_version`, and timing values.

- [ ] **Step 1: Write failing documentation contract tests**

```python
def test_docs_name_p0_rules_and_effect_routes():
    text = Path("docs/semantic/method.md").read_text()
    for token in ("Authorization Trace", "auto_allow_audit", "clarify_then_retry", "openclaw_approval", "policy_version"):
        assert token in text

def test_docs_preserve_openclaw_single_approval_owner():
    text = Path("docs/features/runtime-hook.md").read_text()
    assert "OpenClaw" in text and "唯一审批" in text
```

- [ ] **Step 2: Run tests and verify missing documentation**

Run: `python -m pytest tests/test_policy_docs.py -q`

Expected: FAIL until the policy contracts and P0 examples are documented.

- [ ] **Step 3: Update the documents**

Document the Feishu-derived domains, personal-office resource scopes, P0 traces, four-level fallback, hard-block precedence, principal/capability identity, and versioned bundle rollback. Add metric definitions: complete coverage ≥85% on P0, unknown ≤10%, low-risk auto-allow precision ≥99%, high-risk recall ≥98%, total manual approvals −40%, low-risk approvals −60%, local evaluator P95 ≤50 ms.

- [ ] **Step 4: Run documentation, frontend and backend verification**

Run: `python -m pytest tests/test_policy_docs.py -q && python -m pytest -q && (cd frontend && npm run build) && (cd docs && npm run docs:build)`

Expected: PASS; generated frontend and VuePress documentation build successfully.

- [ ] **Step 5: Commit**

```bash
git add docs/semantic docs/api/http.md docs/features/runtime-hook.md docs/ops/roadmap.md tests/test_policy_docs.py
git commit -m "docs: document permission policy contracts and rollout"
```

## Verification and Release Gate

After all tasks are complete, run:

```bash
python -m pytest -q
(cd frontend && npm run build)
(cd docs && npm run docs:build)
node --check runtime/openclaw-guard-plugin/index.js
```

The original plan proposed a calendar-based observation period; that gate is removed for the personal-office deployment. PMKB `1.1.0` baseline rules are enforced immediately. New rules, batch rollout, or expansion of auto-allow scope use offline replay followed by at most 20 relevant events of bounded validation; explicit confirmation can activate a narrowly scoped personal preference immediately. Promotion still requires the Task 9 coverage, unknown-rate, automatic-allow precision, high-risk recall, approval-volume, and latency thresholds, and any hard-risk false negative, policy bundle validation error, or principal-state merge anomaly must disable the new bundle version and return to the previous catalog while retaining all audit records.
