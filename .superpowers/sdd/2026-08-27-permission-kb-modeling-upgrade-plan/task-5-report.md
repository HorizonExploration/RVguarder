# Task 5 report

Implemented bounded effective-permission closure and least-privilege diffing.

- Added `PermissionClosure`, applying only explicit `implies` edges transitively while retaining direct grants and nested inherited, active, and delegated capability records.
- Expired and revoked grants are excluded and retained as provenance on the effective frozenset and diff result.
- Added requested delta, redundancy, required-trace excess, scope expansion, and hard-violation reporting with scope and classification coverage checks.
- Made `PermissionRef` hashable so it can satisfy the specified `frozenset[PermissionRef]` interface.

Verification: `python -m pytest tests/test_permission_diff.py tests/test_perf_smoke.py -q` — **9 passed**.

Round 1 fix: scope coverage now requires exact scope equality; broader grants do not
silently satisfy narrower requests. `PermissionRef` now uses Pydantic frozen-model
semantics, preserving hash correctness after insertion into frozensets. Added
regressions for both invariants. Verification: **11 passed**.

Concerns:

- The current P0 JSON relation bundle contains policy-combination effects but no `implies` edges; implication closure therefore remains empty unless a bundle supplies an explicit `implies` relation.
- Revocation is modeled through existing `CapabilityGrant.constraints` (`revoked`, `revoked_at`, or inactive status), since the model has no dedicated revoked field.
