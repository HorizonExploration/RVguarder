# Task 6 report: sparse toxic-combination evaluation

Implemented `RiskGraph` and `ComboViolation` in `openclaw_guard/policy/risk_graph.py`.

- Relations are indexed by the rarest required permission family; evaluation does not enumerate permission subsets.
- Matching combines effective and requested permissions and checks relation endpoints plus trace conditions for external targets/recipients, sensitive data, persistence, quantity, classification, and principal lineage.
- Matched relation IDs and trace/relation evidence are retained in each violation. Existing P0 relation IDs are exposed through stable `COMBO-*` identifiers.
- Added focused tests for the secret-read plus external-egress block, unrelated permissions, and condition/evidence preservation.

Verification:

- `python -m pytest tests/test_permission_risk_graph.py -q` — 3 passed.
- `python -m pytest tests -q` — passed.
- The brief references `tests/test_runtime_verification.py`, which is not present in this checkout; the full available suite was run instead.

Concerns: relation JSON currently uses short IDs, so the graph provides compatibility aliases for the required canonical P0 combination IDs.
