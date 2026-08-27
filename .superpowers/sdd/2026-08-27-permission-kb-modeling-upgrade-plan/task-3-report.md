# Task 3 report: compile hook events into Authorization Trace

## Files

- `openclaw_guard/policy/trace.py`: deterministic `TraceCompiler` extracting principal, canonical operation, resource/scope, classification/quantity, recipient context, provenance, confidence, coverage, and preserving legacy RV steps.
- `openclaw_guard/rv/ir.py`: optional authorization evidence fields on `ToolCallIR` (`negated`, `excluded_entities`, `quantity`, `provenance`) for backward-compatible structured traces.
- `openclaw_guard/engine/pipeline.py`: compile and attach `authorization_trace` during event annotation without changing detector decisions or event action types.
- `tests/test_authorization_trace.py`: extraction, partial coverage, and legacy compatibility tests.

## Tests

`python -m pytest tests/test_authorization_trace.py tests/test_ir.py tests/test_semantic_enhancer.py tests/test_pipeline.py -q` — **43 passed** (including field-confidence bounds and unknown-field regressions).

Focused RED was verified first: collection failed because `openclaw_guard.policy.trace` did not exist. The implementation then passed the focused and compatibility suites.

## Commit

`5754636` (`feat: compile authorization traces from hook events`).

## Concerns

- Pipelines attach traces when the bundled `policies/permissions` catalog is available; a malformed/unavailable bundle leaves the existing semantic/RV path unchanged.
- Authorization trace compilation is evidence-only and does not perform policy matching or allow/block decisions.
- Classification now takes the highest level across semantic metadata, labels, and all RV step sensitivity/classification values; resource-required operation families report explicit `partial` coverage and resource gap fields when evidence is absent.
- Field confidence is emitted for `operation`, `resource`, `scope`, and `overall`, deterministically bounded to `[0, 1]`; unknown or missing evidence cannot receive full confidence.
