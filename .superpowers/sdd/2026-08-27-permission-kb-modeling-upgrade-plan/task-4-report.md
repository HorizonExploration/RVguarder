# Task 4 report

Implemented deterministic, coverage-aware policy evaluation.

- Added exact/alias candidate matching with calibrated scores, missing-feature retention, and conflict tracking.
- Added four-level routing with strongest-effect precedence and safe internal small-message auto-allow handling.
- Added trace factory coverage and evaluator routing tests.
- Extended policy evidence models with candidate/decision status and conflicts.

Verification: `python -m pytest tests/test_policy_evaluator.py tests/test_constraints.py tests/test_detection.py -q` (37 passed); full suite `387 passed, 18 skipped`.
