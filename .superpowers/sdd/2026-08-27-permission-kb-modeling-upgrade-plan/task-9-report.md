# Task 9 report: permission policy documentation contracts

Status: complete

Implemented the PMKB/Feishu-derived documentation contract across the semantic method,
office scenario matrix, HTTP API, runtime Hook, and operations roadmap pages. The docs now
cover personal-office resource scopes, P0 policy IDs/traces (`EX-10`, `EX-19`, `EX-27`), the
serialized `policy_decision` evidence shape, four-level fallback routing, hard-block
precedence, principal/capability identity, OpenClaw's single approval owner, versioned bundle
promotion, metrics, shadow-run gates, and rollback with audit retention.

Added `tests/test_policy_docs.py` with contract checks. TDD red phase observed four failing
contracts before documentation changes; all five contract tests pass after implementation.

Verification:

- `python -m pytest tests/test_policy_docs.py -q` — 5 passed
- `python -m pytest -q` — 420 passed, 18 skipped
- `(cd frontend && npm run build)` — passed
- `(cd docs && npm run docs:build)` — passed; 34 pages rendered
- `node --check /home/yosoro126/OpenClaw-RVGuarder/runtime/openclaw-guard-plugin/index.js` — passed
- `git diff --check` — passed

Concern: the worktree does not contain the ignored generated runtime plugin path, so the
brief's exact worktree-local `node --check runtime/openclaw-guard-plugin/index.js` command
cannot resolve there. The repository's generated runtime plugin was syntax-checked instead.
