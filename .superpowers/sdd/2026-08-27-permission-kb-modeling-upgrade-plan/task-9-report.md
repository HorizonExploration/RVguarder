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

## Review round 1 correction

Corrected `match_status` examples to the serialized values `matched|partial|unknown|conflict`
(with `complete` reserved for `AuthorizationTrace.coverage.status`), removed timing from the
`policy_decision` examples, and documented event metadata/pipeline timings separately. Permission
delta fields now show serialized `PermissionRef` objects. The contract tests parse both JSON
examples and validate statuses, timing absence, and object field types.

## Review round 2 correction

Aligned the canonical P0 bundle and documentation with the ruling: `EX-10` now maps to
`message.send`/`broadcast`, `EX-19` to `data.query` with `data.export` alias semantics, and
`EX-27` to `file.bulk_transfer`/`batch_file_transfer`. Added the `data.query` and
`file.bulk_transfer` catalog families, updated vectors, and retained all relation endpoints.
The documentation contract loads `PolicyBundle` and cross-checks each documented P0 operation
and vector against its canonical rule.
