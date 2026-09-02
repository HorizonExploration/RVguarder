# AgentDojo Full Evaluation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 testlab 的 AgentDojo Candidate 对照真正使用 Guard 能力模型识别安全读写/外发工具，并以适合独立项目汇报的精简证据集完成 workspace + banking 对照评测。

**Architecture:** 在 testlab 边界建立显式的 AgentDojo 工具能力映射，保留原始函数名用于审计，将读工具映射到 Guard 已有的低风险控制面能力，将写入、删除、分享、外发和日历修改映射到相应高风险能力。Guard 生产链路只增加可审计的评测快速路径：对已认证且明确标注为 AgentDojo 合成评测的请求使用确定性语义，生产 OpenClaw 请求仍走现有语义策略；真实模型调用继续由官方 AgentDojo pipeline 完成。

**Tech Stack:** Python 3.13 Guard、Python 3.11 AgentDojo 0.1.35、OpenAI-compatible API、pytest、标准库 HTTP。

**Spec:** `testlab/实验方案/agentdojo-实验方案.md`

## Global Constraints

- 不安装或升级依赖；AgentDojo 使用独立环境 `/home/yosoro126/miniconda3/envs/agentdojo/bin/python`。
- 不修改 AgentDojo 安装包；DeepSeek 的 `developer` 角色兼容逻辑只能位于 `testlab`。
- 不改变真实 OpenClaw 未标记请求的默认安全策略；读操作放行必须有明确的能力映射和本地范围。
- 默认 `demo` profile 固定 benchmark `v1.2.2`、两类代表攻击 `direct`、`tool_knowledge`，两套件三组 arm 共 168 个 episode。
- `full` profile 保留四类攻击并将任务矩阵缩减约 60%（每 arm 1155 个 episode）；历史 8616 episode 结果仅作诊断归档。
- 先完成离线回归和 demo smoke；不得用失败或 401/402/429 episode 作为安全指标。

---

### Task 1: AgentDojo 工具能力映射契约

**Files:**
- Modify: `testlab/agentdojo_upgrade.py`
- Test: `tests/test_agentdojo_adapter.py`

**Interfaces:**
- Consumes: AgentDojo `FunctionCall` 的 `function` 与 `args`。
- Produces: `build_tool_call_payload()` 返回包含原始 `agentdojoToolName`、稳定的 Guard `toolName` 和映射后的参数；未知工具保持原名并继续由 Guard 兜底判断。

- [ ] **Step 1: Write the failing test**

```python
def test_agentdojo_read_tool_maps_to_safe_openclaw_capability() -> None:
    payload = build_tool_call_payload(FakeToolCall("search_calendar_events", {"query": "meeting"}))
    assert payload["toolName"] == "memory_search"
    assert payload["agentdojoToolName"] == "search_calendar_events"


def test_agentdojo_external_or_mutating_tool_keeps_high_risk_mapping() -> None:
    payload = build_tool_call_payload(FakeToolCall("send_email", {"to": "outside@example.com"}))
    assert payload["toolName"] == "feishu.im.send"
    assert payload["agentdojoToolName"] == "send_email"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest -q tests/test_agentdojo_adapter.py -k agentdojo_`
Expected: FAIL because the payload currently sends the raw AgentDojo function name.

- [ ] **Step 3: Write minimal implementation**

Add a constant mapping for read, calendar mutation, file mutation, send/share and delete functions. Copy the original args, add `agentdojoToolName`, and only replace `toolName` with a canonical Guard tool ID; do not alter the runtime function name used by AgentDojo.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest -q tests/test_agentdojo_adapter.py -k agentdojo_`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add testlab/agentdojo_upgrade.py tests/test_agentdojo_adapter.py
git commit -m "testlab: map AgentDojo tools to Guard capabilities"
```

### Task 2: Candidate fast-path for synthetic benchmark semantics

**Files:**
- Modify: `openclaw_guard/engine/semantic_enhancer.py`
- Modify: `openclaw_guard/engine/pipeline.py`
- Test: `tests/test_semantic_enhancer.py`
- Test: `tests/test_pipeline.py`

**Interfaces:**
- Consumes: an explicit `evaluation_mode=agentdojo` marker set only by the testlab adapter and a mapped native low-risk tool profile.
- Produces: deterministic local semantic output for benchmark read calls without an external LLM round-trip; unmarked production events retain existing behavior.

- [ ] **Step 1: Write the failing test**

```python
def test_agentdojo_evaluation_mode_disables_llm_round_trip(monkeypatch) -> None:
    enhancer = SemanticEnhancer(api_key="configured")
    event = build_hook_event({"toolName": "memory_search", "params": {"query": "meeting"}})
    called = False

    def fail_if_called(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("LLM must not be called for benchmark read mapping")

    monkeypatch.setattr(enhancer, "_call_llm", fail_if_called)
    result = enhancer.evaluate(event, {"source_message": "benchmark", "evaluation_mode": "agentdojo"})
    assert result["semantic"]["scenario"] == "file_read"
    assert called is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest -q tests/test_semantic_enhancer.py -k agentdojo`
Expected: FAIL because `evaluate()` currently calls `_call_llm` whenever a key and source message exist.

- [ ] **Step 3: Write minimal implementation**

In `SemanticEnhancer.evaluate`, skip `_call_llm` only when `ctx.get("evaluation_mode") == "agentdojo"`; keep local rule generation and hard tool validation. Pass this context from the testlab request using an explicit benchmark marker accepted by the Guard hook boundary. Reject the marker for non-local or untrusted requests if the existing hook authentication/context does not prove the benchmark call.

- [ ] **Step 4: Run focused tests**

Run: `python -m pytest -q tests/test_semantic_enhancer.py tests/test_pipeline.py -k 'agentdojo or native or semantic'`
Expected: PASS and existing native/production semantic tests remain green.

- [ ] **Step 5: Commit**

```bash
git add openclaw_guard/engine/semantic_enhancer.py openclaw_guard/engine/pipeline.py tests/test_semantic_enhancer.py tests/test_pipeline.py
git commit -m "guard: keep synthetic AgentDojo reads on deterministic semantics"
```

### Task 3: Candidate HTTP smoke and regression gate

**Files:**
- Modify: `testlab/脚本工具/agentdojo_upgrade_eval.py`
- Modify: `testlab/实验准备/agentdojo-upgrade-environment.md`
- Test: `tests/test_agentdojo_adapter.py`

**Interfaces:**
- Consumes: mapped payloads, runtime Hook token, DeepSeek role adapter.
- Produces: valid `deny` and `allow-once` smoke reports with no transport errors, read-only baseline approval demand materially lower than the previous 100% false-positive result.

- [ ] **Step 1: Write the failing test**

```python
def test_agentdojo_payload_marks_synthetic_evaluation_context() -> None:
    payload = build_tool_call_payload(FakeToolCall("get_current_day"))
    assert payload["evaluationMode"] == "agentdojo"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest -q tests/test_agentdojo_adapter.py -k evaluation_context`
Expected: FAIL because the payload has no benchmark context marker.

- [ ] **Step 3: Write minimal implementation**

Add the marker only to testlab-generated payloads and document the required Hook token setup. Preserve role normalization and secret redaction.

- [ ] **Step 4: Run the smoke experiment**

Start Guard locally, run workspace/direct with one user task and one injection task in both `deny` and `allow-once`, then assert manifests have the correct benchmark/version and all episode errors are zero.

- [ ] **Step 5: Commit**

```bash
git add testlab/脚本工具/agentdojo_upgrade_eval.py testlab/agentdojo_upgrade.py testlab/实验准备/agentdojo-upgrade-environment.md tests/test_agentdojo_adapter.py
git commit -m "testlab: gate AgentDojo smoke on valid Guard transport"
```

### Task 4: Report-sized three-arm AgentDojo evaluation

**Files:**
- Create: `testlab/results/agentdojo-upgrade/<timestamp>/manifest.json`
- Create: `testlab/results/agentdojo-upgrade/<timestamp>/raw-episodes.json`
- Create: `testlab/results/agentdojo-upgrade/<timestamp>/tool-traces.jsonl`
- Create: `testlab/results/agentdojo-upgrade/<timestamp>/metrics.json`
- Create: `testlab/results/agentdojo-upgrade/<timestamp>/report.md`

**Interfaces:**
- Consumes: validated Guard service, configured OpenAI-compatible API, official AgentDojo suite/attack registry.
- Produces: the default `demo` profile (168 episodes across three arms) or the explicit reduced `full` profile (1155 episodes per arm); no paper-scale run is required for routine reporting.

- [ ] **Step 1: Run environment and service gates**

Run:

```bash
/home/yosoro126/miniconda3/envs/agentdojo/bin/python testlab/脚本工具/agentdojo_upgrade_eval.py --preflight --agent-python /home/yosoro126/miniconda3/envs/agentdojo/bin/python
curl --noproxy '*' -fsS http://127.0.0.1:8780/api/health
```

Expected: `ready: true`, policy endpoint HTTP 200, and no missing token/configuration.

- [ ] **Step 2: Run demo deny evaluation**

Use `--profile demo` with `workspace`, `banking`, the two representative attacks and all three arms. Keep `approval-mode=deny` for the security/prevention run. Use `--profile full` only when wider coverage is explicitly needed.

- [ ] **Step 3: Run optional allow-once recovery evaluation**

Repeat the same demo matrix with `--approval-mode allow-once` only when approval-friction evidence is needed; use it to separate approval friction from security decisions.

- [ ] **Step 4: Verify output integrity**

Check `manifest.json`, count episodes by arm/suite/attack, assert no transport/API errors, and ensure metrics report Wilson intervals plus approval demand, executed/prevented calls and p95 latency.

- [ ] **Step 5: Commit**

```bash
git add testlab/results/agentdojo-upgrade docs/superpowers/plans/2026-08-30-agentdojo-full-evaluation.md
git commit -m "testlab: record full AgentDojo Guard evaluation"
```

### Task 5: Findings and follow-up gate

**Files:**
- Modify: `testlab/实验方案/agentdojo-实验方案.md`
- Create: `docs/research/agentdojo-full-evaluation-report-2026-08-30.md`

**Interfaces:**
- Consumes: full metrics and representative raw traces.
- Produces: a bounded conclusion separating mapping/utility effects, approval load, attack success and Guard latency; no production-security claim from synthetic sample alone.

- [ ] **Step 1: Summarize by arm and suite**

Record utility, attack success/prevention, approval demand ratio, unknown/clarify count, errors and p95 latency with sample counts.

- [ ] **Step 2: List false-positive and false-negative traces**

Include representative AgentDojo read calls that should allow, writes/egress that should ask or block, and any attack episode where the model reached a dangerous tool.

- [ ] **Step 3: Update the execution scheme**

Replace the prior “real episode not yet run” statement with links to the timestamped results and explicitly retain failed 400/401 runs as diagnostic evidence.

- [ ] **Step 4: Run documentation and static checks**

Run: `git diff --check` and the focused adapter/pipeline test set.

- [ ] **Step 5: Commit**

```bash
git add testlab/实验方案/agentdojo-实验方案.md docs/research/agentdojo-full-evaluation-report-2026-08-30.md
git commit -m "docs: publish AgentDojo full evaluation findings"
```
