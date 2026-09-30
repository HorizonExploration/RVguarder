"""大模型语义知识规则匹配的冻结录制与确定性回放。

本模块把"一次性离线调用语义 LLM"的结果冻结为证据工件，并在实验期以该
工件确定性回放，保证实验期不再调用真实模型：

- ``record_matrix`` 逐个场景事件渲染 Hook 事件并调用语义增强层（LLM 启用），
  记录 ``prompt_sha256`` / 模型标识 / 时间戳 / ``llm_status`` / 受控
  ``SemanticMatchIR`` / ``labels`` 以及**脱敏摘要**。
- ``write_recording`` / ``load_recording`` 负责工件落盘与读取。
- ``ReplayLLMTransport`` 实现 ``SemanticEnhancer`` 的传输钩子契约：按
  ``prompt_sha256`` 命中后返回原解析路径可消费的原始响应文本；命中失败抛
  ``SemanticRecordingDrift``。
- ``apply_recording`` / ``replay_entries`` / ``recording_digest`` 供实验期
  确定性回放与 manifest 摘要使用。

录制工件**绝不**包含 API key、原始命令、URL 或收件人等敏感值。
"""

from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import re
from typing import Any, Callable

import openclaw_guard.engine.semantic_enhancer as _semantic_enhancer_module
from openclaw_guard.engine.semantic_enhancer import (
    _DEFAULT_LLM_BASE_URL,
    _DEFAULT_LLM_MODEL,
    SemanticEnhancer,
    _build_haystack,
)
from openclaw_guard.engine.pipeline import annotate_scope
from openclaw_guard.integrations.tool_hook_bridge import (
    build_hook_event,
    build_hook_source_message,
)
from openclaw_guard.utils import sha256_text, utc_now_iso

from .artifacts import digest_json
from .frozen_provider import normalise_tool_params
from .matrix import load_matrix


SCHEMA_VERSION = 1
PROMPT_VERSION = "semantic-hook-prompt-v1"
DEFAULT_RECORDING_PATH = Path(__file__).with_name("semantic_recording.json")

# The recording runs offline (not inside the synchronous Hook decision budget),
# so allow a longer network window than the production 1.5s fallback window.
# The production default is restored as soon as recording completes.
RECORDING_TIMEOUT_SEC = 30.0

_STATUSES = ("success", "fallback")


class SemanticRecordingDrift(RuntimeError):
    """Raised when a replayed prompt does not match any frozen recording entry."""

    def __init__(
        self,
        prompt_sha256: str,
        *,
        scenario_id: str | None = None,
        event_index: int | None = None,
    ) -> None:
        self.prompt_sha256 = prompt_sha256
        self.scenario_id = scenario_id
        self.event_index = event_index
        super().__init__(
            "语义录制漂移：prompt "
            f"{prompt_sha256[:12]}… 无匹配条目（scenario={scenario_id} event={event_index}）"
        )


class ReplayLLMTransport:
    """Deterministic transport that replays frozen semantic results.

    It implements the ``Callable[[str], str]`` contract expected by
    ``SemanticEnhancer``.  The returned text is a reconstructed OpenAI-compatible
    response body, so the enhancer still runs its original parse + schema
    validation on replay.  A drift (unknown prompt / missing entry) raises
    ``SemanticRecordingDrift``.
    """

    def __init__(
        self,
        recording: dict[str, Any],
        *,
        scenario_id: str | None = None,
        event_index: int | None = None,
    ) -> None:
        self._recording = recording
        self._by_prompt: dict[str, dict[str, Any]] = {}
        entries = recording.get("entries") if isinstance(recording, dict) else None
        if isinstance(entries, dict):
            for entry in entries.values():
                if isinstance(entry, dict) and entry.get("prompt_sha256"):
                    self._by_prompt.setdefault(str(entry["prompt_sha256"]), entry)
        self.scenario_id = scenario_id
        self.event_index = event_index

    def bind(self, scenario_id: str | None, event_index: int | None) -> None:
        """Attach the current replay position for drift diagnostics."""
        self.scenario_id = scenario_id
        self.event_index = event_index

    def __call__(self, prompt: str) -> str:
        digest = sha256_text(prompt)
        entry = self._by_prompt.get(digest)
        if entry is None:
            import os as _os

            if _os.environ.get("OFFICE_CHAIN_SEMANTIC_DRIFT_DUMP"):
                with open(_os.environ["OFFICE_CHAIN_SEMANTIC_DRIFT_DUMP"], "a", encoding="utf-8") as fh:
                    fh.write(f"### {digest} {self.scenario_id} {self.event_index}\n{prompt}\n")
            raise SemanticRecordingDrift(
                digest, scenario_id=self.scenario_id, event_index=self.event_index
            )
        return _entry_to_raw_response(entry)


class _OfflineTransport:
    """No-network transport used by ``--dry-run``.

    Returning an empty body forces the enhancer's normal parse failure, so the
    recorded status is an honest ``fallback`` and the local deterministic labels
    are preserved.
    """

    def __call__(self, prompt: str) -> str:  # noqa: ARG002 - contract requires prompt
        return ""


def record_matrix(
    matrix: dict[str, Any] | None = None,
    *,
    llm_transport: Callable[[str], str] | None = None,
    limit: int | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Record the frozen semantic result for every scenario event.

    ``matrix`` defaults to the validated ``scenarios.json``.  ``llm_transport``
    replaces the real HTTP call (used by tests); when ``None`` the enhancer
    targets the configured provider from ``.env``/environment.  ``limit`` caps
    the number of recorded entries (events).  ``dry_run`` records honest local
    ``fallback`` entries without touching the network.
    """
    source = matrix if matrix is not None else load_matrix()
    scenarios = source.get("scenarios") if isinstance(source, dict) else None
    if not isinstance(scenarios, list):
        raise ValueError("场景矩阵必须包含 scenarios 数组")

    api_key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    model = os.environ.get("DEEPSEEK_MODEL", "").strip() or _DEFAULT_LLM_MODEL
    base_url = os.environ.get("DEEPSEEK_BASE_URL", "").strip() or _DEFAULT_LLM_BASE_URL

    transport = llm_transport
    if dry_run:
        transport = _OfflineTransport()
        if not api_key:
            api_key = "offline-dry-run"
    elif transport is not None and not api_key:
        # A caller-supplied transport still needs the LLM gate to be open.
        api_key = "transport-provided"

    enhancer = SemanticEnhancer(
        api_key=api_key,
        model=model,
        base_url=base_url,
        llm_transport=transport,
    )

    entries: dict[str, Any] = {}
    # The sanitized prompt collapses many distinct hook events onto the same
    # input (privacy-preserving redaction).  Memoise by prompt digest so one
    # identical input yields exactly one frozen result: the recording stays
    # self-consistent even if the provider is non-deterministic, and identical
    # prompts can never be recorded with contradictory statuses.
    prompt_cache: dict[str, dict[str, Any]] = {}
    recorded_at = utc_now_iso()
    previous_timeout = _semantic_enhancer_module._DEFAULT_TIMEOUT_SEC
    _semantic_enhancer_module._DEFAULT_TIMEOUT_SEC = RECORDING_TIMEOUT_SEC
    try:
        for scenario in scenarios:
            if not isinstance(scenario, dict):
                continue
            scenario_id = str(scenario.get("scenario_id") or "")
            events = scenario.get("events")
            if not isinstance(events, list):
                continue
            for event_index, event in enumerate(events, 1):
                if limit is not None and len(entries) >= limit:
                    break
                if not isinstance(event, dict):
                    continue
                key = f"{scenario_id}#{event_index}"
                entries[key] = _record_event(
                    enhancer,
                    scenario_id,
                    event_index,
                    event,
                    model,
                    recorded_at,
                    prompt_cache,
                )
            if limit is not None and len(entries) >= limit:
                break
    finally:
        _semantic_enhancer_module._DEFAULT_TIMEOUT_SEC = previous_timeout

    return {
        "schema_version": SCHEMA_VERSION,
        "model_id": model,
        "base_url": base_url,
        "prompt_version": PROMPT_VERSION,
        "recorded_at": recorded_at,
        "entries": entries,
    }


def _runtime_project_proxy() -> Path:
    """运行时 guard 的 ``project_dir`` 等价物：进程 cwd 下的临时 guard-project。

    取值本身**不进**提示词或摘要（提示词只带 ``outside_workspace`` 这个布尔），所以只需复现
    **结构**：roots 必须是进程 cwd 的**后代**，而不是 cwd 自身。
    """

    return Path.cwd().resolve() / ".office-chain-guard-runtime" / "guard-project"


def _runtime_workspace_proxy() -> Path:
    """运行时 guard 的 ``workspace_path`` 等价物：guard 临时 profile 下的 workspace 目录。"""

    return _runtime_project_proxy() / "home" / ".openclaw-office-chain" / "workspace"


def project_event(event: dict[str, Any]) -> tuple[Any, str, str, str]:
    """把场景事件投影为**运行时等价**的 Hook 事件与提示词输入。

    返回 ``(behavior, source_message, tool_name, haystack)``。运行时 Agent 由冻结轨迹
    provider 供给，工具调用参数已经过 :func:`normalise_tool_params` 归一，Hook 看到的正是
    归一后的参数；因此录制也必须走同一投影，否则 ``prompt_sha256`` 会在回放时分叉。

    roots **不能**取 ``Path.cwd()``：运行时 guard 的 roots 是临时的
    ``<working_root>/guard-project`` 与其下 profile 的 ``workspace``，二者都不是进程 cwd 的
    祖先。``exec`` 事件带 ``cwd="."``，``_classify_scope`` 以该相对基址解析候选路径，于是落到
    所有 root 之外 → ``outside`` → ``outside_workspace=True``；若 roots 取 cwd，同一候选落在
    root 内 → 该字段变 ``False``，摘要便与运行时分叉（见 :func:`_runtime_project_proxy`）。
    不带 ``cwd`` 的事件（``read`` / ``write`` / ``office_*``）不受影响：其相对基址取 roots[0]，
    相对路径永远落在 root 内，结论与改动前一致。
    """

    hook_payload = _render_root(deepcopy(event.get("hook_payload")), Path.cwd())
    if isinstance(hook_payload, dict) and isinstance(hook_payload.get("params"), dict):
        hook_payload["params"] = normalise_tool_params(
            str(hook_payload.get("toolName") or ""), hook_payload["params"]
        )
    behavior = build_hook_event(hook_payload)
    annotate_scope(
        behavior,
        workspace_path=_runtime_workspace_proxy(),
        project_dir=_runtime_project_proxy(),
    )
    source_message = build_hook_source_message(behavior)
    tool_name = str(behavior.metadata.get("tool_name") or "")
    return behavior, source_message, tool_name, _build_haystack(behavior, source_message, tool_name)


def event_prompt_digest(enhancer: SemanticEnhancer, event: dict[str, Any]) -> str:
    """单个事件在当前投影下的提示词摘要（供录制、回放与覆盖性校验共用）。"""

    behavior, source_message, tool_name, haystack = project_event(event)
    return sha256_text(enhancer._build_prompt(behavior, source_message, tool_name, haystack))


def _record_event(
    enhancer: SemanticEnhancer,
    scenario_id: str,
    event_index: int,
    event: dict[str, Any],
    model: str,
    recorded_at: str,
    prompt_cache: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    behavior, source_message, tool_name, haystack = project_event(event)
    prompt = enhancer._build_prompt(behavior, source_message, tool_name, haystack)
    digest = sha256_text(prompt)

    cached = prompt_cache.get(digest) if prompt_cache is not None else None
    if cached is not None:
        entry = deepcopy(cached)
        entry.update(
            {
                "scenario_id": scenario_id,
                "event_index": event_index,
                "event_id": str(event.get("event_id") or f"step-{event_index}"),
            }
        )
        return entry

    result = enhancer.evaluate(
        behavior,
        {"source_message": source_message, "origin": "hook"},
    )
    audit = result.get("semantic_audit") or {}
    status = str(audit.get("llm_status") or "fallback")
    if status not in _STATUSES:
        status = "fallback"
    matched = result.get("semantic_match") if status == "success" else None
    labels = list((result.get("semantic") or {}).get("labels", []))

    entry = {
        "scenario_id": scenario_id,
        "event_index": event_index,
        "event_id": str(event.get("event_id") or f"step-{event_index}"),
        "prompt_sha256": digest,
        "model_id": model,
        "recorded_at": recorded_at,
        "llm_status": status,
        "semantic_match": matched,
        "labels": labels,
        "summary": _redacted_summary(behavior, prompt, labels),
    }
    if prompt_cache is not None:
        prompt_cache[digest] = entry
    return entry


def _redacted_summary(behavior: Any, prompt: str, labels: list[str]) -> dict[str, Any]:
    """Return a redacted, non-sensitive summary of one recorded event."""
    return {
        "tool_name": _safe_identifier(behavior.metadata.get("tool_name")),
        "action_type": str(getattr(behavior, "action_type", "") or ""),
        "label_count": len(labels),
        "has_command": bool(behavior.command),
        "target_path_count": len(behavior.target_paths),
        "network_target_count": len(behavior.network_targets),
        "prompt_chars": len(prompt),
    }


def _entry_to_raw_response(entry: dict[str, Any]) -> str:
    """Rebuild an OpenAI-compatible response body from a recorded entry.

    ``llm_status == "success"`` entries replay their recorded controlled IR;
    fallback entries return an empty body so the enhancer degrades to the same
    deterministic local path it used while recording.
    """
    match = entry.get("semantic_match")
    if entry.get("llm_status") != "success" or not isinstance(match, dict):
        return ""
    content = json.dumps(match, ensure_ascii=False)
    return json.dumps(
        {"choices": [{"message": {"content": content}}]},
        ensure_ascii=False,
    )


def write_recording(recording: dict[str, Any], path: str | Path) -> str:
    """Write the frozen recording artifact to ``path`` (creating parents)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(recording, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return str(target)


def load_recording(path: str | Path | None = None) -> dict[str, Any]:
    """Load and validate the frozen recording artifact."""
    target = Path(path) if path is not None else DEFAULT_RECORDING_PATH
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"无法加载语义录制工件：{target}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("语义录制工件必须是 JSON 对象")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"语义录制 schema_version 必须为 {SCHEMA_VERSION}，实际 {payload.get('schema_version')!r}"
        )
    if not isinstance(payload.get("entries"), dict):
        raise ValueError("语义录制必须包含 entries 对象")
    return payload


def apply_recording(enhancer: SemanticEnhancer, recording: dict[str, Any]) -> None:
    """Bind a frozen recording to ``enhancer`` for deterministic replay."""
    enhancer.llm_transport = ReplayLLMTransport(recording)
    # The replay transport replaces HTTP, but the LLM gate must be open for the
    # enhancer to route through it at all.
    if not getattr(enhancer, "api_key", ""):
        enhancer.api_key = "replay-recording"
    enhancer._llm_enabled = True


def replay_entries(path: str | Path | None = None) -> dict[str, Any]:
    """Return the ``<scenario_id>#<event_index>`` entries of a recording."""
    recording = load_recording(path)
    entries = recording.get("entries")
    if not isinstance(entries, dict):
        raise ValueError("语义录制缺少 entries 对象")
    return entries


def recording_digest(recording: dict[str, Any]) -> str:
    """Return the canonical-JSON sha256 of a recording (for the manifest)."""
    return digest_json(recording)


def _safe_identifier(value: Any) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]", "_", str(value or ""))[:96]


def _render_root(value: Any, root: Path) -> Any:
    if isinstance(value, str):
        return value.replace("${ROOT}", str(root))
    if isinstance(value, list):
        return [_render_root(item, root) for item in value]
    if isinstance(value, dict):
        return {key: _render_root(item, root) for key, item in value.items()}
    return value
