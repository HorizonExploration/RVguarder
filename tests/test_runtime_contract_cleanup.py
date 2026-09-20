from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_runtime_has_no_retired_legacy_or_agentdojo_authorization_paths() -> None:
    assert not (ROOT / "openclaw_guard/policy/legacy.py").exists()
    runtime_files = [
        *ROOT.joinpath("openclaw_guard/policy").glob("*.py"),
        ROOT / "openclaw_guard/integrations/tool_hook_bridge.py",
        ROOT / "openclaw_guard/engine/semantic_enhancer.py",
        ROOT / "openclaw_guard/engine/pipeline.py",
    ]
    source = "\n".join(path.read_text(encoding="utf-8") for path in runtime_files)
    for retired_symbol in (
        "legacy_rules(",
        "LEGACY-",
        "legacy_action_types",
        "legacy_labels_all",
        "legacy_steps",
        "evaluationMode",
        "agentdojoToolName",
        "evaluation_mode",
    ):
        assert retired_symbol not in source
