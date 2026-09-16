from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_action_card_renders_structured_approval_sections_and_trust_scope():
    source = (ROOT / "frontend/src/components/ActionCard.jsx").read_text(encoding="utf-8")
    assert "approval_presentation" in source
    assert "intent_summary" in source
    assert "command_preview" in source
    assert "allow_always" in source
    assert "approval-section" in source


def test_action_card_does_not_render_guard_approval_buttons_for_hook_actions():
    source = (ROOT / "frontend/src/components/ActionCard.jsx").read_text(encoding="utf-8")
    assert "请在 OpenClaw 审批中心处理" in source
    assert "canApprove = item.source !== 'hook_bridge'" in source


def test_action_card_never_falls_back_to_raw_hook_command_details():
    source = (ROOT / "frontend/src/components/ActionCard.jsx").read_text(encoding="utf-8")
    assert "presentation.command_preview || item.event?.command" not in source


def test_trace_timeline_uses_the_same_compact_approval_summary():
    source = (ROOT / "frontend/src/components/TraceTimeline.jsx").read_text(encoding="utf-8")
    assert "approval_presentation" in source
    assert "intent_summary" in source


def test_summary_refresh_is_uncached_and_tracks_mutable_skill_state():
    api_source = (ROOT / "frontend/src/api.js").read_text(encoding="utf-8")
    store_source = (ROOT / "frontend/src/store.js").read_text(encoding="utf-8")
    assert "cache: 'no-store'" in api_source
    assert "_ts=${Date.now()}" in api_source
    assert "skills: summary.skills || {}" in store_source
