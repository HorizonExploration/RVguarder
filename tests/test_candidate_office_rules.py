"""候选规约的有限工具范围与原独立阻断；不替代Docker阶段验收。"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from test_rv_authorization_guard import scoped
from openclaw_guard.rv.rv_dsl import Ruleset, ToolGuard, load_ruleset
from openclaw_guard.rv.runtime_verification import RuntimeVerificationEngine


CANDIDATE = Path(__file__).resolve().parents[1] / "docs/research/close-experiment-gaps/m1-candidate-rules-r2.json"


def history_engine(step, checker=None):
    """提交真实调用格式的成功外部读取，不注入Oracle血缘。"""
    engine = RuntimeVerificationEngine(authorization_checker=checker)
    engine._spec_ruleset = load_ruleset(CANDIDATE)
    read = deepcopy(step)
    read.update(step_id="run:attachment", execution_state="succeeded", tool_name="read",
                operation_family="file.read", effects=["read"], props=["external_source", "effect:read"])
    read["provenance"]["tool_call_id"] = "attachment"
    engine.evaluate([read])
    return engine


def test_exact_authorization_preserves_authorized_egress_but_missing_auth_independently_blocks(scoped):
    step, fact, _ = scoped
    unauthorized = history_engine(step).preview([step])
    assert unauthorized["verdict"] == "block"
    assert unauthorized["triggered_rule_id"].startswith("untrusted_external_content")
    allowed = history_engine(step, lambda *_: fact).preview([step])
    assert allowed["verdict"] != "block"
    assert allowed["authorization_exceptions"]


def test_office_authorization_cannot_suppress_other_tools_or_delete_block(scoped):
    step, fact, _ = scoped
    other = deepcopy(step)
    other.update(tool_name="exec", operation_family="process.execute")
    assert history_engine(step, lambda *_: fact).preview([other])["verdict"] == "block"
    rules = load_ruleset(CANDIDATE)
    assert all(rule.unless_authorized is None for monitor in rules.monitors for rule in monitor.rules
               if "delete" in rule.id or "sticky" in rule.id or "repeat" in rule.id)


def test_tool_guard_rejects_unrecognized_fields_and_matches_exact_names(scoped):
    with pytest.raises(ValidationError):
        ToolGuard.model_validate({"tool_names_typo": ["office_message_send"]})
    step, _, _ = scoped
    for names, excluded, expected in [(["read"], [], "ok"), ([], ["office_message_send"], "ok"),
                                      (["office_message_send"], [], "block")]:
        engine = RuntimeVerificationEngine()
        engine._spec_ruleset = Ruleset.model_validate({"version": 2, "event_model": "tool-call-v1", "monitors": [
            {"name": "finite", "rules": [{"id": "exact", "from": "*", "verdict": "block",
              "when": {"tool": {"names": names, "excluded_names": excluded}}}]}]})
        assert engine.preview([step])["verdict"] == expected


def test_upload_cannot_establish_its_own_attachment_read_history(scoped):
    step, _, _ = scoped
    step["props"] += ["attachment_download", "attachment_open", "external_source"]
    engine = RuntimeVerificationEngine()
    engine._spec_ruleset = load_ruleset(CANDIDATE)
    assert engine.preview([step])["verdict"] != "block"
    result = history_engine(step).preview([step])
    assert result["verdict"] == "block"
    assert result["matched_history_step_ids"] == ["run:attachment"]
