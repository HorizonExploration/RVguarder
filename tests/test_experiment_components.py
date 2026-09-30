"""组件消融门（experiment_components）的单元测试。

覆盖：默认全开、from_disabled 解析与别名、未知名称报错、config_hash 稳定性与
区分度、using() 异常安全恢复，以及禁用后组件确实失效的最小断言。
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from openclaw_guard.engine import experiment_components as ec
from openclaw_guard.engine.experiment_components import (
    COMPONENT_NAMES,
    ExperimentComponents,
)
from openclaw_guard.engine.semantic_enhancer import SemanticEnhancer
from openclaw_guard.integrations.tool_hook_bridge import build_hook_event
from openclaw_guard.models import BehaviorEvent, DetectionDecision
from openclaw_guard.services import build_services
from openclaw_guard.utils import utc_now_iso


@pytest.fixture(autouse=True)
def _reset_components():
    """每个测试前后都恢复默认全开，避免模块级状态串扰。"""
    ec.reset()
    try:
        yield
    finally:
        ec.reset()


def _make_services() -> tuple[object, tempfile.TemporaryDirectory]:
    tmp = tempfile.TemporaryDirectory()
    project = Path(tmp.name) / "OpenclawGuard"
    project.mkdir()
    config_path = project / "openclaw.json"
    config_path.write_text(json.dumps({"models": {"providers": {}}}), encoding="utf-8")
    return build_services(project, config_path=config_path), tmp


def test_default_is_all_enabled_and_import_has_no_side_effects() -> None:
    assert COMPONENT_NAMES == (
        "semantic_llm",
        "cross_step_rv",
        "authorization",
        "approval_trust",
    )
    components = ec.current()
    assert components == ExperimentComponents.all_enabled()
    assert components.enabled() == COMPONENT_NAMES
    assert components.disabled() == ()


def test_from_disabled_parses_aliases_and_empty_spec() -> None:
    disabled = ExperimentComponents.from_disabled("cross_step,semantic_llm")
    assert disabled.cross_step_rv is False
    assert disabled.semantic_llm is False
    assert disabled.authorization is True
    assert disabled.approval_trust is True
    assert disabled.disabled() == ("semantic_llm", "cross_step_rv")

    # 规范全名同样被接受。
    assert ExperimentComponents.from_disabled("cross_step_rv").cross_step_rv is False
    assert ExperimentComponents.from_disabled("auth").authorization is False

    # 空字符串 ⇒ 全部启用。
    assert ExperimentComponents.from_disabled("") == ExperimentComponents.all_enabled()
    assert ExperimentComponents.from_disabled("  ") == ExperimentComponents.all_enabled()


def test_from_disabled_unknown_name_raises() -> None:
    with pytest.raises(ValueError):
        ExperimentComponents.from_disabled("cross_step,not_a_component")


def test_config_hash_is_stable_and_distinguishes_sets() -> None:
    baseline = ExperimentComponents.all_enabled()
    assert baseline.config_hash() == ExperimentComponents.all_enabled().config_hash()

    assert baseline.config_hash() != ExperimentComponents(semantic_llm=False).config_hash()
    assert (
        ExperimentComponents(semantic_llm=False).config_hash()
        != ExperimentComponents(cross_step_rv=False).config_hash()
    )
    # 逐字段取值都体现在哈希里。
    hashes = {
        ExperimentComponents(**{name: name != target for name in COMPONENT_NAMES}).config_hash()
        for target in COMPONENT_NAMES
    }
    assert len(hashes) == len(COMPONENT_NAMES)


def test_configure_and_using_restore_previous_state() -> None:
    ec.configure(ExperimentComponents(cross_step_rv=False))
    assert ec.current().cross_step_rv is False

    with pytest.raises(RuntimeError):
        with ec.using(ExperimentComponents(semantic_llm=False)):
            assert ec.current().semantic_llm is False
            assert ec.current().cross_step_rv is True
            raise RuntimeError("boom")

    # 异常退出后恢复到 using() 之前的配置。
    assert ec.current() == ExperimentComponents(cross_step_rv=False)


def test_semantic_llm_disabled_skips_provider_call() -> None:
    event = BehaviorEvent(
        event_id="evt-ablation-semantic",
        timestamp=utc_now_iso(),
        action_type="network_egress",
        process_name="openclaw",
        pid=None,
        user="tester",
        raw_payload={"raw_user_intent": "把今天的日报发给 alice@example.com，不要带附件"},
        source="chat",
    )
    enhancer = SemanticEnhancer(api_key="test-key")

    def _unexpected_provider_call(*_args, **_kwargs):
        raise AssertionError("disabled semantic_llm must not call the provider")

    enhancer._call_llm = _unexpected_provider_call  # type: ignore[assignment]

    ec.configure(ExperimentComponents(semantic_llm=False))
    result = enhancer.evaluate(event, {"source_message": "把今天的日报发给 alice@example.com", "origin": "chat"})

    assert result["semantic_audit"] == {"llm_attempted": False, "llm_status": "disabled"}
    # 仍走本地确定性规则，语义结果与 RV trace 不丢。
    assert result["semantic"]["scenario"] == "report_send"
    assert result["rv_trace"][0]["event"] == "report_send"


def test_cross_step_rv_disabled_produces_no_rv_result() -> None:
    services, tmp = _make_services()
    try:
        payload = {
            "action_type": "network_egress",
            "process_name": "openclaw",
            "user": "tester",
            "raw_user_intent": "把今天的日报发给 alice@example.com，不要带附件",
        }
        enabled_result = services.ingest_event(
            dict(payload),
            "把今天的日报发给 alice@example.com，不要带附件",
            auto_execute=False,
        )
        assert "rv_result" in enabled_result["event"]["metadata"]

        ec.configure(ExperimentComponents(cross_step_rv=False))
        disabled_result = services.ingest_event(
            dict(payload),
            "把今天的日报发给 alice@example.com，不要带附件",
            auto_execute=False,
        )
        assert "rv_result" not in disabled_result["event"]["metadata"]
    finally:
        tmp.cleanup()


def test_authorization_disabled_skips_principal_rv_overlay() -> None:
    services, tmp = _make_services()
    try:
        event = build_hook_event(
            {"toolName": "exec", "params": {"command": "cat summary.txt"}, "runId": "r1", "toolCallId": "c1"}
        )
        event.metadata["hook_bridge"] = True
        decision = DetectionDecision(
            event_id=event.event_id,
            timestamp=utc_now_iso(),
            action_type=event.action_type,
            risk_level="safe",
            action="allow",
            reason="fixture",
            rule_ids=[],
            trace=[],
        )

        services.apply_principal_rv(event, decision)
        assert "principal_rv" in event.metadata

        event.metadata.pop("principal_rv")
        ec.configure(ExperimentComponents(authorization=False))
        services.apply_principal_rv(event, decision)
        assert "principal_rv" not in event.metadata
    finally:
        tmp.cleanup()


def test_approval_trust_disabled_does_not_reuse_fingerprint(monkeypatch) -> None:
    services, tmp = _make_services()
    try:
        contains_calls: list[str] = []
        monkeypatch.setattr(
            services.approval_trust,
            "contains",
            lambda fingerprint: contains_calls.append(fingerprint) or True,
        )
        monkeypatch.setattr(services, "rv_enabled", lambda: False)
        monkeypatch.setattr(
            services.policy_engine,
            "decide",
            lambda event, **_kwargs: DetectionDecision(
                event_id=event.event_id,
                timestamp=utc_now_iso(),
                action_type=event.action_type,
                risk_level="caution",
                action="ask",
                reason="fixture approval",
                rule_ids=["fixture-approval"],
                trace=[],
                policy_decision={"effect": "openclaw_approval"},
            ),
        )

        import openclaw_guard.engine.pipeline as pipeline

        monkeypatch.setattr(
            pipeline,
            "build_approval_presentation",
            lambda *_args: {
                "allow_always": {"eligible": True, "fingerprint": "fixture-fingerprint"},
                "risk_summary": {"level": "caution", "reason": "fixture approval"},
            },
        )

        ec.configure(ExperimentComponents(approval_trust=False))
        result = services.handle_before_tool_call(
            {
                "toolName": "exec",
                "params": {"command": "cat summary.txt"},
                "runId": "approval-trust-ablation",
                "toolCallId": "approval-trust-call",
                "sessionId": "approval-trust-session",
            }
        )

        assert result["action"] == "require_approval"
        assert contains_calls == []
    finally:
        tmp.cleanup()
