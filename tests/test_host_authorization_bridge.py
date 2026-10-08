"""宿主引用证据接入有限工具调用的认证和消融边界回归。"""
from __future__ import annotations

import json
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from openclaw_guard.engine.experiment_components import ExperimentComponents, using
from openclaw_guard.engine.pipeline import _annotate_event_context, _apply_rv_if_available
from openclaw_guard.models import DetectionDecision
from openclaw_guard.utils import utc_now_iso
from openclaw_guard.integrations.host_authorization_bridge import HostAuthorizationBridge
from openclaw_guard.integrations.tool_hook_bridge import build_hook_event
from openclaw_guard.policy.catalog import PolicyBundle
from openclaw_guard.policy.trace import TraceCompiler
from openclaw_guard.rv.tool_events import build_tool_call_step
from openclaw_guard.spec.host_authorization import HostAuthorizationError, HostAuthorizationStore, TaskBinding
from openclaw_guard.spec.resource_evidence import HostResourceObserver


@pytest.fixture
def configured(tmp_path):
    """宿主私有存储和已登记办公工具的资源命名空间。"""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "summary.txt").write_text("public summary")
    store = HostAuthorizationStore(tmp_path / "host", agent_workspaces=[workspace])
    observer = HostResourceObserver({"office": workspace})
    grant = store.issue(observer, "office", "summary.txt",
                        binding=TaskBinding("host-task", "hook:binding", "agent", "session", "run"),
                        operation="network.egress", recipient="person@example.test")
    bridge = HostAuthorizationBridge(store, observer, tool_namespaces={"office_document_share": "office"})
    yield workspace, store, bridge, grant
    bridge.close()


def _event_step(**overrides):
    """模拟服务端认证后的Hook上下文，有限事件由真实投影函数生成。"""
    payload = {"toolName": "office_document_share", "params": {"document": "summary.txt", "recipient": "person@example.test"},
               "agentId": "agent", "sessionId": "session", "runId": "run", "toolCallId": "call",
               "_hook_auth_verified": True, "_hook_auth_binding": "binding"}
    payload.update(overrides)
    event = build_hook_event(payload)
    trace = TraceCompiler(PolicyBundle.load("policies/permissions")).compile(event, semantic={}, rv_trace=[])
    return event, build_tool_call_step(event, trace)


def test_authenticated_reference_is_not_verified_content_or_allow(configured):
    """宿主匹配引用授权仍不证明外发字节血缘，也不产生放行裁决。"""
    event, step = _event_step()
    evidence = configured[2].project(event, step)
    assert evidence["reference_grant_match"]
    assert evidence["task_id"] == "host-task"
    assert evidence["grant_id"] == configured[3]["id"]
    assert evidence["content_relationship"] == "parameter_reference_only"
    assert not evidence["content_lineage_verified"]
    assert "decision" not in evidence
    assert step["effects"] == ["egress"]


def test_tool_parameters_cannot_forge_context_task_or_resource_evidence(configured):
    """工具参数中的身份、task和内容版本声明不替换认证上下文。"""
    event, step = _event_step(params={"document": "summary.txt", "recipient": "attacker@example.test",
                                    "task_id": "host-task", "sessionId": "session", "agentId": "agent",
                                    "raw_user_intent": "authorized", "grant_id": configured[3]["id"],
                                    "content_version": configured[3]["resource"]["content_version"]})
    assert not configured[2].project(event, step)["reference_grant_match"]
    event, step = _event_step(sessionId="wrong", params={"document": "summary.txt", "recipient": "person@example.test", "sessionId": "session"})
    assert configured[2].project(event, step)["task_status"] == "unresolved_or_ambiguous"


def test_missing_authentication_does_not_read_host_store(configured):
    """未认证上下文不能读取授权存储或生成可信引用。"""
    event, step = _event_step(_hook_auth_verified=False)
    configured[2].store = Mock()
    assert configured[2].project(event, step)["status"] == "untrusted_context"
    assert not configured[2].store.mock_calls


def test_changed_resource_and_revocation_remove_reference_match(configured):
    """换内容和撤销不能复用原引用授权。"""
    event, step = _event_step()
    (configured[0] / "summary.txt").write_text("private data")
    assert not configured[2].project(event, step)["reference_grant_match"]
    (configured[0] / "summary.txt").write_text("public summary")
    configured[1].revoke(configured[3]["id"])
    assert not configured[2].project(event, step)["reference_grant_match"]


def test_unknown_resource_does_not_fall_back_to_body_or_public_filename(configured):
    """不可读取引用只是不确定，不把public标签或body当作宿主证明。"""
    event, step = _event_step(params={"document": "missing-public.txt", "body": "public summary", "recipient": "person@example.test", "public": True})
    evidence = configured[2].project(event, step)
    assert evidence["status"] == "inconclusive"
    assert not evidence["reference_grant_match"]


def test_disabled_authorization_does_not_query_or_observe(configured):
    """Full-Auth关闭时，宿主资源和授权路径完全不参与。"""
    event, step = _event_step()
    configured[2].store = Mock()
    configured[2].observer = Mock()
    with using(ExperimentComponents(authorization=False)):
        assert configured[2].project(event, step) == {"status": "disabled"}
    assert not configured[2].store.mock_calls
    assert not configured[2].observer.mock_calls


def test_pipeline_keeps_one_finite_event_and_does_not_change_effects(configured):
    """流水线只给唯一真实事件补充上下文，不新增语义调用或动作标签。"""
    event, original = _event_step()
    compiler = TraceCompiler(PolicyBundle.load("policies/permissions"))
    semantic = {"semantic": {"labels": []}, "semantic_match": {}, "semantic_audit": {}, "rv_trace": []}
    services = SimpleNamespace(context=SimpleNamespace(target=SimpleNamespace(workspace_path=configured[0], source_root=None),
                                                       paths=SimpleNamespace(project_dir=configured[0])),
                               semantic_enhancer=SimpleNamespace(evaluate=lambda *args: semantic),
                               policy_engine=SimpleNamespace(compile_trace=lambda e, **kwargs: compiler.compile(e, semantic={}, rv_trace=[])),
                               host_authorization_bridge=configured[2])
    _annotate_event_context(services, event)
    assert len(event.metadata["rv_trace"]) == 1
    projected = event.metadata["rv_trace"][0]
    assert projected["event_model"] == "tool-call-v1"
    assert projected["effects"] == original["effects"]
    assert projected["props"] == original["props"]
    assert projected["context"]["host_authorization"]["status"] == "pending_reference_observation"
    assert not projected["context"]["host_authorization"]["reference_grant_match"]
    services.host_authorization_bridge = Mock(history_preparation=None)
    with using(ExperimentComponents(authorization=False)):
        _annotate_event_context(services, event)
    assert not services.host_authorization_bridge.mock_calls
    assert "host_authorization" not in event.metadata
    assert "host_authorization" not in event.metadata["rv_trace"][0]["context"]


def test_host_config_must_be_private_and_outside_agent_workspace(configured):
    """显式配置不能由Agent工作区文件或可写公共配置取得权威。"""
    workspace, store, bridge, grant = configured
    payload = {"agent_workspaces": [str(workspace)], "state_dir": str(store.state_dir),
               "namespaces": {"office": str(workspace)}, "tool_namespaces": {"office_document_share": "office"}}
    config = store.state_dir / "config.json"
    config.write_text(json.dumps(payload))
    config.chmod(0o600)
    loaded = HostAuthorizationBridge.from_config(config)
    assert loaded.tool_namespaces == bridge.tool_namespaces
    loaded.close()
    config.chmod(0o644)
    with pytest.raises(HostAuthorizationError):
        HostAuthorizationBridge.from_config(config)
    workspace.chmod(0o700)
    config = workspace / "config.json"
    config.write_text(json.dumps(payload))
    config.chmod(0o600)
    with pytest.raises(HostAuthorizationError):
        HostAuthorizationBridge.from_config(config)


def test_operation_or_namespace_mismatch_cannot_reuse_tool_contract(configured):
    """具体工具必须符合有限操作族映射，命名空间必须已由宿主登记。"""
    event, step = _event_step()
    step["operation_family"] = "file.delete"
    assert configured[2].project(event, step)["status"] == "operation_contract_mismatch"
    with pytest.raises(HostAuthorizationError):
        HostAuthorizationBridge(configured[1], configured[2].observer,
                                tool_namespaces={"office_document_share": "unknown"})


def test_slow_reference_observation_does_not_wait_in_before_hook(configured):
    """慢观察不能拖延执行前Hook，后台超2秒也不等待其授权结果。"""
    started = threading.Event()
    release = threading.Event()
    bridge = configured[2]
    def slow_project(event, step):
        started.set()
        release.wait(timeout=3)
        return {"status": "reference_observed", "content_lineage_verified": False}
    bridge.project = slow_project
    event, step = _event_step()
    try:
        before = time.monotonic()
        assert bridge.submit(event, step)["status"] == "pending_reference_observation"
        assert time.monotonic() - before < 0.1
        assert started.wait(timeout=1)
        assert bridge.reference_evidence(event.event_id) is None
        event.metadata["rv_trace"] = [step]
        services = SimpleNamespace(rv_enabled=lambda: True, rv_engine=SimpleNamespace(
            preview=lambda *args, **kwargs: {"verdict": "block", "reason": "existing rule", "triggered_by": "old-rule"}))
        decision = DetectionDecision(event_id=event.event_id, timestamp=utc_now_iso(),
                                     action_type=event.action_type, action="allow", risk_level="safe",
                                     reason="test", rule_ids=[])
        assert _apply_rv_if_available(services, event, decision).action == "block"
        # Worker仍在等待时，新的before提交不被慢观察阻塞。
        before = time.monotonic()
        bridge.submit(event, step)
        assert time.monotonic() - before < 0.1
        for _ in range(32):
            result = bridge.submit(event, step)
        assert result["status"] == "reference_queue_full"
    finally:
        release.set()


def test_disabled_submit_and_closed_queue_do_not_observe(configured):
    """关闭组件或停止观察器时，提交不进入宿主观察路径。"""
    event, step = _event_step()
    bridge = configured[2]
    with using(ExperimentComponents(authorization=False)):
        assert bridge.submit(event, step)["status"] == "disabled"
    bridge.close()
    assert bridge.submit(event, step)["status"] == "disabled"


def test_cli_requires_explicit_host_reference_configuration():
    """宿主观察只能由run显式配置，默认不读私有存储。"""
    from pathlib import Path
    from openclaw_guard.main import build_parser
    assert build_parser().parse_args(["run"]).host_authorization_config is None
    args = build_parser().parse_args(["run", "--host-authorization-config", "/host/config.json"])
    assert args.host_authorization_config == Path("/host/config.json")


@pytest.mark.parametrize("transition", ["disable", "disable_then_enable", "close"])
def test_inflight_reference_cannot_publish_into_new_arm(configured, transition):
    """参考观察已开始时切臂或关闭，不能发布旧臂正向授权诊断。"""
    from openclaw_guard.engine import experiment_components as ec
    bridge = configured[2]
    started, release = threading.Event(), threading.Event()
    def slow_project(event, step):
        started.set()
        release.wait(timeout=3)
        return {"status": "reference_observed", "reference_grant_match": True}
    bridge.project = slow_project
    event, step = _event_step()
    try:
        bridge.submit(event, step)
        assert started.wait(timeout=1)
        if transition == "close":
            bridge.close()
        else:
            ec.configure(ec.ExperimentComponents(authorization=False))
            if transition == "disable_then_enable":
                ec.reset()
        release.set()
        bridge._queue.join()
        assert bridge.reference_evidence(event.event_id) is None
    finally:
        release.set()
        ec.reset()
