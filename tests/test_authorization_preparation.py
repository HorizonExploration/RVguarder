"""有界授权准备的超时、同call复用、关闭和消融代际边界。"""
from __future__ import annotations

import threading
import time
from unittest.mock import patch

from test_native_content_receipts import native_producer
from test_call_authorizer import prepared_fixture
from openclaw_guard.engine import experiment_components as ec
from openclaw_guard.spec.authorization_preparation import BoundedAuthorizationPreparation


def setup_preparation(native_producer):
    """真实验签核验器通过后台队列准备；不代表原生审批验收。"""
    authorizer, proposal, event, step = prepared_fixture(native_producer)
    event.raw_payload["executionProposal"] = proposal
    return BoundedAuthorizationPreparation(authorizer), event, step


def test_prepared_fact_and_permit_only_available_for_actual_rule_exception(native_producer):
    preparation, event, step = setup_preparation(native_producer)
    try:
        assert preparation.prepare(event, step)["status"] == "authorization_prepared"
        fact = preparation.authorization_for_step(step, "rule")
        assert fact is not None
        assert preparation.permit_for_exceptions(step["step_id"], []) is None
        exception = {key: getattr(fact, key) for key in ("step_id", "grant_id", "snapshot_id", "task_id")}
        permit = preparation.permit_for_exceptions(step["step_id"], [exception])
        assert permit["payload"]["grant_id"] == fact.grant_id
        permit["payload"]["grant_id"] = "forged"
        assert preparation.permit_for_exceptions(step["step_id"], [exception])["payload"]["grant_id"] == fact.grant_id
    finally:
        preparation.close()


def test_missing_new_proposal_cannot_reuse_old_same_call_fact(native_producer):
    preparation, event, step = setup_preparation(native_producer)
    try:
        assert preparation.prepare(event, step)["status"] == "authorization_prepared"
        event.raw_payload.pop("executionProposal")
        with patch.object(preparation.authorizer, "prepare") as prepare:
            assert preparation.prepare(event, step)["status"] == "no_execution_proposal"
            prepare.assert_not_called()
        assert preparation.authorization_for_step(step, "rule") is None
    finally:
        preparation.close()


def test_timeout_does_not_publish_late_fact(native_producer):
    preparation, event, step = setup_preparation(native_producer)
    entered, release = threading.Event(), threading.Event()
    real_prepare = preparation.authorizer.prepare
    def slow(*args, **kwargs):
        entered.set()
        release.wait(2)
        return real_prepare(*args, **kwargs)
    try:
        with patch.object(preparation.authorizer, "prepare", side_effect=slow):
            assert preparation.prepare(event, step, wait_ms=0)["status"] == "authorization_preparation_timeout"
            assert entered.wait(1)
            release.set()
            deadline = time.monotonic() + 1
            while preparation._queue.unfinished_tasks and time.monotonic() < deadline:
                time.sleep(0.005)
            assert preparation._queue.unfinished_tasks == 0
            assert preparation.authorization_for_step(step, "rule") is None
    finally:
        release.set()
        preparation.close()


def test_old_generation_and_closed_preparation_cannot_supply_fact(native_producer):
    preparation, event, step = setup_preparation(native_producer)
    try:
        assert preparation.prepare(event, step)["status"] == "authorization_prepared"
        ec.configure(ec.ExperimentComponents(authorization=False))
        assert preparation.authorization_for_step(step, "rule") is None
        ec.reset()
        assert preparation.authorization_for_step(step, "rule") is None
        assert preparation.prepare(event, step)["status"] == "authorization_prepared"
        preparation.close()
        assert preparation.authorization_for_step(step, "rule") is None
        assert preparation.prepare(event, step)["status"] == "disabled"
    finally:
        ec.reset()
        preparation.close()


def test_replaced_ticket_cannot_report_another_requests_fact(native_producer):
    """请求完成之后被替换，只能读取自己票据的结果。"""
    preparation, event, step = setup_preparation(native_producer)
    try:
        assert preparation.prepare(event, step)["status"] == "authorization_prepared"
        with preparation._lock:
            old_token = preparation._latest[step["step_id"]]
            preparation._latest[step["step_id"]] = "new-request"
        assert preparation._get(step["step_id"], expected_token=old_token) is None
    finally:
        preparation.close()
