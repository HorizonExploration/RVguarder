"""后台持久化切臂、关闭及热路径清理的并发屏障回归。"""
from __future__ import annotations

import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from openclaw_guard.engine import experiment_components as ec
from openclaw_guard.spec.cross_history import BoundedHistoryRecorder


@pytest.mark.parametrize('retirement', ['disable', 'close'])
def test_retired_recorder_cannot_commit_after_verification(retirement):
    entered, resume = threading.Event(), threading.Event()
    def verify(*args, **kwargs):
        entered.set()
        assert resume.wait(2)
        return object()
    authority, history = Mock(), Mock()
    authority.verify.side_effect = verify
    recorder = BoundedHistoryRecorder(authority, history)
    try:
        recorder.submit({}, event=SimpleNamespace(metadata={}, raw_payload={'params': {}}),
                        step={'operation_family': 'file.read', 'execution_state': 'succeeded'})
        assert entered.wait(1)
        if retirement == 'disable':
            ec.configure(ec.ExperimentComponents.from_disabled('cross_session'))
        else:
            recorder.close()
        resume.set()
        assert recorder.wait_idle(timeout=1)
        history.record_verified.assert_not_called()
    finally:
        resume.set()
        recorder.close()
        ec.reset()


def test_disabling_waits_for_existing_disk_commit_without_holding_snapshot_lock():
    entered, resume, disabled = threading.Event(), threading.Event(), threading.Event()
    history, authority = Mock(), Mock()
    def record(*args):
        entered.set()
        assert resume.wait(2)
    history.record_verified.side_effect = record
    recorder = BoundedHistoryRecorder(authority, history)
    switcher = threading.Thread(target=lambda: (ec.configure(ec.ExperimentComponents.from_disabled('cross_session')), disabled.set()))
    try:
        recorder.submit({}, event=SimpleNamespace(metadata={}, raw_payload={'params': {}}),
                        step={'operation_family': 'file.read', 'execution_state': 'succeeded'})
        assert entered.wait(1)
        switcher.start()
        assert not disabled.wait(.03)
        assert ec.snapshot()[0].cross_session_rv
        resume.set()
        assert disabled.wait(1)
        assert recorder.wait_idle(timeout=1)
        assert history.record_verified.call_count == 1
    finally:
        resume.set()
        switcher.join(timeout=2)
        recorder.close()
        ec.reset()
