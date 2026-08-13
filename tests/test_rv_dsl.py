from __future__ import annotations

import unittest

from openclaw_guard.rv.runtime_verification import RuntimeVerificationEngine, WindowManager
from openclaw_guard.rv.rv_dsl import (
    ChainRule,
    MonitorSpec,
    Ruleset,
    SequenceRequirement,
    StepRequirement,
    _matches_requirement,
    _sequence_matches,
    compile_monitors,
    load_ruleset,
)


class ChainRuleRequirementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.window = WindowManager(max_size=10, ttl_seconds=None)

    def test_event_matches_by_name_or_prop(self) -> None:
        req = StepRequirement(event="mail_send")
        self.assertTrue(_matches_requirement(req, props={"mail_send"}, event="x", window=self.window))
        self.assertTrue(_matches_requirement(req, props=set(), event="mail_send", window=self.window))
        self.assertFalse(_matches_requirement(req, props=set(), event="other", window=self.window))

    def test_all_any_none_of(self) -> None:
        req = StepRequirement(all_of=["a", "b"], any_of=["x", "y"], none_of=["ban"])
        self.assertTrue(_matches_requirement(req, props={"a", "b", "y"}, event="e", window=self.window))
        self.assertFalse(_matches_requirement(req, props={"a", "y"}, event="e", window=self.window))
        self.assertFalse(_matches_requirement(req, props={"a", "b", "y", "ban"}, event="e", window=self.window))

    def test_count_gte_and_window_any_of(self) -> None:
        self.window.push({"event": "e", "props": ["x"]})
        self.window.push({"event": "e", "props": ["x"]})
        self.window.push({"event": "e", "props": ["y"]})

        req = StepRequirement(
            count_gte={"label": "x", "threshold": 2, "window_size": None},
            window_any_of={"labels": ["y"], "window_size": 2},
        )
        self.assertTrue(_matches_requirement(req, props=set(), event="e", window=self.window))

        req_fail = StepRequirement(
            count_gte={"label": "x", "threshold": 3, "window_size": None},
        )
        self.assertFalse(_matches_requirement(req_fail, props=set(), event="e", window=self.window))

    def test_window_age_gt_seconds(self) -> None:
        self.window.push({"event": "e", "props": []})
        self.window._buffer[0]["_ts_epoch"] = self.window._buffer[0]["_ts_epoch"] - 10
        req = StepRequirement(window_age_gt_seconds=5)
        self.assertTrue(_matches_requirement(req, props=set(), event="e", window=self.window))


class ChainRuleSequenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.window = WindowManager(max_size=10, ttl_seconds=None)

    def test_sequence_matches_respects_order(self) -> None:
        self.window.push({"event": "a", "props": ["p1"]})
        self.window.push({"event": "b", "props": ["p2"]})
        seq = SequenceRequirement(steps=[StepRequirement(any_of=["p1"]), StepRequirement(any_of=["p2"])])
        self.assertTrue(_sequence_matches(seq, window=self.window))

        seq_rev = SequenceRequirement(steps=[StepRequirement(any_of=["p2"]), StepRequirement(any_of=["p1"])])
        self.assertFalse(_sequence_matches(seq_rev, window=self.window))

    def test_sequence_window_size_limits_recent_steps(self) -> None:
        self.window.push({"event": "a", "props": ["p1"]})
        self.window.push({"event": "b", "props": ["p2"]})
        self.window.push({"event": "c", "props": ["p3"]})
        seq = SequenceRequirement(
            steps=[StepRequirement(any_of=["p1"]), StepRequirement(any_of=["p3"])],
            window_size=2,
        )
        self.assertFalse(_sequence_matches(seq, window=self.window))


class DslCompilerMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.window = WindowManager(max_size=10, ttl_seconds=None)

    def test_compile_monitors_state_transition_and_verdict(self) -> None:
        ruleset = Ruleset(
            monitors=[
                MonitorSpec(
                    name="DemoMonitor",
                    initial="idle",
                    rules=[
                        ChainRule(id="t1", **{"from": "idle", "to": "armed"}, when=StepRequirement(all_of=["arm"])),
                        ChainRule(id="v1", **{"from": "armed", "to": "blocked"}, verdict="block", when=StepRequirement(all_of=["fire"])),
                    ],
                )
            ]
        )
        monitors = compile_monitors(ruleset)
        self.assertEqual(len(monitors), 1)
        m = monitors[0]

        step1 = {"event": "e1", "props": ["arm"]}
        self.window.push(step1)
        self.assertIsNone(m.feed(step1, self.window))
        self.assertEqual(m.current_state, "armed")

        step2 = {"event": "e2", "props": ["fire"]}
        self.window.push(step2)
        self.assertEqual(m.feed(step2, self.window), "block")
        self.assertEqual(m.current_state, "blocked")

    def test_verdict_selects_highest_severity(self) -> None:
        ruleset = Ruleset(
            monitors=[
                MonitorSpec(
                    name="SeverityMonitor",
                    initial="idle",
                    rules=[
                        ChainRule(id="ask", **{"from": "*", "to": None}, verdict="ask", when=StepRequirement(all_of=["x"])),
                        ChainRule(id="block", **{"from": "*", "to": None}, verdict="block", when=StepRequirement(all_of=["x"])),
                    ],
                )
            ]
        )
        m = compile_monitors(ruleset)[0]
        step = {"event": "e", "props": ["x"]}
        self.window.push(step)
        self.assertEqual(m.feed(step, self.window), "block")

    def test_default_ruleset_loads_and_compiles(self) -> None:
        ruleset = load_ruleset()
        monitors = compile_monitors(ruleset)
        self.assertGreaterEqual(len(monitors), 1)


class RvEngineRuleModeParityTests(unittest.TestCase):
    def _evaluate(self, mode: str, trace: list[dict]) -> dict:
        engine = RuntimeVerificationEngine(window_size=10, window_ttl_seconds=None, rule_mode=mode)
        return engine.evaluate(trace)

    def test_fsm_and_dsl_have_same_verdict_for_known_cases(self) -> None:
        traces = [
            [{"step_id": "s1", "event": "mail_send", "props": ["mail_send", "external_recipient", "contains_secret"]}],
            [{"step_id": "s1", "event": "channel_send", "props": ["channel_send", "bulk_send"]}],
            [{"step_id": "s1", "event": "database_query", "props": ["database_query", "user_table"]}],
        ]
        for trace in traces:
            fsm = self._evaluate("fsm", trace)
            dsl = self._evaluate("dsl", trace)
            self.assertEqual(fsm["verdict"], dsl["verdict"])
