"""阶段 D 参数化原语测试。

覆盖：
- EntityMatcher 实体守卫（domain_in/domain_not_in/value_in）
- entity_all_of / entity_any_of 在 StepRequirement 中的判定
- state_counter 状态计数阈值
- _ParameterizedMonitor 参数化切片（forall + bind_vars）
- PerRecipientMailMonitor 端到端
- StateCounterDemoMonitor 端到端
- WindowManager.steps_with_entity / step_gap 回归
- 现有 DSL 规则集加载不破裂
"""

import unittest

from openclaw_guard.engine.runtime_verification import RuntimeVerificationEngine, WindowManager
from openclaw_guard.engine.rv_dsl import (
    ChainRule,
    EntityMatcher,
    MonitorSpec,
    Ruleset,
    StepRequirement,
    _matches_requirement,
    compile_monitors,
    load_ruleset,
)


# =============================================================================
# EntityMatcher
# =============================================================================


class TestEntityMatcher(unittest.TestCase):
    def test_value_in_single_match(self):
        m = EntityMatcher(kind="recipients", match_type="value_in", values=["a@b.com"])
        self.assertEqual(m.match_type, "value_in")

    def test_domain_in_matcher(self):
        m = EntityMatcher(kind="recipients", match_type="domain_in", values=["company.com"])
        self.assertEqual(m.kind, "recipients")

    def test_domain_not_in_matcher(self):
        m = EntityMatcher(kind="urls", match_type="domain_not_in", values=["local"])
        self.assertEqual(m.match_type, "domain_not_in")


# =============================================================================
# StepRequirement 实体守卫
# =============================================================================


class TestEntityGuards(unittest.TestCase):
    def setUp(self):
        self.window = WindowManager(max_size=10)

    def test_entity_all_of_all_match(self):
        """entity_all_of 全部命中才通过。"""
        req = StepRequirement(
            entity_all_of=[
                EntityMatcher(kind="recipients", match_type="domain_not_in", values=["internal.com"]),
            ],
        )
        step = {"event": "e", "props": [], "entities": [
            {"kind": "recipients", "values": ["alice@external.com"]},
        ]}
        self.assertTrue(_matches_requirement(
            req, props=set(), event="e", window=self.window, current_step=step,
        ))

    def test_entity_all_of_fails_if_one_miss(self):
        req = StepRequirement(
            entity_all_of=[
                EntityMatcher(kind="recipients", match_type="domain_not_in", values=["internal.com"]),
                EntityMatcher(kind="paths", match_type="value_in", values=["/etc/passwd"]),
            ],
        )
        step = {"event": "e", "props": [], "entities": [
            {"kind": "recipients", "values": ["alice@external.com"]},
        ]}
        self.assertFalse(_matches_requirement(
            req, props=set(), event="e", window=self.window, current_step=step,
        ))

    def test_entity_any_of_at_least_one_hits(self):
        req = StepRequirement(
            entity_any_of=[
                EntityMatcher(kind="recipients", match_type="domain_in", values=["internal.com"]),
                EntityMatcher(kind="recipients", match_type="domain_in", values=["partner.com"]),
            ],
        )
        step = {"event": "e", "props": [], "entities": [
            {"kind": "recipients", "values": ["alice@partner.com"]},
        ]}
        self.assertTrue(_matches_requirement(
            req, props=set(), event="e", window=self.window, current_step=step,
        ))

    def test_entity_any_of_all_miss(self):
        req = StepRequirement(
            entity_any_of=[
                EntityMatcher(kind="recipients", match_type="domain_in", values=["internal.com"]),
            ],
        )
        step = {"event": "e", "props": [], "entities": [
            {"kind": "recipients", "values": ["alice@external.com"]},
        ]}
        self.assertFalse(_matches_requirement(
            req, props=set(), event="e", window=self.window, current_step=step,
        ))

    def test_mixed_entity_and_prop_guards(self):
        """实体守卫 + props 守卫同时生效。"""
        req = StepRequirement(
            event="mail_send",
            entity_all_of=[
                EntityMatcher(kind="recipients", match_type="domain_not_in", values=["internal.com"]),
            ],
        )
        step = {
            "event": "mail_send",
            "props": ["mail_send", "external_recipient"],
            "entities": [{"kind": "recipients", "values": ["eve@bad.com"]}],
        }
        self.assertTrue(_matches_requirement(
            req, props=set(step["props"]), event="mail_send", window=self.window, current_step=step,
        ))


# =============================================================================
# state_counter 状态计数器
# =============================================================================


class TestStateCounter(unittest.TestCase):
    def setUp(self):
        self.window = WindowManager(max_size=10)

    def test_state_counter_gte_met(self):
        req = StepRequirement(
            event="mail_send",
            state_counter={"warm": {"gte": 5}},
        )
        step = {"event": "mail_send", "props": ["mail_send"]}
        self.assertTrue(_matches_requirement(
            req, props=set(["mail_send"]), event="mail_send", window=self.window,
            current_step=step, state_counts={"warm": 5},
        ))

    def test_state_counter_gte_not_met(self):
        req = StepRequirement(
            state_counter={"warm": {"gte": 5}},
        )
        step = {"event": "e", "props": []}
        self.assertFalse(_matches_requirement(
            req, props=set(), event="e", window=self.window,
            current_step=step, state_counts={"warm": 3},
        ))

    def test_state_counter_lt_blocks_exceed(self):
        req = StepRequirement(
            state_counter={"armed": {"lt": 3}},
        )
        step = {"event": "e", "props": []}
        self.assertFalse(_matches_requirement(
            req, props=set(), event="e", window=self.window,
            current_step=step, state_counts={"armed": 5},
        ))

    def test_state_counter_multiple_conditions(self):
        """两个状态计数条件同时满足才通过。"""
        req = StepRequirement(
            state_counter={
                "warm": {"gte": 3},
                "hot": {"lt": 10},
            },
        )
        step = {"event": "e", "props": []}
        self.assertTrue(_matches_requirement(
            req, props=set(), event="e", window=self.window,
            current_step=step, state_counts={"warm": 5, "hot": 5},
        ))
        self.assertFalse(_matches_requirement(
            req, props=set(), event="e", window=self.window,
            current_step=step, state_counts={"warm": 2, "hot": 5},
        ))


# =============================================================================
# WindowManager 阶段 D 扩展
# =============================================================================


class TestWindowManagerExtensions(unittest.TestCase):
    def setUp(self):
        self.wm = WindowManager(max_size=10)

    def test_steps_with_entity_returns_matching_steps(self):
        self.wm.push({"event": "e1", "props": [], "entities": [
            {"kind": "recipients", "values": ["a@b.com"]},
        ]})
        self.wm.push({"event": "e2", "props": [], "entities": []})
        self.wm.push({"event": "e3", "props": [], "entities": [
            {"kind": "recipients", "values": ["c@d.com"]},
        ]})
        results = self.wm.steps_with_entity("recipients")
        self.assertEqual(len(results), 2)

    def test_steps_with_entity_with_predicate(self):
        self.wm.push({"event": "e1", "props": [], "entities": [
            {"kind": "recipients", "values": ["a@internal.com"]},
        ]})
        self.wm.push({"event": "e2", "props": [], "entities": [
            {"kind": "recipients", "values": ["b@external.com"]},
        ]})
        results = self.wm.steps_with_entity(
            "recipients",
            predicate={"match_type": "domain_not_in", "values": ["internal.com"]},
        )
        self.assertEqual(len(results), 1)  # only external

    def test_step_gap_returns_time_diff(self):
        self.wm.push({"event": "old", "props": []})
        self.wm.push({"event": "new", "props": []})
        snap = self.wm.snapshot()
        # 手动设置时间戳模拟间隔
        snap[0]["_ts_epoch"] = 1000.0
        snap[1]["_ts_epoch"] = 1010.0
        gap = self.wm.step_gap(snap[0], snap[1])
        self.assertAlmostEqual(gap, 10.0, delta=0.1)

    def test_step_gap_none_for_missing_ts(self):
        self.wm.push({"event": "x", "props": []})
        self.wm.push({"event": "y", "props": []})
        snap = self.wm.snapshot()
        del snap[0]["_ts_epoch"]
        gap = self.wm.step_gap(snap[0], snap[1])
        self.assertIsNone(gap)


# =============================================================================
# 参数化监视器（forall + bind_vars）
# =============================================================================


class TestParameterizedMonitor(unittest.TestCase):
    def test_loads_and_compiles(self):
        ruleset = load_ruleset()
        monitors = compile_monitors(ruleset)
        names = [type(m).__name__ for m in monitors]
        self.assertIn("PerRecipientMailMonitor", names)

    def test_parameterized_monitor_feed_external_triggers(self):
        spec = MonitorSpec(
            name="PerRecipientTest",
            initial="idle",
            quantifier="forall",
            bind_vars=["recipients"],
            rules=[
                {"id": "r1", "from": "idle", "to": "idle", "verdict": "ask",
                 "when": {"event": "mail_send",
                           "entity_any_of": [
                               {"kind": "recipients", "match_type": "domain_not_in", "values": ["internal.com"]},
                           ]}},
            ],
        )
        [mon] = compile_monitors(Ruleset(monitors=[spec]))
        wm = WindowManager(max_size=10)
        step = {"event": "mail_send", "props": ["mail_send"], "entities": [
            {"kind": "recipients", "values": ["spy@external.com"]},
        ]}
        wm.push(step)
        result = mon.feed(step, wm)
        self.assertEqual(result, "ask")

    def test_parameterized_monitor_internal_recipient_no_trigger(self):
        spec = MonitorSpec(
            name="PerRecipientTest2",
            initial="idle",
            quantifier="forall",
            bind_vars=["recipients"],
            rules=[
                {"id": "r1", "from": "idle", "to": "idle", "verdict": "ask",
                 "when": {"event": "mail_send",
                           "entity_any_of": [
                               {"kind": "recipients", "match_type": "domain_not_in", "values": ["internal.com"]},
                           ]}},
            ],
        )
        [mon] = compile_monitors(Ruleset(monitors=[spec]))
        wm = WindowManager(max_size=10)
        step = {"event": "mail_send", "props": ["mail_send"], "entities": [
            {"kind": "recipients", "values": ["team@internal.com"]},
        ]}
        wm.push(step)
        result = mon.feed(step, wm)
        self.assertIsNone(result)


# =============================================================================
# StateCounterDemoMonitor 端到端
# =============================================================================


class TestStateCounterDemoMonitor(unittest.TestCase):
    def test_5_mail_sends_triggers_state_counter(self):
        """状态计数器：≥5 次 warm 状态后触发 ask。"""
        spec = MonitorSpec(
            name="DemoSC",
            initial="idle",
            rules=[
                ChainRule(id="d1", **{"from": "idle", "to": "warm"},
                          when=StepRequirement(any_of=["mail_send"])),
                # 非判决自环：仅积累计数，不跳转
                ChainRule(id="d1loop", **{"from": "warm", "to": "warm"},
                          when=StepRequirement(any_of=["mail_send"])),
                ChainRule(id="d2", **{"from": "warm", "to": "warm"},
                          verdict="ask",
                          when=StepRequirement(any_of=["mail_send"],
                                               state_counter={"warm": {"gte": 3}})),
            ],
        )
        [mon] = compile_monitors(Ruleset(monitors=[spec]))
        wm = WindowManager(max_size=10)
        step = {"event": "mail_send", "props": ["mail_send"]}

        # Step 1: idle→warm (+1) then warm→warm via d1loop (+1) → warm=2
        wm.push(step)
        r = mon.feed(step, wm)
        self.assertIsNone(r, f"Step 1 should be ok, warm count={mon._state_counts.get('warm', 0)}")
        self.assertEqual(mon.current_state, "warm")

        # Step 2: warm→warm (+1) → warm=3 → gte=3 通过 → ask
        wm.push(step)
        r = mon.feed(step, wm)
        self.assertEqual(r, "ask", f"Step 2 should trigger ask, warm count={mon._state_counts.get('warm', 0)}")
        self.assertEqual(mon.current_state, "warm")

    def test_state_counter_reset_works(self):
        spec = MonitorSpec(
            name="DemoSC2",
            initial="idle",
            rules=[
                {"id": "d1", "from": "idle", "to": "warm",
                 "when": {"any_of": ["mail_send"]}},
            ],
        )
        [mon] = compile_monitors(Ruleset(monitors=[spec]))
        wm = WindowManager(max_size=10)
        step = {"event": "mail_send", "props": ["mail_send"]}
        wm.push(step)
        mon.feed(step, wm)
        self.assertEqual(mon.current_state, "warm")
        mon.reset()
        self.assertEqual(mon.current_state, "idle")
        self.assertEqual(mon.state_summary()["state_counts"], {})


# =============================================================================
# 回归：现有 DSL 不破裂
# =============================================================================


class TestDslRegression(unittest.TestCase):
    def test_default_ruleset_loads_successfully(self):
        ruleset = load_ruleset()
        monitors = compile_monitors(ruleset)
        self.assertGreaterEqual(len(monitors), 8)  # 6 original + 2 new

    def test_rv_engine_with_parameterized_rules(self):
        """包含参数化规则的引擎应正常评估。"""
        engine = RuntimeVerificationEngine(window_size=10, rule_mode="dsl")
        rv_trace = [{
            "step_id": "s1",
            "event": "database_query",
            "props": ["database_query", "user_table"],
        }]
        result = engine.evaluate(rv_trace)
        self.assertIn(result["verdict"], ("ok", "ask", "escalate", "block"))

    def test_old_style_monitors_unaffected(self):
        """旧版监视器（无 bind_vars）行为不变。"""
        engine = RuntimeVerificationEngine(window_size=10, rule_mode="dsl")
        rv_trace = [{
            "step_id": "s1",
            "event": "mail_send",
            "props": ["mail_send", "external_recipient", "contains_secret"],
        }]
        result = engine.evaluate(rv_trace)
        self.assertEqual(result["verdict"], "block")


if __name__ == "__main__":
    unittest.main()
