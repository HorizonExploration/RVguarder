"""研究攻击夹具的结构回归测试。

这些测试只验证场景可加载、ID 唯一且事件包含最小审计字段；不执行任何真实攻击。
"""

from __future__ import annotations

import unittest

from testlab.research.fixtures import load_scenarios, scenario_ids
from testlab.research.baseline import run_current_rv_baseline


class ResearchAttackFixtureTests(unittest.TestCase):
    def test_scenarios_are_unique_and_cover_requested_classes(self) -> None:
        scenarios = load_scenarios()
        ids = scenario_ids()
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(scenarios), 8)
        self.assertEqual(
            {item["attack_class"] for item in scenarios},
            {
                "indirect_prompt_injection",
                "excessive_agency",
                "permission_creep",
                "toxic_combination",
                "cross_session_accumulation",
                "semantic_paraphrase",
                "tool_name_spoofing",
                "skill_supply_chain",
            },
        )

    def test_events_are_side_effect_free_fixture_records(self) -> None:
        for scenario in load_scenarios():
            for event in scenario["events"]:
                self.assertIsInstance(event.get("kind"), str)
                self.assertNotIn("command", event)
                self.assertNotIn("url", event)
                self.assertNotIn("credential", event)

    def test_current_rv_baseline_adapter_is_reproducible(self) -> None:
        results = run_current_rv_baseline()
        scenarios = {item["scenario_id"]: item for item in load_scenarios()}
        self.assertEqual([item["scenario_id"] for item in results], scenario_ids())
        for item in results:
            self.assertIn(item["final_verdict"], {"ok", "ask", "escalate", "block"})
            self.assertEqual(len(item["verdicts"]), len(scenarios[item["scenario_id"]]["events"]))


if __name__ == "__main__":
    unittest.main()
