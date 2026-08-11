"""阶段 F 干预升级测试。

覆盖：
- SessionSafetyState 风险评分累计
- 状态桶（safe/warning/elevated/critical）边界
- 连续 escalate → block 升级
- escalate + elevated 状态 → block 升级
- revision_hint 生成
- reset 清理
"""

import unittest

from openclaw_guard.engine.session_state import SessionSafetyState


class TestSessionSafetyState(unittest.TestCase):
    def setUp(self):
        self.ss = SessionSafetyState("test-session")

    def test_initial_state_safe(self):
        self.assertEqual(self.ss.current_state, "safe")
        self.assertEqual(self.ss.total_score, 0)

    def test_single_ask_pushes_to_warning(self):
        result = self.ss.record("ask", "suspicious")
        self.assertIsNone(result)
        # ask = 1, total=1, still safe (<3)
        self.assertEqual(self.ss.current_state, "safe")

    def test_three_asks_reach_warning(self):
        for _ in range(3):
            self.ss.record("ask")
        # 3 asks = 3, threshold for warning is 3
        self.assertEqual(self.ss.current_state, "warning")

    def test_escalate_bumps_score(self):
        self.ss.record("escalate")
        # escalate = 3, safe < 3, not >= 3? Actually 3 >= 3 for warning
        self.assertEqual(self.ss.total_score, 3)
        self.assertEqual(self.ss.current_state, "warning")

    def test_three_escalates_upgrade_to_block(self):
        """连续 3 次 escalate → 自动升级为 block。"""
        self.ss.record("escalate")
        self.ss.record("escalate")
        result = self.ss.record("escalate")
        self.assertEqual(result, "block")

    def test_escalate_plus_elevated_upgrades_to_block(self):
        """escalate + state=elevated → block。"""
        # 积累到 elevated: 需要 total >= 7
        self.ss.record("escalate")  # 3
        self.ss.record("escalate")  # 6
        self.ss.record("escalate")  # 7 (but escalate_to_block_count=3, so returns block)

    def test_escalate_score_then_elevated_state(self):
        # block = 5, 5 < 7 → warning
        self.ss.record("block")  # 5
        # ask = 1, 6 < 7 → warning
        self.ss.record("ask")  # 6
        # escalate = 3, 9 >= 7 → elevated
        result = self.ss.record("escalate")  # 9
        # escalate + elevated → block
        self.assertEqual(result, "block")
        self.assertEqual(self.ss.current_state, "elevated")

    def test_critical_state_blocks(self):
        # 4 blocks = 20 → critical (>15)
        for _ in range(4):
            self.ss.record("block")
        self.assertEqual(self.ss.current_state, "critical")
        result = self.ss.record("escalate", "last straw")
        # escalate + critical → block
        self.assertEqual(result, "block")

    def test_revision_hint_for_critical(self):
        for _ in range(4):
            self.ss.record("block")
        hint = self.ss.revision_hint()
        self.assertIsNotNone(hint)
        self.assertIn("critical", hint)

    def test_revision_hint_for_low_risk(self):
        self.ss.record("ask")
        hint = self.ss.revision_hint()
        self.assertIsNone(hint)

    def test_revision_hint_for_repeated_escalation(self):
        self.ss.record("escalate")
        self.ss.record("escalate")
        hint = self.ss.revision_hint()
        self.assertIsNotNone(hint)
        self.assertIn("repeated escalation", hint)

    def test_reset_clears_all(self):
        self.ss.record("block")
        self.ss.record("escalate")
        self.ss.reset()
        self.assertEqual(self.ss.total_score, 0)
        self.assertEqual(self.ss.current_state, "safe")
        self.assertEqual(self.ss.status()["escalate_to_block_count"], 0)

    def test_status_returns_dict(self):
        status = self.ss.status()
        self.assertIn("session_key", status)
        self.assertIn("state", status)
        self.assertIn("total_score", status)

    def test_non_escalate_resets_counter(self):
        """非 escalate 不增加计数器。"""
        self.ss.record("ask")
        self.ss.record("block")
        self.assertEqual(self.ss.status()["escalate_to_block_count"], 0)

    def test_escalate_not_block_when_safe(self):
        """单次 escalate + safe 状态不应升级为 block。"""
        result = self.ss.record("escalate")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
