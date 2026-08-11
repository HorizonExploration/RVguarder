"""约束推理引擎单元测试。

覆盖：
- 实体约束（域内/域外/值匹配）
- 标签约束（require_all / require_any）
- 动作约束
- 加权评分
- 置信度门控
- 10 条已迁移规则与旧 lambda 行为对齐
"""

import unittest

from openclaw_guard.engine.constraints import (
    ActionConstraint,
    ConstraintEngine,
    ConstraintRule,
    EntityConstraint,
    TagConstraint,
    migrated_constraint_rules,
)
from openclaw_guard.engine.ir import Entity, ToolCallIR


# =============================================================================
# EntityConstraint
# =============================================================================


class TestEntityConstraint(unittest.TestCase):
    def test_value_in_matches(self):
        c = EntityConstraint(kind="recipients", match_type="value_in", values=["alice@example.com"])
        self.assertTrue(c.matches(["alice@example.com"]))
        self.assertFalse(c.matches(["bob@other.com"]))

    def test_domain_in_matches(self):
        c = EntityConstraint(kind="recipients", match_type="domain_in", values=["example.com"])
        self.assertTrue(c.matches(["alice@example.com"]))
        self.assertFalse(c.matches(["alice@other.com"]))

    def test_domain_not_in_blocks_external(self):
        c = EntityConstraint(kind="recipients", match_type="domain_not_in", values=["internal.com"])
        self.assertTrue(c.matches(["alice@external.com"]))
        self.assertFalse(c.matches(["alice@internal.com"]))

    def test_empty_values_always_false(self):
        c = EntityConstraint(kind="recipients", match_type="value_in", values=["alice@example.com"])
        self.assertFalse(c.matches([]))


# =============================================================================
# ConstraintRule
# =============================================================================


class TestConstraintRule(unittest.TestCase):
    def test_minimal_rule(self):
        rule = ConstraintRule(
            rule_id="TEST-001",
            title="test",
            description="desc",
            severity="high",
            risk_level="dangerous",
            decision="ask",
        )
        self.assertEqual(rule.rule_id, "TEST-001")
        self.assertIsNone(rule.action)
        self.assertIsNone(rule.tags)
        self.assertIsNone(rule.entity)

    def test_full_rule_with_all_constraints(self):
        rule = ConstraintRule(
            rule_id="TEST-002",
            title="full test",
            description="all constraints",
            severity="critical",
            risk_level="blocked",
            decision="block",
            action=ActionConstraint(action_types=["command_exec"]),
            tags=TagConstraint(require_all=["command_rm_rf"]),
            entity=EntityConstraint(kind="paths", match_type="value_in", values=["/etc/passwd"]),
        )
        self.assertIsNotNone(rule.action)
        self.assertIsNotNone(rule.tags)
        self.assertIsNotNone(rule.entity)


# =============================================================================
# ConstraintEngine
# =============================================================================


class TestConstraintEngine(unittest.TestCase):
    def test_empty_ir_returns_empty(self):
        engine = ConstraintEngine(migrated_constraint_rules())
        results = engine.evaluate([])
        self.assertEqual(results, [])

    def test_rm_rf_matches_cmd_001(self):
        engine = ConstraintEngine(migrated_constraint_rules())
        ir = ToolCallIR(
            step_id="s1",
            event="command_exec",
            props=["command_rm_rf", "command_exec"],
        )
        results = engine.evaluate([ir])
        self.assertTrue(any(r.rule_id == "CMD-001" for r, _ in results))

    def test_curl_pipe_sh_matches_cmd_002(self):
        engine = ConstraintEngine(migrated_constraint_rules())
        ir = ToolCallIR(
            step_id="s1",
            event="command_exec",
            props=["command_pipe_curl_sh", "command_exec"],
        )
        results = engine.evaluate([ir])
        self.assertTrue(any(r.rule_id == "CMD-002" for r, _ in results))

    def test_sudo_matches_cmd_004(self):
        engine = ConstraintEngine(migrated_constraint_rules())
        ir = ToolCallIR(
            step_id="s1",
            event="command_exec",
            props=["command_sudo", "command_exec"],
        )
        results = engine.evaluate([ir])
        matched_ids = [r.rule_id for r, _ in results]
        self.assertIn("CMD-004", matched_ids)

    def test_system_path_delete_matches_file_001(self):
        engine = ConstraintEngine(migrated_constraint_rules())
        ir = ToolCallIR(
            step_id="s1",
            event="file_delete",
            props=["file_delete", "path_system_root"],
        )
        results = engine.evaluate([ir])
        self.assertTrue(any(r.rule_id == "FILE-001" for r, _ in results))

    def test_sensitive_creds_delete_matches_file_002(self):
        engine = ConstraintEngine(migrated_constraint_rules())
        ir = ToolCallIR(
            step_id="s1",
            event="file_delete",
            props=["file_delete", "path_sensitive_creds"],
        )
        results = engine.evaluate([ir])
        self.assertTrue(any(r.rule_id == "FILE-002" for r, _ in results))

    def test_network_http_matches_net_001(self):
        engine = ConstraintEngine(migrated_constraint_rules())
        ir = ToolCallIR(
            step_id="s1",
            event="network_egress",
            props=["network_egress", "network_http"],
        )
        results = engine.evaluate([ir])
        self.assertTrue(any(r.rule_id == "NET-001" for r, _ in results))

    def test_network_secret_payload_matches_net_005(self):
        engine = ConstraintEngine(migrated_constraint_rules())
        ir = ToolCallIR(
            step_id="s1",
            event="network_egress",
            props=["network_egress", "network_secret_payload"],
        )
        results = engine.evaluate([ir])
        self.assertTrue(any(r.rule_id == "NET-005" for r, _ in results))

    def test_config_auth_disable_matches_cfg_002(self):
        engine = ConstraintEngine(migrated_constraint_rules())
        ir = ToolCallIR(
            step_id="s1",
            event="config_modify",
            props=["config_modify", "config_auth_disable"],
        )
        results = engine.evaluate([ir])
        self.assertTrue(any(r.rule_id == "CFG-002" for r, _ in results))

    def test_skill_persistence_matches_skl_005(self):
        engine = ConstraintEngine(migrated_constraint_rules())
        ir = ToolCallIR(
            step_id="s1",
            event="skill_run",
            props=["skill_run", "skill_persistence"],
        )
        results = engine.evaluate([ir])
        self.assertTrue(any(r.rule_id == "SKL-005" for r, _ in results))

    def test_wrong_action_type_no_match(self):
        """错误的 action_type 不应匹配带动作约束的规则。"""
        engine = ConstraintEngine(migrated_constraint_rules())
        ir = ToolCallIR(
            step_id="s1",
            event="chat_message",
            props=["command_rm_rf"],
        )
        results = engine.evaluate([ir])
        matched_ids = [r.rule_id for r, _ in results]
        self.assertNotIn("CMD-001", matched_ids)

    def test_missing_tag_no_match(self):
        engine = ConstraintEngine(migrated_constraint_rules())
        ir = ToolCallIR(
            step_id="s1",
            event="command_exec",
            props=["command_exec"],
        )
        results = engine.evaluate([ir])
        matched_ids = [r.rule_id for r, _ in results]
        self.assertNotIn("CMD-001", matched_ids)

    def test_results_sorted_by_score(self):
        engine = ConstraintEngine(migrated_constraint_rules())
        ir = ToolCallIR(
            step_id="s1",
            event="network_egress",
            props=["network_egress", "network_http", "network_secret_payload"],
        )
        results = engine.evaluate([ir])
        # NET-005 (secret_payload) is block → higher severity;
        # NET-001 (http) is ask → lower; both should match but score may differ
        self.assertGreaterEqual(len(results), 2)
        # scores should be non-increasing
        for i in range(len(results) - 1):
            self.assertGreaterEqual(results[i][1], results[i + 1][1])

    def test_entity_constraint_rule(self):
        """实体级规则：外部收件人 → 命中。"""
        engine = ConstraintEngine([
            ConstraintRule(
                rule_id="TEST-ENTITY",
                title="external recipient rule",
                description="blocks external recipients",
                severity="high",
                risk_level="dangerous",
                decision="escalate",
                entity=EntityConstraint(
                    kind="recipients",
                    match_type="domain_not_in",
                    values=["internal.com"],
                ),
            ),
        ])
        ir = ToolCallIR(
            step_id="s1",
            event="mail_send",
            props=["mail_send"],
            entities=[
                Entity(kind="recipients", values=["alice@external.com"]),
            ],
        )
        results = engine.evaluate([ir])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0].rule_id, "TEST-ENTITY")

    def test_entity_constraint_internal_no_match(self):
        """内部收件人 → entity domain_not_in 不命中。"""
        engine = ConstraintEngine([
            ConstraintRule(
                rule_id="TEST-ENTITY-2",
                title="external only",
                description="only blocks external",
                severity="high",
                risk_level="dangerous",
                decision="escalate",
                entity=EntityConstraint(
                    kind="recipients",
                    match_type="domain_not_in",
                    values=["internal.com"],
                ),
            ),
        ])
        ir = ToolCallIR(
            step_id="s1",
            event="mail_send",
            props=["mail_send"],
            entities=[
                Entity(kind="recipients", values=["alice@internal.com"]),
            ],
        )
        results = engine.evaluate([ir])
        self.assertEqual(results, [])

    def test_confidence_threshold_gating(self):
        """规则的 confidence_threshold 过滤低评分命中。"""
        engine = ConstraintEngine([
            ConstraintRule(
                rule_id="HIGH-CONF",
                title="high confidence only",
                description="requires 0.9",
                severity="critical",
                risk_level="blocked",
                decision="block",
                action=ActionConstraint(action_types=["command_exec"]),
                tags=TagConstraint(require_all=["command_rm_rf"]),
                confidence_threshold=0.9,
            ),
        ])
        # 满分命中：action + tag both match → score 1.0
        ir = ToolCallIR(
            step_id="s1",
            event="command_exec",
            props=["command_rm_rf", "command_exec"],
        )
        results = engine.evaluate([ir])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0].rule_id, "HIGH-CONF")

    def test_confidence_threshold_filters_low_score(self):
        """低评分命中被置信度阈值过滤。"""
        engine = ConstraintEngine([
            ConstraintRule(
                rule_id="HIGH-CONF",
                title="high confidence only",
                description="requires 0.9",
                severity="critical",
                risk_level="blocked",
                decision="block",
                action=ActionConstraint(action_types=["command_exec"]),
                tags=TagConstraint(require_all=["command_rm_rf"]),
                confidence_threshold=0.9,
            ),
        ])
        # 标签未命中，只有 action 匹配 → score ≈ 0.25/0.65 ≈ 0.385 → 低于 0.9
        ir = ToolCallIR(
            step_id="s1",
            event="command_exec",
            props=["command_exec", "some_other_tag"],
        )
        results = engine.evaluate([ir])
        self.assertEqual(results, [])

    def test_migrated_rules_count_is_10(self):
        self.assertEqual(len(migrated_constraint_rules()), 10)

    def test_all_props_backward_compatible(self):
        """确保 ToolCallIR 无 entities/constraints 时（向后兼容）仍正常工作。"""
        engine = ConstraintEngine(migrated_constraint_rules())
        ir = ToolCallIR(
            step_id="s1",
            event="command_exec",
            props=["command_rm_rf", "command_exec"],
            # entities/constraints/confidence 都不设（旧数据）
        )
        results = engine.evaluate([ir])
        self.assertTrue(any(r.rule_id == "CMD-001" for r, _ in results))


if __name__ == "__main__":
    unittest.main()
