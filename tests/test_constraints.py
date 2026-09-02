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

from openclaw_guard.rv.constraints import (
    ActionConstraint,
    ConstraintEngine,
    ConstraintRule,
    EntityConstraint,
    SensitivityConstraint,
    TagConstraint,
    TemporalConstraint,
    migrated_constraint_rules,
)
from openclaw_guard.rv.ir import Constraint, Entity, ToolCallIR


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

    def test_sensitivity_constraint_matches_high(self):
        """敏感度约束：high 命中 levels=["high", "critical"]。"""
        engine = ConstraintEngine([
            ConstraintRule(
                rule_id="SENS-001",
                title="sensitive data egress",
                description="blocks high sensitivity",
                severity="critical",
                risk_level="blocked",
                decision="block",
                sensitivity=SensitivityConstraint(levels=["high", "critical"]),
            ),
        ])
        ir = ToolCallIR(
            step_id="s1",
            event="network_egress",
            props=["network_egress"],
            sensitivity="high",
        )
        results = engine.evaluate([ir])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0].rule_id, "SENS-001")

    def test_sensitivity_constraint_not_in(self):
        """敏感度约束：none 不在敏感列表 → match_type="not_in" 命中。"""
        engine = ConstraintEngine([
            ConstraintRule(
                rule_id="SENS-002",
                title="non-sensitive only",
                description="allow non-sensitive",
                severity="low",
                risk_level="safe",
                decision="allow",
                sensitivity=SensitivityConstraint(
                    levels=["high", "critical"], match_type="not_in"
                ),
            ),
        ])
        ir = ToolCallIR(
            step_id="s1",
            event="file_read",
            props=["file_read"],
            sensitivity="none",
        )
        results = engine.evaluate([ir])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0].rule_id, "SENS-002")

    def test_sensitivity_constraint_no_match(self):
        """敏感度约束：low 不在 levels=["high", "critical"] → 不命中。"""
        engine = ConstraintEngine([
            ConstraintRule(
                rule_id="SENS-003",
                title="high only",
                description="blocks high sensitivity",
                severity="critical",
                risk_level="blocked",
                decision="block",
                sensitivity=SensitivityConstraint(levels=["high", "critical"]),
            ),
        ])
        ir = ToolCallIR(
            step_id="s1",
            event="network_egress",
            props=["network_egress"],
            sensitivity="low",
        )
        results = engine.evaluate([ir])
        self.assertEqual(results, [])

    def test_temporal_constraint_matches(self):
        """时序约束：time_range=today 命中 values=["today", "this_week"]。"""
        engine = ConstraintEngine([
            ConstraintRule(
                rule_id="TMP-001",
                title="today-only scope",
                description="requires today scope",
                severity="medium",
                risk_level="caution",
                decision="ask",
                temporal=TemporalConstraint(values=["today", "this_week"]),
            ),
        ])
        ir = ToolCallIR(
            step_id="s1",
            event="report_send",
            props=["report_send"],
            constraints=[Constraint(kind="time_range", value="today")],
        )
        results = engine.evaluate([ir])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0].rule_id, "TMP-001")

    def test_temporal_constraint_no_match(self):
        """时序约束：time_range=yesterday 不在 values → 不命中。"""
        engine = ConstraintEngine([
            ConstraintRule(
                rule_id="TMP-002",
                title="today-only scope",
                description="requires today scope",
                severity="medium",
                risk_level="caution",
                decision="ask",
                temporal=TemporalConstraint(values=["today", "this_week"]),
            ),
        ])
        ir = ToolCallIR(
            step_id="s1",
            event="report_send",
            props=["report_send"],
            constraints=[Constraint(kind="time_range", value="yesterday")],
        )
        results = engine.evaluate([ir])
        self.assertEqual(results, [])

    def test_confidence_threshold_gating(self):
        """高语义置信度（≥阈值）命中规则。"""
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
        # 约束满分命中 + 语义置信度 0.95 ≥ 0.9 → 命中
        ir = ToolCallIR(
            step_id="s1",
            event="command_exec",
            props=["command_rm_rf", "command_exec"],
            confidence=0.95,
        )
        results = engine.evaluate([ir])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0].rule_id, "HIGH-CONF")

    def test_confidence_threshold_filters_low_confidence(self):
        """低语义置信度（<阈值）即使约束命中也被过滤。"""
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
        # 约束满分命中，但语义置信度 0.3 < 0.9 → 保守回退，不命中
        ir = ToolCallIR(
            step_id="s1",
            event="command_exec",
            props=["command_rm_rf", "command_exec"],
            confidence=0.3,
        )
        results = engine.evaluate([ir])
        self.assertEqual(results, [])

    def test_migrated_rules_cover_all_legacy_detection_rules(self):
        self.assertEqual(len(migrated_constraint_rules()), 47)

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

    def test_migrated_rules_align_with_detection(self):
        """迁移规则与冻结 LEGACY 元数据按 rule_id 定义对齐。

        10 条迁移规则在 constraints.py 与 detection.py 两处定义（保留双定义），
        本测试兜底两处漂移：任一规则任一字段不一致即失败。
        """
        from openclaw_guard.policy.legacy import legacy_rules

        detection_by_id = {rule.rule_id: rule for rule in legacy_rules()}
        self.assertGreaterEqual(len(detection_by_id), 10)

        for c_rule in migrated_constraint_rules():
            d_rule = detection_by_id.get(c_rule.rule_id)
            self.assertIsNotNone(
                d_rule,
                f"迁移规则 {c_rule.rule_id} 在 LEGACY 元数据中不存在",
            )
            # 元数据一致
            self.assertEqual(c_rule.title, d_rule.title, f"{c_rule.rule_id} title 漂移")
            self.assertEqual(c_rule.description, d_rule.description, f"{c_rule.rule_id} description 漂移")
            self.assertEqual(c_rule.decision, d_rule.decision, f"{c_rule.rule_id} decision 漂移")
            self.assertEqual(c_rule.severity, d_rule.severity, f"{c_rule.rule_id} severity 漂移")
            self.assertEqual(c_rule.risk_level, d_rule.risk_level, f"{c_rule.rule_id} risk_level 漂移")
            # 动作约束 ↔ action_types（归一化为 str 比较）
            expected_actions = [str(a) for a in d_rule.action_types]
            actual_actions = list(c_rule.action.action_types) if c_rule.action else []
            self.assertEqual(actual_actions, expected_actions, f"{c_rule.rule_id} action_types 漂移")
            # 标签约束 ↔ match_labels
            self.assertIsNotNone(c_rule.tags, f"{c_rule.rule_id} 缺少 tags 约束")
            self.assertEqual(
                list(c_rule.tags.require_all), list(d_rule.match_labels),
                f"{c_rule.rule_id} match_labels 漂移",
            )
            self.assertEqual(list(c_rule.tags.require_any), [], f"{c_rule.rule_id} require_any 应为空")
            # 迁移规则不应携带实体/敏感度/时序约束（与 detection 标签规则语义等价）
            self.assertIsNone(c_rule.entity, f"{c_rule.rule_id} 不应有 entity 约束")
            self.assertIsNone(c_rule.sensitivity, f"{c_rule.rule_id} 不应有 sensitivity 约束")
            self.assertIsNone(c_rule.temporal, f"{c_rule.rule_id} 不应有 temporal 约束")


if __name__ == "__main__":
    unittest.main()
