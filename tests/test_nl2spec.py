"""阶段 E NL2Spec 测试。

覆盖：
- nl2spec_generator 内置模板匹配
- Ruleset.origin/source_nl 标记
- spec_validator 正/反例注入 + 语法校验 + 冲突检测
- 迭代 validate_and_fix 循环保护
"""

import unittest

from openclaw_guard.engine.nl2spec_generator import generate_ruleset
from openclaw_guard.engine.rv_dsl import (
    ChainRule,
    MonitorSpec,
    Ruleset,
    StepRequirement,
    compile_monitors,
    load_ruleset,
)
from openclaw_guard.engine.spec_validator import SpecValidator, ValidationReport
from openclaw_guard.engine.eval_traces import POSITIVE_TRACES, NEGATIVE_TRACES


class TestNl2SpecGenerator(unittest.TestCase):
    def test_rm_rf_keyword_generates_block_rule(self):
        ruleset = generate_ruleset("禁止执行 rm -rf 递归删除命令")
        self.assertIsNotNone(ruleset)
        self.assertGreaterEqual(len(ruleset.monitors), 1)
        self.assertEqual(ruleset.monitors[0].name, "NL2SpecFileGuard")

    def test_curl_pipe_keyword_generates_block_rule(self):
        ruleset = generate_ruleset("用户不应执行 curl|sh 管道命令")
        self.assertIsNotNone(ruleset)
        self.assertTrue(any("Curl" in m.name for m in ruleset.monitors))

    def test_external_mail_keyword_generates_rules(self):
        ruleset = generate_ruleset("当发送外部邮件时需要确认")
        self.assertIsNotNone(ruleset)
        self.assertGreaterEqual(len(ruleset.monitors[0].rules), 1)

    def test_no_match_returns_none(self):
        ruleset = generate_ruleset("这条策略描述完全不匹配任何已知模板")
        self.assertIsNone(ruleset)

    def test_generated_rules_have_nl2spec_origin(self):
        ruleset = generate_ruleset("禁止执行 rm -rf")
        self.assertIsNotNone(ruleset)
        for monitor in ruleset.monitors:
            for rule in monitor.rules:
                self.assertEqual(rule.origin, "nl2spec")

    def test_generated_rules_have_source_nl(self):
        nl = "禁止执行 rm -rf 命令"
        ruleset = generate_ruleset(nl)
        self.assertIsNotNone(ruleset)
        for monitor in ruleset.monitors:
            for rule in monitor.rules:
                self.assertEqual(rule.source_nl, nl)

    def test_multiple_keyword_match_generates_multiple_monitors(self):
        ruleset = generate_ruleset("禁止 rm -rf 和禁用审计")
        self.assertIsNotNone(ruleset)
        self.assertGreaterEqual(len(ruleset.monitors), 2)


class TestSpecValidator(unittest.TestCase):
    def setUp(self):
        self.ruleset = load_ruleset()

    def test_default_ruleset_passes_positive(self):
        """正常办公行为不应触发任何判定。使用精确匹配规则的 trace。"""
        # 只包含绝对安全的步骤：chat 无外发、文件只读
        safe_traces = [
            {
                "name": "safe_chat",
                "steps": [
                    {"step_id": "s1", "event": "channel_send", "props": ["channel_send"]},
                ],
            },
            {
                "name": "safe_file_read",
                "steps": [
                    {"step_id": "s1", "event": "file_read", "props": ["file_read"]},
                ],
            },
        ]
        validator = SpecValidator(positive_traces=safe_traces)
        report = validator.validate(self.ruleset)
        self.assertEqual(len(report.false_positives), 0,
                         f"Unexpected false positives: {report.false_positives}")

    def test_default_ruleset_detects_negatives(self):
        """攻击链 trace 应被现有监视器检测到。使用精确触发规则的反例。"""
        attack_traces = [
            {
                "name": "mail_secret_external",
                "expected_verdict": "block",
                "steps": [
                    {"step_id": "s1", "event": "mail_send",
                     "props": ["mail_send", "external_recipient", "contains_secret"]},
                ],
            },
            {
                "name": "cred_chain_escalate",
                "expected_verdict": "escalate",
                "steps": [
                    {"step_id": "s1", "event": "file_read",
                     "props": ["file_read", "path_sensitive_creds"]},
                    {"step_id": "s2", "event": "connect",
                     "props": ["network_egress", "ssh"]},
                ],
            },
            {
                "name": "batch_export",
                "expected_verdict": "block",
                "steps": [
                    {"step_id": "s1", "event": "export", "props": ["batch_export"]},
                ],
            },
        ]
        validator = SpecValidator(negative_traces=attack_traces)
        report = validator.validate(self.ruleset)
        self.assertEqual(len(report.false_negatives), 0,
                         f"Should catch all, missed: {report.false_negatives}")

    def test_empty_ruleset_triggers_error(self):
        validator = SpecValidator()
        report = validator.validate(Ruleset(monitors=[]))
        self.assertFalse(report.is_valid)
        self.assertGreaterEqual(len(report.errors), 1)

    def test_duplicate_rule_id_triggers_warning(self):
        ruleset = Ruleset(monitors=[
            MonitorSpec(name="Dup", initial="idle", rules=[
                ChainRule(id="dup", **{"from": "idle"}, when=StepRequirement()),
                ChainRule(id="dup", **{"from": "idle"}, when=StepRequirement()),
            ]),
        ])
        validator = SpecValidator()
        report = validator.validate(ruleset)
        self.assertTrue(report.has_warnings)

    def test_conflict_detection(self):
        ruleset = Ruleset(monitors=[
            MonitorSpec(name="Conflict", initial="idle", rules=[
                ChainRule(id="r1", **{"from": "idle"}, verdict="block",
                          when=StepRequirement(any_of=["test"])),
                ChainRule(id="r2", **{"from": "idle"}, verdict="ask",
                          when=StepRequirement(any_of=["test"])),
            ]),
        ])
        validator = SpecValidator()
        report = validator.validate(ruleset)
        self.assertTrue(report.has_warnings)

    def test_validate_and_fix_loop_protection(self):
        """迭代修正不应超过 max_iterations。"""
        ruleset = Ruleset(monitors=[])
        validator = SpecValidator(
            negative_traces=NEGATIVE_TRACES[:1],
            max_iterations=3,
        )
        fixed, report = validator.validate_and_fix(ruleset)
        self.assertFalse(report.is_valid)  # 空 ruleset 无法自动修复


class TestEvalTraces(unittest.TestCase):
    def test_positive_traces_count(self):
        self.assertGreaterEqual(len(POSITIVE_TRACES), 5)

    def test_negative_traces_count(self):
        self.assertGreaterEqual(len(NEGATIVE_TRACES), 5)

    def test_traces_have_required_fields(self):
        for trace in POSITIVE_TRACES:
            self.assertIn("steps", trace)
            self.assertGreater(len(trace["steps"]), 0)
        for trace in NEGATIVE_TRACES:
            self.assertIn("steps", trace)
            self.assertIn("expected_verdict", trace)


if __name__ == "__main__":
    unittest.main()
