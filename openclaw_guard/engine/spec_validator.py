"""
spec_validator.py —— 阶段 E：规约校验与修正反馈回环。

功能：
1. 语法校验：Ruleset 是否能通过 Pydantic 验证
2. 正/反例 trace 注入：给定已知正/负例 trace，验证规则是否产生预期判定
3. 冲突检测：同一 monitored 状态下的规则是否存在互斥 verdict
4. 修正反馈：对不通过的案例，生成可读的修正建议
5. 迭代循环：validate → fix → revalidate，最大轮次保护
"""

from __future__ import annotations

from typing import Any

from openclaw_guard.engine.runtime_verification import RuntimeVerificationEngine
from openclaw_guard.engine.rv_dsl import (
    ChainRule,
    MonitorSpec,
    Ruleset,
    compile_monitors,
)


class ValidationReport:
    """校验报告。"""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.false_negatives: list[dict[str, Any]] = []  # 应触发但未触发
        self.false_positives: list[dict[str, Any]] = []  # 不应触发但触发

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0 and len(self.false_negatives) == 0

    @property
    def has_warnings(self) -> bool:
        return len(self.warnings) > 0 or len(self.false_positives) > 0

    @property
    def suggestion(self) -> str | None:
        """生成第一条修正建议。"""
        if self.false_negatives:
            fn = self.false_negatives[0]
            return (
                f"False negative: trace {fn.get('name', '')} should trigger "
                f"verdict >= {fn.get('expected', '')} but got {fn.get('actual', 'ok')}. "
                f"Consider adding a rule with verdict={fn.get('expected', 'escalate')}"
            )
        if self.false_positives:
            fp = self.false_positives[0]
            return (
                f"False positive: trace {fp.get('name', '')} triggered {fp.get('actual', '')} "
                f"but should be ok. Consider adding none_of or entity constraints."
            )
        if self.errors:
            return self.errors[0]
        return None


class SpecValidator:
    """规约校验器。

    Usage:
        validator = SpecValidator(positive_traces=[...], negative_traces=[...])
        result = validator.validate(ruleset)
        if not result.is_valid:
            print(result.suggestion)
    """

    def __init__(
        self,
        positive_traces: list[dict[str, Any]] | None = None,
        negative_traces: list[dict[str, Any]] | None = None,
        max_iterations: int = 5,
    ) -> None:
        self._positive_traces = positive_traces or []
        self._negative_traces = negative_traces or []
        self._max_iterations = max_iterations

    def validate(self, ruleset: Ruleset) -> ValidationReport:
        """对 Ruleset 执行全面校验。"""
        report = ValidationReport()

        # 1. 语法校验（Pydantic 已保证，此处检查语义）
        self._check_syntax(ruleset, report)

        # 2. 正/反例 trace 注入
        if self._positive_traces or self._negative_traces:
            self._check_traces(ruleset, report)

        # 3. 冲突检测
        self._check_conflicts(ruleset, report)

        return report

    def validate_and_fix(
        self,
        ruleset: Ruleset,
        generator_callback=None,
    ) -> tuple[Ruleset, ValidationReport]:
        """迭代校验 + 修正，最多 max_iterations 轮。"""
        for iteration in range(self._max_iterations):
            report = self.validate(ruleset)
            if report.is_valid:
                return ruleset, report

            if generator_callback is None:
                break

            # 尝试修正
            suggestion = report.suggestion
            if suggestion is None:
                break

            ruleset = generator_callback(ruleset, report)

        return ruleset, self.validate(ruleset)

    # ── 内部检查 ──

    @staticmethod
    def _check_syntax(ruleset: Ruleset, report: ValidationReport) -> None:
        if not ruleset.monitors:
            report.errors.append("Ruleset has no monitors")
        seen_ids: set[str] = set()
        for monitor in ruleset.monitors:
            for rule in monitor.rules:
                if rule.id in seen_ids:
                    report.warnings.append(f"Duplicate rule id: {rule.id}")
                seen_ids.add(rule.id)

    def _check_traces(self, ruleset: Ruleset, report: ValidationReport) -> None:
        engine = RuntimeVerificationEngine(window_size=10, rule_mode="dsl")
        # 注入 ruleset 确保使用被测规则而非默认规则
        engine._spec_ruleset = ruleset
        engine._spec_monitors_template = None  # 触发懒加载重建

        # 正例：应不触发任何 verdict
        for trace in self._positive_traces:
            name = trace.get("name", "unnamed")
            steps = trace.get("steps", [])
            result = engine.evaluate(steps)
            if result["verdict"] != "ok":
                report.false_positives.append({
                    "name": name,
                    "actual": result["verdict"],
                    "triggered_by": result.get("triggered_by", []),
                })

        # 反例：应触发指定 verdict 或更高
        for trace in self._negative_traces:
            name = trace.get("name", "unnamed")
            steps = trace.get("steps", [])
            expected = trace.get("expected_verdict", "block")
            result = engine.evaluate(steps)
            severity_map = {"block": 4, "escalate": 3, "ask": 2, "ok": 1}
            if severity_map.get(result["verdict"], 0) < severity_map.get(expected, 0):
                report.false_negatives.append({
                    "name": name,
                    "expected": expected,
                    "actual": result["verdict"],
                })

    @staticmethod
    def _check_conflicts(ruleset: Ruleset, report: ValidationReport) -> None:
        """检测同一状态下的互斥 verdict 规则。"""
        for monitor in ruleset.monitors:
            for i, r1 in enumerate(monitor.rules):
                if r1.verdict is None:
                    continue
                for r2 in monitor.rules[i + 1:]:
                    if r2.verdict is None:
                        continue
                    if (
                        (r1.from_state == r2.from_state or r1.from_state == "*" or r2.from_state == "*")
                        and r1.verdict != r2.verdict
                        and r1.when.model_dump(exclude_defaults=True) == r2.when.model_dump(exclude_defaults=True)
                    ):
                        report.warnings.append(
                            f"Conflicting verdict in {monitor.name}: "
                            f"{r1.id}={r1.verdict} vs {r2.id}={r2.verdict}"
                        )
