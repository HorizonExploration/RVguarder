"""IR 数据模型单元测试。

覆盖：
- Entity / Constraint / ToolCallIR 实例化与默认值
- 空实体/约束场景（向后兼容）
- model_dump 序列化
- 从 ToolCallIR 列表构建 rv_trace 的模拟场景
"""

import unittest

from openclaw_guard.engine.ir import Constraint, Entity, ToolCallIR


class TestEntity(unittest.TestCase):
    def test_basic_entity(self):
        e = Entity(kind="recipients", values=["alice@example.com"])
        self.assertEqual(e.kind, "recipients")
        self.assertEqual(e.values, ["alice@example.com"])

    def test_entity_default_values(self):
        e = Entity(kind="paths")
        self.assertEqual(e.values, [])

    def test_entity_serialization(self):
        e = Entity(kind="urls", values=["https://example.com"])
        d = e.model_dump()
        self.assertEqual(d["kind"], "urls")
        self.assertEqual(d["values"], ["https://example.com"])


class TestConstraint(unittest.TestCase):
    def test_string_constraint(self):
        c = Constraint(kind="time_range", value="today")
        self.assertEqual(c.kind, "time_range")
        self.assertEqual(c.value, "today")

    def test_bool_constraint(self):
        c = Constraint(kind="human_review", value=True)
        self.assertEqual(c.kind, "human_review")
        self.assertTrue(c.value)

    def test_constraint_serialization(self):
        c = Constraint(kind="exclude", value="attachments")
        d = c.model_dump()
        self.assertEqual(d["kind"], "exclude")
        self.assertEqual(d["value"], "attachments")


class TestToolCallIR(unittest.TestCase):
    def test_minimal_ir(self):
        ir = ToolCallIR(step_id="s1", event="mail_send")
        self.assertEqual(ir.step_id, "s1")
        self.assertEqual(ir.event, "mail_send")
        self.assertEqual(ir.props, [])
        self.assertEqual(ir.entities, [])
        self.assertEqual(ir.constraints, [])
        self.assertIsNone(ir.confidence)

    def test_full_ir_with_entities_and_constraints(self):
        ir = ToolCallIR(
            step_id="s1",
            event="mail_send",
            props=["mail_send", "external_recipient"],
            entities=[
                Entity(kind="recipients", values=["alice@example.com"]),
                Entity(kind="tool_name", values=["mail-send"]),
            ],
            constraints=[
                Constraint(kind="time_range", value="today"),
            ],
            confidence=0.88,
        )
        self.assertEqual(len(ir.entities), 2)
        self.assertEqual(ir.entities[0].kind, "recipients")
        self.assertEqual(len(ir.constraints), 1)
        self.assertEqual(ir.confidence, 0.88)

    def test_model_dump_includes_all_fields(self):
        ir = ToolCallIR(
            step_id="s1",
            event="report_send",
            confidence=0.75,
        )
        d = ir.model_dump()
        self.assertIn("step_id", d)
        self.assertIn("event", d)
        self.assertIn("props", d)
        self.assertIn("entities", d)
        self.assertIn("constraints", d)
        self.assertIn("confidence", d)

    def test_ir_list_as_rv_trace(self):
        """验证 ToolCallIR 列表可模拟完整的 rv_trace。"""
        trace = [
            ToolCallIR(
                step_id="s1",
                event="file_read",
                props=["file_read", "contains_secret"],
                entities=[Entity(kind="paths", values=["/data/secrets.txt"])],
                confidence=0.9,
            ),
            ToolCallIR(
                step_id="s2",
                event="mail_send",
                props=["mail_send", "external_recipient"],
                entities=[
                    Entity(kind="recipients", values=["alice@example.com"]),
                ],
                constraints=[
                    Constraint(kind="exclude", value="attachments"),
                ],
                confidence=0.92,
            ),
        ]
        self.assertEqual(len(trace), 2)
        self.assertEqual(trace[0].event, "file_read")
        self.assertEqual(trace[1].event, "mail_send")
        # 可以从列表 dump 为可序列化的 dict 列表
        trace_dicts = [t.model_dump() for t in trace]
        self.assertEqual(len(trace_dicts), 2)
        self.assertEqual(trace_dicts[0]["props"], ["file_read", "contains_secret"])


if __name__ == "__main__":
    unittest.main()
