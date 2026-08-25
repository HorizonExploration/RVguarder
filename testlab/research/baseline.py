"""将研究场景映射到当前 RV-FSM 的只读基线适配器。"""

from __future__ import annotations

from typing import Any

from openclaw_guard.rv.runtime_verification import RuntimeVerificationEngine

from .fixtures import load_scenarios


_EVENT_MAP: dict[str, tuple[str, list[str]]] = {
    "tool.read_email": ("mail_read", ["external_source"]),
    "secret.read": ("file_read", ["file_read", "contains_secret"]),
    "network.egress": ("network_egress", ["network_egress"]),
    "task.request": ("chat_message", ["chat_message"]),
    "capability.grant": ("config_modify", ["config_modify"]),
    "permission.current": ("chat_message", ["permission_state"]),
    "permission.request": ("chat_message", ["permission_request"]),
    "credential.read": ("file_read", ["file_read", "path_sensitive_creds"]),
    "process.execute": ("command_exec", ["command_exec"]),
    "config.audit_disable": ("config_modify", ["config_modify", "config_audit_disable"]),
    "message.send": ("mail_send", ["mail_send"]),
    "tool.invoke": ("command_exec", ["command_exec"]),
    "skill.install": ("skill_run", ["skill_run"]),
    "skill.manifest": ("skill_run", ["skill_run"]),
}


def run_current_rv_baseline(scenarios: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """运行当前 FSM 的只读基线适配器，不触发任何真实工具。"""
    results: list[dict[str, Any]] = []
    for scenario in scenarios or load_scenarios():
        engine = RuntimeVerificationEngine(window_size=10, window_ttl_seconds=None, rule_mode="fsm")
        verdicts: list[str] = []
        for index, source in enumerate(scenario["events"], 1):
            event_name, props = _EVENT_MAP[source["kind"]]
            step_props = list(props)
            if source.get("classification") == "external":
                step_props.append("external_recipient")
            if source.get("classification") == "secret":
                step_props.append("contains_secret")
            result = engine.evaluate(
                [{"step_id": f"{scenario['scenario_id']}-{index}", "event": event_name, "props": step_props}],
                session_key=str(source.get("session") or "_default"),
            )
            verdicts.append(str(result["verdict"]))
        rank = {"ok": 0, "ask": 1, "escalate": 2, "block": 3}
        final = max(verdicts, key=lambda value: rank.get(value, 0))
        results.append({"scenario_id": scenario["scenario_id"], "verdicts": verdicts, "final_verdict": final})
    return results
