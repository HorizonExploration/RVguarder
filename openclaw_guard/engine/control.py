from __future__ import annotations

from uuid import uuid4

from openclaw_guard.models import BehaviorEvent, ControlledAction, DetectionDecision
from openclaw_guard.engine.whitelist import WhitelistEngine
from openclaw_guard.utils import utc_now_iso


class GuardController:
    def __init__(self, whitelist: WhitelistEngine) -> None:
        self.whitelist = whitelist

    def decide(self, event: BehaviorEvent, decision: DetectionDecision, source_message: str) -> ControlledAction:
        matches = self.whitelist.evaluate(event)
        final = decision
        trace = list(decision.trace)
        if (matches and decision.action != "block" and _can_whitelist_override(event)
                and _pmkb_allows_whitelist_override(decision)):
            final = DetectionDecision(
                event_id=decision.event_id,
                timestamp=decision.timestamp,
                action_type=decision.action_type,
                risk_level="safe",
                action="allow",
                reason="命中白名单，按允许动作执行。",
                rule_ids=decision.rule_ids,
                trace=trace + [{"stage": "whitelist", "outcome": "allow", "matches": matches}],
                requires_second_confirmation=False,
                confirmation_word=None,
                policy_decision=decision.policy_decision,
            )
        status = "proposed"
        if final.action in {"ask", "escalate", "revise"}:
            status = "pending_approval"
        elif final.action == "block":
            status = "blocked"
        summary = _target_summary(event)
        return ControlledAction(
            action_id=uuid4().hex[:16],
            source_message=source_message,
            created_at=utc_now_iso(),
            status=status,
            event=event,
            decision=final,
            target_summary=summary,
            decision_trace=final.trace,
            matched_whitelists=matches,
            matched_rules=final.rule_ids,
            source="hook_bridge" if event.metadata.get("hook_bridge") else "chat_relay",
            decision_state="pending" if status == "pending_approval" else ("denied" if status == "blocked" else "allowed"),
            execution_state="not_started" if status in {"pending_approval", "blocked"} else "running",
            sync_state="local_only",
        )


def _target_summary(event: BehaviorEvent) -> str:
    # 优先使用语义增强层生成的摘要
    semantic = event.metadata.get("semantic")
    if isinstance(semantic, dict):
        intent = semantic.get("intent")
        if isinstance(intent, dict) and intent.get("goal"):
            return str(intent["goal"])

    raw_intent = str(event.raw_payload.get("raw_user_intent") or "").strip()
    if event.target_paths:
        return ", ".join(event.target_paths[:3])
    if event.network_targets:
        return ", ".join(event.network_targets[:3])
    if event.command:
        return event.command
    if event.action_type == "file_delete":
        if raw_intent:
            return raw_intent[:80]
        return "删除请求（未解析到目标路径）"
    if event.action_type == "file_write":
        if raw_intent:
            return raw_intent[:80]
        return "写入请求（未解析到目标路径）"
    if event.action_type == "config_modify":
        if raw_intent:
            return raw_intent[:80]
        return "配置修改请求"
    if raw_intent:
        return raw_intent[:80]
    return "未解析到目标"


def _can_whitelist_override(event: BehaviorEvent) -> bool:
    return event.action_type == "chat_message"


def _pmkb_allows_whitelist_override(decision: DetectionDecision) -> bool:
    """Keep PMKB approvals and blocks above convenience whitelist overrides."""
    evidence = decision.policy_decision
    return not isinstance(evidence, dict) or evidence.get("effect") == "auto_allow_audit"
