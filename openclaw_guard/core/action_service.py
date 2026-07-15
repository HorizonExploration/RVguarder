"""
动作拦截决策与生命周期管理。

将高风险工具调用的判定、审批、拒绝和执行流程
从 manager.py 抽离，供 api.py / web.py 直接调用。
"""

from __future__ import annotations

import json
import threading
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from openclaw_guard.config import AppContext
from openclaw_guard.integrations.control import GuardController
from openclaw_guard.integrations.detection import DetectionEngine
from openclaw_guard.integrations.whitelist import WhitelistEngine
from openclaw_guard.models import ControlledAction

MAX_ACTIONS_SIZE = 1000


class ActionService:
    """负责动作的拦截、决策、审批、拒绝和执行。"""

    def __init__(
        self,
        context: AppContext,
        detector: DetectionEngine,
        whitelist: WhitelistEngine,
        controller: GuardController,
        actions_path: Path,
        audit_append: Callable[..., Any],
    ) -> None:
        self.context = context
        self.detector = detector
        self.whitelist = whitelist
        self.controller = controller
        self.actions_path = actions_path
        self.audit_append = audit_append

    # — 持久化 —

    def _load(self) -> list[ControlledAction]:
        try:
            data = json.loads(self.actions_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        items = data.get("items", []) if isinstance(data, dict) else []
        result: list[ControlledAction] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            try:
                result.append(ControlledAction(**item))
            except Exception:
                continue
        return result[-MAX_ACTIONS_SIZE:]

    def _save_all(self, items: list[ControlledAction]) -> None:
        if len(items) > MAX_ACTIONS_SIZE:
            items = items[-MAX_ACTIONS_SIZE:]
        self.actions_path.parent.mkdir(parents=True, exist_ok=True)
        self.actions_path.write_text(
            json.dumps({"items": [item.to_dict() for item in items]}, ensure_ascii=False),
            encoding="utf-8",
        )

    def _replace(self, action: ControlledAction, *, items: list[ControlledAction] | None = None) -> list[ControlledAction]:
        target = items if items is not None else self._load()
        replaced = False
        for i, item in enumerate(target):
            if item.action_id == action.action_id:
                target[i] = action
                replaced = True
                break
        if not replaced:
            target.append(action)
        self._save_all(target)
        return target

    def _find(self, action_id: str, *, items: list[ControlledAction] | None = None) -> ControlledAction | None:
        action_items = items if items is not None else self._load()
        for item in action_items:
            if item.action_id == action_id:
                return item
        return None

    def _find_by_hook_key(self, hook_key: str) -> ControlledAction | None:
        for item in self._load():
            meta = (item.event.metadata or {}) if item.event else {}
            if meta.get("hook_key") == hook_key:
                return item
        return None

    # — 查询 —

    def list_actions(self, status: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        actions = self._load()
        if status:
            actions = [a for a in actions if a.status == status]
        return [a.to_dict() for a in list(reversed(actions))[:limit]]

    def get_action(self, action_id: str) -> dict[str, Any] | None:
        action = self._find(action_id)
        return action.to_dict() if action else None

    # — 事件摄入 —

    def ingest(self, payload: dict[str, Any], source_message: str = "", *, auto_execute: bool = True) -> dict[str, Any]:
        from openclaw_guard.models import BehaviorEvent, DetectionDecision

        event_payload = deepcopy(payload)
        raw_intent = str(payload.get("raw_user_intent") or source_message or "")
        event_payload["raw_user_intent"] = raw_intent

        event = BehaviorEvent(**event_payload)
        items = self._load()
        decision = self.detector.decide(event, items)
        final_decision = self.whitelist.refine(decision, event)
        final_decision = self.controller.enforce(final_decision, items)

        from uuid import uuid4
        action_id = uuid4().hex[:16]
        action = ControlledAction(
            action_id=action_id,
            source_message=raw_intent,
            status=(
                "pending_approval" if final_decision.action in {"warn", "escalate"}
                else "blocked" if final_decision.action == "block"
                else "proposed"
            ),
            event=event,
            decision=final_decision,
            created_at="",
            target_summary=str(payload.get("tool_name") or final_decision.reason or ""),
            decision_trace=list(final_decision.trace or []),
            matched_whitelists=list(final_decision.matched_whitelists or []),
            matched_rules=list(final_decision.matched_rules or []),
        )
        self._replace(action)
        self.audit_append("action_ingest", action.to_dict())
        return action.to_dict()

    # — 审批 / 拒绝 —

    def approve(self, action_id: str, confirmation_text: str | None = None) -> dict[str, Any]:
        action = self._find(action_id)
        if not action:
            raise KeyError(action_id)
        if action.status != "pending_approval":
            raise ValueError("action_not_pending")
        if action.decision.requires_second_confirmation and (
            not confirmation_text or confirmation_text.strip().upper() != (action.decision.confirmation_word or "EXECUTE").strip().upper()
        ):
            raise ValueError("confirmation_word_required")
        action.status = "approved"
        self._replace(action)
        self.audit_append("action_approved", action.to_dict())
        return {"action": action.to_dict(), "status": "approved"}

    def reject(self, action_id: str) -> dict[str, Any]:
        action = self._find(action_id)
        if not action:
            raise KeyError(action_id)
        if action.status != "pending_approval":
            raise ValueError("action_not_pending")
        action.status = "rejected"
        self._replace(action)
        self.audit_append("action_rejected", action.to_dict())
        return {"action": action.to_dict(), "status": "rejected"}
