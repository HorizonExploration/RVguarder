"""
动作拦截决策与生命周期管理。

将高风险工具调用的判定、审批、拒绝和执行流程
从 manager.py 抽离，供 api.py / web.py 直接调用。
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any, Callable

from openclaw_guard.config import AppContext
from openclaw_guard.engine.control import GuardController
from openclaw_guard.engine.detection import DetectionEngine
from openclaw_guard.engine.whitelist import WhitelistEngine
from openclaw_guard.models import ControlledAction

MAX_ACTIONS_SIZE = 1000

logger = logging.getLogger(__name__)


class ActionService:
    """负责动作的拦截、决策、审批、拒绝和执行。"""

    def __init__(
        self,
        context: AppContext,
        detector: DetectionEngine,
        whitelist: WhitelistEngine,
        controller: GuardController,
        semantic_enhancer: Any,
        actions_path: Path,
        audit_append: Callable[..., Any],
    ) -> None:
        self.context = context
        self.detector = detector
        self.whitelist = whitelist
        self.controller = controller
        self.semantic_enhancer = semantic_enhancer
        self.actions_path = actions_path
        self.audit_append = audit_append
        self._cache: list[ControlledAction] | None = None
        self._lock = threading.Lock()

    # — 持久化 —

    def _load(self, force_refresh: bool = False) -> list[ControlledAction]:
        with self._lock:
            if self._cache is not None and not force_refresh:
                return self._cache
            
            try:
                data = json.loads(self.actions_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._cache = []
                return self._cache
                
            items = data.get("items", []) if isinstance(data, dict) else []
            result: list[ControlledAction] = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                try:
                    action = ControlledAction(**item)
                    if action.event and action.event.metadata.get("hook_bridge"):
                        action.source = "hook_bridge"
                    if action.event and action.event.metadata.get("tool_name") == "before_prompt_build":
                        # Older versions persisted this non-blocking precheck as
                        # pending_approval even though OpenClaw never exposes a
                        # resolution callback for it. Keep the history visible,
                        # but make it non-pending when loading legacy records.
                        action.execution_result.setdefault("precheck", True)
                        if action.status in {"pending_approval", "proposed"}:
                            action.status = "allow"
                            action.decision_state = "allowed"
                            action.sync_state = "not_applicable"
                    if action.status == "pending_approval":
                        action.decision_state = "pending"
                    elif action.status in {"approved", "allow", "executed", "executing"}:
                        action.decision_state = "allowed"
                    elif action.status in {"rejected", "blocked"}:
                        action.decision_state = "denied"
                    if action.status == "executing":
                        action.execution_state = "running"
                    elif action.status == "executed":
                        action.execution_state = "executed"
                    elif action.status == "failed":
                        action.execution_state = "failed"
                    result.append(action)
                except Exception:
                    continue
            self._cache = result[-MAX_ACTIONS_SIZE:]
            return self._cache

    def _save_all(self, items: list[ControlledAction]) -> None:
        with self._lock:
            if len(items) > MAX_ACTIONS_SIZE:
                items = items[-MAX_ACTIONS_SIZE:]
            self._cache = items
            
            self.actions_path.parent.mkdir(parents=True, exist_ok=True)
            self.actions_path.write_text(
                json.dumps({"items": [item.to_dict() for item in items]}, ensure_ascii=False),
                encoding="utf-8",
            )

    def _replace(self, action: ControlledAction, *, items: list[ControlledAction] | None = None) -> list[ControlledAction]:
        target = items if items is not None else self._load()
        with self._lock:
            replaced = False
            for i, item in enumerate(target):
                if item.action_id == action.action_id:
                    target[i] = action
                    replaced = True
                    break
            if not replaced:
                target.append(action)
            # 释放锁之前更新缓存
            self._cache = target
            
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

    def clear_all(self) -> None:
        """清空所有动作记录。"""
        self._save_all([])
        self.audit_append("actions_cleared", {})
