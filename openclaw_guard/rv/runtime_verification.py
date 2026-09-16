"""
运行时验证核心引擎 —— 滑动窗口管理器 + DSL 规约引擎。

基于声明式 ChainRule DSL，为所有安全监视器提供：
- 带时间过期的滑动上下文窗口（WindowManager）
- 多步序列匹配
- 累积统计
- Per-session 会话隔离
- 状态序列化/反序列化
- 主引擎编排（RuntimeVerificationEngine）

设计原则：
- 监视器（Monitors）通过 DSL 状态转移追踪跨步攻击链
- WindowManager 提供统计增强（累积计数、序列匹配、窗口查询）
- Engine 负责 per-session 窗口隔离和判定融合
"""

from __future__ import annotations

import os
import time as _time
from collections import deque
from typing import Any

from openclaw_guard.utils import utc_now_iso


def _entity_matches(values: list[str], match_type: str, target_values: list[str]) -> bool:
    """实体值匹配辅助函数。

    支持三种 match_type:
    - "value_in": values 中至少一个在 target_values 中
    - "domain_in": 取值的域名部分，至少一个匹配
    - "domain_not_in": 取值的域名部分，没有任何一个在列表中
    """
    if not values:
        return False

    def _domain(v: str) -> str:
        return v.rsplit("@", 1)[-1].lower() if "@" in v else v.lower()

    if match_type == "value_in":
        targets = {v.lower() for v in target_values}
        return any(v.lower() in targets for v in values)
    if match_type == "domain_in":
        domains = {d.lower() for d in target_values}
        return any(_domain(v) in domains for v in values)
    if match_type == "domain_not_in":
        domains = {d.lower() for d in target_values}
        return not any(_domain(v) in domains for v in values)
    return False


class WindowManager:
    """滑动窗口管理器。

    维护最近 N 步的 rv_trace 轨迹，提供：
    - 窗口快照与最近一步查询
    - 序列模式匹配（给定标签序列是否在窗口中成立）
    - 累积计数器（统计指定标签的出现次数）
    - 存在性检查（窗口中是否存在某标签）
    - 时间过期（基于 TTL 的自动清理）
    - 序列化/反序列化（支持持久化）
    - 按标签检索（steps_with_label）

    Thread-safe 约束：外部调用方保证串行访问。
    """

    def __init__(self, max_size: int = 10, ttl_seconds: int | None = 300) -> None:
        self._buffer: deque[dict[str, Any]] = deque(maxlen=max_size)
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds

    # ── 写入 ──

    def push(self, step: dict[str, Any], *, preserve_timestamp: bool = False) -> None:
        """追加一个事件步到窗口尾部。自动处理时间过期。

        ``preserve_timestamp`` 仅用于从持久化窗口重放历史步骤；实时输入仍
        使用当前时间戳，避免调用方伪造窗口年龄。
        """
        if not preserve_timestamp or "_ts_epoch" not in step:
            step["_ts"] = utc_now_iso()
            step["_ts_epoch"] = _time.time()
        elif "_ts" not in step:
            step["_ts"] = utc_now_iso()
        self._buffer.append(step)
        if self._ttl_seconds is not None:
            self._expire_old()

    # ── 时间过期 ──

    def _expire_old(self) -> int:
        """移除超过 TTL 的步骤。返回移除的数量。"""
        if self._ttl_seconds is None or not self._buffer:
            return 0
        cutoff = _time.time() - self._ttl_seconds
        removed = 0
        while self._buffer and self._buffer[0].get("_ts_epoch", 0) < cutoff:
            self._buffer.popleft()
            removed += 1
        return removed

    def set_ttl(self, ttl_seconds: int | None) -> None:
        """动态更新 TTL 并立即清理过期条目。"""
        self._ttl_seconds = ttl_seconds
        if ttl_seconds is not None:
            self._expire_old()

    def age_of_oldest(self) -> float | None:
        """返回最老步骤的年龄（秒），用于窗口规则判定。窗口为空返回 None。"""
        if not self._buffer:
            return None
        oldest_epoch = self._buffer[0].get("_ts_epoch", 0)
        if oldest_epoch == 0:
            return None
        return _time.time() - oldest_epoch

    # ── 快照与查询 ──

    def snapshot(self) -> list[dict[str, Any]]:
        """获取当前窗口的完整快照（从旧到新）。"""
        self._expire_old()
        return list(self._buffer)

    def latest(self) -> dict[str, Any] | None:
        """获取最近一步事件。"""
        return self._buffer[-1] if self._buffer else None

    def steps_with_label(self, label: str, window_size: int | None = None) -> list[dict[str, Any]]:
        """返回窗口中包含指定标签的所有步骤。

        Args:
            label: 目标标签名
            window_size: 仅在最近 N 步内检查，默认全窗口

        Returns:
            匹配步骤列表（从旧到新）
        """
        recent = self.snapshot()
        if window_size and window_size < len(recent):
            recent = recent[-window_size:]
        return [s for s in recent if label in set(s.get("props", []))]

    # ── 阶段 D：实体与时间查询 ──

    def steps_with_entity(self, kind: str, predicate: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """返回窗口中包含指定 entity kind 的步骤列表。

        Args:
            kind: 实体类别（如 "recipients", "paths"）
            predicate: 可选过滤条件，如 {"match_type": "value_in", "values": ["a@b.com"]}

        Returns:
            匹配步骤列表（从旧到新）
        """
        recent = self.snapshot()
        results: list[dict[str, Any]] = []
        for step in recent:
            entities = step.get("entities") or []
            for e in entities:
                if isinstance(e, dict) and e.get("kind") == kind:
                    if predicate is None:
                        results.append(step)
                        break
                    else:
                        if _entity_matches(e.get("values", []), predicate.get("match_type", ""), predicate.get("values", [])):
                            results.append(step)
                            break
        return results

    def step_gap(self, older_step: dict[str, Any] | None, newer_step: dict[str, Any] | None) -> float | None:
        """计算两步之间的时间间隔（秒）。

        若任一步骤为 None 或缺少 _ts_epoch，返回 None。
        """
        if older_step is None or newer_step is None:
            return None
        older_ts = older_step.get("_ts_epoch")
        newer_ts = newer_step.get("_ts_epoch")
        if older_ts is None or newer_ts is None:
            return None
        return abs(float(newer_ts) - float(older_ts))

    # ── 序列匹配 ──

    def sequence_matches(
        self,
        pattern: list[set[str]],
        window_size: int | None = None,
    ) -> bool:
        """检查窗口中是否存在指定的标签序列。

        例：sequence_matches([{"file_search"}, {"file_delete"}])
        表示"先出现 file_search 标签，后出现 file_delete 标签"。

        Args:
            pattern: 标签集合列表，顺序敏感
            window_size: 仅在最近 N 步内检查，默认全窗口

        Returns:
            序列是否匹配
        """
        recent = self.snapshot()
        if window_size and window_size < len(recent):
            recent = recent[-window_size:]

        pi = 0
        for step in recent:
            props = set(step.get("props", []))
            if pi < len(pattern) and pattern[pi].issubset(props):
                pi += 1
        return pi == len(pattern)

    # ── 累积计数 ──

    def cumulative_count(self, label: str, window_size: int | None = None) -> int:
        """统计窗口中指定标签的总出现次数。

        Args:
            label: 目标标签名
            window_size: 统计范围，默认全窗口

        Returns:
            出现次数
        """
        recent = self.snapshot()
        if window_size and window_size < len(recent):
            recent = recent[-window_size:]
        return sum(1 for step in recent if label in step.get("props", []))

    # ── 存在性检查 ──

    def contains_any(self, labels: set[str], window_size: int | None = None) -> bool:
        """检查窗口中是否存在至少包含一个指定标签的事件步。"""
        recent = self.snapshot()
        if window_size and window_size < len(recent):
            recent = recent[-window_size:]
        for step in recent:
            if labels & set(step.get("props", [])):
                return True
        return False

    # ── 序列化 ──

    def to_dict(self) -> dict[str, Any]:
        """序列化窗口状态供持久化。"""
        return {
            "max_size": self._max_size,
            "ttl_seconds": self._ttl_seconds,
            "buffer": list(self._buffer),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WindowManager:
        """从序列化数据恢复窗口。

        恢复后的窗口保留原始时间戳，但会基于当前时间重新检查过期。
        """
        wm = cls(
            max_size=data.get("max_size", 10),
            ttl_seconds=data.get("ttl_seconds"),
        )
        buffer_data = data.get("buffer", [])
        if isinstance(buffer_data, list):
            for item in buffer_data:
                if isinstance(item, dict):
                    # 保留原始时间戳用于审计
                    wm._buffer.append(item)
        # 立即过期旧条目
        if wm._ttl_seconds is not None:
            wm._expire_old()
        return wm

    # ── 管理 ──

    def clear(self) -> None:
        """清空窗口。"""
        self._buffer.clear()

    def __len__(self) -> int:
        return len(self._buffer)


class RuntimeVerificationEngine:
    """运行时验证主引擎 —— Per-session 窗口隔离。

    统筹所有安全监视器 + 滑动窗口 + 判定融合。
    消费语义层产出的 rv_trace，产出 RV 判定结果。

    Per-session 设计：
    - evaluate() 接受 session_key 参数
    - 不同 session 拥有独立的 WindowManager 和 Monitor 实例
    - "_default" session 保持向后兼容
    """

    def __init__(
        self,
        window_size: int = 10,
        window_ttl_seconds: int | None = 300,
        rule_mode: str | None = None,
        baseline_dfa_path: str | None = None,
        principal_state_limit: int = 256,
        permission_bundle: Any | None = None,
    ) -> None:
        self._window_size = window_size
        self._window_ttl = window_ttl_seconds
        self._rule_mode = self._normalize_rule_mode(
            rule_mode or os.getenv("OPENCLAW_RV_RULE_MODE")
        )
        # 默认共享窗口（向后兼容）
        self.window = WindowManager(max_size=window_size, ttl_seconds=window_ttl_seconds)
        # Per-session 隔离存储
        self._session_windows: dict[str, WindowManager] = {}
        self._session_monitors: dict[str, list] = {}
        self._session_permission_monitors: dict[str, list] = {}
        self._principal_monitors: dict[tuple[str, str, tuple[str, ...]], list] = {}
        # Identity metrics are retained for observability; monitor instances
        # themselves are rebuilt per evaluation and never kept as mutable state.
        self._principal_monitor_keys: set[tuple[str, str, tuple[str, ...]]] = set()
        self._principal_states: dict[tuple[str, str, tuple[str, ...]], Any] = {}
        self._principal_state_limit = max(1, principal_state_limit)
        self._spec_monitors_template: list | None = None
        self._spec_ruleset: Any | None = None
        self._permission_ruleset: Any | None = None
        self._permission_monitors_template: list | None = None
        if permission_bundle is not None:
            self.configure_permission_monitors(permission_bundle)
        # 基线自动机监视器（阶段 C）
        self._baseline_monitor: Any | None = None
        self._init_baseline_monitor(baseline_dfa_path)

    # ── 懒加载初始化监视器模板 ──

    def _normalize_rule_mode(self, value: str | None) -> str:
        if not value:
            return "dsl"
        v = str(value).strip().lower()
        if v in {"dsl", "spec", "spec-driven", "spec_driven"}:
            return "dsl"
        # Handwritten FSM was retired from the production path.  Keep the
        # historical setting readable so old preferences do not break startup,
        # but always execute the generated DSL automata.
        if v in {"fsm", "handwritten", "hand-written"}:
            return "dsl"
        return "dsl"

    def _init_baseline_monitor(self, dfa_path: str | None) -> None:
        """懒加载基线 DFA 监视器。"""
        path = dfa_path or os.getenv("OPENCLAW_RV_BASELINE_DFA_PATH")
        if not path:
            return
        try:
            from openclaw_guard.rv.baseline_learner import BaselineDFA
            from openclaw_guard.rv.baseline_monitor import BaselineMonitor

            dfa = BaselineDFA.load(path)
            self._baseline_monitor = BaselineMonitor(dfa)
        except Exception:
            pass  # DFA 加载失败时静默跳过，不影响正常引擎功能

    def rule_mode(self) -> str:
        return self._rule_mode

    def set_rule_mode(self, mode: str) -> None:
        new_mode = self._normalize_rule_mode(mode)
        if new_mode == self._rule_mode:
            return
        self._rule_mode = new_mode
        self._session_monitors.clear()
        self._spec_monitors_template = None
        self._permission_monitors_template = None
        self._principal_monitors.clear()
        self._principal_monitor_keys.clear()
        self._session_permission_monitors.clear()

    def reset_rules(self) -> None:
        """重置规约缓存，下次 evaluate 重新加载 rv_rules.json。

        供 NL2Spec 编译（阶段 E）合并新规则到 rv_rules.json 后调用。
        """
        self._spec_ruleset = None
        self._spec_monitors_template = None
        self._session_monitors.clear()

    def configure_permission_monitors(self, bundle: Any | None) -> None:
        """Compile one PMKB bundle into symbolic permission monitor specs.

        Passing ``None`` disables generated permission monitors.  The caller
        keeps ownership of bundle loading, so this hot path never reads remote
        policy data or blocks an OpenClaw hook.
        """
        if bundle is None:
            self._permission_ruleset = None
        else:
            from openclaw_guard.policy.rv_compiler import PermissionAutomatonCompiler

            self._permission_ruleset = PermissionAutomatonCompiler(bundle).compile_ruleset()
        self._permission_monitors_template = None
        self._session_monitors.clear()
        self._session_permission_monitors.clear()
        self._principal_monitors.clear()
        self._principal_monitor_keys.clear()

    def _lazy_init_permission_monitors(self) -> None:
        if self._permission_monitors_template is not None:
            return
        if self._permission_ruleset is None:
            self._permission_monitors_template = []
            return
        from openclaw_guard.rv.rv_dsl import compile_monitors

        self._permission_monitors_template = compile_monitors(self._permission_ruleset)

    def _lazy_init_monitors(self) -> None:
        self._lazy_init_spec_monitors()

    def _lazy_init_spec_monitors(self) -> None:
        if self._spec_monitors_template is not None:
            return
        from openclaw_guard.rv.rv_dsl import compile_monitors, load_ruleset

        if self._spec_ruleset is None:
            rules_path = os.getenv("OPENCLAW_RV_RULES_PATH")
            self._spec_ruleset = load_ruleset(rules_path) if rules_path else load_ruleset()
        self._spec_monitors_template = compile_monitors(self._spec_ruleset)

    def _create_monitors(self) -> list:
        """基于模板创建新的监视器实例。"""
        self._lazy_init_monitors()
        from openclaw_guard.rv.rv_dsl import compile_monitors

        return compile_monitors(self._spec_ruleset)

    def _create_permission_monitors(self, scope: str) -> list:
        """Create fresh PMKB monitor instances for one state scope."""
        self._lazy_init_permission_monitors()
        if self._permission_ruleset is None:
            return []
        from openclaw_guard.rv.rv_dsl import Ruleset, compile_monitors

        specs = [spec for spec in self._permission_ruleset.monitors if spec.scope == scope]
        return compile_monitors(Ruleset(version=self._permission_ruleset.version, monitors=specs))

    def _permission_monitor_templates_for(self, scope: str) -> list:
        """Return stable default-session PMKB monitor instances for one scope."""
        self._lazy_init_permission_monitors()
        if self._permission_ruleset is None:
            return []
        return [
            monitor
            for spec, monitor in zip(self._permission_ruleset.monitors, self._permission_monitors_template or [])
            if spec.scope == scope
        ]

    # ── 核心方法 ──

    def preview(
        self,
        rv_trace: list[dict[str, Any]],
        session_key: str = "_default",
        *,
        authorization_trace: Any | None = None,
        policy_decision: Any | None = None,
    ) -> dict[str, Any]:
        """Evaluate a candidate trace without changing the session state.

        A tool can be denied or wait for an OpenClaw approval after the
        ``before_tool_call`` hook.  Recording it at that point would turn an
        unexecuted proposal into part of a future attack chain.  Preview uses
        a fresh set of automata replayed from the committed window instead.

        PMKB remains the single-step authorization authority; its generated
        monitors are therefore deliberately not run in this preview path.
        """
        permission_step = self._permission_step(authorization_trace, policy_decision)
        existing_window = (
            self.window if session_key == "_default" else self._session_windows.get(session_key)
        )
        history = existing_window.snapshot() if existing_window is not None else []
        replay_window = WindowManager(max_size=self._window_size, ttl_seconds=self._window_ttl)
        replay_steps = [dict(step) for step in [*history, *rv_trace]]
        for index, step in enumerate(replay_steps):
            replay_window.push(step, preserve_timestamp=index < len(history))

        severity_map: dict[str, int] = {
            "block": 4, "escalate": 3, "ask": 2, "ok": 1,
        }
        final = "ok"
        triggered_by: str | None = None
        reason: str | None = None
        monitor_timings: dict[str, float] = {}
        monitors = self._create_monitors()
        for monitor in monitors:
            started = _time.perf_counter()
            for step in replay_steps:
                try:
                    result = monitor.feed(step, replay_window)
                except Exception:
                    result = None
                if result and severity_map.get(result, 0) > severity_map.get(final, 0):
                    final = result
                    triggered_by = monitor.__class__.__name__
                    reason = f"{monitor.__class__.__name__}: {result}"
            monitor_timings[monitor.__class__.__name__] = round(
                (_time.perf_counter() - started) * 1000.0, 4
            )

        permission_monitors = self._create_permission_monitors("session") if permission_step else []
        for monitor in permission_monitors:
            started = _time.perf_counter()
            try:
                result = monitor.feed(permission_step, replay_window)
            except Exception:
                result = None
            if result and severity_map.get(result, 0) > severity_map.get(final, 0):
                final = result
                triggered_by = monitor.__class__.__name__
                reason = f"{monitor.__class__.__name__}: {result}"
            monitor_timings[monitor.__class__.__name__] = round(
                (_time.perf_counter() - started) * 1000.0, 4
            )

        principal_monitors = (
            self._create_permission_monitors("principal")
            if permission_step and self._verified_principal(authorization_trace)
            else []
        )
        for monitor in principal_monitors:
            started = _time.perf_counter()
            try:
                result = monitor.feed(permission_step, replay_window)
            except Exception:
                result = None
            if result and severity_map.get(result, 0) > severity_map.get(final, 0):
                final = result
                triggered_by = monitor.__class__.__name__
                reason = f"{monitor.__class__.__name__}: {result}"
            monitor_timings[monitor.__class__.__name__] = round(
                (_time.perf_counter() - started) * 1000.0, 4
            )

        return {
            "verdict": final,
            "triggered_by": triggered_by,
            "reason": reason,
            "window_size": len(replay_window),
            "session_key": session_key,
            "rule_mode": self._rule_mode,
            "monitor_timings_ms": monitor_timings,
            "baseline_result": None,
            "monitor_sources": {
                "behavior": len(monitors),
                "permission": len(permission_monitors),
                "principal_permission": len(principal_monitors),
            },
        }

    def evaluate(
        self,
        rv_trace: list[dict[str, Any]],
        session_key: str = "_default",
        *,
        authorization_trace: Any | None = None,
        policy_decision: Any | None = None,
    ) -> dict[str, Any]:
        """执行在线运行时验证。

        对语义层产出的 rv_trace 执行：
        1. 将新事件步推入 per-session 滑动窗口
        2. 依次过所有生成的 DSL 监视器
        3. 取最高风险等级的判定作为最终结果

        Args:
            rv_trace: 语义层产出的步骤列表
            session_key: 会话标识（用于 per-session 窗口隔离）
                         默认 "_default" 保持向后兼容

        Returns:
            {
                "verdict": "ok" | "ask" | "block" | "escalate",
                "triggered_by": str | None,   # 触发规则的监视器名
                "reason": str | None,
                "window_size": int,
                "session_key": str,
            }
        """
        permission_step = self._permission_step(authorization_trace, policy_decision)

        # Commit first, then reconstruct behavior monitors from the effective
        # window.  Reusing a prior monitor instance would retain a terminal state
        # after its triggering steps have expired from the window.
        window = self._get_session_window(session_key)
        for step in rv_trace:
            window.push(dict(step))
        committed_steps = [dict(step) for step in window.snapshot()]
        monitors = self._create_monitors()

        # 2) 遍历监视器收集判定
        severity_map: dict[str, int] = {
            "block": 4, "escalate": 3, "ask": 2, "ok": 1,
        }
        final = "ok"
        triggered_by: str | None = None
        reason: str | None = None
        monitor_timings: dict[str, float] = {}

        for monitor in monitors:
            m_start = _time.perf_counter()
            for step in committed_steps:
                try:
                    result = monitor.feed(step, window)
                except Exception:
                    result = None
                if result and severity_map.get(result, 0) > severity_map.get(final, 0):
                    final = result
                    triggered_by = monitor.__class__.__name__
                    reason = f"{monitor.__class__.__name__}: {result}"
            monitor_timings[monitor.__class__.__name__] = round(
                (_time.perf_counter() - m_start) * 1000.0, 4
            )

        # PMKB monitors are one-decision projections.  Rebuild them for every
        # evaluation so an expired or rejected call cannot leave a terminal
        # permission state behind in a later window.
        permission_monitors = self._create_permission_monitors("session")
        if permission_step is not None:
            for monitor in permission_monitors:
                m_start = _time.perf_counter()
                try:
                    result = monitor.feed(permission_step, window)
                except Exception:
                    result = None
                if result and severity_map.get(result, 0) > severity_map.get(final, 0):
                    final = result
                    triggered_by = monitor.__class__.__name__
                    reason = f"{monitor.__class__.__name__}: {result}"
                monitor_timings[monitor.__class__.__name__] = round(
                    (_time.perf_counter() - m_start) * 1000.0, 4
                )

        principal_monitor_count = 0
        if permission_step is not None:
            self._record_principal_monitor_key(authorization_trace)
            principal_monitors = (
                self._create_permission_monitors("principal")
                if self._verified_principal(authorization_trace)
                else []
            )
            principal_monitor_count = len(principal_monitors)
            for monitor in principal_monitors:
                m_start = _time.perf_counter()
                try:
                    result = monitor.feed(permission_step, window)
                except Exception:
                    result = None
                if result and severity_map.get(result, 0) > severity_map.get(final, 0):
                    final = result
                    triggered_by = monitor.__class__.__name__
                    reason = f"{monitor.__class__.__name__}: {result}"
                monitor_timings[monitor.__class__.__name__] = round(
                    (_time.perf_counter() - m_start) * 1000.0, 4
                )

        return {
            "verdict": final,
            "triggered_by": triggered_by,
            "reason": reason,
            "window_size": len(window),
            "session_key": session_key,
            "rule_mode": self._rule_mode,
            "monitor_timings_ms": monitor_timings,
            "baseline_result": self._run_baseline(rv_trace, severity_map, final),
            "monitor_sources": {
                "behavior": len(monitors),
                "permission": len(permission_monitors),
                "principal_permission": principal_monitor_count,
            },
        }

    @staticmethod
    def _model_data(value: Any) -> dict[str, Any]:
        """Return a JSON-shaped view of a Pydantic model or mapping."""
        if hasattr(value, "model_dump"):
            dumped = value.model_dump(mode="json")
            return dumped if isinstance(dumped, dict) else {}
        return dict(value) if isinstance(value, dict) else {}

    def _permission_step(self, authorization_trace: Any, policy_decision: Any) -> dict[str, Any] | None:
        """Build one synthetic RV step from PMKB evidence when both parts exist."""
        trace = self._model_data(authorization_trace)
        decision = self._model_data(policy_decision)
        if not trace or not decision:
            return None
        operation = trace.get("operation") if isinstance(trace.get("operation"), dict) else {}
        p_after = decision.get("p_after") if isinstance(decision.get("p_after"), list) else []
        p_after_families = [str(item.get("family")) for item in p_after if isinstance(item, dict) and item.get("family")]
        policy = dict(decision)
        policy["operation_family"] = str(operation.get("family") or "")
        policy["p_after_families"] = p_after_families
        props = ["pmkb", f"pmkb:operation:{policy['operation_family']}"]
        props.extend(f"pmkb:rule:{item}" for item in policy.get("selected_rule_ids", []) if item)
        props.extend(f"pmkb:relation:{item}" for item in policy.get("combo_violations", []) if item)
        return {"event": "pmkb.permission", "props": props, "policy": policy}

    def _get_principal_monitors(self, authorization_trace: Any) -> list:
        """Get generated relation monitors for a verified principal identity."""
        trace = self._model_data(authorization_trace)
        principal = trace.get("principal") if isinstance(trace.get("principal"), dict) else {}
        if principal.get("trust") != "verified" or not principal.get("id"):
            return []
        agent_id = str(trace.get("agent_id") or "")
        lineage_raw = trace.get("capability_lineage")
        lineage = tuple(str(item) for item in lineage_raw) if isinstance(lineage_raw, list) else ()
        key = (str(principal["id"]), agent_id, lineage)
        if key not in self._principal_monitors:
            self._principal_monitors[key] = self._create_permission_monitors("principal")
        return self._principal_monitors[key]

    @staticmethod
    def _verified_principal(authorization_trace: Any) -> bool:
        """Return whether the host supplied a complete trusted identity."""
        if authorization_trace is None:
            return False
        if hasattr(authorization_trace, "model_dump"):
            trace = authorization_trace.model_dump(mode="json")
        elif isinstance(authorization_trace, dict):
            trace = authorization_trace
        else:
            return False
        principal = trace.get("principal") if isinstance(trace.get("principal"), dict) else {}
        return bool(principal.get("trust") == "verified" and principal.get("id"))

    def _record_principal_monitor_key(self, authorization_trace: Any) -> None:
        if not self._verified_principal(authorization_trace):
            return
        trace = self._model_data(authorization_trace)
        principal = trace.get("principal") if isinstance(trace.get("principal"), dict) else {}
        lineage_raw = trace.get("capability_lineage")
        lineage = tuple(str(item) for item in lineage_raw) if isinstance(lineage_raw, list) else ()
        self._principal_monitor_keys.add((
            str(principal.get("id") or ""),
            str(trace.get("agent_id") or ""),
            lineage,
        ))

    def _run_baseline(
        self,
        rv_trace: list[dict[str, Any]],
        severity_map: dict[str, int],
        current_verdict: str,
    ) -> dict[str, Any] | None:
        """运行基线监视器并返回结果。

        基线判定作为独立信号，不覆盖现有监视器的判定。
        仅当基线检测到异常且 severity 高于当前 verdict 时才升级。
        """
        if self._baseline_monitor is None:
            return None

        bm = self._baseline_monitor
        bm_result: str | None = None
        for step in rv_trace:
            r = bm.feed(step)
            if r and severity_map.get(r, 0) > severity_map.get(bm_result or "ok", 0):
                bm_result = r

        return {
            "anomaly_detected": bm_result is not None,
            "verdict": bm_result or "ok",
            "current_state": bm.current_state,
            "anomaly_count": bm.anomaly_count,
            "step_count": bm.step_count,
        }

    # ── Session 管理 ──

    def _get_session_window(self, session_key: str) -> WindowManager:
        """获取或创建 per-session 窗口。"""
        if session_key == "_default":
            return self.window
        if session_key not in self._session_windows:
            self._session_windows[session_key] = WindowManager(
                max_size=self._window_size,
                ttl_seconds=self._window_ttl,
            )
        return self._session_windows[session_key]

    def _get_session_monitors(self, session_key: str) -> list:
        """获取或创建 per-session 监视器实例。"""
        if session_key == "_default":
            self._lazy_init_monitors()
            return self._spec_monitors_template  # type: ignore[return-value]
        if session_key not in self._session_monitors:
            self._session_monitors[session_key] = self._create_monitors()
        return self._session_monitors[session_key]

    def _get_session_permission_monitors(self, session_key: str) -> list:
        """Get PMKB rule monitors without contaminating the behavior window."""
        if session_key == "_default":
            return self._permission_monitor_templates_for("session")
        if session_key not in self._session_permission_monitors:
            self._session_permission_monitors[session_key] = self._create_permission_monitors("session")
        return self._session_permission_monitors[session_key]

    def release_session(self, session_key: str) -> None:
        """释放某个会话的 RV 状态（窗口 + 监视器）。"""
        self._session_windows.pop(session_key, None)
        self._session_monitors.pop(session_key, None)
        self._session_permission_monitors.pop(session_key, None)

    def state_for_principal(
        self,
        principal_id: str,
        agent_id: str,
        lineage: tuple[str, ...],
    ) -> Any:
        """Return bounded cross-session state for one complete identity key.

        A goal is deliberately excluded from this key: it may partition work,
        but cannot authenticate an identity merge.  Conversely, a difference in
        any principal, agent, or capability-lineage component always yields a
        separate state object.
        """
        from openclaw_guard.spec.session_state import PrincipalSecurityState

        key = (str(principal_id), str(agent_id), tuple(str(item) for item in lineage))
        state = self._principal_states.get(key)
        if state is not None:
            return state
        if len(self._principal_states) >= self._principal_state_limit:
            oldest_key = min(self._principal_states, key=lambda item: self._principal_states[item].last_seen_at)
            self._principal_states.pop(oldest_key, None)
        state = PrincipalSecurityState(
            key[0], key[1], key[2], ttl_seconds=self._window_ttl,
        )
        self._principal_states[key] = state
        return state

    def session_count(self) -> int:
        """返回当前活跃的 per-session 数量（不含 _default）。"""
        return len(self._session_windows)

    def principal_monitor_count(self) -> int:
        """Return the number of isolated principal monitor sets."""
        return len(self._principal_monitor_keys)

    # ── 序列化 ──

    def serialize_state(self) -> dict[str, Any]:
        """序列化所有窗口状态供持久化。"""
        state: dict[str, Any] = {
            "_window_size": self._window_size,
            "_window_ttl": self._window_ttl,
            "default_window": self.window.to_dict(),
            "session_windows": {
                k: w.to_dict() for k, w in self._session_windows.items()
            },
            "principal_states": [
                principal_state.to_dict()
                for principal_state in self._principal_states.values()
            ],
        }
        return state

    def deserialize_state(self, state: dict[str, Any]) -> None:
        """从序列化数据恢复所有窗口状态。"""
        if "default_window" in state:
            self.window = WindowManager.from_dict(state["default_window"])
        if "session_windows" in state:
            for k, data in state["session_windows"].items():
                if isinstance(data, dict):
                    self._session_windows[k] = WindowManager.from_dict(data)
        raw_principal_states = state.get("principal_states", [])
        if isinstance(raw_principal_states, list):
            from openclaw_guard.spec.session_state import PrincipalSecurityState

            for data in raw_principal_states:
                if not isinstance(data, dict):
                    continue
                principal_state = PrincipalSecurityState.from_dict(data)
                key = (
                    principal_state.principal_id,
                    principal_state.agent_id,
                    principal_state.capability_lineage,
                )
                if all(key) and len(self._principal_states) < self._principal_state_limit:
                    self._principal_states[key] = principal_state

    # ── 摘要 ──

    def result_summary(self, session_key: str = "_default") -> dict[str, Any]:
        """返回当前会话窗口的摘要信息，供前端展示。"""
        window = self._get_session_window(session_key)
        snap = [dict(step) for step in window.snapshot()]
        monitors = self._create_monitors()
        for monitor in monitors:
            for step in snap:
                try:
                    monitor.feed(step, window)
                except Exception:
                    continue
        return {
            "window_size": len(window),
            "monitor_count": len(monitors),
            "rule_mode": self._rule_mode,
            "session_key": session_key,
            "monitor_states": {
                m.__class__.__name__: m.state_summary()
                for m in monitors
            },
            "window_snapshot": [
                {
                    "event": s.get("event"),
                    "props": s.get("props", [])[:6],
                }
                for s in snap
            ],
        }

    def reset(self, session_key: str | None = None) -> None:
        """重置监视器状态和滑动窗口。

        Args:
            session_key: 要重置的会话，None 表示重置所有
        """
        if session_key is not None:
            window = self._get_session_window(session_key)
            window.clear()
            for m in self._get_session_monitors(session_key):
                try:
                    m.reset()
                except Exception:
                    pass
            for m in self._get_session_permission_monitors(session_key):
                try:
                    m.reset()
                except Exception:
                    pass
        else:
            # 重置所有
            self.window.clear()
            self._lazy_init_monitors()
            monitors = self._spec_monitors_template
            if monitors:
                for m in monitors:
                    try:
                        m.reset()
                    except Exception:
                        pass
            for wm in self._session_windows.values():
                wm.clear()
            for monitors in self._session_monitors.values():
                for m in monitors:
                    try:
                        m.reset()
                    except Exception:
                        pass
            for monitors in self._session_permission_monitors.values():
                for m in monitors:
                    try:
                        m.reset()
                    except Exception:
                        pass
            self._principal_states.clear()
            self._principal_monitors.clear()
            self._principal_monitor_keys.clear()
            self._session_permission_monitors.clear()
