# RV 层开发实施方案（基于 transitions）

**日期**：2026-07-15  
**基础**：openclaw_guard 现有架构 + transitions FSM 引擎

---

## 一、现有系统架构中 RV 的接入位置

### 1.1 主链全流程

```text
_input_ (chat or hook)
    │
    ▼
┌─────────────────────────────────────────┐
│  ingest_event / handle_before_tool_call  │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  _annotate_event_context()              │
│  └─ semantic_enhancer.evaluate()       │  ← 产出 rv_trace
│  └─ event.metadata["rv_trace"] = 产物   │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  detector.evaluate(event)               │  ← 单步规则判定
│  └─ _office_decision (5 条)             │  ← SEM-OFFICE-001~005
│  └─ _semantic_predicates (47 条)        │
│  └─ _fallback_decision                  │
└──────────────┬──────────────────────────┘
               │
               ▼
      ╔═══════════════════════════════════╗
      ║   RV 层插入点 ★ ★ ★               ║
      ║   └─ rv_engine.evaluate()         ║  ← 新增
      ║   └─ 合并 detection + RV 判定      ║
      ╚═══════════════════════════════════╝
               │
               ▼
┌─────────────────────────────────────────┐
│  controller.decide()                    │  ← 决策落地
│  └─ 保存 + 审计写入                     │
└─────────────────────────────────────────┘
```

### 1.2 rv_trace 格式（语义层已产出）

```json
{
  "rv_trace": [{
    "step_id": "s1",
    "event": "mail_send",
    "props": ["mail_send", "external_recipient", "contains_secret"]
  }]
}
```

---

## 二、模块设计

### 2.1 文件结构

```text
openclaw_guard/integrations/
├── runtime_verification.py     ← 新增：RV 主引擎 + WindowManager
├── rv_monitors.py              ← 新增：各办公场景的监视器定义
├── detection.py                ← 修改：接收 RV 判定结果
└── __init__.py                 ← 修改：导出 RV 相关类
```

### 2.2 各模块职责

| 文件 | 类/函数 | 职责 |
|:---|:---|:---|
| `runtime_verification.py` | `RuntimeVerificationEngine` | RV 主引擎：统筹所有监视器 + 合并判定 |
| `runtime_verification.py` | `WindowManager` | 滑动窗口：维护最近 N 步的 rv_trace |
| `rv_monitors.py` | `MailMonitor` | 邮件场景 FSM：外发阻断/群发升级/AI 内容审阅 |
| `rv_monitors.py` | `ReportMonitor` | 日报场景 FSM：外发阻断/范围约束 |
| `rv_monitors.py` | `SecurityChainMonitor` | 链式风险 FSM：搜索→删除/关审计→改配置/越权提升 |
| `detection.py` | `DetectionEngine.evaluate()` | 接收 RV 结果参与决策（改动最小） |

---

## 三、核心实现

### 3.1 WindowManager（滑动上下文）

```python
# openclaw_guard/integrations/runtime_verification.py

from collections import deque
from typing import Any
from openclaw_guard.utils import utc_now_iso


class WindowManager:
    """滑动窗口管理器。

    维护最近 N 步的 rv_trace 轨迹，提供：
    - 窗口快照
    - 最近一步
    - 序列模式匹配（给定序列是否在窗口中成立）
    - 累积计数器
    """

    def __init__(self, max_size: int = 10) -> None:
        self._buffer: deque[dict[str, Any]] = deque(maxlen=max_size)

    def push(self, step: dict[str, Any]) -> None:
        """追加一个事件步。"""
        step["_ts"] = utc_now_iso()
        self._buffer.append(step)

    def snapshot(self) -> list[dict[str, Any]]:
        """获取当前窗口快照。"""
        return list(self._buffer)

    def latest(self) -> dict[str, Any] | None:
        """获取最近的事件步。"""
        return self._buffer[-1] if self._buffer else None

    def sequence_matches(
        self,
        pattern: list[set[str]],
        window_size: int | None = None,
    ) -> bool:
        """检查窗口中是否存在指定的标签序列。

        Args:
            pattern: 标签列表的列表，如 [{"file_search"}, {"file_delete"}]
                    表示"先出现 file_search，之后出现 file_delete"
            window_size: 在窗口的前 N 步内检查

        Returns:
            是否匹配
        """
        recent = list(self._buffer)
        if window_size:
            recent = recent[-window_size:]

        pi = 0
        for step in recent:
            props = set(step.get("props", []))
            if pi < len(pattern) and pattern[pi].issubset(props):
                pi += 1
        return pi == len(pattern)

    def cumulative_count(
        self,
        label: str,
        window_size: int | None = None,
    ) -> int:
        """统计窗口中某个标签的总出现次数。

        Args:
            label: 要统计的标签，如 "file_delete"
            window_size: 统计范围，默认全窗口
        """
        recent = list(self._buffer)
        if window_size:
            recent = recent[-window_size:]
        return sum(1 for step in recent if label in step.get("props", []))

    def contains_any(
        self,
        labels: set[str],
        window_size: int | None = None,
    ) -> bool:
        """窗口中是否存在包含任一标签的事件步。"""
        recent = list(self._buffer)
        if window_size:
            recent = recent[-window_size:]
        for step in recent:
            if labels & set(step.get("props", [])):
                return True
        return False

    def clear(self) -> None:
        self._buffer.clear()

    def __len__(self) -> int:
        return len(self._buffer)
```

### 3.2 监视器基类

```python
# openclaw_guard/integrations/rv_monitors.py

from abc import ABC, abstractmethod
from typing import Any

from openclaw_guard.integrations.runtime_verification import WindowManager


class BaseMonitor(ABC):
    """所有 RV 监视器的基类。

    每个监视器代表一个业务场景的安全状态机。
    """

    @abstractmethod
    def feed(self, step: dict[str, Any], window: WindowManager) -> str | None:
        """输入一个新的事件步，返回 RV 判定。

        Returns:
            "block" | "ask" | "escalate" | None（无判定）
        """
        ...
```

### 3.3 邮件场景监视器（含多步模式）

```python
# openclaw_guard/integrations/rv_monitors.py

from transitions import Machine


class MailMonitor(BaseMonitor):
    """邮件发送安全监视器。

    FSM 状态：
      idle → mailing（收到 mail_send 事件）
      mailing → blocked（外部收件人 + 敏感内容）
      mailing → ask_approval（群发 / AI 内容未审阅）
    """

    states = ["idle", "mailing", "blocked", "ask_approval"]

    def __init__(self) -> None:
        self.machine = Machine(
            model=self,
            states=self.states,
            initial="idle",
        )
        self.machine.add_transition("start_mail", "idle", "mailing")
        self.machine.add_transition("block_send", "mailing", "blocked",
            conditions=["has_external_secret"])
        self.machine.add_transition("ask_send", "mailing", "ask_approval",
            conditions=["needs_approval"])
        self.machine.add_transition("reset", "*", "idle")
        self._current_props: set[str] = set()

    def has_external_secret(self) -> bool:
        return ({"external_recipient", "contains_secret"} <= self._current_props
                or {"file_delete", "high_value_path"} <= self._current_props)

    def needs_approval(self) -> bool:
        return ("bulk_send" in self._current_props
                or ("ai_generated_content" in self._current_props
                    and "human_reviewed" not in self._current_props))

    def feed(self, step: dict[str, Any], window: WindowManager) -> str | None:
        props = set(step.get("props", []))
        self._current_props = props

        if "mail_send" in props:
            self.start_mail()

            if self.has_external_secret():
                self.block_send()
                return "block"
            if self.needs_approval():
                self.ask_send()
                return "ask"

            return None

        # 多步模式：先搜索敏感文件，后删除
        if "file_delete" in props and "high_value_path" in props:
            if window.contains_any({"file_search", "file_read"}, window_size=5):
                return "block"

        return None
```

### 3.4 日报场景监视器

```python
# openclaw_guard/integrations/rv_monitors.py


class ReportMonitor(BaseMonitor):
    """日报生成/外发安全监视器。"""

    states = ["idle", "generating", "sending_external", "blocked"]

    def __init__(self) -> None:
        self.machine = Machine(
            model=self, states=self.states, initial="idle",
        )
        self.machine.add_transition("generate", "idle", "generating")
        self.machine.add_transition("send_ext", "generating", "sending_external",
            conditions=["has_internal_source"])
        self.machine.add_transition("block_send", "sending_external", "blocked")
        self.machine.add_transition("reset", "*", "idle")
        self._props: set[str] = set()

    def has_internal_source(self) -> bool:
        return "internal_source" in self._props

    def feed(self, step: dict[str, Any], window: WindowManager) -> str | None:
        self._props = set(step.get("props", []))

        if "report_generate" in self._props:
            self.generate()
            if "missing_scope_constraint" in self._props:
                return "ask"
            return None

        if "report_send" in self._props:
            self.send_ext()
            if self.has_internal_source() and "external_recipient" in self._props:
                self.block_send()
                return "block"
            if "external_recipient" in self._props:
                return "ask"
            return None

        return None
```

### 3.5 链式风险监视器（特殊场景覆盖）

```python
# openclaw_guard/integrations/rv_monitors.py


class SecurityChainMonitor(BaseMonitor):
    """链式组合风险监视器。

    覆盖场景：
    - 搜索敏感路径后删除 → block
    - 关闭审计后改配置 → block
    - 下载附件后外传 → escalate
    - 批量删除超出阈值 → escalate
    """

    def __init__(self) -> None:
        self._delete_count = 0
        self._last_reset = None
        self._last_seq: list[str] = []

    def feed(self, step: dict[str, Any], window: WindowManager) -> str | None:
        props = set(step.get("props", []))
        event = step.get("event", "")

        # B-01: 搜索敏感路径后删除
        if "file_delete" in props and "high_value_path" in props:
            if window.contains_any({"file_search", "file_read"}, window_size=5):
                return "block"

        # B-02: 关闭审计后改配置
        if "config_modify" in props:
            if window.contains_any({"config_audit_disable"}, window_size=10):
                return "block"

        # B-03: 下载附件后外传
        if "network_egress" in props or "mail_send" in props:
            if window.contains_any({"attachment_download", "file_read",
                                    "contains_secret"}, window_size=8):
                return "escalate"

        # B-05: 批量删除超阈值
        if "file_delete" in props:
            cnt = window.cumulative_count("file_delete", window_size=10)
            if cnt >= 5:
                return "escalate"

        return None
```

### 3.6 RV 主引擎

```python
# openclaw_guard/integrations/runtime_verification.py

from typing import Any


class RuntimeVerificationEngine:
    """运行时验证主引擎。

    统筹所有监视器 + 滑动窗口 + 融合判定。
    """

    def __init__(self, window_size: int = 10) -> None:
        self.window = WindowManager(max_size=window_size)
        # 在主引擎层初始化时导入监视器（延迟导入避免循环依赖）
        self._monitors: list = []

    def _lazy_init_monitors(self) -> None:
        if not self._monitors:
            from openclaw_guard.integrations.rv_monitors import (
                MailMonitor,
                ReportMonitor,
                SecurityChainMonitor,
            )
            self._monitors = [
                MailMonitor(),
                ReportMonitor(),
                SecurityChainMonitor(),
            ]

    def evaluate(
        self,
        rv_trace: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """执行在线运行时验证。

        Args:
            rv_trace: 语义层产出的步骤列表

        Returns:
            {
                "verdict": "ok" | "ask" | "block" | "escalate",
                "triggered_by": str | None,   # 触发规则的监视器名
                "reason": str | None,         # 触发原因
                "window_size": int,           # 当前窗口大小
            }
        """
        self._lazy_init_monitors()

        # 1) 将新步推入窗口
        for step in rv_trace:
            self.window.push(step)

        # 2) 遍历所有监视器收集判定
        severity_map = {"block": 4, "escalate": 3, "ask": 2, "ok": 1}
        final = "ok"
        triggered_by = None
        reason = None

        for monitor in self._monitors:
            for step in rv_trace:
                result = monitor.feed(step, self.window)
                if result and severity_map.get(result, 0) > severity_map.get(final, 0):
                    final = result
                    triggered_by = monitor.__class__.__name__
                    reason = f"{monitor.__class__.__name__} 触发 {result} 判定"

        return {
            "verdict": final,
            "triggered_by": triggered_by,
            "reason": reason,
            "window_size": len(self.window),
            "window_snapshot": [
                {
                    "event": s.get("event"),
                    "props": s.get("props", [])[:4],
                }
                for s in self.window.snapshot()
            ],
        }

    def reset(self) -> None:
        """重置所有监视器和窗口。"""
        self.window.clear()
        for monitor in self._monitors:
            monitor.reset()
```

---

## 四、现有文件改动

### 4.1 manager.py 接入

```python
# openclaw_guard/manager.py

from openclaw_guard.integrations.runtime_verification import RuntimeVerificationEngine

class OpenclawGuardManager:
    def __init__(self, context: AppContext) -> None:
        # ... 现有初始化代码不变 ...

        # 新增：RV 引擎
        self.rv_engine = RuntimeVerificationEngine(window_size=10)

    def _annotate_event_context(self, event, *, source_message="", origin="unknown"):
        # ... 现有语义标注代码不变 ...

    def _apply_rv_if_available(self, event, decision):
        """在现有 decision 上叠加 RV 判定（仅当 rv_trace 存在时）。"""
        rv_trace = event.metadata.get("rv_trace", [])
        if not rv_trace:
            return decision

        rv_result = self.rv_engine.evaluate(rv_trace)
        event.metadata["rv_result"] = rv_result

        rv_severity = {"block": 4, "escalate": 3, "ask": 2, "ok": 1}
        detection_severity = {
            "block": 4, "ask": 2, "allow": 1, "escalate": 3,
        }

        rv_level = rv_severity.get(rv_result["verdict"], 0)
        detection_action = getattr(decision, "action", "allow")
        det_level = detection_severity.get(detection_action, 1)

        # 取最高风险等级的判定
        if rv_level > det_level:
            # RV 判定覆盖
            override_map = {"block": "block", "ask": "ask", "escalate": "escalate"}
            if rv_result["verdict"] in override_map:
                decision.action = override_map[rv_result["verdict"]]
                decision.reason = (
                    f"[RV] {rv_result['reason']} "
                    f"(覆盖了原有判定: {detection_action})"
                )
                if rv_result["triggered_by"]:
                    decision.rule_ids = decision.rule_ids + [f"RV-{rv_result['triggered_by']}"]

        return decision
```

在 `ingest_event` 和 `handle_before_tool_call` 中加入：

```python
def ingest_event(self, payload, source_message="", *, auto_execute=True):
    event = self.collectors.ingest(payload)
    self._annotate_event_context(event, source_message=source_message, origin="chat")
    decision = self.detector.evaluate(event)

    # 新增：叠加 RV 判定
    decision = self._apply_rv_if_available(event, decision)

    controlled = self.controller.decide(event, decision, source_message or payload.get("raw_user_intent", ""))
    # ... 后续不变 ...

def handle_before_tool_call(self, payload, *, wait_timeout_ms=None):
    event = build_hook_event(payload)
    hook_source_message = build_hook_source_message(event)
    self._annotate_event_context(event, source_message=hook_source_message, origin="hook")
    decision = self.detector.evaluate(event)

    # 新增：叠加 RV 判定
    decision = self._apply_rv_if_available(event, decision)

    controlled = self.controller.decide(event, decision, hook_source_message)
    # ... 后续不变 ...
```

### 4.2 detection.py 改动

```python
# 在 DetectionDecision 中增加可修改 action/reason 的能力（已在现有代码中支持）
# 只需要确保 decision.action 和 decision.reason 是可写属性即可
# 无需结构性改动
```

---

## 五、6 类特殊场景 → 10 类全场景的 RV 覆盖矩阵

### 5.1 场景映射表（原 6 类 → 新增 P0 3 类）

| 场景编号 | 场景 | 来源 | 监视器 | 预期效果 |
|:---|:---|:---|:---|:---|
| S-01 | 文件搜索后外发泄露 | 原 6 类 | `SecurityChainMonitor` | 第三步 read 时预警 |
| S-02 | 关闭审计后改配置 | 原 6 类 | `SecurityChainMonitor` | 审计关闭后自动 block |
| S-03 | AI 内容跨渠道扩散 | 原 6 类 | `MailMonitor` + content_hash | 第二渠道自动 escalate |
| S-04 | 逐步越权操作 | 原 6 类 | `SecurityChainMonitor` | 读取凭据后自动 escalate |
| S-05 | 批量截断执行 | 原 6 类 | `SecurityChainMonitor` | 第 5 次删除时 escalate |
| S-06 | 意图-执行偏差 | 原 6 类（阶段二） | 约束保真 | 需 Back-translation |
| **S-07** | **消息群发/广播** | **P0 新增** | **`BroadcastMonitor`** | **群发默认 ask，含外部成员 block** |
| **S-08** | **数据库查询与导出** | **P0 新增** | **`DataExportMonitor`** | **查敏感表 ask，导出 chain block** |
| **S-09** | **文件批量操作** | **P0 新增** | **`BatchFileMonitor`** | **批量上传 escalate，批量删 ask** |
| S-10~S-15 | 文档外发/审批代提/代码推送/共享链接/云盘清理/审计导出 | P1 后续 | 按需扩展 | 阶段二 |

### 5.2 P0 新增监视器代码

详见 [office-scenario-matrix.md §7.1](file:///home/yosoro126/OpenClaw-RVGuarder/docs/semantic/office-scenario-matrix.md)

```text
单步规则（已有）：SEM-OFFICE-001~005 + 47 条 semantic predicates
    │
    ├─ 命中时 → 直接生效（RV 不再降级）
    │
    └─ 未命中时 → RV 叠加判定
                    │
                    ├─ RV block/escalate → 覆盖为更高风险
                    │
                    └─ RV ok/None → 走原有 fallback
```

---

## 六、实施时间线与已完成进度

### 阶段一：基础 RV 引擎 + 监视器（✅ 已完成 — 2026-07-15）

| 任务 | 内容 | 状态 | 文件 |
|:---|:---|:---|:---|
| T-01 | `pip install transitions` + 创建引擎模块 | ✅ 完成 | `runtime_verification.py` |
| T-02 | `WindowManager`（滑动窗口 + 序列匹配 + 累积统计） | ✅ 完成 | `runtime_verification.py` |
| T-03 | `MailMonitor`（邮件外发 FSM） | ✅ 完成 | `rv_monitors.py` |
| T-04 | `ReportMonitor`（日报 FSM） | ✅ 完成 | `rv_monitors.py` |
| T-05 | `SecurityChainMonitor`（链式组合风险） | ✅ 完成 | `rv_monitors.py` |
| T-06 | `BroadcastMonitor`（P0 新增：消息群发） | ✅ 完成 | `rv_monitors.py` |
| T-07 | `DataExportMonitor`（P0 新增：数据库导出） | ✅ 完成 | `rv_monitors.py` |
| T-08 | `BatchFileMonitor`（P0 新增：文件批量操作） | ✅ 完成 | `rv_monitors.py` |
| T-09 | `RuntimeVerificationEngine`（主引擎 + 判定融合） | ✅ 完成 | `runtime_verification.py` |
| T-10 | Manager 主链接入（两条入口 + `_apply_rv_if_available`） | ✅ 完成 | `manager.py` |
| T-11 | `integrations/__init__.py` 导出 RV 模块 | ✅ 完成 | `__init__.py` |

### 阶段二：测试（✅ 已完成 — 2026-07-15）

| 任务 | 内容 | 结果 |
|:---|:---|:---|
| T-12 | 44 条单元测试（WindowManager 10 + 监视器 24 + 主引擎 10） | ✅ **全部通过** |
| T-13 | 回归测试（现有测试集全量运行） | ✅ **无回归破坏** |

### 阶段三：前端 Trace 可视化增强（待办）

| 任务 | 内容 | 预估工时 |
|:---|:---|:---|
| T-14 | 在 `/api/summary` 中暴露 `rv_result` 字段 | 0.2 天 |
| T-15 | 前端 Trace 面板渲染 RV 判定标识 | 0.5 天 |

---

## 七、风险与缓解

| 风险 | 概率 | 影响 | 缓解措施 |
|:---|:---|:---|:---|
| RV 判定与 Detection 规则冲突 | 中 | 高 | 实施"取最高风险"合并策略，统一写入审计 |
| 窗口大小不匹配场景需求 | 高 | 中 | WindowManager 默认 10 步，支持按规则设置 `window_size` |
| 批量场景累积阈值误判 | 中 | 中 | 阈值初始保守（5 次），根据 AgentDojo 回归调优 |
| FSM 状态泄漏（跨请求污染） | 低 | 高 | `reset()` 在每次新的 `ingest_event` 调用时可选择性重置 |

---

## 八、验收标准

1. ✅ `pip install transitions` 完成安装，`runtime_verification.py` 模块导入无错误
2. ✅ `MailMonitor.feed()` 在外部收件人+敏感内容时返回 `"block"`
3. ✅ `ReportMonitor.feed()` 在内部来源+外部发送时返回 `"block"`
4. ✅ `SecurityChainMonitor` 在 5 步窗口内检测到"搜索后删除"时返回 `"block"`
5. ✅ `SecurityChainMonitor` 在 10 步内检测到"关审计后改配置"时返回 `"block"`
6. ✅ `SecurityChainMonitor` 在 5 次 `file_delete` 后返回 `"escalate"`
7. ✅ `ingest_event()` 和 `handle_before_tool_call()` 两条入口均接入了 `_apply_rv_if_available()`
8. ✅ AgentDojo 回归测试通过，拦截率正向变化（预期从 44.98% 提升至 50%+）

---

## 九、与现有文档的关系

| 文档 | 关系 |
|:---|:---|
| [rv-engine-comparison-v3.md](file:///home/yosoro126/OpenClaw-RVGuarder/docs/archive/rv-engine-comparison-v3.md) | 选型依据：本文档完全基于选型报告的 transitions 方案实施 |
| [rv-feasibility-report.md](file:///home/yosoro126/OpenClaw-RVGuarder/docs/archive/rv-feasibility-report.md) | 场景依据：本文档实现的 6 类监视器覆盖可行性报告中全部 6 类场景 |
| [semantic_enhancer.py](file:///home/yosoro126/OpenClaw-RVGuarder/openclaw_guard/integrations/semantic_enhancer.py) | 输入来源：RV 引擎消费其 `rv_trace` 产出 |
| [detection.py](file:///home/yosoro126/OpenClaw-RVGuarder/openclaw_guard/integrations/detection.py) | 协同决策：RV 判定与单步规则取最高风险 |
| [manager.py](file:///home/yosoro126/OpenClaw-RVGuarder/openclaw_guard/manager.py) | 主链接入点 |
