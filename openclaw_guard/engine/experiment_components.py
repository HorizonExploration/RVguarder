"""实验期组件消融门（ablation gates）。

本模块提供五个可独立开关的安全组件门，供 office-attack-chain 实验在
不改动默认生产行为的前提下，按臂启用/禁用组件以做增量归因：

- ``semantic_llm``   —— 大模型语义标签（``SemanticEnhancer`` 的 LLM 调用）。
  接入点：``openclaw_guard/engine/semantic_enhancer.py::SemanticEnhancer.evaluate``。
  关闭后不再发起任何 LLM 请求，退化为本地确定性规则路径。
- ``cross_step_rv``  —— 跨步骤运行时验证（RV 预判 + 提交）。
  接入点：``openclaw_guard/services.py::GuardServices.rv_enabled``。
  关闭后 RV 预判（``_apply_rv_if_available``）与执行后提交
  （``handle_after_tool_call_pipeline``）统一跳过，等价于 ``rv_enabled() == False``。
- ``authorization``  —— 授权事实 / 受信授权处理。
  接入点：``openclaw_guard/services.py::GuardServices.apply_principal_rv`` 与
  ``GuardServices.record_executed_principal_action``（主体授权/能力 RV 覆盖与
  执行后主体证据记录）。
  新增宿主授权引用证据接入 ``engine.pipeline::_annotate_event_context``，
  同样受此门控制：关闭后不查询授权或读取宿主资源。该证据只描述参数引用，
  尚未证明工具内容血缘，不能用于自动放行或降低 PMKB/RV 裁决。
- ``approval_trust`` —— 精确审批信任（allow-always 指纹复用）。
  接入点：``openclaw_guard/engine/pipeline.py::handle_before_tool_call_pipeline``
  的精确命令信任复用分支。关闭后禁用指纹复用，每次仍需重新审批。

默认全部启用，``current()`` 返回 ``ExperimentComponents.all_enabled()``，
因此**导入本模块不会改变任何现有行为**。模块级配置由 ``threading.Lock`` 保护，
可通过 ``configure`` / ``reset`` / ``using`` 在实验套件内切换。
"""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Callable, TypeVar
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

__all__ = [
    "COMPONENT_NAMES",
    "ExperimentComponents",
    "current",
    "configure",
    "reset",
    "using",
]


COMPONENT_NAMES: tuple[str, ...] = (
    "semantic_llm",
    "cross_step_rv",
    "authorization",
    "approval_trust",
    "cross_session_rv",
)

# 允许的别名 → 规范组件名。既接受规范全名，也接受实验规格里的短名。
_ALIASES: dict[str, str] = {
    "semantic_llm": "semantic_llm",
    "semantic": "semantic_llm",
    "cross_step": "cross_step_rv",
    "cross_step_rv": "cross_step_rv",
    "rv": "cross_step_rv",
    "authorization": "authorization",
    "auth": "authorization",
    "approval_trust": "approval_trust",
    "approval": "approval_trust",
    "cross_session_rv": "cross_session_rv",
    "cross_session": "cross_session_rv",
}


@dataclass(frozen=True)
class ExperimentComponents:
    """五个组件门的启用/禁用快照（不可变）。"""

    semantic_llm: bool = True
    cross_step_rv: bool = True
    authorization: bool = True
    approval_trust: bool = True
    cross_session_rv: bool = True

    def enabled(self) -> tuple[str, ...]:
        """返回启用的组件名（按 ``COMPONENT_NAMES`` 顺序）。"""
        return tuple(name for name in COMPONENT_NAMES if getattr(self, name))

    def disabled(self) -> tuple[str, ...]:
        """返回禁用的组件名（按 ``COMPONENT_NAMES`` 顺序）。"""
        return tuple(name for name in COMPONENT_NAMES if not getattr(self, name))

    def config_hash(self) -> str:
        """对规范化 JSON（键排序 + 紧凑分隔符）求 sha256 hex。"""
        canonical = json.dumps(
            {name: bool(getattr(self, name)) for name in COMPONENT_NAMES},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @classmethod
    def all_enabled(cls) -> "ExperimentComponents":
        """返回全部启用的默认配置。"""
        return cls()

    @classmethod
    def from_disabled(cls, spec: str) -> ExperimentComponents:
        """从逗号分隔的禁用列表构造配置。

        ``spec`` 形如 ``"cross_step,semantic_llm"``；支持短名到全名的映射
        （``cross_step`` → ``cross_step_rv``）。空字符串表示全部启用；
        出现未知名称时抛 ``ValueError``。
        """
        disabled: set[str] = set()
        for raw in str(spec or "").split(","):
            token = raw.strip().lower()
            if not token:
                continue
            name = _ALIASES.get(token)
            if name is None:
                raise ValueError(f"unknown experiment component: {raw.strip()}")
            disabled.add(name)
        return cls(**{name: name not in disabled for name in COMPONENT_NAMES})


_lock = threading.Lock()
_persistence_fence = threading.RLock()
_current: ExperimentComponents = ExperimentComponents.all_enabled()
_generation = 0
_T = TypeVar("_T")


def snapshot() -> tuple[ExperimentComponents, int]:
    """原子取得组件与代际，防止后台结果从旧实验臂流入新臂。"""
    with _lock:
        return _current, _generation


def commit_if_current(generation: int, component: str, callback: Callable[[], _T]) -> tuple[bool, _T | None]:
    """同一代际且组件开启才提交；回调只能作短内存提交，不可进行IO。"""
    if component not in COMPONENT_NAMES:
        raise ValueError("unknown experiment component")
    with _lock:
        if generation != _generation or not getattr(_current, component):
            return False, None
        return True, callback()


@contextmanager
def persistent_component_commit(generation: int, component: str) -> Iterator[bool]:
    """后台持久提交与宿主切臂串行；不持有热路径内存锁等待磁盘。"""
    if component not in COMPONENT_NAMES:
        raise ValueError("unknown experiment component")
    with _persistence_fence:
        with _lock:
            accepted = generation == _generation and getattr(_current, component)
        yield accepted


def current() -> ExperimentComponents:
    """返回当前生效的组件配置快照（线程安全）。"""
    with _lock:
        return _current


def configure(components: ExperimentComponents) -> None:
    """设置当前生效的组件配置（线程安全）。"""
    if not isinstance(components, ExperimentComponents):
        raise TypeError("configure() expects an ExperimentComponents instance")
    global _current, _generation
    with _persistence_fence:
        with _lock:
            _current = components
            _generation += 1


def reset() -> None:
    """恢复为默认的“全部启用”配置。"""
    configure(ExperimentComponents.all_enabled())


@contextmanager
def using(components: ExperimentComponents) -> Iterator[ExperimentComponents]:
    """临时切换组件配置，退出（含异常）时恢复先前配置。"""
    global _current, _generation
    with _persistence_fence:
        with _lock:
            previous = _current
            _current = components
            _generation += 1
    try:
        yield components
    finally:
        with _persistence_fence:
            with _lock:
                _current = previous
                _generation += 1
