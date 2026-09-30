"""实验期组件消融门（ablation gates）。

本模块提供四个可独立开关的安全组件门，供 office-attack-chain 实验在
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
  注意：本工作树中**不存在** ``trusted_authorization`` 受信授权存储（该存储
  属于更早的 Q5 实验桩，已被回滚）。因此本门只能映射到现存的主体授权证据
  路径；规格中"受信授权事实/信任范围"这一独立维度在当前工作树**不可独立
  开关**，其取值仍记录在 ``config_hash`` 中，但不臆造新的授权点位。
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
}


@dataclass(frozen=True)
class ExperimentComponents:
    """四个组件门的启用/禁用快照（不可变）。"""

    semantic_llm: bool = True
    cross_step_rv: bool = True
    authorization: bool = True
    approval_trust: bool = True

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
_current: ExperimentComponents = ExperimentComponents.all_enabled()


def current() -> ExperimentComponents:
    """返回当前生效的组件配置快照（线程安全）。"""
    with _lock:
        return _current


def configure(components: ExperimentComponents) -> None:
    """设置当前生效的组件配置（线程安全）。"""
    if not isinstance(components, ExperimentComponents):
        raise TypeError("configure() expects an ExperimentComponents instance")
    global _current
    with _lock:
        _current = components


def reset() -> None:
    """恢复为默认的“全部启用”配置。"""
    configure(ExperimentComponents.all_enabled())


@contextmanager
def using(components: ExperimentComponents) -> Iterator[ExperimentComponents]:
    """临时切换组件配置，退出（含异常）时恢复先前配置。"""
    global _current
    with _lock:
        previous = _current
        _current = components
    try:
        yield components
    finally:
        with _lock:
            _current = previous
