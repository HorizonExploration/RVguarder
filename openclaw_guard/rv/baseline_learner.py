"""
baseline_learner.py —— 阶段 C 基线自动机学习器。

从正常会话 trace 的抽象符号序列离线学习紧凑 DFA：
1. 前缀树构建：将各 trace 的符号序列合并到一棵 Trie 中
2. 频率驱动状态合并：共享相同出边模式的叶子节点合并，降低规模
3. 序列化/加载：支持 JSON 序列化与从文件加载

设计原则：
- 所有叶子节点为接受状态（代表正常行为路径终点）
- 合并后 DFA 规模显著小于原始 trace 规模
- 纯 Python 实现，零外部依赖
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class BaselineDFA:
    """基线确定性有限自动机。

    Attributes:
        states: 状态 ID 集合
        transitions: 转移表 {(state, symbol) -> next_state}
        start_state: 起始状态 ID
        accepting_states: 接受状态集合（正常行为终点）
        symbol_set: 所有出现过的符号集合
    """

    def __init__(self) -> None:
        self.states: set[int] = {0}
        self.transitions: dict[tuple[int, str], int] = {}
        self.start_state: int = 0
        self.accepting_states: set[int] = set()
        self.symbol_set: set[str] = set()
        self.state_count: int = 1  # 下一个可用状态 ID

    def add_transition(self, src: int, symbol: str, dst: int) -> None:
        self.transitions[(src, symbol)] = dst
        self.symbol_set.add(symbol)
        self.states.add(src)
        self.states.add(dst)

    def next_state(self, current: int, symbol: str) -> int | None:
        """给定当前状态和符号，返回下一状态；无转移返回 None。"""
        return self.transitions.get((current, symbol))

    def is_accepting(self, state: int) -> bool:
        return state in self.accepting_states

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典。"""
        trans_dict: dict[str, dict[str, int]] = {}
        for (src, sym), dst in self.transitions.items():
            trans_dict.setdefault(str(src), {})[sym] = dst
        return {
            "states": sorted(self.states),
            "transitions": trans_dict,
            "start_state": self.start_state,
            "accepting_states": sorted(self.accepting_states),
            "symbol_set": sorted(self.symbol_set),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BaselineDFA:
        """从字典反序列化。"""
        dfa = cls()
        dfa.states = set(data.get("states", []))
        dfa.start_state = data.get("start_state", 0)
        dfa.accepting_states = set(data.get("accepting_states", []))
        dfa.symbol_set = set(data.get("symbol_set", []))
        dfa.state_count = max(dfa.states) + 1 if dfa.states else 1
        trans_dict = data.get("transitions", {})
        for src_str, targets in trans_dict.items():
            src = int(src_str)
            for sym, dst in targets.items():
                dfa.transitions[(src, sym)] = dst
        return dfa

    def save(self, path: str | Path) -> None:
        """保存到 JSON 文件。"""
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> BaselineDFA:
        """从 JSON 文件加载。"""
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def stats(self) -> dict[str, int]:
        """返回 DFA 统计信息。"""
        return {
            "state_count": len(self.states),
            "transition_count": len(self.transitions),
            "accepting_count": len(self.accepting_states),
        }


class BaselineLearner:
    """基线 DFA 学习器。

    从正常会话 trace 序列中学习行为基线自动机。

    算法：
    1. 前缀树 (Trie) 构建：每个 trace 的符号序列插入 Trie
    2. 频率驱动合并：出边模式相同的叶子节点合并
    3. 所有 Trie 节点标记为接受状态
    """

    def __init__(self) -> None:
        self._trie_root: dict[int, dict[str, int]] = {0: {}}  # state -> {symbol -> next_state}
        self._next_id: int = 1
        self._leaf_states: set[int] = set()

    def add_trace(self, symbols: list[str]) -> None:
        """将一条符号序列插入前缀树。"""
        if not symbols:
            return
        current = 0
        for sym in symbols:
            children = self._trie_root.setdefault(current, {})
            if sym not in children:
                children[sym] = self._next_id
                self._next_id += 1
            current = children[sym]
        # 确保叶子节点也被记录（以便 trie_size 统计和合并）
        self._trie_root.setdefault(current, {})
        self._leaf_states.add(current)

    def learn(self) -> BaselineDFA:
        """学习并返回紧凑 DFA。

        步骤：
        1. 频率驱动状态合并（出边模式相同 → 合并）
        2. 构建紧凑 DFA
        """
        # 状态合并：收集每个状态的出边模式
        merged = self._merge_states()

        # 构建 DFA
        dfa = BaselineDFA()
        dfa.state_count = max(merged.keys()) + 1 if merged else 1

        seen_states: set[int] = set()
        for src, children in merged.items():
            seen_states.add(src)
            for sym, dst in children.items():
                dfa.add_transition(src, sym, dst)
                seen_states.add(dst)

        # 所有可达状态为接受状态（前缀树中任意路径均代表正常行为前缀）
        dfa.accepting_states = seen_states
        dfa.states = seen_states

        return dfa

    def _merge_states(self) -> dict[int, dict[str, int]]:
        """状态合并：叶子节点合并 + 同构节点迭代合并。

        算法：
        1. 所有叶子节点（无出边）合并为一个状态（取最小 ID）
        2. 迭代合并：出边映射相同的节点合并，直到收敛
        """
        if not self._trie_root:
            return {}

        # 初始化映射：每个状态先映射到自己
        state_map: dict[int, int] = {s: s for s in self._trie_root}
        # 收集所有叶子节点
        all_states = set(self._trie_root.keys())
        non_leaf = {s for s, children in self._trie_root.items() if children}
        leaves = all_states - non_leaf

        # 叶子节点合并为一（取最小 ID）
        if leaves:
            leaf_repr = min(leaves)
            for leaf in leaves:
                state_map[leaf] = leaf_repr

        # 迭代合并同构内部节点
        changed = True
        while changed:
            changed = False
            # 计算每个 canonical 状态的出边签名（symbol → canonical_target）
            sig_to_canonical: dict[frozenset, int] = {}
            new_state_map: dict[int, int] = {}

            for src in sorted(self._trie_root):
                canonical = state_map.get(src, src)
                children = self._trie_root.get(src, {})
                if not children:
                    new_state_map[src] = canonical
                    continue

                # 构建归一化出边签名
                sig_items = []
                for sym, child in children.items():
                    canonical_child = state_map.get(child, child)
                    sig_items.append((sym, canonical_child))
                sig = frozenset(sig_items)

                if sig not in sig_to_canonical:
                    sig_to_canonical[sig] = canonical
                new_state_map[src] = sig_to_canonical[sig]

            # 检查是否有变化
            for src in new_state_map:
                if new_state_map.get(src) != state_map.get(src):
                    changed = True
                    break
            state_map = new_state_map

        # 根据映射重写 transfer 表
        merged: dict[int, dict[str, int]] = {}
        for src, children in self._trie_root.items():
            canonical_src = state_map.get(src, src)
            mapped_children: dict[str, int] = {}
            for sym, child in children.items():
                mapped_children[sym] = state_map.get(child, child)
            if canonical_src not in merged:
                merged[canonical_src] = {}
            merged[canonical_src].update(mapped_children)

        return merged

    def trie_size(self) -> int:
        """返回前缀树节点数。"""
        return len(self._trie_root)


def learn_from_traces(traces: list[list[str]]) -> BaselineDFA:
    """便捷函数：从符号序列列表学习 DFA。"""
    learner = BaselineLearner()
    for trace in traces:
        learner.add_trace(trace)
    return learner.learn()
