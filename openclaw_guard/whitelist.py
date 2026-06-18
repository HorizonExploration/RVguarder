from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from openclaw_guard.models import BehaviorEvent


class PrefixTrieNode:
    __slots__ = ("children", "terminal", "label")

    def __init__(self) -> None:
        self.children: dict[str, "PrefixTrieNode"] = {}
        self.terminal = False
        self.label: str | None = None


class PrefixTrie:
    def __init__(self) -> None:
        self.root = PrefixTrieNode()

    def add(self, prefix: str, label: str | None = None) -> None:
        node = self.root
        for char in prefix:
            node = node.children.setdefault(char, PrefixTrieNode())
        node.terminal = True
        node.label = label or prefix

    def match(self, value: str) -> str | None:
        node = self.root
        last_label: str | None = None
        for char in value:
            if char not in node.children:
                break
            node = node.children[char]
            if node.terminal:
                last_label = node.label
        return last_label


class RadixTree:
    def __init__(self) -> None:
        self.prefixes: dict[str, str] = {}

    def add(self, prefix: str, label: str | None = None) -> None:
        self.prefixes[prefix] = label or prefix

    def match(self, value: str) -> str | None:
        matched = None
        matched_len = -1
        for prefix, label in self.prefixes.items():
            if value.startswith(prefix) and len(prefix) > matched_len:
                matched = label
                matched_len = len(prefix)
        return matched


@dataclass
class WhitelistPolicy:
    file_paths: list[str] = field(default_factory=list)
    command_prefixes: list[str] = field(default_factory=list)
    network_prefixes: list[str] = field(default_factory=list)
    api_names: list[str] = field(default_factory=list)
    skills: list[str] = field(default_factory=list)


class WhitelistEngine:
    def __init__(self, policy: WhitelistPolicy) -> None:
        self.policy = policy
        self.file_trie = PrefixTrie()
        self.command_trie = PrefixTrie()
        self.network_radix = RadixTree()
        self.api_trie = PrefixTrie()
        self.skill_trie = PrefixTrie()
        for item in policy.file_paths:
            self.file_trie.add(item, f"file:{item}")
        for item in policy.command_prefixes:
            self.command_trie.add(item, f"command:{item}")
        for item in policy.network_prefixes:
            self.network_radix.add(item, f"network:{item}")
        for item in policy.api_names:
            self.api_trie.add(item, f"api:{item}")
        for item in policy.skills:
            self.skill_trie.add(item, f"skill:{item}")

    def evaluate(self, event: BehaviorEvent) -> list[str]:
        matches: list[str] = []
        for path in event.target_paths:
            if label := self.file_trie.match(path):
                matches.append(label)
        if event.command and (label := self.command_trie.match(event.command)):
            matches.append(label)
        for target in event.network_targets:
            if label := self.network_radix.match(target):
                matches.append(label)
        if event.api_name and (label := self.api_trie.match(event.api_name)):
            matches.append(label)
        if event.skill_name and (label := self.skill_trie.match(event.skill_name)):
            matches.append(label)
        return matches


def default_police_whitelist() -> WhitelistPolicy:
    return WhitelistPolicy(
        file_paths=["/tmp/openclaw-", "/var/log/openclaw", str(Path.home() / ".openclaw")],
        command_prefixes=["ls ", "pwd", "cat ", "grep ", "find "],
        network_prefixes=["http://127.0.0.1", "https://127.0.0.1", "ws://127.0.0.1", "wss://127.0.0.1"],
        api_names=["chat.history", "models.list", "node.list"],
        skills=["safe-read", "workspace-index"],
    )
