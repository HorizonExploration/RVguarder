"""Deterministic classification for shell commands used by the daily-workflow gate.

The semantic model may add useful intent labels, but the decision boundary for
shell commands must not depend on an LLM.  This module deliberately returns a
small, auditable classification instead of attempting to be a shell sandbox.
Unknown syntax remains non-automatable and is handled by the policy layer.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
from typing import Any

from openclaw_guard.engine.python_effects import inline_python_effects


_SAFE_COMMANDS = {
    "pwd", "ls", "find", "grep", "rg", "cat", "head", "tail", "sed",
    "echo", "printf", "wc", "sort", "uniq", "cut", "file", "stat", "du",
    "tree", "cd",
}
_SAFE_GIT_SUBCOMMANDS = {"status", "log", "diff", "show", "branch", "rev-parse", "ls-files"}
_DESTRUCTIVE_COMMANDS = {
    "rm", "rmdir", "mv", "cp", "mkdir", "touch", "tee", "dd", "install",
    "truncate", "chmod", "chown", "chgrp", "ln", "kill", "systemctl",
    "npm", "pip", "python", "python3", "node", "perl", "ruby",
}
_NETWORK_COMMANDS = {"curl", "wget", "nc", "netcat", "ssh", "scp", "sftp", "rsync", "ftp"}
_PRIVILEGED_COMMANDS = {"sudo", "su", "doas", "pkexec"}
_OPERATORS = {";", "&&", "||", "|", ">", ">>", "<", "<<", "(", ")"}
_PATH_RE = re.compile(r"^(?:/|\./|\.\./|~[/\\]|[A-Za-z]:[/\\])")


@dataclass(frozen=True)
class CommandSafety:
    """Stable command classification consumed by semantic and policy layers."""

    classification: str
    safe_read_only: bool
    commands: tuple[str, ...] = ()
    path_hints: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    potential_effects: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "safe_read_only": self.safe_read_only,
            "commands": list(self.commands),
            "path_hints": list(self.path_hints),
            "reason_codes": list(self.reason_codes),
            "potential_effects": list(self.potential_effects),
        }


def analyze_command(command: str | None) -> CommandSafety:
    """有界分析整条有限exec调用；能力提示不是子调用或实际副作用收据。"""
    raw = str(command or "").strip()
    if len(raw) > 32768:
        return CommandSafety("unknown", False, reason_codes=("command_budget",), potential_effects=("unknown",))
    first = _analyze_command_prefix(raw)
    if not raw or any(char in raw for char in ("\n", "\r", "$", "`")):
        return first
    try:
        lexer = shlex.shlex(raw, posix=True, punctuation_chars=";&|><()")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return first
    if len(tokens) > 512:
        return CommandSafety("unknown", False, reason_codes=("command_budget",), potential_effects=("unknown",))
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token in {";", "&&", "||", "|"}:
            segments.append([])
        else:
            segments[-1].append(token)
    if len(segments) > 32 or any(not segment for segment in segments):
        return CommandSafety("unknown", False, reason_codes=("command_budget_or_empty_segment",), potential_effects=("unknown",))
    commands, reasons, capabilities, classifications, inline_paths = [], [], [], [], []
    for segment in segments:
        result = _analyze_command_prefix(shlex.join(segment))
        name = _command_name(segment)
        if name:
            commands.append(name)
        reasons.extend(result.reason_codes)
        classifications.append(result.classification)
        if re.fullmatch(r"python(?:3(?:\.\d+)?)?", name or ""):
            python_effects, python_paths, python_reasons = inline_python_effects(segment)
            capabilities.extend(python_effects)
            inline_paths.extend(python_paths)
            reasons.extend(python_reasons)
        elif name in _NETWORK_COMMANDS:
            capabilities.append("egress")
        elif name in {"rm", "rmdir"}:
            capabilities.append("delete")
        elif name in {"cp", "mv"}:
            capabilities.extend(["read", "write", "transform"])
            if name == "mv":
                capabilities.append("delete")
        elif name in {"tar", "zip", "gzip", "bzip2", "xz"}:
            capabilities.extend(["read", "write", "transform", "unknown"])
        elif result.safe_read_only:
            capabilities.append("read")
        else:
            capabilities.append("unknown")
        if any(token.startswith((">", "<")) for token in segment):
            capabilities.append("write")
    # 网络能力必须保留；delete还通过完整commands单独投影，不能被首段遮蔽。
    rank = {"unknown": 0, "read_only": 0, "mutating": 1, "destructive": 2, "network": 3, "privileged": 4}
    classification = max([first.classification, *classifications], key=lambda value: rank[value])
    safe = first.safe_read_only and all(value == "read_only" for value in classifications)
    if not safe and classification == "read_only":
        classification = "unknown"
    return CommandSafety(classification, safe, tuple(commands), tuple(dict.fromkeys([*_path_hints(tokens), *inline_paths]))[:16],
                         tuple(dict.fromkeys(reasons)), tuple(dict.fromkeys(capabilities)))


def _analyze_command_prefix(command: str | None) -> CommandSafety:
    """Classify a command without executing it.

    Pipes are accepted only when every segment is a known read-only command.
    Redirections, substitutions, privileged/network commands, mutating git
    subcommands and ``find`` execution predicates are never read-only.
    """

    raw = str(command or "").strip()
    if not raw:
        return CommandSafety("unknown", False, reason_codes=("empty_command",))
    if "\n" in raw or "\r" in raw:
        return CommandSafety("unknown", False, reason_codes=("multiline_shell",))
    if "$" in raw or "`" in raw:
        return CommandSafety("unknown", False, reason_codes=("command_substitution",))
    try:
        lexer = shlex.shlex(raw, posix=True, punctuation_chars=";&|><()")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return CommandSafety("unknown", False, reason_codes=("shell_parse_error",))
    if not tokens:
        return CommandSafety("unknown", False, reason_codes=("empty_command",))

    operators = [token for token in tokens if token in _OPERATORS or token.startswith((">", "<"))]
    if any(token.startswith((">", "<")) for token in operators):
        return CommandSafety("mutating", False, path_hints=_path_hints(tokens), reason_codes=("redirection",))
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token in _OPERATORS:
            if token == "|":
                segments.append([])
                continue
            if token in {";", "&&", "||"}:
                segments.append([])
                continue
            return CommandSafety("unknown", False, path_hints=_path_hints(tokens), reason_codes=("shell_operator",))
        if token and all(char in ";&|><()" for char in token):
            return CommandSafety("unknown", False, reason_codes=("unsupported_shell_operator",))
        segments[-1].append(token)
    if any(not segment for segment in segments):
        return CommandSafety("unknown", False, path_hints=_path_hints(tokens), reason_codes=("empty_segment",))

    commands: list[str] = []
    reasons: list[str] = []
    for segment in segments:
        command_name = _command_name(segment)
        if not command_name:
            return CommandSafety("unknown", False, path_hints=_path_hints(tokens), reason_codes=("missing_command",))
        commands.append(command_name)
        effect_gap = _unverified_effect(segment, command_name)
        if effect_gap:
            return CommandSafety("unknown", False, tuple(commands), _path_hints(tokens), (effect_gap,))
        if command_name in _PRIVILEGED_COMMANDS:
            reasons.append("privileged_command")
            return CommandSafety("privileged", False, tuple(commands), _path_hints(tokens), tuple(dict.fromkeys(reasons)))
        if command_name in _NETWORK_COMMANDS:
            reasons.append("network_command")
            return CommandSafety("network", False, tuple(commands), _path_hints(tokens), tuple(dict.fromkeys(reasons)))
        if command_name in _DESTRUCTIVE_COMMANDS:
            reasons.append("mutating_command")
            if command_name == "rm" and any(arg in {"-rf", "-fr", "--recursive", "--force"} for arg in segment[1:]):
                reasons.append("recursive_delete")
                return CommandSafety("destructive", False, tuple(commands), _path_hints(tokens), tuple(dict.fromkeys(reasons)))
            return CommandSafety("mutating", False, tuple(commands), _path_hints(tokens), tuple(dict.fromkeys(reasons)))
        if command_name == "git":
            git_args = [item for item in segment[1:] if not item.startswith("-")]
            if not git_args or git_args[0] not in _SAFE_GIT_SUBCOMMANDS:
                return CommandSafety("mutating", False, tuple(commands), _path_hints(tokens), ("git_mutation_or_unknown",))
        elif command_name == "find":
            if any(item in {"-exec", "-execdir", "-delete", "-ok"} for item in segment[1:]):
                return CommandSafety("mutating", False, tuple(commands), _path_hints(tokens), ("find_execution_predicate",))
        elif command_name == "sed" and any(item == "-i" or item.startswith("-i") for item in segment[1:]):
            return CommandSafety("mutating", False, tuple(commands), _path_hints(tokens), ("sed_in_place",))
        elif command_name not in _SAFE_COMMANDS:
            return CommandSafety("unknown", False, tuple(commands), _path_hints(tokens), ("unknown_command",))

    return CommandSafety(
        "read_only",
        True,
        tuple(commands),
        _path_hints(tokens),
        ("known_read_only_commands",),
    )


def _command_name(segment: list[str]) -> str:
    # 不跳过环境赋值，不把工作区中的同名程序当作系统只读工具。
    token = segment[0] if segment else ""
    if not token or "=" in token or token.startswith("-"):
        return ""
    if "/" in token and token.rsplit("/", 1)[0] not in {"/bin", "/usr/bin"}:
        return ""
    return token.rsplit("/", 1)[-1]


def _unverified_effect(segment: list[str], command_name: str) -> str | None:
    """识别工具内部的写入或子进程能力，未知脚本交给原生审批。"""
    args = segment[1:]
    if command_name == "sed":
        # sed 是脚本解释器；只自动放行可完整验证的行号打印表达式。
        remaining = [arg for arg in args if arg not in {"-n", "--quiet", "--silent"}]
        if not remaining or not re.fullmatch(r"(?:[0-9]+|\$)(?:,(?:[0-9]+|\$))?p", remaining[0]):
            return "unverified_sed_program"
        if any(arg.startswith("-") for arg in remaining[1:]):
            return "unverified_sed_options"
    if command_name == "find" and any(arg in {
        "-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls",
    } for arg in args):
        return "find_side_effect"
    if command_name == "rg" and any(arg.split("=", 1)[0] in {
        "--pre", "--hostname-bin",
    } for arg in args):
        return "search_external_program"
    if command_name in {"sort", "tree"} and any(
        arg.startswith("-o") or arg.split("=", 1)[0] in {
            "--output", "--compress-program", "--exec",
        } for arg in args
    ):
        return "output_or_external_program"
    if command_name == "uniq":
        # uniq 的第二个位置参数是输出文件；不解析不熟悉的选项参数。
        if any(arg.startswith("-") and arg not in {"-c", "-d", "-u", "-i"} for arg in args) or len([
            arg for arg in args if not arg.startswith("-")
        ]) > 1:
            return "uniq_output_or_unknown_options"
    if command_name == "file" and any(arg == "--compile" or (
        arg.startswith("-") and not arg.startswith("--") and "C" in arg
    ) for arg in args):
        return "magic_database_write"
    if command_name == "git":
        # 全局选项可能设置 pager、外部 diff 或仓库配置，不能跳过后猜测子命令。
        if not args or args[0] not in _SAFE_GIT_SUBCOMMANDS:
            return "unverified_git_invocation"
        if any(arg.split("=", 1)[0] in {
            "--ext-diff", "--textconv", "--output", "--open-files-in-pager",
        } or arg.startswith("-O") for arg in args[1:]):
            return "git_external_program_or_output"
        if args[0] == "branch" and args[1:] not in ([], ["--list"], ["-l"], ["--show-current"]):
            return "git_branch_mutation_or_unknown"
    return None


def _path_hints(tokens: list[str]) -> tuple[str, ...]:
    hints: list[str] = []
    for token in tokens:
        candidate = token.strip("\"'")
        if not candidate or candidate in _OPERATORS or candidate.startswith("-"):
            continue
        if _PATH_RE.match(candidate) or "/" in candidate or "\\" in candidate:
            if candidate not in hints:
                hints.append(candidate)
    return tuple(hints[:16])
