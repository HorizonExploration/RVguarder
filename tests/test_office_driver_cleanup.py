"""隔离profile清理归属回归；不运行Docker或实验。"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from testlab.office_chain.office_driver import _cleanup_sandboxes


def test_cleanup_uses_exact_profile_mount_and_preserves_existing_containers():
    """当前SDK名称不含profile；只能删除新建且精确关联profile的容器。"""
    root = str(Path.home() / ".openclaw-office-chain-test")
    sources = {"owned": root + "/sandbox/skills", "neighbor": root + "-other/sandbox",
               "daily": str(Path.home() / ".openclaw/workspace"), "existing": root + "/sandbox"}
    removed = []

    def run(command, **kwargs):
        if command[1] == "ps":
            return SimpleNamespace(returncode=0, stdout="\n".join(sources))
        if command[1] == "inspect":
            return SimpleNamespace(returncode=0, stdout=json.dumps([{"Source": sources[command[-1]]}]))
        removed.append(command[-1])
        return SimpleNamespace(returncode=0, stdout="")

    with patch("testlab.office_chain.office_driver._run", side_effect=run):
        assert _cleanup_sandboxes({"existing"}, profile="office-chain-test", toolchain={"docker": "docker"}) == ["owned"]
    assert removed == ["owned"]


def test_cleanup_without_profile_does_not_query_or_remove_containers():
    """缺失归属信息时不做全局清理。"""
    with patch("testlab.office_chain.office_driver._run") as run:
        assert _cleanup_sandboxes(set(), profile="", toolchain={"docker": "docker"}) == []
        run.assert_not_called()
