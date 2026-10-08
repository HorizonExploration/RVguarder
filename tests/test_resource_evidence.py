"""可信宿主资源描述的命名空间、内容版本与逃逸回归。"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from openclaw_guard.spec.resource_evidence import HostResourceObserver, ResourceEvidenceError


def test_same_filename_changed_content_has_different_version(tmp_path):
    """文件名不证明内容相同，版本绑定真实读取的字节。"""
    file = tmp_path / "public.txt"
    file.write_bytes(b"public summary")
    observer = HostResourceObserver({"workspace": tmp_path})
    first = observer.observe("workspace", "./public.txt")
    file.write_bytes(b"private credentials")
    second = observer.observe("workspace", "public.txt")
    assert first.resource_id == second.resource_id
    assert first.content_version != second.content_version
    assert second.content_version == "sha256:" + hashlib.sha256(b"private credentials").hexdigest()
    assert second.classification == "unknown"


@pytest.mark.parametrize("path", ["../outside", "/etc/passwd", "sub/../../outside", "a\\outside", ""])
def test_paths_cannot_escape_host_namespace(tmp_path, path):
    """拒绝绝对路径和目录逃逸，而非将其重写成工作区路径。"""
    with pytest.raises(ResourceEvidenceError):
        HostResourceObserver({"w": tmp_path}).observe("w", path)


@pytest.mark.parametrize("intermediate", [False, True])
def test_symlinks_are_not_followed(tmp_path, intermediate):
    """中间目录和末端文件链接均不得读取命名空间外的资源。"""
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "data").write_text("secret")
    (root / "link").symlink_to(outside if intermediate else outside / "data")
    with pytest.raises(ResourceEvidenceError):
        HostResourceObserver({"w": root}).observe("w", "link/data" if intermediate else "link")


def test_namespace_identity_and_scope_are_not_reused(tmp_path):
    """不同命名空间不混同；注册后被替换的目录不能继承原身份。"""
    root = tmp_path / "root"
    root.mkdir()
    (root / "data").write_bytes(b"same")
    observer = HostResourceObserver({"a": root, "b": root})
    assert observer.observe("a", "data").resource_id != observer.observe("b", "data").resource_id
    root.rename(tmp_path / "old")
    root.mkdir()
    (root / "data").write_bytes(b"same")
    with pytest.raises(ResourceEvidenceError, match="directory changed"):
        observer.observe("a", "data")


def test_public_filename_and_unknown_namespace_do_not_prove_classification(tmp_path):
    """公开分类需宿主证据，文件名和不存在的映射不能产生证据。"""
    (tmp_path / "public.txt").write_text("secret")
    observer = HostResourceObserver({"w": tmp_path})
    assert observer.observe("w", "public.txt").classification == "unknown"
    with pytest.raises(ResourceEvidenceError):
        observer.observe("w", "public.txt", classification="public")
    with pytest.raises(ResourceEvidenceError):
        observer.observe("unknown", "public.txt")


def test_resource_must_be_regular_and_bounded(tmp_path):
    """目录和超限文件不会被误当作有效内容快照。"""
    (tmp_path / "large").write_bytes(b"12345")
    (tmp_path / "folder").mkdir()
    observer = HostResourceObserver({"w": tmp_path}, max_bytes=4)
    for path in ("large", "folder"):
        with pytest.raises(ResourceEvidenceError):
            observer.observe("w", path)
