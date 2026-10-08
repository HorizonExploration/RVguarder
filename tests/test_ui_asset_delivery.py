"""核验干净wheel资源路径与秘密文件排除，覆盖安装后404缺陷。"""
from pathlib import Path

import pytest

from openclaw_guard import ui
from openclaw_guard.ui_assets import stage_ui_assets


def frontend(source: Path) -> None:
    """最小可交付前端引用真实bundle文件。"""
    (source / "assets").mkdir(parents=True)
    (source / "index.html").write_text('<script src="/assets/index-test.js"></script>')
    (source / "assets/index-test.js").write_text("console.log('public bundle')")


def test_clean_installed_package_can_serve_its_bundled_assets(tmp_path, monkeypatch):
    package = tmp_path / "site-packages/openclaw_guard"
    frontend(package / "static_ui")
    monkeypatch.setattr(ui, "__file__", str(package / "ui.py"))
    target = tmp_path / "workspace/ui"
    ui.build_ui(target)
    assert (target / "index.html").is_file()
    assert "public bundle" in (target / "assets/index-test.js").read_text()


def test_staging_excludes_runtime_secrets_and_databases(tmp_path):
    source = tmp_path / "built"
    frontend(source)
    (source / ".env").write_text("secret")
    (source / "audit.sqlite3").write_bytes(b"private state")
    names = stage_ui_assets(source, tmp_path / "wheel/static_ui")
    assert names == ["assets/index-test.js", "index.html"]
    assert not (tmp_path / "wheel/static_ui/.env").exists()


def test_missing_frontend_build_refuses_incomplete_wheel(tmp_path):
    with pytest.raises(FileNotFoundError, match="Frontend build missing"):
        stage_ui_assets(tmp_path / "missing", tmp_path / "wheel")


def test_dangling_bundle_reference_refuses_incomplete_wheel(tmp_path):
    source = tmp_path / "built"
    frontend(source)
    (source / "assets/index-test.js").unlink()
    with pytest.raises(ValueError, match="missing or unsupported"):
        stage_ui_assets(source, tmp_path / "wheel")


def test_symlink_cannot_smuggle_host_file_into_wheel(tmp_path):
    source = tmp_path / "built"
    frontend(source)
    (source / "assets/hidden.js").symlink_to(tmp_path / "private-file")
    with pytest.raises(ValueError, match="symlinks"):
        stage_ui_assets(source, tmp_path / "wheel")
