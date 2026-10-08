"""相对cwd以受控工作区解析，不能依赖Guard进程宿主cwd或越界放行。"""
from openclaw_guard.engine.pipeline import _classify_scope


def test_relative_cwd_uses_trusted_workspace_not_host_process(tmp_path, monkeypatch):
    workspace, host = tmp_path / 'workspace', tmp_path / 'host'
    workspace.mkdir()
    host.mkdir()
    monkeypatch.chdir(host)
    assert _classify_scope(['notes/public.txt'], roots=[('workspace', workspace)], working_directory='.') == 'workspace'


def test_relative_cwd_traversal_stays_outside(tmp_path):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    assert _classify_scope(['private.txt'], roots=[('workspace', workspace)], working_directory='..') == 'outside'


def test_absolute_outside_cwd_stays_outside(tmp_path):
    workspace, outside = tmp_path / 'workspace', tmp_path / 'outside'
    workspace.mkdir()
    outside.mkdir()
    assert _classify_scope(['private.txt'], roots=[('workspace', workspace)], working_directory=str(outside)) == 'outside'


def test_absolute_workspace_cwd_remains_inside(tmp_path):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    assert _classify_scope(['public.txt'], roots=[('workspace', workspace)], working_directory=str(workspace)) == 'workspace'


def test_relative_cwd_symlink_escape_stays_outside(tmp_path):
    workspace, outside = tmp_path / 'workspace', tmp_path / 'outside'
    workspace.mkdir()
    outside.mkdir()
    (workspace / 'linked').symlink_to(outside, target_is_directory=True)
    assert _classify_scope(['private.txt'], roots=[('workspace', workspace)], working_directory='linked') == 'outside'
