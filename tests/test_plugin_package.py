"""验证插件候选包可重复、无内嵌凭据且不接触日常Gateway。"""
from __future__ import annotations

import json
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from openclaw_guard.integrations.plugin_package import build_plugin_package
from openclaw_guard.main import main


def test_candidate_archive_is_reproducible_and_has_no_embedded_token(tmp_path: Path):
    """相同源码的归档字节一致，仅包含明确登记的插件文件。"""
    first = build_plugin_package(tmp_path/'one')
    second = build_plugin_package(tmp_path/'two')
    assert first['sha256'] == second['sha256']
    assert first['release_qualified'] is False
    with tarfile.open(first['archive']) as archive:
        names = archive.getnames()
        assert len(names) == 6
        assert all(name.startswith('package/') for name in names)
        source = archive.extractfile('package/index.js').read().decode()
        assert 'const DEFAULT_AUTH_TOKEN = ""' in source
        config = json.load(archive.extractfile('package/guard.config.example.json'))
        assert config['startupHealthCheck'] is True
        assert config['authToken'] == 'SET_LOCALLY_FROM_BACKEND'
        contract = json.load(archive.extractfile('package/release-contract.json'))
        assert contract['release_qualified'] is False


def test_package_refuses_to_overwrite_existing_directory(tmp_path: Path):
    """构建不能覆盖用户已有输出。"""
    target=tmp_path/'existing';target.mkdir();(target/'keep.txt').write_text('keep')
    with pytest.raises(FileExistsError):build_plugin_package(target)
    assert (target/'keep.txt').read_text()=='keep'


def test_cli_package_does_not_initialize_manager(tmp_path: Path, capsys):
    """构建命令不创建运行状态或访问OpenClaw安装。"""
    # ``main`` 会调用 ``load_dotenv``；在测试进程里放行它会把仓库 .env 的
    # 真实密钥永久注入 os.environ，污染后续测试并触发真实网络调用。
    with patch('openclaw_guard.main.load_dotenv'), patch(
        'openclaw_guard.main.build_manager', side_effect=AssertionError('manager should not start')
    ):
        assert main(['build-plugin','--output',str(tmp_path/'package')])==0
    assert json.loads(capsys.readouterr().out)['status']=='test-candidate'
