"""仅在实验拥有的隔离 profile 中通过 SDK 安装候选归档并核验实际源码。"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
from unittest.mock import patch

from openclaw_guard.integrations.hook_runtime import HOOK_PLUGIN_ID
from openclaw_guard.services import GuardServices
from testlab.office_chain import authorized_driver as driver


@contextmanager
def installed_archive(archive: Path):
    """恢复所有补丁；不输出私有凭据，不修改日常配置或产品安装代码。"""
    with tarfile.open(archive) as package:
        members = [m for m in package.getmembers() if m.name in ('package/index.js', 'index.js')]
        if len(members) != 1:
            raise ValueError('archive must contain one plugin index.js')
        expected = package.extractfile(members[0]).read()
    toolchain = driver.resolve_toolchain()
    env = driver._child_env(toolchain)
    original_install, original_cleanup = GuardServices.install_hook, driver._Gateway.cleanup
    evidence = {'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
                'installation': [], 'uninstallation': [], 'verified': False}

    def install(manager):
        original_install(manager)
        config_path = Path(manager.context.target.config_path)
        profile_dir = config_path.parent
        if not profile_dir.name.startswith('.openclaw-office-chain-'):
            raise ValueError('only owned isolated profiles may be changed')
        profile = profile_dir.name.removeprefix('.openclaw-')
        config = json.loads(config_path.read_text())
        entry = config['plugins']['entries'].pop(HOOK_PLUGIN_ID)
        generated = manager.runtime_hook['plugin_dir']
        paths = config['plugins'].get('load', {}).get('paths', [])
        config['plugins'].setdefault('load', {})['paths'] = [p for p in paths if p != generated]
        config_path.write_text(json.dumps(config))
        result = subprocess.run([toolchain['openclaw'], '--profile', profile, 'plugins', 'install',
            str(archive), '--force', '--accept-capabilities'], env=env, capture_output=True, timeout=120)
        item = {'profile': profile, 'returncode': result.returncode}
        evidence['installation'].append(item)
        if result.returncode:
            raise RuntimeError('SDK archive install failed; code ' + str(result.returncode))
        config = json.loads(config_path.read_text())
        installed = config['plugins']['installs'][HOOK_PLUGIN_ID]
        actual = (Path(installed['installPath']) / 'index.js').read_bytes()
        item.update(installed_source_sha256=hashlib.sha256(actual).hexdigest(),
                    source_matches_archive=actual == expected,
                    generated_source_load_removed=generated not in config['plugins'].get('load', {}).get('paths', []))
        if actual != expected:
            raise RuntimeError('SDK installed source differs from candidate archive')
        config['plugins']['entries'][HOOK_PLUGIN_ID] = entry
        config_path.write_text(json.dumps(config))
        return {'status': 'ok'}

    def cleanup(gateway):
        gateway.stop()
        try:
            if any(i['profile'] == gateway.profile and i['returncode'] == 0 for i in evidence['installation']):
                result = subprocess.run([toolchain['openclaw'], '--profile', gateway.profile, 'plugins',
                    'uninstall', HOOK_PLUGIN_ID, '--force'], env=env, capture_output=True, timeout=120)
                config = json.loads(gateway.config_path.read_text())
                evidence['uninstallation'].append({'returncode': result.returncode,
                    'inactive': HOOK_PLUGIN_ID not in config.get('plugins', {}).get('entries', {}) or
                        config['plugins']['entries'][HOOK_PLUGIN_ID].get('enabled') is False,
                    'install_removed': HOOK_PLUGIN_ID not in config.get('plugins', {}).get('installs', {})})
        finally:
            original_cleanup(gateway)

    with patch.object(GuardServices, 'install_hook', install), patch.object(driver._Gateway, 'cleanup', cleanup):
        yield evidence
    evidence['verified'] = (bool(evidence['installation']) and
        len(evidence['installation']) == len(evidence['uninstallation']) and
        all(i.get('source_matches_archive') and i.get('generated_source_load_removed') for i in evidence['installation']) and
        all(i['returncode'] == 0 and i['inactive'] and i['install_removed'] for i in evidence['uninstallation']))
