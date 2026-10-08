"""实际解释器资源属性必须来自工具路径，不依赖模型识别攻击链。"""
from __future__ import annotations

import pytest

from openclaw_guard.engine.semantic_enhancer import SemanticEnhancer
from testlab.office_chain.semantic_recording import project_event


@pytest.mark.parametrize('suffix',['.py','.js','.mjs','.cjs','.rb','.pl','.lua','.sh'])
def test_native_write_projects_interpreter_script_resource(suffix):
    """一次真实write仍只有一个事件，脚本后缀属于确定性资源属性。"""
    behavior,*_=project_event({'hook_payload':{'toolName':'write','params':{'path':'scripts/helper'+suffix,'content':'fixture'}}})
    result=SemanticEnhancer(api_key='').evaluate(behavior)
    assert 'path_script' in result['semantic']['labels']
    assert 'file_read' not in result['semantic']['labels']
