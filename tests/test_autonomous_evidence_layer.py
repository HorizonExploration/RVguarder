"""自主层记录不能污染固定轨迹或下一臂的模型调用采集器。"""
import io
import json
from unittest.mock import patch

import pytest

from scripts.run_native_autonomous import AutonomousProvider
from testlab.office_chain.authorized_driver import run_authorized_scenario


def test_late_model_response_stays_in_original_collector():
    """更换臂级采集器后，旧实例返回的结果仍归属旧实例。"""
    first = []
    AutonomousProvider.observations = first
    provider = AutonomousProvider({'scenario_id': 'first'})
    second = []
    AutonomousProvider.observations = second
    response = {'model': 'reported-alias', 'usage': {'total_tokens': 4}, 'choices': []}
    with patch.dict('os.environ', {'DEEPSEEK_API_KEY': 'synthetic-test-key'}), patch(
        'scripts.run_native_autonomous.urllib.request.urlopen', return_value=io.BytesIO(json.dumps(response).encode())
    ):
        provider.chat_completion({'messages': []})
    assert first[0]['scenario_id'] == 'first'
    assert first[0]['reported_model'] == 'reported-alias'
    assert second == []


def test_invalid_evidence_layer_rejected_before_runtime(tmp_path):
    """不接受任意层名，避免含糊的证据标签。"""
    with pytest.raises(ValueError, match='evidence layer'):
        run_authorized_scenario({}, output=tmp_path / 'raw.json', rules_path=tmp_path / 'rules.json',
            evidence_layer='ambiguous')
