"""隔离测量真实服务Hook同步写入；只作工程性能诊断，不计安全分母。"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import tempfile
import time
from unittest.mock import patch

from openclaw_guard.engine.experiment_components import ExperimentComponents, using
from openclaw_guard.services import build_services


def main() -> None:
    """保留逐调用计时与写入次数，不覆盖结果，不触及Gateway。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--calls', type=int, default=30)
    args = parser.parse_args()
    if not 5 <= args.calls <= 100:
        parser.error('calls must be between 5 and 100')
    rows = []
    with tempfile.TemporaryDirectory(prefix='rv-persistence-profile-') as directory, using(ExperimentComponents(semantic_llm=False)):
        project = Path(directory)
        config = project / 'openclaw.json'
        config.write_text('{}')
        services = build_services(project, config_path=config)
        try:
            for index in range(args.calls):
                with patch.object(services.action_service, '_save_all', wraps=services.action_service._save_all) as saver:
                    started = time.perf_counter()
                    result = services.handle_before_tool_call({'toolName': 'read',
                        'params': {'path': str(project / 'notes.txt')}, 'sessionId': f'profile-{index}',
                        'runId': 'performance-only', 'toolCallId': f'call-{index}'})
                    rows.append({'index': index, 'elapsed_ms': (time.perf_counter() - started) * 1000,
                                 'action': result['action'], 'synchronous_action_writes': saver.call_count})
        finally:
            services.audit_store.close()
    samples = sorted(row['elapsed_ms'] for row in rows[5:]) or sorted(row['elapsed_ms'] for row in rows)
    source = Path('openclaw_guard/engine/pipeline.py')
    report = {'scope': 'Local service boundary only; local semantics, synthetic workspaces; not SDK/Q5 evidence',
              'pipeline_sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'rows': rows,
              'warmup_excluded': min(5, len(rows)), 'p95_ms': samples[math.ceil(.95 * len(samples)) - 1],
              'total_action_writes': sum(row['synchronous_action_writes'] for row in rows)}
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({key: report[key] for key in ('p95_ms', 'total_action_writes')}))


if __name__ == '__main__':
    main()
