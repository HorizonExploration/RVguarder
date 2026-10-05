"""测试进程的环境隔离护栏。

``openclaw_guard.main.main()`` 会执行 ``load_dotenv(override=False)``，把仓库
``.env``（含真实 API 密钥）写入 ``os.environ``。任何在测试中真实调用该入口的
用例都会污染同进程的后续测试，并可能触发真实网络请求。这里在每个测试结束后
还原环境变量，保证测试保持封闭、可重复。
"""
from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _restore_process_environment():
    snapshot = dict(os.environ)
    try:
        yield
    finally:
        for key in list(os.environ):
            if key not in snapshot:
                del os.environ[key]
        for key, value in snapshot.items():
            if os.environ.get(key) != value:
                os.environ[key] = value
