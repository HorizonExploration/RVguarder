"""FastAPI 层 —— 替代旧 web.py 和 api/ 的 HTTP 传输层。

兼容旧导入路径：
  from openclaw_guard.web import launch_web   # 旧 main.py 导入
  from openclaw_guard.web import _error_message  # test_web_cli.py 导入
"""

from openclaw_guard.web.app import UvicornServerHandle, create_app, launch_web
from openclaw_guard.web.errors import GuardError, _error_message

__all__ = [
    "create_app",
    "launch_web",
    "UvicornServerHandle",
    "GuardError",
    "_error_message",
]
