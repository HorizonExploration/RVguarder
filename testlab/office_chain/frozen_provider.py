"""本地 OpenAI 兼容的冻结轨迹 provider（office-attack-chain-v1）。

本模块只提供**模型响应**：按场景登记顺序回放预先登记的助手工具调用，并在观测到的
历史与登记前缀不一致时拒绝服务（trajectory drift）。

它 SHALL NOT 绕过 OpenClaw：工具可见性、``before_tool_call`` Hook 派发、原生审批、
沙箱执行与合成 receipts 全部仍由 OpenClaw 负责；本模块不执行任何工具、不派发 Hook、
不做审批，也不触碰沙箱。

仅使用标准库（``http.server`` / ``threading`` / ``json`` / ``hashlib``）。
"""

from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping


DEFAULT_MODEL_ID = "rvguard-office-chain-fixed-v1"

# 单个请求体上限，避免一次读取过大 body。
_MAX_BODY_BYTES = 4_000_000

# 办公工具参数的语义键映射：把场景 ``hook_payload.params`` 归一为真实工具调用参数。
# 未列出的键原样保留；仅对需要语义重命名的键做转换。
# 注意：``automations`` 已不再出现在场景中——它是 OpenClaw 的调度器工具
# （``action: add|list|get|remove|runs|status``），不能执行命令，原先"命令→action"的
# 映射会让调用直接失败并使整次运行不被准入；shell/删除步骤改用 ``exec`` 表达。
_PARAM_ALIASES: dict[str, dict[str, str]] = {
    "office_message_send": {"recipients": "recipient", "text": "body", "content": "body"},
    "office_document_share": {"recipients": "recipient"},
}


class FixedTrajectoryError(RuntimeError):
    """请求无法与冻结轨迹对齐（trajectory drift）或登记数据非法。"""


def _normalize_params(tool_name: str, params: dict[str, Any]) -> dict[str, Any]:
    """把办公场景参数归一为工具调用参数（语义键一致）。"""
    aliases = _PARAM_ALIASES.get(tool_name, {})
    normalized: dict[str, Any] = {}
    for key, value in params.items():
        target = aliases.get(key, key)
        # 单收件人列表折叠为标量，保持 ``recipient`` 语义为单个对象。
        if target == "recipient" and isinstance(value, list) and len(value) == 1:
            value = value[0]
        normalized[target] = value
    return normalized


def normalise_tool_params(tool_name: str, params: Mapping[str, Any]) -> dict[str, Any]:
    """把场景参数归一为真实工具调用参数（录制与回放必须共用这一映射）。

    运行时 Hook 看到的是 provider 交给 OpenClaw 的**归一化后**参数，因此语义录制也必须
    用同一映射渲染事件，否则录制与回放的 ``prompt_sha256`` 会分叉。
    """

    return _normalize_params(tool_name, dict(params))


def scenario_tool_calls(scenario: dict) -> list[dict]:
    """按事件顺序返回预登记工具调用：[{"toolName": str, "params": dict}, ...]。

    只做 Hook 载荷到工具调用参数的映射，不裁剪 ``depends_on`` 未满足的依赖事件
    （是否派发由驱动层决定），因此输出严格对应场景的登记事件顺序。
    """
    if not isinstance(scenario, dict):
        raise FixedTrajectoryError("scenario 必须是对象")
    events = scenario.get("events")
    if not isinstance(events, list) or not events:
        raise FixedTrajectoryError("scenario 必须包含非空 events 数组")
    calls: list[dict] = []
    for index, event in enumerate(events):
        hook = event.get("hook_payload") if isinstance(event, dict) else None
        if not isinstance(hook, dict):
            raise FixedTrajectoryError(f"事件[{index}] 缺少 hook_payload")
        tool_name = hook.get("toolName")
        params = hook.get("params")
        if not isinstance(tool_name, str) or not tool_name:
            raise FixedTrajectoryError(f"事件[{index}] hook_payload.toolName 非法")
        if not isinstance(params, dict):
            raise FixedTrajectoryError(f"事件[{index}] hook_payload.params 必须是对象")
        calls.append({"toolName": tool_name, "params": normalise_tool_params(tool_name, params)})
    return calls


def _observed_tool_names(messages: list[dict[str, Any]]) -> list[str]:
    """从请求历史中抽取已发生过的助手工具调用名（按序）。"""
    names: list[str] = []
    for message in messages:
        if not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        calls = message.get("tool_calls")
        if isinstance(calls, list):
            for call in calls:
                function = call.get("function") if isinstance(call, dict) else None
                name = function.get("name") if isinstance(function, dict) else None
                if isinstance(name, str) and name:
                    names.append(name)
        function_call = message.get("function_call")
        if isinstance(function_call, dict) and isinstance(function_call.get("name"), str):
            names.append(function_call["name"])
    return names


class FrozenTrajectoryProvider:
    """按场景回放冻结工具调用的 OpenAI 兼容模型 provider。"""

    def __init__(self, scenario: dict, *, model_id: str = DEFAULT_MODEL_ID) -> None:
        self._scenario = scenario
        self._model_id = model_id
        self._calls = scenario_tool_calls(scenario)
        self._scenario_id = str(scenario.get("scenario_id") or "") if isinstance(scenario, dict) else ""
        self._names = [call["toolName"] for call in self._calls]

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def expected_prefix(self) -> list[dict]:
        """已登记的助手工具调用序列（确定性、可比较）。"""
        return [
            {"toolName": call["toolName"], "params": dict(call["params"])}
            for call in self._calls
        ]

    def _call_id(self, index: int) -> str:
        seed = f"{self._model_id}|{self._scenario_id}|{index}".encode("utf-8")
        return f"call_fixed_{hashlib.sha256(seed).hexdigest()[:24]}"

    def chat_completion(self, request: dict) -> dict:
        """据请求历史返回下一段助手工具调用；历史漂移时抛 ``FixedTrajectoryError``。"""
        messages = request.get("messages") if isinstance(request, dict) else None
        if not isinstance(messages, list) or not all(isinstance(item, dict) for item in messages):
            raise FixedTrajectoryError("request messages must be an array of objects")
        observed = _observed_tool_names(messages)
        expected = self._names[: len(observed)]
        if observed != expected:
            raise FixedTrajectoryError(
                f"trajectory drift (observed {observed}, expected {expected})"
            )
        if len(observed) >= len(self._names):
            message: dict[str, Any] = {
                "role": "assistant",
                "content": "固定任务轨迹已完成。",
                "tool_calls": [],
            }
            finish_reason = "stop"
        else:
            index = len(observed)
            call = self._calls[index]
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [{
                    "id": self._call_id(index),
                    "type": "function",
                    "function": {
                        "name": call["toolName"],
                        "arguments": json.dumps(
                            call["params"], ensure_ascii=False, separators=(",", ":")
                        ),
                    },
                }],
            }
            finish_reason = "tool_calls"
        return {
            "id": f"chatcmpl_fixed_{hashlib.sha256(self._scenario_id.encode('utf-8')).hexdigest()[:24]}",
            "object": "chat.completion",
            "created": 0,
            "model": self._model_id,
            "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }


def completion_for(
    scenario: dict, messages: list[dict], *, model_id: str = DEFAULT_MODEL_ID
) -> dict:
    """对单个场景与给定历史计算一次 ChatCompletion 响应。"""
    provider = FrozenTrajectoryProvider(scenario, model_id=model_id)
    return provider.chat_completion({"model": model_id, "messages": messages})


def make_handler(provider: FrozenTrajectoryProvider):
    """构造 OpenAI 兼容的 ``BaseHTTPRequestHandler`` 子类。"""

    class Handler(BaseHTTPRequestHandler):
        server_version = "RVguardOfficeChainFixed/1"

        def log_message(self, fmt: str, *args: Any) -> None:
            # 请求正文与头部刻意不写入日志。
            return

        def _json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _not_found(self) -> None:
            self._json(404, {"error": {"type": "not_found", "message": "unknown route"}})

        def _invalid(self, message: str) -> None:
            self._json(400, {"error": {"type": "invalid_request", "message": message}})

        def do_GET(self) -> None:
            if self.path == "/v1/models":
                self._json(200, {
                    "object": "list",
                    "data": [{"id": provider.model_id, "object": "model", "owned_by": "rvguard"}],
                })
                return
            self._not_found()

        def do_POST(self) -> None:
            if self.path != "/v1/chat/completions":
                self._not_found()
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except (TypeError, ValueError):
                self._invalid("invalid Content-Length")
                return
            if length <= 0 or length > _MAX_BODY_BYTES:
                self._invalid("invalid request size")
                return
            try:
                request = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._invalid("request body must be valid JSON")
                return
            if not isinstance(request, dict) or not isinstance(request.get("messages"), list):
                self._invalid("request must contain a messages array")
                return
            try:
                response = provider.chat_completion(request)
            except FixedTrajectoryError as exc:
                self._json(409, {"error": {"type": "trajectory_drift", "message": str(exc)}})
                return
            self._json(200, response)

    return Handler


def serve(
    provider: FrozenTrajectoryProvider, *, host: str = "127.0.0.1", port: int = 0
) -> tuple[object, int, object]:
    """启动 HTTP 端点，返回 ``(http_server, bound_port, thread)``。

    ``port=0`` 时由系统动态分配端口；调用 ``server.shutdown()`` 可停止服务。
    """
    server = ThreadingHTTPServer((host, port), make_handler(provider))
    thread = threading.Thread(target=server.serve_forever, name="frozen-trajectory", daemon=True)
    thread.start()
    return server, int(server.server_address[1]), thread
