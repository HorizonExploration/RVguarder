"""统一异常类型、错误消息映射、全局异常处理器。

当前错误 shape 约定：{"error": code, "error_code": code, "detail": ...}
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


# ─── 错误消息映射 ────────────────────────────────────────────────

_ERROR_MESSAGES: dict[str, str] = {
    "message_empty": "输入不能为空。",
    "action_not_found": "未找到对应动作记录。",
    "gateway_unreachable": "无法连接 OpenClaw gateway，请检查 OpenClaw 是否启动。",
    "hook_unauthorized": "Hook 鉴权失败。",
    "internal_error": "服务内部错误。",
}


def _error_message(code: str) -> str:
    """返回 code 对应的中文可读消息；未注册的 code 原样返回。"""
    return _ERROR_MESSAGES.get(code, code)


# ─── 守卫异常 ────────────────────────────────────────────────────


class GuardError(Exception):
    """携带现有 {"error","error_code","detail"} 约定的业务异常。

    FastAPI 全局处理器会将 GuardError 转为 JSONResponse，不再经过默认 HTML 错误页。
    """

    def __init__(self, code: str, status_code: int = 400, detail: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.detail = detail

    def to_dict(self) -> dict:
        payload: dict = {"error": self.code, "error_code": self.code}
        if self.detail:
            payload["detail"] = self.detail
        return payload


# ─── 全局异常处理器注册 ──────────────────────────────────────────


def register_exception_handlers(app: FastAPI) -> None:
    """为 app 注册统一的 JSON 异常处理器。

    优先级：
    1. GuardError — 业务异常，按 code/status_code 返回
    2. StarletteHTTPException — 未知 API 路径 404 等，返回 JSON 而非 HTML
    3. RequestValidationError — Query/Path 参数校验失败
    4. Exception — 兜底，复刻 do_POST 的 catch-all
    """

    @app.exception_handler(GuardError)
    async def _guard_error(request: Request, exc: GuardError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=exc.to_dict())

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": "not_found", "error_code": "not_found", "detail": str(exc.detail)},
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"error": "validation_error", "error_code": "validation_error", "detail": str(exc)},
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        code = str(getattr(exc, "code", "internal_error"))
        status = int(getattr(exc, "status_code", 500))
        return JSONResponse(
            status_code=status,
            content={"error": code, "error_code": code, "detail": str(exc)},
        )
