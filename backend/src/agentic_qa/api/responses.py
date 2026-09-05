# SPDX-License-Identifier: Apache-2.0
from typing import Any

from fastapi import Request


def success_response(request: Request, data: Any, message: str = "ok") -> dict[str, Any]:
    return {
        "success": True,
        "message": message,
        "data": data,
        "requestId": request.state.request_id,
    }


def error_response(request: Request, message: str, error_code: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "success": False,
        "message": message,
        "errorCode": error_code,
        "details": details or {},
        "requestId": request.state.request_id,
    }
