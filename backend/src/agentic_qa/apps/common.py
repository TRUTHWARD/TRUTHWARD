# SPDX-License-Identifier: Apache-2.0
from collections.abc import Sequence
from contextlib import asynccontextmanager
import asyncio
import time

from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from agentic_qa.api.deps import initialize_request_context
from agentic_qa.api.responses import error_response
from agentic_qa.guardrails.result import GuardrailViolationError
from agentic_qa.infra.bootstrap import initialize_database
from agentic_qa.infra.operational_controls import (
    api_rate_limiter,
    operational_metrics,
    rate_limit_identity,
)
from agentic_qa.infra.redaction import redact_sensitive_data, redact_sensitive_text
from agentic_qa.infra.settings import get_settings
from agentic_qa.schemas.contracts import ContractValidationError


def create_service_app(service_name: str, routers: Sequence[APIRouter]) -> FastAPI:
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        initialize_database()
        yield

    app = FastAPI(
        title=f"{service_name}",
        version="0.1.0",
        docs_url="/docs",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def request_context_middleware(request: Request, call_next):
        started = time.monotonic()
        initialize_request_context(
            request,
            request.headers.get("X-Request-Id"),
            request.headers.get("X-Trace-Id"),
            request.headers.get("X-Parent-Span-Id"),
        )
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                declared_bytes = int(content_length)
            except ValueError:
                declared_bytes = settings.api_max_request_bytes + 1
            if declared_bytes < 0 or declared_bytes > settings.api_max_request_bytes:
                operational_metrics.record_request(
                    status_code=413,
                    latency_ms=int((time.monotonic() - started) * 1000),
                    reason="payload_too_large",
                )
                return JSONResponse(
                    status_code=413,
                    headers={"Connection": "close"},
                    content=error_response(
                        request,
                        message="request payload exceeds the configured limit",
                        error_code="REQUEST_PAYLOAD_TOO_LARGE",
                        details={"maxBytes": settings.api_max_request_bytes},
                    ),
                )
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            received = bytearray()
            body_too_large = False
            async for chunk in request.stream():
                if len(received) + len(chunk) > settings.api_max_request_bytes:
                    body_too_large = True
                    break
                received.extend(chunk)
            if body_too_large:
                operational_metrics.record_request(
                    status_code=413,
                    latency_ms=int((time.monotonic() - started) * 1000),
                    reason="payload_too_large",
                )
                return JSONResponse(
                    status_code=413,
                    headers={"Connection": "close"},
                    content=error_response(
                        request,
                        message="request payload exceeds the configured limit",
                        error_code="REQUEST_PAYLOAD_TOO_LARGE",
                        details={"maxBytes": settings.api_max_request_bytes},
                    ),
                )
            # Starlette's cached request will replay this bounded body to the
            # downstream parser. No route can observe an unbounded body.
            request._body = bytes(received)  # type: ignore[attr-defined]

        health_path = request.url.path.rstrip("/").endswith(("/health", "/readiness"))
        if not health_path:
            identity = rate_limit_identity(
                request.client.host if request.client else None,
                request.headers.get("authorization"),
            )
            decision = api_rate_limiter.check(
                f"{service_name}:{identity}",
                limit=settings.api_rate_limit_requests,
                window_seconds=settings.api_rate_limit_window_seconds,
            )
            if not decision.allowed:
                operational_metrics.record_request(
                    status_code=429,
                    latency_ms=int((time.monotonic() - started) * 1000),
                    reason="rate_limited",
                )
                return JSONResponse(
                    status_code=429,
                    headers={
                        "Retry-After": str(decision.retry_after_seconds),
                        "X-RateLimit-Limit": str(decision.limit),
                        "X-RateLimit-Remaining": "0",
                    },
                    content=error_response(
                        request,
                        message="request rate limit exceeded",
                        error_code="RATE_LIMIT_EXCEEDED",
                        details={"retryAfterSeconds": decision.retry_after_seconds},
                    ),
                )
        try:
            response = await asyncio.wait_for(
                call_next(request),
                timeout=settings.api_request_timeout_seconds,
            )
        except TimeoutError:
            operational_metrics.record_request(
                status_code=504,
                latency_ms=int((time.monotonic() - started) * 1000),
                reason="request_timeout",
            )
            return JSONResponse(
                status_code=504,
                content=error_response(
                    request,
                    message="request timed out before a response was available",
                    error_code="REQUEST_TIMEOUT",
                ),
            )
        operational_metrics.record_request(
            status_code=response.status_code,
            latency_ms=int((time.monotonic() - started) * 1000),
        )
        return response

    def build_guardrail_response(request: Request, exc: GuardrailViolationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=error_response(
                request,
                message=redact_sensitive_text(exc.result.reason),
                error_code="GUARDRAIL_BLOCKED",
                details={
                    "ruleId": exc.result.rule_id,
                    "decision": exc.result.decision.value,
                    "evidence": redact_sensitive_data(exc.result.evidence),
                    "metadata": redact_sensitive_data(exc.result.metadata),
                },
            ),
        )

    @app.exception_handler(GuardrailViolationError)
    async def guardrail_exception_handler(request: Request, exc: GuardrailViolationError) -> JSONResponse:
        return build_guardrail_response(request, exc)

    @app.exception_handler(ContractValidationError)
    async def contract_validation_exception_handler(request: Request, exc: ContractValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=error_response(
                request,
                message=redact_sensitive_text(str(exc)),
                error_code="CONTRACT_VALIDATION_ERROR",
                details={
                    "contract": exc.contract_name,
                    "issues": redact_sensitive_data(exc.issues),
                },
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def request_validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        issues = [
            redact_sensitive_text(str(error.get("msg", "")))
            for error in exc.errors()
        ]
        is_correction_validation = (
            request.url.path.endswith("/validate")
            and "/corrections/proposals/" in request.url.path
        )
        contract_name = "correction-validation" if is_correction_validation else "request-body"
        return JSONResponse(
            status_code=422,
            content=error_response(
                request,
                message="; ".join(issue for issue in issues if issue) or "request validation failed",
                error_code="CONTRACT_VALIDATION_ERROR",
                details={
                    "contract": contract_name,
                    "issues": issues,
                },
            ),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content=error_response(
                request,
                message="an internal service error occurred",
                error_code="INTERNAL_SERVER_ERROR",
                details={"retryable": True},
            ),
        )

    @app.get("/")
    async def root() -> dict[str, object]:
        return {
            "service": service_name,
            "prefix": settings.api_prefix,
            "docs": "/docs",
        }

    for router in routers:
        app.include_router(router, prefix=settings.api_prefix)

    return app
