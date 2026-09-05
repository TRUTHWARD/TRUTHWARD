# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass
from time import sleep
from typing import Any, Callable, Mapping

import httpx


RETRYABLE_HTTP_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


@dataclass(frozen=True, slots=True)
class ManagedHttpResponse:
    status_code: int
    headers: Mapping[str, str]
    text: str
    url: str
    attempts: int


class ManagedHttpRequestError(RuntimeError):
    def __init__(
        self,
        *,
        kind: str,
        attempts: int,
        status_code: int | None = None,
    ) -> None:
        self.kind = kind
        self.attempts = attempts
        self.status_code = status_code
        super().__init__(self.summary)

    @property
    def summary(self) -> str:
        if self.status_code is not None:
            return f"http {self.status_code} after {self.attempts} attempt(s)"
        return f"{self.kind} after {self.attempts} attempt(s)"


def _retry_delay_seconds(
    headers: Mapping[str, str],
    *,
    default_delay_seconds: float,
    maximum_delay_seconds: float,
) -> float:
    raw_retry_after = str(headers.get("retry-after") or "").strip()
    if raw_retry_after:
        try:
            return max(0.0, min(float(raw_retry_after), maximum_delay_seconds))
        except ValueError:
            pass
    return max(0.0, min(default_delay_seconds, maximum_delay_seconds))


def managed_http_request(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    json_body: Any | None = None,
    content: bytes | str | None = None,
    timeout_seconds: float = 20.0,
    max_retries: int = 0,
    retryable_status_codes: frozenset[int] = RETRYABLE_HTTP_STATUS_CODES,
    follow_redirects: bool = True,
    retry_delay_seconds: float = 0.05,
    maximum_retry_delay_seconds: float = 1.0,
    sleep_fn: Callable[[float], None] = sleep,
) -> ManagedHttpResponse:
    """Execute one bounded HTTP operation with transport-only retry semantics.

    Callers decide whether an operation is safe to retry. This helper contains
    no provider routing, authorization, approval, or product policy.
    """

    attempts_allowed = max(1, int(max_retries) + 1)
    with httpx.Client(
        timeout=max(float(timeout_seconds), 0.001),
        follow_redirects=follow_redirects,
        trust_env=False,
        verify=not url.startswith(("http://127.0.0.1", "http://localhost")),
    ) as client:
        for attempt in range(1, attempts_allowed + 1):
            try:
                response = client.request(
                    method,
                    url,
                    headers=dict(headers or {}),
                    json=json_body,
                    content=content,
                )
            except httpx.TimeoutException as exc:
                if attempt < attempts_allowed:
                    sleep_fn(min(retry_delay_seconds, maximum_retry_delay_seconds))
                    continue
                raise ManagedHttpRequestError(kind="timeout", attempts=attempt) from exc
            except httpx.TransportError as exc:
                if attempt < attempts_allowed:
                    sleep_fn(min(retry_delay_seconds, maximum_retry_delay_seconds))
                    continue
                raise ManagedHttpRequestError(kind="transport error", attempts=attempt) from exc

            if response.status_code in retryable_status_codes and attempt < attempts_allowed:
                sleep_fn(
                    _retry_delay_seconds(
                        response.headers,
                        default_delay_seconds=retry_delay_seconds,
                        maximum_delay_seconds=maximum_retry_delay_seconds,
                    )
                )
                continue
            if response.status_code >= 400:
                raise ManagedHttpRequestError(
                    kind="http",
                    attempts=attempt,
                    status_code=response.status_code,
                )
            return ManagedHttpResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                text=response.text,
                url=str(response.url),
                attempts=attempt,
            )

    raise ManagedHttpRequestError(kind="transport error", attempts=attempts_allowed)
