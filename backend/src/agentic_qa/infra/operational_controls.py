# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int


class FixedWindowRateLimiter:
    """Process-local safety limiter for every API service instance.

    Distributed deployments may enforce a stricter gateway/Redis policy, but
    this limiter remains a fail-closed per-instance backstop and never stores
    raw Authorization material.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._windows: dict[str, deque[float]] = {}

    def check(self, key: str, *, limit: int, window_seconds: int) -> RateLimitDecision:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            window = self._windows.setdefault(key, deque())
            while window and window[0] <= cutoff:
                window.popleft()
            if len(window) >= limit:
                retry_after = max(1, int(window_seconds - (now - window[0]) + 0.999))
                return RateLimitDecision(False, limit, 0, retry_after)
            window.append(now)
            remaining = max(0, limit - len(window))
            if len(self._windows) > 20_000:
                self._prune(cutoff)
            return RateLimitDecision(True, limit, remaining, 0)

    def _prune(self, cutoff: float) -> None:
        stale = [key for key, values in self._windows.items() if not values or values[-1] <= cutoff]
        for key in stale[:5_000]:
            self._windows.pop(key, None)


class OperationalMetricsRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Counter[str] = Counter()
        self._latency_total_ms = 0
        self._latency_max_ms = 0

    def record_request(self, *, status_code: int, latency_ms: int, reason: str | None = None) -> None:
        with self._lock:
            self._counters["http.requests.total"] += 1
            self._counters[f"http.status.{status_code}"] += 1
            if status_code >= 400:
                self._counters["http.errors.total"] += 1
            if reason:
                self._counters[f"http.protection.{reason}"] += 1
            self._latency_total_ms += max(0, latency_ms)
            self._latency_max_ms = max(self._latency_max_ms, max(0, latency_ms))

    def increment(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[name] += amount

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            total = self._counters["http.requests.total"]
            return {
                "schemaVersion": "phase8.operational-metrics.v1",
                "counters": dict(sorted(self._counters.items())),
                "httpLatency": {
                    "averageMs": round(self._latency_total_ms / total, 3) if total else 0.0,
                    "maxMs": self._latency_max_ms,
                    "sampleCount": total,
                },
                "secretMaterialIncluded": False,
                "rawRequestIncluded": False,
                "rawResponseIncluded": False,
            }


def rate_limit_identity(client_host: str | None, authorization: str | None) -> str:
    material = f"{client_host or 'unknown'}|{authorization or 'anonymous'}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


api_rate_limiter = FixedWindowRateLimiter()
operational_metrics = OperationalMetricsRegistry()
