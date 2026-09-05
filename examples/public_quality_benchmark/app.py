# SPDX-License-Identifier: Apache-2.0
"""Apache-2.0 deterministic vulnerable sample for TST-P2-032.

The defects in this file are intentional. Keep the server loopback-only.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import time
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

APP_VERSION = "public-quality-sample/1.0.0"
SYNTHETIC_API_KEY = "aqb_synthetic_public_canary_31"


def calculate_cart_total(price: float, quantity: int) -> float:
    """INTENTIONAL AQB-FUNC-001: quantity is ignored."""

    del quantity
    return round(price, 2)


def apply_coupon(subtotal: float, coupon: str) -> float:
    """INTENTIONAL AQB-FUNC-002: coupon matching is case-sensitive."""

    return round(subtotal * 0.9, 2) if coupon == "SAVE10" else round(subtotal, 2)


def build_user_lookup(connection: sqlite3.Connection, username: str):
    """INTENTIONAL AQB-SEC-002: unsafe SQL construction, never called by HTTP."""

    query = f"SELECT id, username FROM users WHERE username = '{username}'"
    return connection.execute(query).fetchall()


def build_safe_order_lookup(order_id: str) -> tuple[str, tuple[str]]:
    """Negative control: parameterized SQL."""

    return "SELECT id, status FROM orders WHERE id = ?", (order_id,)


class SampleHandler(BaseHTTPRequestHandler):
    server_version = APP_VERSION

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _send_json(
        self,
        payload: dict[str, object],
        *,
        status: HTTPStatus = HTTPStatus.OK,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # INTENTIONAL AQB-SEC-004: no Content-Security-Policy header.
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if parsed.path == "/":
            self._send_html("<main><h1>Deterministic quality sample</h1></main>")
            return
        if parsed.path == "/api/health":
            self._send_json({"status": "ok", "version": APP_VERSION})
            return
        if parsed.path == "/api/cart/total":
            price = float(params.get("price", ["0"])[0])
            quantity = int(params.get("quantity", ["1"])[0])
            self._send_json({"total": calculate_cart_total(price, quantity)})
            return
        if parsed.path == "/api/cart/coupon":
            subtotal = float(params.get("subtotal", ["0"])[0])
            coupon = params.get("coupon", [""])[0]
            self._send_json({"total": apply_coupon(subtotal, coupon)})
            return
        if parsed.path == "/api/search":
            # INTENTIONAL AQB-PERF-001: fixed 250 ms blocking work.
            time.sleep(0.25)
            self._send_json(
                {"items": [], "query": params.get("q", [""])[0]},
                extra_headers={"X-Deterministic-Work-Ms": "250"},
            )
            return
        if parsed.path == "/api/echo":
            # INTENTIONAL AQB-SEC-001: unescaped input is reflected into HTML.
            value = params.get("value", [""])[0]
            self._send_html(f"<main>Echo: {value}</main>")
            return
        if parsed.path == "/api/debug":
            # INTENTIONAL AQB-SEC-003: synthetic credential disclosure.
            self._send_json({"debug": True, "apiKey": SYNTHETIC_API_KEY})
            return
        if parsed.path == "/api/orders/safe":
            query, values = build_safe_order_lookup(params.get("id", [""])[0])
            self._send_json({"queryShape": query, "parameterCount": len(values)})
            return
        if parsed.path == "/api/profile":
            safe_name = escape(params.get("name", [""])[0])
            self._send_html(f"<main>Profile: {safe_name}</main>")
            return
        self._send_json(
            {"error": "not_found", "path": quote(parsed.path)},
            status=HTTPStatus.NOT_FOUND,
        )


class LoopbackSampleServer(ThreadingHTTPServer):
    daemon_threads = True


def build_server(host: str = "127.0.0.1", port: int = 0) -> LoopbackSampleServer:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("public quality sample must bind to loopback")
    return LoopbackSampleServer((host, port), SampleHandler)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = build_server(args.host, args.port)
    print(
        f"{APP_VERSION} listening on http://{server.server_address[0]}:{server.server_address[1]}"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
