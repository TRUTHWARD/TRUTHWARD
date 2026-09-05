# SPDX-License-Identifier: Apache-2.0
"""Run a real browser example on the same machine as the Community API.

Creates a new example project, environment, plan and execution using the public API.
Uses an existing local account. Passwords and tokens are never saved to the report.
"""
from __future__ import annotations

import argparse
from getpass import getpass
import json
import os
from pathlib import Path
import sys
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from uuid import uuid4

from target import create_server


def verify_result(task: dict, artifacts: list[dict]) -> dict:
    result = task.get("resultPayload") or {}
    runner = result.get("runnerMetadata") or {}
    kinds = sorted({item["artifactType"] for item in artifacts if item.get("metadata", {}).get("actualExecution") is True})
    checks = {
        "taskCompleted": task.get("status") == "completed",
        "actualExecution": result.get("executionMode") == "actual" and result.get("actualExecution") is True,
        "playwrightExecuted": runner.get("namedTool") == "playwright" and runner.get("namedToolExecuted") is True,
        "pinnedChromium": runner.get("pinnedChromium") is True,
        "noCustomCommand": runner.get("customCommandExecuted") is False,
        "requiredArtifacts": {"report", "screenshot", "trace"}.issubset(kinds),
    }
    return {"status": "passed" if all(checks.values()) else "failed", "checks": checks, "artifactTypes": kinds, "taskId": task["id"]}


def main() -> int:
    if not (3, 11) <= sys.version_info[:2] < (3, 15):
        raise SystemExit("Python 3.11-3.14 is required")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default="http://127.0.0.1:8000/api/v1")
    parser.add_argument("--output", type=Path, default=Path(".tmp/community-browser-result.json"))
    args = parser.parse_args()
    parsed = urlsplit(args.api)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.username or parsed.password or parsed.query or parsed.fragment:
        parser.error("Use a loopback Community API on this machine; the example target is also local")
    api = args.api.rstrip("/")
    token = os.environ.get("TRUTHWARD_TOKEN", "")
    own_login = False
    report: dict = {"schemaVersion": "community-browser-example-result.v1", "status": "failed"}

    def call(method: str, path: str, body=None):
        request = Request(api + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                          headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + token} if token else {})})
        try:
            with urlopen(request, timeout=180) as response:
                return json.load(response)["data"]
        except HTTPError as exc:
            raise RuntimeError(f"{method} {path}: HTTP {exc.code}") from None
        except (URLError, TimeoutError):
            raise RuntimeError(f"{method} {path}: connection unavailable or timed out; check the UI before retrying") from None

    server = create_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target_url = f"http://127.0.0.1:{server.server_port}"
    try:
        if not token:
            identity = input("Community username or email: ").strip()
            token = call("POST", "/auth/login", {"identity": identity, "password": getpass("Community password: ")})["token"]
            own_login = True
        suffix = uuid4().hex[:10]
        project = call("POST", "/projects", {"key": "browser-" + suffix, "name": "Browser example " + suffix, "metadata": {}})
        report["projectId"] = project["id"]
        environment = call("POST", f"/projects/{project['id']}/environments", {"key": "browser-example", "name": "Browser example", "baseUrl": target_url, "variables": {}, "metadata": {}})
        report["environmentId"] = environment["id"]
        plan_payload = json.loads(Path(__file__).with_name("plan.json").read_text(encoding="utf-8"))
        plan_payload.update(projectId=project["id"], environmentId=environment["id"])
        plan_payload["domainConfig"]["functional"]["targetUrl"] = target_url
        plan = call("POST", "/test-plans", plan_payload)
        report["planId"] = plan["id"]
        execution = call("POST", "/executions", {"planId": plan["id"], "environment": "browser-example", "options": {"runFunctional": True, "runPerformance": False, "runSecurity": False, "enableTriage": False, "enableHealing": False, "parallelism": 1}})
        report["executionId"] = execution["id"]
        deadline = time.monotonic() + 180
        while True:
            tasks = call("GET", f"/executions/{execution['id']}/tasks")["items"]
            if tasks and all(task["status"] in {"completed", "failed", "cancelled"} for task in tasks):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Execution is still pending; inspect the recorded execution in the UI before retrying")
            time.sleep(2)
        if len(tasks) != 1:
            raise RuntimeError("Expected one functional task; inspect the execution")
        artifacts = call("GET", f"/tasks/{tasks[0]['id']}/artifacts")["items"]
        report.update(verify_result(tasks[0], artifacts))
        report["artifactIds"] = [item["id"] for item in artifacts]
    except (RuntimeError, ValueError, KeyError) as exc:
        report["error"] = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
    finally:
        if own_login:
            try:
                call("POST", "/auth/logout")
            except RuntimeError:
                report["logout"] = "unavailable"
        server.shutdown()
        server.server_close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
