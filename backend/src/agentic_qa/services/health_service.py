# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
import re
import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from agentic_qa.domain.enums import HealthStatus, TestDomain
from agentic_qa.domain.models import GraphLearningPolicyBinding, Memory, Model
from agentic_qa.infra.credentials import CredentialReferenceError, CredentialResolver
from agentic_qa.infra.operational_controls import operational_metrics
from agentic_qa.infra.settings import get_settings
from agentic_qa.tools.runner_registry import RunnerRegistry


PROJECT_ROOT = Path(__file__).resolve().parents[4]
MIGRATIONS_DIR = PROJECT_ROOT / "scripts" / "migrations"
CELERY_RUNTIME_REPORT = PROJECT_ROOT / ".tmp" / "celery-runtime-report.json"
NUMBERED_MIGRATION = re.compile(r"^[0-9]+_.*\.sql$")

EXPECTED_QUEUE_TASKS = {
    "plan.generate",
    "execution.run",
    "execution.retry",
    "execution.heal",
    "execution.gate",
    "gate_policy.simulate",
    "runtime.ping",
    "triage.rerun",
    "memory.summarize",
    "memory.compress",
}

READINESS_RANK = {
    "missing_dependency": 4,
    "unavailable": 4,
    "deployment_specific_not_validated": 2,
    "not_configured": 1,
    "local_passed": 0,
}


class HealthService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_health(self) -> dict[str, object]:
        settings = get_settings()
        db_status = self._database_status()
        queue_status = self._queue_status()
        model_status, model_details = self._model_gateway_status()
        execution_status, execution_details = self._execution_service_status()
        memory_status = "healthy" if db_status == "healthy" else "degraded"
        scheduler_status = "healthy" if db_status == "healthy" and queue_status != "unavailable" else "degraded"
        services = {
            "db": db_status,
            "redis": queue_status,
            "modelGateway": model_status,
            "executionService": execution_status,
            "memoryService": memory_status,
            "schedulerService": scheduler_status,
        }
        return {
            "status": "healthy" if all(value == "healthy" for value in services.values()) else "degraded",
            "services": services,
            "details": {
                "db": {"urlConfigured": bool(settings.database_url)},
                "redis": {"mode": settings.queue_mode, "urlConfigured": bool(settings.redis_url)},
                "modelGateway": model_details,
                "executionService": execution_details,
                "memoryService": {
                    "memoryCount": self.db.scalar(select(func.count()).select_from(Memory)) or 0,
                },
                "schedulerService": {
                    "supportsDailySummarize": True,
                    "supportsWeeklyCompress": True,
                },
                "operationalHardening": operational_metrics.snapshot(),
            },
        }

    def get_readiness(self) -> dict[str, object]:
        health = self.get_health()
        services = dict(health["services"])
        critical_services = {
            "db": services["db"],
            "redis": services["redis"],
            "modelGateway": services["modelGateway"],
            "executionService": services["executionService"],
        }
        ready = all(status != "unavailable" for status in critical_services.values())
        categories = [
            self._category("queue-runtime", "Celery / Redis worker runtime", self._queue_runtime_items()),
            self._category("storage-profile", "Replay Repository storage profile", self._storage_profile_items()),
            self._category("connector-actual-validation", "Connector actual validation", self._connector_actual_validation_items()),
            self._category("migration-schema-static-checks", "Migration / schema / static checks", self._validation_items()),
            self._category("operational-hardening", "P27 operational hardening", self._operational_hardening_items()),
        ]
        return {
            "schemaVersion": "phase8.runtime-readiness.v1",
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "status": "ready" if ready else "not_ready",
            "ready": ready,
            "dependencies": critical_services,
            "categories": categories,
            "summary": self._readiness_summary(categories),
            "secretSafe": True,
            "writeActions": False,
        }

    def _database_status(self) -> str:
        try:
            self.db.execute(text("SELECT 1"))
        except Exception:
            return "unavailable"
        return "healthy"

    def _queue_status(self) -> str:
        settings = get_settings()
        if settings.queue_mode == "inline":
            return "healthy"
        return "healthy" if settings.redis_url else "unavailable"

    def _model_gateway_status(self) -> tuple[str, dict[str, object]]:
        enabled_models = list(self.db.scalars(select(Model).where(Model.enabled.is_(True))))
        unavailable_count = sum(1 for model in enabled_models if model.health_status == HealthStatus.UNAVAILABLE)
        status = "degraded" if unavailable_count else "healthy"
        return status, {
            "enabledModelCount": len(enabled_models),
            "unavailableModelCount": unavailable_count,
            "supportsProviders": ["openai", "ollama", "openai_compatible"],
        }

    def _execution_service_status(self) -> tuple[str, dict[str, object]]:
        registry = RunnerRegistry()
        available_runners = registry.available_runner_ids()
        configured_domains = {
            TestDomain.FUNCTIONAL.value: "playwright" in available_runners,
            TestDomain.PERFORMANCE.value: "k6" in available_runners,
            TestDomain.SECURITY.value: any(runner in available_runners for runner in ("zap", "semgrep", "nuclei")),
        }
        status = "healthy" if all(configured_domains.values()) else "degraded"
        return status, {
            "runnerIds": available_runners,
            "domains": configured_domains,
        }

    def _queue_runtime_items(self) -> list[dict[str, object]]:
        from agentic_qa.infra.queue import celery_app

        settings = get_settings()
        registered_tasks = {name for name in celery_app.tasks if name in EXPECTED_QUEUE_TASKS}
        missing_tasks = sorted(EXPECTED_QUEUE_TASKS - registered_tasks)
        runtime_report = self._load_celery_runtime_report()
        task_status = "missing_dependency" if missing_tasks else "local_passed"
        items = [
            self._item(
                "celery-task-registration",
                "Celery task registration",
                task_status,
                "Required queue tasks are registered." if not missing_tasks else "Required queue tasks are missing.",
                {
                    "expectedTaskCount": len(EXPECTED_QUEUE_TASKS),
                    "registeredTaskCount": len(registered_tasks),
                    "missingTaskCount": len(missing_tasks),
                    "missingTasks": missing_tasks,
                },
                ["scripts/check-celery-runtime.ps1"],
                "./scripts/check-celery-runtime.ps1 -AllowMissingRedis",
            )
        ]

        if settings.queue_mode == "inline":
            items.append(
                self._item(
                    "redis-worker-lifecycle",
                    "Redis / Celery worker lifecycle",
                    "local_passed",
                    "Inline queue mode is active; Redis and a worker are not required for local smoke.",
                    {
                        "queueMode": settings.queue_mode,
                        "redisUrlConfigured": bool(settings.redis_url),
                        "workerRequired": False,
                        "workerLifecycleValidated": False,
                    },
                    ["scripts/check-celery-runtime.ps1"],
                    "./scripts/check-celery-runtime.ps1 -RequireWorker",
                )
            )
            items.append(self._celery_execution_smoke_item(settings, runtime_report, redis_reachable=None))
            return items

        redis_reachable = self._tcp_reachable(settings.redis_url)
        items.append(
            self._item(
                "redis-worker-lifecycle",
                "Redis / Celery worker lifecycle",
                "deployment_specific_not_validated" if redis_reachable else "missing_dependency",
                (
                    "Redis is reachable; full worker lifecycle remains deployment-specific."
                    if redis_reachable
                    else "Redis is not reachable for QUEUE_MODE=celery."
                ),
                {
                    "queueMode": settings.queue_mode,
                    "redisUrlConfigured": bool(settings.redis_url),
                    "redisReachable": redis_reachable,
                    "workerRequired": True,
                    "workerLifecycleValidated": False,
                },
                ["scripts/check-celery-runtime.ps1"],
                "./scripts/check-celery-runtime.ps1 -RequireWorker",
            )
        )
        items.append(self._celery_execution_smoke_item(settings, runtime_report, redis_reachable=redis_reachable))
        return items

    def _load_celery_runtime_report(self) -> dict[str, object] | None:
        if not CELERY_RUNTIME_REPORT.exists():
            return None
        try:
            data = json.loads(CELERY_RUNTIME_REPORT.read_text(encoding="utf-8"))
        except Exception:
            return {
                "status": "failed",
                "summary": "Celery runtime report exists but could not be parsed.",
                "reportPath": str(CELERY_RUNTIME_REPORT),
            }
        if isinstance(data, dict):
            return data
        return None

    def _celery_execution_smoke_item(
        self,
        settings,
        report: dict[str, object] | None,
        *,
        redis_reachable: bool | None,
    ) -> dict[str, object]:
        evidence_refs = ["scripts/check-celery-runtime.ps1"]
        if CELERY_RUNTIME_REPORT.exists():
            evidence_refs.append(str(CELERY_RUNTIME_REPORT.relative_to(PROJECT_ROOT)))

        status = "deployment_specific_not_validated"
        summary = "Worker-backed execution smoke has not been validated in this runtime."
        details: dict[str, object] = {
            "queueMode": settings.queue_mode,
            "redisUrlConfigured": bool(settings.redis_url),
            "redisReachable": redis_reachable,
            "workerRequired": settings.queue_mode != "inline",
            "workerLifecycleValidated": False,
            "executionSmokeValidated": False,
            "reportPresent": report is not None,
        }
        if report is not None:
            details.update(
                {
                    "reportStatus": report.get("status"),
                    "generatedAt": report.get("generatedAt"),
                    "queueName": report.get("queueName"),
                    "workerLifecycleValidated": bool(report.get("workerLifecycleValidated")),
                    "executionSmokeValidated": bool(report.get("executionSmokeValidated")),
                    "executionId": report.get("executionId"),
                    "jobId": report.get("jobId"),
                    "counts": report.get("counts") if isinstance(report.get("counts"), dict) else {},
                }
            )
            report_status = str(report.get("status") or "")
            if report_status == "passed" and report.get("executionSmokeValidated"):
                status = "local_passed"
                summary = "Worker-backed execution smoke completed through queue, task outputs, NORMALIZE, Gate, and replay export."
            elif report_status == "skipped":
                status = str(report.get("readinessStatus") or "missing_dependency")
                summary = str(report.get("summary") or summary)
            elif report_status == "failed":
                status = "unavailable"
                summary = str(report.get("summary") or "Worker-backed execution smoke failed.")
        elif settings.queue_mode == "celery" and redis_reachable is False:
            status = "missing_dependency"
            summary = "Redis is not reachable, so worker-backed execution smoke cannot run."
        elif settings.queue_mode == "inline":
            summary = "Inline queue mode is active; non-inline worker-backed execution smoke is deployment-specific."

        return self._item(
            "worker-backed-execution-smoke",
            "Worker-backed execution smoke",
            status,
            summary,
            details,
            evidence_refs,
            "./scripts/check-celery-runtime.ps1 -RequireWorker",
        )

    def _storage_profile_items(self) -> list[dict[str, object]]:
        settings = get_settings()
        supported_adapters = {"local", "object"}
        configured_adapter = settings.replay_repository_storage_adapter
        adapter_supported = configured_adapter in supported_adapters
        actual_requested = os.environ.get("REPLAY_OBJECT_STORAGE_ACTUAL") == "1"
        credential_ref = os.environ.get("REPLAY_OBJECT_CREDENTIAL_REF", "").strip()
        secret_ref = os.environ.get("REPLAY_OBJECT_SECRET_REF", "").strip()
        ref_validation = self._replay_object_ref_validation(credential_ref=credential_ref, secret_ref=secret_ref)
        actual_missing = []
        if actual_requested and not credential_ref:
            actual_missing.append("REPLAY_OBJECT_CREDENTIAL_REF")
        if actual_requested and not ref_validation["valid"]:
            actual_missing.extend(ref_validation["errors"])
        if not actual_requested:
            actual_status = "deployment_specific_not_validated"
            actual_summary = "External object storage actual validation is opt-in and has not been requested in this runtime."
        elif actual_missing:
            actual_status = "missing_dependency"
            actual_summary = "External object storage actual validation was requested but required ref-only inputs are missing or invalid."
        else:
            actual_status = "deployment_specific_not_validated"
            actual_summary = (
                "External object storage credential refs are configured and ref-only validated; readiness does not call cloud providers."
            )
        return [
            self._item(
                "replay-storage-profile",
                "Replay Repository storage profile",
                "local_passed" if adapter_supported else "missing_dependency",
                "Configured StorageAdapter profile is supported." if adapter_supported else "Configured StorageAdapter profile is unsupported.",
                {
                    "configuredAdapter": configured_adapter,
                    "supportedAdapters": sorted(supported_adapters),
                    "localStorageDirConfigured": bool(settings.replay_repository_storage_dir),
                    "objectStorageProfileConfigured": bool(settings.replay_repository_object_storage_dir),
                    "objectBucketConfigured": bool(settings.replay_repository_object_storage_bucket),
                },
                ["scripts/check-replay-storage-profile.ps1", "tools/smoke/replay_storage_profile_smoke.py"],
                "./scripts/check-replay-storage-profile.ps1",
            ),
            self._item(
                "external-storage-actual-validation",
                "External storage actual validation",
                actual_status,
                actual_summary,
                {
                    "actualOptIn": actual_requested,
                    "actualProviderValidated": False,
                    "actualExternalCallPerformed": False,
                    "credentialRefConfigured": bool(credential_ref),
                    "secretRefConfigured": bool(secret_ref),
                    "credentialRefBoundaryValidated": bool(ref_validation["valid"]) and bool(credential_ref),
                    "credentialRefScheme": ref_validation["credentialRefScheme"],
                    "secretRefScheme": ref_validation["secretRefScheme"],
                    "missingRequirements": actual_missing,
                    "credentialMaterialStored": False,
                    "secretMaterialStored": False,
                },
                ["scripts/check-replay-storage-profile.ps1"],
                "./scripts/check-replay-storage-profile.ps1 -Actual -CredentialRef credential://replay/object",
            ),
        ]

    def _replay_object_ref_validation(self, *, credential_ref: str, secret_ref: str) -> dict[str, object]:
        resolver = CredentialResolver()
        errors: list[str] = []
        credential_scheme = None
        secret_scheme = None
        if credential_ref:
            try:
                credential_scheme = resolver.validate_reference(
                    credential_ref,
                    field_name="credentialRef",
                    scope={"resource": "replay_repository_object_storage"},
                ).scheme
            except CredentialReferenceError:
                errors.append("REPLAY_OBJECT_CREDENTIAL_REF")
        if secret_ref:
            try:
                secret_scheme = resolver.validate_reference(
                    secret_ref,
                    field_name="secretRef",
                    scope={"resource": "replay_repository_object_storage"},
                ).scheme
            except CredentialReferenceError:
                errors.append("REPLAY_OBJECT_SECRET_REF")
        return {
            "valid": not errors,
            "errors": errors,
            "credentialRefScheme": credential_scheme,
            "secretRefScheme": secret_scheme,
        }

    def _connector_actual_validation_items(self) -> list[dict[str, object]]:
        actual_requested = os.environ.get("GITHUB_CONNECTOR_ACTUAL") == "1"
        token_env_name = os.environ.get("GITHUB_CONNECTOR_TOKEN_ENV", "GITHUB_CONNECTOR_TOKEN")
        github_requirements = {
            "actualOptIn": actual_requested,
            "repositoryConfigured": bool(os.environ.get("GITHUB_CONNECTOR_REPOSITORY")),
            "pullNumberConfigured": bool(os.environ.get("GITHUB_CONNECTOR_PULL_NUMBER")),
            "credentialRefConfigured": bool(os.environ.get("GITHUB_CONNECTOR_CREDENTIAL_REF")),
            "tokenMaterialConfigured": bool(os.environ.get(token_env_name)),
        }
        missing_github_requirements = [
            name
            for name, configured in github_requirements.items()
            if name != "actualOptIn" and actual_requested and not configured
        ]
        if not actual_requested:
            github_status = "deployment_specific_not_validated"
            github_summary = "GitHub actual validation is opt-in and has not been requested in this runtime."
        elif missing_github_requirements:
            github_status = "missing_dependency"
            github_summary = "GitHub actual validation was requested but required runtime inputs are missing."
        else:
            github_status = "deployment_specific_not_validated"
            github_summary = "GitHub actual validation is configured, but readiness does not call external connectors."

        return [
            self._item(
                "github-connector-actual-validation",
                "GitHub connector actual validation",
                github_status,
                github_summary,
                {
                    **github_requirements,
                    "missingRequirementCount": len(missing_github_requirements),
                    "missingRequirements": missing_github_requirements,
                    "actualExternalCallPerformed": False,
                    "secretMaterialStored": False,
                },
                ["scripts/check-github-connector-actual.ps1", "tools/smoke/github_connector_actual_validation.py"],
                "./scripts/check-github-connector-actual.ps1 -Actual",
            ),
            self._item(
                "issue-tracker-actual-validation",
                "Jira / ZenTao actual validation",
                "deployment_specific_not_validated",
                "Issue tracker adapters are contract/mock validated locally; real provider credentials remain deployment-specific.",
                {
                    "actualExternalCallPerformed": False,
                    "localContractValidation": True,
                    "secretMaterialStored": False,
                },
                ["tests/unit/test_connectors.py", "tests/integration/test_frontend_backend_contract.py"],
                None,
            ),
        ]

    def _validation_items(self) -> list[dict[str, object]]:
        migration_files = sorted(path.name for path in MIGRATIONS_DIR.glob("*.sql") if NUMBERED_MIGRATION.match(path.name))
        manifest_exists = (MIGRATIONS_DIR / "MANIFEST.sha256").exists()
        ledger = self._schema_migration_ledger_status(len(migration_files))
        static_entrypoints = [
            "scripts/run-static-checks.ps1",
            "tools/static_checks/check_frontend_backend_contract.py",
            "tools/static_checks/check_migration_integrity.py",
            "tools/static_checks/check_db_schema_drift.py",
            "scripts/apply-migrations.ps1",
        ]
        missing_entrypoints = [relative for relative in static_entrypoints if not (PROJECT_ROOT / relative).exists()]
        return [
            self._item(
                "migration-ledger",
                "Migration ledger repeatability",
                ledger["status"],
                str(ledger["summary"]),
                {
                    "numberedMigrationCount": len(migration_files),
                    "manifestExists": manifest_exists,
                    "schemaMigrationsTablePresent": ledger["tablePresent"],
                    "appliedMigrationCount": ledger["appliedMigrationCount"],
                    "autoCreateTables": get_settings().auto_create_tables,
                },
                ["scripts/apply-migrations.ps1", "scripts/migrations/MANIFEST.sha256"],
                "./scripts/apply-migrations.ps1",
            ),
            self._item(
                "static-check-entrypoints",
                "Static check entrypoints",
                "missing_dependency" if missing_entrypoints else "deployment_specific_not_validated",
                (
                    "Static check entrypoints are present; readiness does not execute CI/CD validation or assume a fixed workflow/job name."
                    if not missing_entrypoints
                    else "Required static check entrypoints are missing."
                ),
                {
                    "entrypoints": static_entrypoints,
                    "missingEntryPoints": missing_entrypoints,
                    "fixedWorkflowJobAssumption": False,
                    "lastRunTrackedByRuntime": False,
                },
                static_entrypoints,
                "./scripts/run-static-checks.ps1",
            ),
        ]

    def _operational_hardening_items(self) -> list[dict[str, object]]:
        settings = get_settings()
        snapshot = operational_metrics.snapshot()
        counters = dict(snapshot["counters"])
        rate_limited = int(counters.get("http.protection.rate_limited", 0))
        timeouts = int(counters.get("http.protection.request_timeout", 0))
        server_errors = sum(
            int(value)
            for key, value in counters.items()
            if key.startswith("http.status.5")
        )
        alerts = []
        autonomy_rollbacks = int(counters.get("graph.auto_promotion.rollback", 0))
        autonomy_suspensions = int(
            counters.get("graph.auto_promotion.auto_suspension", 0)
        )
        autonomy_rejections = int(
            counters.get("graph.auto_promotion.eligibility_rejected", 0)
        )
        paused_autonomy_bindings = int(
            self.db.scalar(
                select(func.count())
                .select_from(GraphLearningPolicyBinding)
                .where(GraphLearningPolicyBinding.autonomy_paused.is_(True))
            )
            or 0
        )
        if rate_limited:
            alerts.append({"code": "HTTP_RATE_LIMIT_ACTIVE", "count": rate_limited, "dedupeKey": "p27:http-rate-limit"})
        if timeouts:
            alerts.append({"code": "HTTP_TIMEOUT_ACTIVE", "count": timeouts, "dedupeKey": "p27:http-timeout"})
        if server_errors:
            alerts.append({"code": "HTTP_5XX_ACTIVE", "count": server_errors, "dedupeKey": "p27:http-5xx"})
        if settings.controlled_autonomy_global_kill_switch:
            alerts.append({"code": "CONTROLLED_AUTONOMY_GLOBAL_KILL_SWITCH_ACTIVE", "count": 1, "dedupeKey": "p27:autonomy-global-kill"})
        if autonomy_rollbacks:
            alerts.append({"code": "CONTROLLED_AUTONOMY_ROLLBACK_ACTIVE", "count": autonomy_rollbacks, "dedupeKey": "p27:autonomy-rollback"})
        if autonomy_suspensions or paused_autonomy_bindings:
            alerts.append({"code": "CONTROLLED_AUTONOMY_SUSPENDED", "count": max(autonomy_suspensions, paused_autonomy_bindings), "dedupeKey": "p27:autonomy-suspended"})
        if autonomy_rejections:
            alerts.append({"code": "CONTROLLED_AUTONOMY_ELIGIBILITY_REJECTED", "count": autonomy_rejections, "dedupeKey": "p27:autonomy-eligibility-rejected"})
        return [
            self._item(
                "http-protection-contract",
                "HTTP limits, timeout, and error contract",
                "local_passed",
                "Process-local payload, rate, timeout, and stable error protections are configured.",
                {
                    "maxRequestBytes": settings.api_max_request_bytes,
                    "rateLimitRequests": settings.api_rate_limit_requests,
                    "rateLimitWindowSeconds": settings.api_rate_limit_window_seconds,
                    "requestTimeoutSeconds": settings.api_request_timeout_seconds,
                    "handledStatuses": [401, 403, 409, 413, 422, 429, 500, 503, 504],
                    "authorizationMaterialStored": False,
                },
                ["backend/src/agentic_qa/apps/common.py", "backend/src/agentic_qa/infra/operational_controls.py"],
                None,
            ),
            self._item(
                "operational-metrics-alerts",
                "Operational metrics and deduplicated alert projection",
                "local_passed",
                "Aggregate counters exclude request/response bodies and credential material.",
                {
                    "metrics": snapshot,
                    "activeAlerts": alerts,
                    "trackedSignals": [
                        "run_volume",
                        "latency",
                        "errors",
                        "guardrail_blocked_warn",
                        "shadow_diff",
                        "stale",
                        "sandbox_violation",
                        "webhook_retry",
                        "ci_write_failure",
                        "human_auto_promotion_outcome",
                        "eligibility_rejection_reason",
                        "auto_promotion_conflict_rollback_suspension_rate",
                    ],
                    "rawPayloadIncluded": False,
                },
                ["backend/src/agentic_qa/services/observability_service.py", "docs/OBSERVABILITY_ALERT_RUNBOOK.md"],
                None,
            ),
            self._item(
                "controlled-autonomy-operational-guard",
                "Controlled autonomy kill switch and safety thresholds",
                "local_passed",
                "Global and scope kill switches, transactional quantity limits, and rollback-rate auto-pause are enforced by the Graph Promotion Service.",
                {
                    "globalKillSwitch": settings.controlled_autonomy_global_kill_switch,
                    "maximumPromotionsPerWindow": settings.controlled_autonomy_max_promotions_per_window,
                    "windowSeconds": settings.controlled_autonomy_window_seconds,
                    "rollbackRateThreshold": settings.controlled_autonomy_rollback_rate_threshold,
                    "minimumPromotionsForRatePause": settings.controlled_autonomy_minimum_promotions_for_rate_pause,
                    "pausedBindingCount": paused_autonomy_bindings,
                    "policyHashRevalidation": True,
                    "mediumHighRiskHumanOnly": True,
                },
                [
                    "backend/src/agentic_qa/services/graph_promotion_service.py",
                    "docs/OBSERVABILITY_ALERT_RUNBOOK.md",
                ],
                None,
            ),
        ]

    def _schema_migration_ledger_status(self, expected_count: int) -> dict[str, object]:
        auto_create_tables = get_settings().auto_create_tables
        try:
            applied_count = int(self.db.execute(text("SELECT COUNT(*) FROM schema_migrations")).scalar_one())
        except Exception:
            self.db.rollback()
            return {
                "status": "deployment_specific_not_validated" if auto_create_tables else "missing_dependency",
                "summary": (
                    "schema_migrations ledger is not present in auto-create local mode."
                    if auto_create_tables
                    else "schema_migrations ledger is missing; numbered migrations have not been applied."
                ),
                "tablePresent": False,
                "appliedMigrationCount": 0,
            }
        if applied_count >= expected_count:
            return {
                "status": "local_passed",
                "summary": "schema_migrations ledger covers all numbered migrations.",
                "tablePresent": True,
                "appliedMigrationCount": applied_count,
            }
        return {
            "status": "missing_dependency",
            "summary": "schema_migrations ledger does not cover all numbered migrations.",
            "tablePresent": True,
            "appliedMigrationCount": applied_count,
        }

    def _category(self, category_id: str, title: str, items: list[dict[str, object]]) -> dict[str, object]:
        status = max((str(item["status"]) for item in items), key=lambda value: READINESS_RANK.get(value, 3))
        return {
            "id": category_id,
            "title": title,
            "status": status,
            "items": items,
        }

    def _item(
        self,
        item_id: str,
        label: str,
        status: str,
        summary: str,
        details: dict[str, object],
        evidence_refs: list[str],
        validation_command: str | None,
    ) -> dict[str, object]:
        return {
            "id": item_id,
            "label": label,
            "status": status,
            "summary": summary,
            "details": details,
            "evidenceRefs": evidence_refs,
            "validationCommand": validation_command,
            "secretSafe": True,
        }

    def _readiness_summary(self, categories: list[dict[str, object]]) -> dict[str, int]:
        counts = {
            "localPassed": 0,
            "deploymentSpecificNotValidated": 0,
            "missingDependency": 0,
            "notConfigured": 0,
            "unavailable": 0,
        }
        for category in categories:
            for item in category["items"]:
                status = item["status"]
                if status == "local_passed":
                    counts["localPassed"] += 1
                elif status == "deployment_specific_not_validated":
                    counts["deploymentSpecificNotValidated"] += 1
                elif status == "missing_dependency":
                    counts["missingDependency"] += 1
                elif status == "not_configured":
                    counts["notConfigured"] += 1
                elif status == "unavailable":
                    counts["unavailable"] += 1
        return counts

    def _tcp_reachable(self, url: str, timeout_seconds: float = 0.25) -> bool:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return False
        port = parsed.port or 6379
        try:
            with socket.create_connection((host, port), timeout=timeout_seconds):
                return True
        except OSError:
            return False
