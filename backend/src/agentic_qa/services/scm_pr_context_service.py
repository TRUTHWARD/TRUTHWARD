# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Mapping
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agentic_qa.connectors.scm_webhook import (
    ScmWebhookProtocolError,
    adapt_webhook,
    verify_signature,
)
from agentic_qa.connectors.contracts import ConnectorOperationRequest
from agentic_qa.connectors.github import GitHubReadOnlyConnector
from agentic_qa.connectors.gitlab import GitLabReadOnlyConnector
from agentic_qa.domain.enums import GraphSource, GraphStatus, ModelRole
from agentic_qa.domain.models import (
    AuditLog,
    CapabilityMappingRecord,
    CanonicalExecutionGraphEdge,
    CanonicalExecutionGraphNode,
    CanonicalExecutionGraphVersion,
    GuardrailEvent,
    Project,
    RequirementMatchRecord,
    RequirementMatchSnapshotRecord,
    RequirementVersion,
    ScmPrContextRecord,
    ScmPrContextVersionRecord,
    ScmWebhookReceipt,
    SkillConnectorBinding,
)
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.result import GuardrailDecision, GuardrailResult
from agentic_qa.guardrails.runtime.audit import RuntimeGuardrailEngine
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.artifact_storage import ArtifactStorageAdapter, artifact_storage_adapter
from agentic_qa.infra.credentials import CredentialResolver
from agentic_qa.infra.redaction import redact_sensitive_data, redact_sensitive_text
from agentic_qa.infra.safe_projection import ConnectorBindingSafeProjectionBuilder
from agentic_qa.infra.security import CurrentUser, DEMO_ADMIN_ID
from agentic_qa.infra.trace import ensure_trace, traced_operation
from agentic_qa.schemas.change_sets import ChangeSourceRef, CodeChangeSetIngestRequest
from agentic_qa.schemas.model_outputs import RequirementMatchModelOutput
from agentic_qa.schemas.scm_pr import (
    PRContext,
    PRRevision,
    REQUIREMENT_MATCH_ALGORITHM_VERSION,
    RequirementMatch,
    RequirementMatchCandidate,
    RequirementMatchReason,
    RequirementMatchSnapshot,
    ScmRef,
    WebhookEnvelope,
)
from agentic_qa.services.change_set_service import ChangeSetError, ChangeSetService
from agentic_qa.services.common import ServiceContext, acquire_transaction_advisory_lock, canonical_hash
from agentic_qa.services.skill_service import SkillService
from agentic_qa.services.scope_service import ScopeAuthorizationError, ScopeAuthorizationService
from agentic_qa.skills.integrations import IntegrationSkillInput, build_integration_skill_registry
from agentic_qa.tools.model_gateway import ModelGatewayTool


@dataclass(frozen=True, slots=True)
class ScmProjectScope:
    project: Project
    tenant_id: str
    workspace_id: str
    repository_ref: str
    repository_native_id: str
    installation_ref: str
    binding_snapshot: dict[str, Any]


@dataclass(frozen=True, slots=True)
class RequirementCatalogEntry:
    requirement_id: str
    version_id: UUID
    version_no: int
    content_hash: str


class ScmPrContextError(Exception):
    def __init__(self, code: str, *, status_code: int = 409, field: str | None = None) -> None:
        self.code = code
        self.status_code = status_code
        self.field = field
        super().__init__(code)


class ScmPrContextService:
    """P20 Service-owned verified SCM intake and requirement matching boundary."""

    def __init__(self, db: Session, *, storage: ArtifactStorageAdapter | None = None) -> None:
        self.db = db
        self.storage = storage or artifact_storage_adapter()
        self.credentials = CredentialResolver()
        self.connector_snapshot_builder = ConnectorBindingSafeProjectionBuilder()
        self.guardrails = RuntimeGuardrailEngine(db)
        self.skill_service = SkillService(db, build_integration_skill_registry())

    def admit_webhook(
        self,
        connector_binding_id: UUID,
        headers: Mapping[str, str],
        raw_body: bytes,
        *,
        request_id: str,
        trace_id: str,
        received_at: datetime | None = None,
    ) -> dict[str, Any]:
        binding = self.db.get(SkillConnectorBinding, connector_binding_id)
        if binding is None or binding.status != "active":
            raise ScmPrContextError("SCM_CONNECTOR_BINDING_UNAVAILABLE", status_code=404)
        provider = str(binding.connector_name).strip().lower()
        now = received_at or datetime.now(timezone.utc)
        try:
            validated_binding = self.credentials.validate_binding(
                connector_name=provider,
                secret_ref=binding.secret_ref,
                credential_ref=binding.credential_ref,
                scope=dict(binding.scope or {}),
            )
            runtime_credentials = self.credentials.runtime_credentials_for_binding(validated_binding)
            verified_event_at = verify_signature(
                provider,
                headers,
                raw_body,
                str(runtime_credentials.get("token") or ""),
                now=now,
            )
            envelope = adapt_webhook(
                provider,
                headers,
                raw_body,
                received_at=now,
                verified_event_at=verified_event_at,
            )
        except ScmWebhookProtocolError as exc:
            raise ScmPrContextError(exc.code, status_code=exc.status_code) from exc
        except ValueError as exc:
            raise ScmPrContextError("SCM_CONNECTOR_BINDING_INVALID", status_code=409) from exc

        scope = self._resolve_binding_scope(binding, envelope)
        payload_snapshot = self._minimal_payload_snapshot(envelope, scope.project)
        redacted_diff = self._redacted_diff(envelope.payloadSnapshot)
        revision = self._revision_from_snapshot(provider, payload_snapshot)
        idempotency_key = canonical_hash(
            {
                "provider": provider,
                "installationRef": envelope.installationRef,
                "repositoryNativeId": envelope.repository.nativeId,
                "deliveryId": envelope.deliveryId,
                "eventType": envelope.eventType,
                "action": envelope.action,
                "headSha": revision.headSha,
            }
        )
        system_context = self._system_context(request_id, trace_id)
        ensure_trace(self.db, execution_id=None, root_span_name="scm.webhook.intake", trace_id=trace_id)
        acquire_transaction_advisory_lock(
            self.db,
            "p20-scm-webhook-delivery",
            f"{binding.id}:{provider}:{envelope.deliveryId}",
        )
        existing = self.db.scalar(
            select(ScmWebhookReceipt).where(
                ScmWebhookReceipt.connector_binding_id == binding.id,
                ScmWebhookReceipt.provider == provider,
                ScmWebhookReceipt.delivery_id == envelope.deliveryId,
            )
        )
        if existing is not None:
            if existing.payload_hash != envelope.payloadHash or existing.idempotency_key != idempotency_key:
                self._write_delivery_conflict_audit(existing, system_context, envelope.payloadHash)
                self.db.commit()
                raise ScmPrContextError("SCM_WEBHOOK_DELIVERY_CONFLICT", status_code=409)
            return self._receipt_projection(existing, duplicate=True)

        guardrail_refs = self._record_webhook_preflight(scope, binding, envelope, system_context)
        receipt_id = uuid4()
        diff_storage_ref: str | None = None
        if redacted_diff:
            storage_result = self.storage.write_artifact(
                namespace="scm-webhook-intake",
                artifact_id=str(receipt_id),
                filename="redacted.diff",
                payload=redacted_diff.encode("utf-8"),
            )
            diff_storage_ref = str(storage_result["storageRef"])
            payload_snapshot["diffArtifact"] = {
                "storageRef": diff_storage_ref,
                "contentHash": storage_result["contentHash"],
                "byteSize": storage_result["byteSize"],
                "redacted": True,
            }
        sanitized_envelope = envelope.model_dump(mode="json")
        sanitized_envelope["payloadSnapshot"] = payload_snapshot
        receipt = ScmWebhookReceipt(
            id=receipt_id,
            tenant_id=scope.tenant_id,
            workspace_id=scope.workspace_id,
            project_id=scope.project.id,
            connector_binding_id=binding.id,
            provider=provider,
            delivery_id=envelope.deliveryId,
            event_type=envelope.eventType,
            action=envelope.action,
            installation_ref=envelope.installationRef,
            repository_ref=scope.repository_ref,
            repository_native_id=scope.repository_native_id,
            pull_request_number=envelope.pullRequestNumber,
            head_sha=revision.headSha.lower(),
            provider_event_at=envelope.providerEventAt,
            received_at=envelope.receivedAt,
            payload_hash=envelope.payloadHash,
            idempotency_key=idempotency_key,
            envelope_snapshot=sanitized_envelope,
            binding_snapshot=scope.binding_snapshot,
            status="queued",
            trace_id=UUID(str(trace_id)),
            guardrail_event_refs=guardrail_refs,
            audit_refs=[],
        )
        self.db.add(receipt)
        try:
            self.db.flush()
        except IntegrityError as exc:
            return self._recover_delivery_race(
                binding,
                envelope,
                idempotency_key,
                diff_storage_ref,
                exc,
            )
        audit = write_audit_log(
            self.db,
            system_context.user.id,
            "scm.webhook.accept",
            "scm_webhook_receipt",
            str(receipt.id),
            request_id,
            trace_id,
            details={
                "provider": provider,
                "deliveryId": envelope.deliveryId,
                "connectorBindingId": str(binding.id),
                "projectId": str(scope.project.id),
                "repositoryRef": scope.repository_ref,
                "repositoryNativeId": scope.repository_native_id,
                "headSha": revision.headSha,
                "payloadHash": envelope.payloadHash,
                "signatureVerified": True,
                "tenantDerivedFromBinding": True,
                "rawPayloadPersisted": False,
                "gateDecisionCreated": False,
                "executionCreated": False,
            },
        )
        receipt.audit_refs = [self._audit_ref(audit)]
        try:
            self.db.commit()
        except IntegrityError as exc:
            return self._recover_delivery_race(
                binding,
                envelope,
                idempotency_key,
                diff_storage_ref,
                exc,
            )

        try:
            from agentic_qa.infra.queue import enqueue_task

            enqueue_task("scm.webhook.process", str(receipt.id), request_id, trace_id)
        except Exception as exc:
            failed_receipt = self.db.get(ScmWebhookReceipt, receipt.id)
            if failed_receipt is not None:
                failed_receipt.status = "failed"
                failed_receipt.error_code = "SCM_WEBHOOK_QUEUE_UNAVAILABLE"
                self.db.commit()
            raise ScmPrContextError("SCM_WEBHOOK_QUEUE_UNAVAILABLE", status_code=503) from exc
        self.db.refresh(receipt)
        return self._receipt_projection(receipt, duplicate=False)

    def process_receipt(self, receipt_id: UUID, *, request_id: str, trace_id: str) -> dict[str, Any]:
        receipt = self.db.get(ScmWebhookReceipt, receipt_id)
        if receipt is None:
            raise ScmPrContextError("SCM_WEBHOOK_RECEIPT_NOT_FOUND", status_code=404)
        if receipt.status == "processed" and receipt.pr_context_version_id:
            return self._detail_by_version(receipt.project_id, receipt.pr_context_version_id)
        binding = self.db.get(SkillConnectorBinding, receipt.connector_binding_id)
        if binding is None or binding.status != "active":
            self._fail_receipt(receipt, "SCM_CONNECTOR_BINDING_UNAVAILABLE")
            raise ScmPrContextError("SCM_CONNECTOR_BINDING_UNAVAILABLE", status_code=409)
        envelope = WebhookEnvelope.model_validate(receipt.envelope_snapshot)
        scope = self._resolve_binding_scope(binding, envelope)
        if (
            scope.project.id != receipt.project_id
            or scope.tenant_id != receipt.tenant_id
            or scope.workspace_id != receipt.workspace_id
            or scope.repository_ref != receipt.repository_ref
        ):
            self._fail_receipt(receipt, "SCM_CONNECTOR_BINDING_CHANGED")
            raise ScmPrContextError("SCM_CONNECTOR_BINDING_CHANGED", status_code=409)

        receipt.status = "processing"
        receipt.attempt_count += 1
        receipt.error_code = None
        self.db.commit()
        context = self._system_context(request_id, trace_id)
        try:
            with traced_operation(
                self.db,
                trace_id=trace_id,
                execution_id=None,
                root_span_name="scm.webhook.process",
                span_name="scm.pr-context.build",
                service_name="orchestrator-service",
                attributes={
                    "receiptId": str(receipt.id),
                    "projectId": str(receipt.project_id),
                    "repositoryRef": receipt.repository_ref,
                    "pullRequestNumber": receipt.pull_request_number,
                    "gateDecisionCreated": False,
                    "executionCreated": False,
                },
            ):
                result = self._process_verified_receipt(receipt, binding, scope, envelope, context)
            return result
        except Exception as exc:
            self.db.rollback()
            receipt = self.db.get(ScmWebhookReceipt, receipt_id)
            if receipt is not None and receipt.status != "processed":
                receipt.status = "failed"
                receipt.error_code = exc.code if isinstance(exc, ScmPrContextError) else "SCM_WEBHOOK_PROCESSING_FAILED"
                self.db.commit()
            raise

    def list_contexts(
        self,
        project_id: UUID,
        context: ServiceContext,
        *,
        page: int = 1,
        page_size: int = 50,
        repository_ref: str | None = None,
        state: str | None = None,
    ) -> dict[str, Any]:
        scope = self._require_read_scope(project_id, context)
        statement = select(ScmPrContextRecord).where(
            ScmPrContextRecord.tenant_id == scope[0],
            ScmPrContextRecord.workspace_id == scope[1],
            ScmPrContextRecord.project_id == project_id,
        )
        if repository_ref:
            statement = statement.where(ScmPrContextRecord.repository_ref == repository_ref)
        if state:
            statement = statement.where(ScmPrContextRecord.state == state)
        total = self.db.scalar(select(func.count()).select_from(statement.subquery())) or 0
        rows = list(
            self.db.scalars(
                statement.order_by(ScmPrContextRecord.updated_at.desc(), ScmPrContextRecord.id.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        return {
            "items": [self._context_summary(row) for row in rows],
            "total": total,
            "page": page,
            "pageSize": page_size,
            "readOnly": True,
            "admissionImplemented": True,
        }

    def get_context(self, project_id: UUID, context_id: UUID, context: ServiceContext) -> dict[str, Any]:
        scope = self._require_read_scope(project_id, context)
        row = self.db.scalar(
            select(ScmPrContextRecord).where(
                ScmPrContextRecord.id == context_id,
                ScmPrContextRecord.project_id == project_id,
                ScmPrContextRecord.tenant_id == scope[0],
                ScmPrContextRecord.workspace_id == scope[1],
            )
        )
        if row is None:
            raise ScmPrContextError("PR_CONTEXT_NOT_FOUND", status_code=404)
        version = self.db.scalar(
            select(ScmPrContextVersionRecord).where(
                ScmPrContextVersionRecord.context_id == row.id,
                ScmPrContextVersionRecord.version == row.latest_version,
            )
        )
        if version is None:
            raise ScmPrContextError("PR_CONTEXT_VERSION_NOT_FOUND", status_code=404)
        return self._detail_projection(version)

    def get_context_version(
        self,
        project_id: UUID,
        context_id: UUID,
        version_number: int,
        context: ServiceContext,
    ) -> dict[str, Any]:
        scope = self._require_read_scope(project_id, context)
        version = self.db.scalar(
            select(ScmPrContextVersionRecord)
            .join(ScmPrContextRecord, ScmPrContextRecord.id == ScmPrContextVersionRecord.context_id)
            .where(
                ScmPrContextVersionRecord.context_id == context_id,
                ScmPrContextVersionRecord.version == version_number,
                ScmPrContextRecord.project_id == project_id,
                ScmPrContextRecord.tenant_id == scope[0],
                ScmPrContextRecord.workspace_id == scope[1],
            )
        )
        if version is None:
            raise ScmPrContextError("PR_CONTEXT_VERSION_NOT_FOUND", status_code=404)
        return self._detail_projection(version)

    def _process_verified_receipt(
        self,
        receipt: ScmWebhookReceipt,
        binding: SkillConnectorBinding,
        scope: ScmProjectScope,
        envelope: WebhookEnvelope,
        context: ServiceContext,
    ) -> dict[str, Any]:
        payload = dict(envelope.payloadSnapshot)
        revision = self._revision_from_snapshot(receipt.provider, payload)
        identity = f"{receipt.tenant_id}:{receipt.workspace_id}:{receipt.project_id}:{receipt.provider}:{receipt.repository_ref}:{receipt.pull_request_number}"
        acquire_transaction_advisory_lock(self.db, "p20-pr-context", identity)
        pr_context = self.db.scalar(
            select(ScmPrContextRecord).where(
                ScmPrContextRecord.tenant_id == receipt.tenant_id,
                ScmPrContextRecord.workspace_id == receipt.workspace_id,
                ScmPrContextRecord.project_id == receipt.project_id,
                ScmPrContextRecord.provider == receipt.provider,
                ScmPrContextRecord.repository_ref == receipt.repository_ref,
                ScmPrContextRecord.pull_request_number == receipt.pull_request_number,
            )
        )
        if pr_context is not None and self._utc(receipt.provider_event_at) < self._utc(pr_context.latest_provider_event_at):
            receipt.status = "ignored_out_of_order"
            receipt.error_code = "SCM_WEBHOOK_OUT_OF_ORDER"
            self.db.commit()
            return self._receipt_projection(receipt, duplicate=False)

        changed_files = self._changed_files(payload)
        explicit_refs, unknown_explicit_refs, evidence_by_requirement = self._extract_explicit_refs(
            scope.project,
            payload,
            self._requirement_catalog(scope.project.id),
        )
        diff = self._load_diff_from_snapshot(payload)
        managed_invocation_id = uuid5(
            NAMESPACE_URL,
            f"agentic-qa:p20-scm-context:{receipt.id}",
        )
        connector_call_refs: list[dict[str, Any]] = []
        connector_evidence_refs: list[dict[str, Any]] = []
        if diff is None and receipt.provider in {"github", "gitlab"}:
            diff, connector_call_refs, connector_evidence_refs = self._fetch_provider_diff(
                binding,
                scope,
                envelope,
                managed_invocation_id,
                context,
            )
        change_set = self._ingest_change_set(scope, receipt, revision, diff, context) if diff is not None else None
        if change_set:
            changed_files = self._changed_files_from_change_set(change_set)
        skill_request = self._skill_request(receipt, binding, revision, changed_files, payload, explicit_refs, context)
        managed_invocation = self.skill_service.start_managed_invocation(
            skill_id="scm-pr-workflow",
            context=context,
            request=skill_request.model_dump(mode="json"),
            source_workflow="scm.webhook.pr_context",
            policy_snapshot={
                "webhookSignatureVerified": True,
                "repositoryBindingVerified": True,
                "writesGate": False,
                "createsExecution": False,
                "aiMayConfirmMatch": False,
            },
            connector_binding_snapshot=scope.binding_snapshot,
            idempotency_key=f"p20-scm-context:{receipt.id}",
            invocation_id=managed_invocation_id,
        )
        invocation = self.skill_service.run_integration_skill_for_invocation(
            managed_invocation,
            skill_request,
            context,
            connector_call_refs=connector_call_refs,
            commit=True,
        )
        if invocation.get("status") != "completed":
            raise ScmPrContextError("SCM_PR_WORKFLOW_SKILL_FAILED", status_code=500)
        invocation_id = UUID(str(invocation["id"]))

        # ChangeSet and Skill invocations commit independently. Re-read the identity
        # under a fresh transaction before creating the immutable context version.
        acquire_transaction_advisory_lock(self.db, "p20-pr-context", identity)
        pr_context = self.db.scalar(
            select(ScmPrContextRecord).where(
                ScmPrContextRecord.tenant_id == receipt.tenant_id,
                ScmPrContextRecord.workspace_id == receipt.workspace_id,
                ScmPrContextRecord.project_id == receipt.project_id,
                ScmPrContextRecord.provider == receipt.provider,
                ScmPrContextRecord.repository_ref == receipt.repository_ref,
                ScmPrContextRecord.pull_request_number == receipt.pull_request_number,
            )
        )
        state = self._state(payload, receipt.action)
        if pr_context is None:
            pr_context = ScmPrContextRecord(
                id=uuid4(),
                tenant_id=receipt.tenant_id,
                workspace_id=receipt.workspace_id,
                project_id=receipt.project_id,
                connector_binding_id=binding.id,
                provider=receipt.provider,
                repository_ref=receipt.repository_ref,
                repository_native_id=receipt.repository_native_id,
                pull_request_number=receipt.pull_request_number,
                state=state,
                latest_version=1,
                latest_head_sha=revision.headSha,
                latest_provider_event_at=receipt.provider_event_at,
            )
            self.db.add(pr_context)
            version_number = 1
        else:
            version_number = pr_context.latest_version + 1
            pr_context.connector_binding_id = binding.id
            pr_context.repository_native_id = receipt.repository_native_id
            pr_context.state = state
            pr_context.latest_version = version_number
            pr_context.latest_head_sha = revision.headSha
            pr_context.latest_provider_event_at = receipt.provider_event_at

        version_id = uuid4()
        change_set_ref = (
            ScmRef(type="code_change_set", ref=f"change-set://{change_set['changeSetId']}", contentHash=change_set["fingerprint"])
            if change_set
            else None
        )
        context_body = {
            "schemaVersion": "phase8.pr-context.v1",
            "contextId": pr_context.id,
            "versionId": version_id,
            "version": version_number,
            "provider": receipt.provider,
            "projectId": receipt.project_id,
            "repositoryRef": receipt.repository_ref,
            "repositoryNativeId": receipt.repository_native_id,
            "pullRequestNumber": receipt.pull_request_number,
            "revision": revision.model_dump(mode="json"),
            "authorRef": self._author_ref(receipt.provider, payload),
            "draft": self._draft(payload),
            "state": state,
            "action": receipt.action,
            "fork": self._is_fork(payload),
            "labels": self._labels(payload),
            "changedFiles": changed_files,
            "changeSetRef": change_set_ref.model_dump(mode="json") if change_set_ref else None,
            "explicitRequirementRefs": explicit_refs,
            "receivedAt": receipt.received_at,
            "providerEventAt": receipt.provider_event_at,
            "bindingSnapshot": scope.binding_snapshot,
            "webhookReceiptRef": {"type": "scm_webhook_receipt", "ref": f"scm-webhook-receipt://{receipt.id}", "contentHash": receipt.payload_hash},
            "skillInvocationRef": {"type": "skill_invocation", "ref": f"skill-invocation://{invocation_id}", "contentHash": None},
            "evidenceRefs": [
                {"type": "webhook_delivery", "ref": f"scm-delivery://{receipt.provider}/{receipt.delivery_id}", "contentHash": receipt.payload_hash},
                *([change_set_ref.model_dump(mode="json")] if change_set_ref else []),
                *connector_evidence_refs,
            ],
            "readOnly": True,
            "gateDecision": None,
            "executionCreated": False,
        }
        context_hash = canonical_hash(context_body)
        context_projection = PRContext.model_validate({**context_body, "contextHash": context_hash})
        replay_snapshot = {
            "schemaVersion": "phase8.pr-context-replay.v1",
            "contextHash": context_hash,
            "webhookReceiptId": str(receipt.id),
            "payloadHash": receipt.payload_hash,
            "deliveryId": receipt.delivery_id,
            "bindingSnapshot": scope.binding_snapshot,
            "baseSha": revision.baseSha,
            "headSha": revision.headSha,
            "skillInvocationId": str(invocation_id),
            "changeSetRef": context_body["changeSetRef"],
            "connectorCallRefs": connector_call_refs,
            "traceId": context.trace_id,
        }
        version = ScmPrContextVersionRecord(
            id=version_id,
            context_id=pr_context.id,
            webhook_receipt_id=receipt.id,
            version=version_number,
            base_ref=revision.baseRef,
            base_sha=revision.baseSha,
            head_ref=revision.headRef,
            head_sha=revision.headSha,
            change_set_id=UUID(str(change_set["changeSetId"])) if change_set else None,
            skill_invocation_id=invocation_id,
            context_hash=context_hash,
            context_snapshot=context_projection.model_dump(mode="json"),
            replay_snapshot=replay_snapshot,
            trace_id=UUID(str(context.trace_id)),
        )
        self.db.add(version)
        self.db.flush()

        candidates, model_refs = self._match_requirements(
            scope,
            version,
            payload,
            changed_files,
            explicit_refs,
            unknown_explicit_refs,
            evidence_by_requirement,
            context,
        )
        match_snapshot = self._persist_match_snapshot(
            version,
            candidates,
            unknown_explicit_refs,
            model_refs,
            receipt.guardrail_event_refs,
            context,
        )
        write_audit_log(
            self.db,
            context.user.id,
            "scm.pr_context.version.create",
            "scm_pr_context_version",
            str(version.id),
            context.request_id,
            context.trace_id,
            details={
                "contextId": str(pr_context.id),
                "version": version_number,
                "provider": receipt.provider,
                "repositoryRef": receipt.repository_ref,
                "pullRequestNumber": receipt.pull_request_number,
                "baseSha": revision.baseSha,
                "headSha": revision.headSha,
                "matchSnapshotId": str(match_snapshot.id),
                "matchStatus": match_snapshot.status,
                "skillInvocationId": str(invocation_id),
                "changeSetId": str(change_set["changeSetId"]) if change_set else None,
                "gateDecisionCreated": False,
                "executionCreated": False,
            },
        )
        receipt.status = "processed"
        receipt.error_code = None
        receipt.pr_context_version_id = version.id
        self.db.commit()
        return self._detail_projection(version)

    def _match_requirements(
        self,
        scope: ScmProjectScope,
        version: ScmPrContextVersionRecord,
        payload: dict[str, Any],
        changed_files: list[dict[str, Any]],
        explicit_refs: list[str],
        unknown_explicit_refs: list[str],
        evidence_by_requirement: dict[str, list[dict[str, Any]]],
        context: ServiceContext,
    ) -> tuple[list[RequirementMatchCandidate], list[dict[str, Any]]]:
        catalog = self._requirement_catalog(scope.project.id)
        matches: list[RequirementMatchCandidate] = []
        for requirement_id in explicit_refs:
            item = catalog[requirement_id.lower()]
            evidence = evidence_by_requirement.get(requirement_id, [])
            matches.append(self._candidate(item, "explicit_reference", 1.0, "confirmed", "EXPLICIT_CONTROLLED_ID", "explicit", evidence, False))
        for requirement_id in unknown_explicit_refs:
            evidence = evidence_by_requirement.get(requirement_id, [])
            matches.append(
                RequirementMatchCandidate(
                    requirementId=requirement_id,
                    requirementVersionId=None,
                    requirementVersion=None,
                    source="explicit_reference",
                    confidence=0.0,
                    status="unknown",
                    reasons=[RequirementMatchReason(code="EXPLICIT_ID_NOT_FOUND", layer="explicit", explanationKey="requirementMatch.reason.explicitNotFound", evidenceRefs=[ScmRef.model_validate(item) for item in evidence])],
                    evidenceRefs=[ScmRef.model_validate(item) for item in evidence],
                    modelInvocationRef=None,
                    reviewRequired=True,
                )
            )
        if any(item.status == "confirmed" for item in matches):
            return matches, []

        mapped = self._manual_mapping_candidates(scope.project, catalog, payload, changed_files)
        matches.extend(mapped)
        if any(item.status == "confirmed" for item in mapped):
            return matches, []

        traced = self._verified_traceability_candidates(scope, catalog, changed_files)
        matches.extend(traced)
        if traced:
            return matches, []

        matches.extend(self._rule_candidates(scope.project, catalog, payload, changed_files))
        matches.extend(self._history_candidates(scope, catalog, version, payload, changed_files))
        if any(item.status == "candidate" for item in matches):
            return self._dedupe_candidates(matches), []

        ai_candidates, model_refs = self._ai_candidates(scope, catalog, payload, changed_files, context)
        matches.extend(ai_candidates)
        return self._dedupe_candidates(matches), model_refs

    def _manual_mapping_candidates(
        self,
        project: Project,
        catalog: dict[str, RequirementCatalogEntry],
        payload: dict[str, Any],
        changed_files: list[dict[str, Any]],
    ) -> list[RequirementMatchCandidate]:
        mappings = project.metadata_json.get("prRequirementMappings")
        if not isinstance(mappings, list):
            return []
        labels = set(self._labels(payload))
        paths = [item["path"] for item in changed_files]
        result: list[RequirementMatchCandidate] = []
        for mapping in mappings:
            if not isinstance(mapping, dict):
                continue
            requirement_id = str(mapping.get("requirementId") or "").strip()
            entry = catalog.get(requirement_id.lower())
            if entry is None or not self._mapping_applies(mapping, labels, paths, payload):
                continue
            verified = bool(mapping.get("verified")) or str(mapping.get("status")) == "confirmed"
            confidence = min(max(float(mapping.get("confidence", 1.0 if verified else 0.75)), 0.0), 1.0)
            status = "confirmed" if verified and confidence >= 0.8 else "candidate"
            evidence = [{"type": "project_mapping", "ref": f"project-mapping://{project.id}/{canonical_hash(mapping)[7:23]}", "contentHash": canonical_hash(mapping)}]
            result.append(self._candidate(entry, "manual_mapping", confidence, status, "PROJECT_MAPPING_MATCH", "mapping", evidence, status != "confirmed"))
        return result

    def _verified_traceability_candidates(
        self,
        scope: ScmProjectScope,
        catalog: dict[str, RequirementCatalogEntry],
        changed_files: list[dict[str, Any]],
    ) -> list[RequirementMatchCandidate]:
        paths = [item["path"] for item in changed_files]
        if not paths:
            return []
        mappings = list(
            self.db.scalars(
                select(CapabilityMappingRecord).where(
                    CapabilityMappingRecord.tenant_id == scope.tenant_id,
                    CapabilityMappingRecord.workspace_id == scope.workspace_id,
                    CapabilityMappingRecord.project_id == scope.project.id,
                    CapabilityMappingRecord.repository_ref == scope.repository_ref,
                    CapabilityMappingRecord.source_entity_type == "code_path",
                    CapabilityMappingRecord.mapping_source == "verified_traceability",
                    CapabilityMappingRecord.status == "active",
                )
            )
        )
        found: list[RequirementMatchCandidate] = []
        for mapping in mappings:
            if not any(self._path_matches(path, mapping.source_entity_ref) for path in paths) or mapping.graph_version_id is None:
                continue
            graph_version = self.db.get(CanonicalExecutionGraphVersion, mapping.graph_version_id)
            if (
                graph_version is None
                or graph_version.status != GraphStatus.ACTIVE
                or graph_version.source != GraphSource.CANONICAL
                or not graph_version.is_frozen
            ):
                continue
            nodes = list(self.db.scalars(select(CanonicalExecutionGraphNode).where(CanonicalExecutionGraphNode.version_id == graph_version.id)))
            capability_nodes = [node for node in nodes if node.node_type == "capability" and self._node_matches_ref(node, mapping.capability_ref)]
            if not capability_nodes:
                continue
            node_by_id = {node.id: node for node in nodes}
            capability_ids = {node.id for node in capability_nodes}
            edges = list(
                self.db.scalars(
                    select(CanonicalExecutionGraphEdge).where(
                        CanonicalExecutionGraphEdge.version_id == graph_version.id,
                        CanonicalExecutionGraphEdge.edge_type.in_(["implements", "depends_on", "affects"]),
                    )
                )
            )
            requirement_nodes: list[CanonicalExecutionGraphNode] = []
            for edge in edges:
                other = None
                if edge.source_node_id in capability_ids:
                    other = node_by_id.get(edge.target_node_id)
                elif edge.target_node_id in capability_ids:
                    other = node_by_id.get(edge.source_node_id)
                if other is not None and other.node_type == "requirement":
                    requirement_nodes.append(other)
            for node in requirement_nodes:
                requirement_id = self._requirement_id_from_node(node)
                entry = catalog.get(requirement_id.lower()) if requirement_id else None
                if entry is None:
                    continue
                confidence = min(float(mapping.confidence), float(node.confidence))
                status = "confirmed" if confidence >= 0.8 else "candidate"
                evidence: list[dict[str, Any]] = [
                    {"type": "capability_mapping", "ref": f"capability-mapping://{mapping.id}", "contentHash": mapping.content_hash},
                    {"type": "canonical_graph_version", "ref": graph_version.version_ref, "contentHash": graph_version.content_hash},
                    {"type": "graph_node", "ref": node.node_ref, "contentHash": None},
                ]
                found.append(self._candidate(entry, "verified_traceability", confidence, status, "VERIFIED_CEG_TRACEABILITY", "traceability", evidence, status != "confirmed"))
        return self._dedupe_candidates(found)

    def _rule_candidates(
        self,
        project: Project,
        catalog: dict[str, RequirementCatalogEntry],
        payload: dict[str, Any],
        changed_files: list[dict[str, Any]],
    ) -> list[RequirementMatchCandidate]:
        rules = project.metadata_json.get("requirementMatchRules")
        if not isinstance(rules, list):
            return []
        labels = set(self._labels(payload))
        paths = [item["path"] for item in changed_files]
        result: list[RequirementMatchCandidate] = []
        for rule in rules:
            if not isinstance(rule, dict) or not self._mapping_applies(rule, labels, paths, payload):
                continue
            entry = catalog.get(str(rule.get("requirementId") or "").strip().lower())
            if entry is None:
                continue
            confidence = min(max(float(rule.get("confidence", 0.7)), 0.0), 0.89)
            evidence = [{"type": "match_rule", "ref": f"match-rule://{project.id}/{canonical_hash(rule)[7:23]}", "contentHash": canonical_hash(rule)}]
            result.append(self._candidate(entry, "rule", confidence, "candidate", "PROJECT_RULE_MATCH", "rule_history", evidence, True))
        return result

    def _history_candidates(
        self,
        scope: ScmProjectScope,
        catalog: dict[str, RequirementCatalogEntry],
        version: ScmPrContextVersionRecord,
        payload: dict[str, Any],
        changed_files: list[dict[str, Any]],
    ) -> list[RequirementMatchCandidate]:
        current_paths = {item["path"] for item in changed_files}
        current_labels = set(self._labels(payload))
        previous = list(
            self.db.scalars(
                select(ScmPrContextVersionRecord)
                .join(ScmPrContextRecord, ScmPrContextRecord.id == ScmPrContextVersionRecord.context_id)
                .where(
                    ScmPrContextRecord.tenant_id == scope.tenant_id,
                    ScmPrContextRecord.workspace_id == scope.workspace_id,
                    ScmPrContextRecord.project_id == scope.project.id,
                    ScmPrContextRecord.repository_ref == scope.repository_ref,
                    ScmPrContextVersionRecord.id != version.id,
                )
                .order_by(ScmPrContextVersionRecord.created_at.desc())
                .limit(50)
            )
        )
        result: list[RequirementMatchCandidate] = []
        for historical_version in previous:
            prior_paths = {str(item.get("path")) for item in historical_version.context_snapshot.get("changedFiles", []) if isinstance(item, dict)}
            prior_labels = {str(item) for item in historical_version.context_snapshot.get("labels", [])}
            if not (current_paths.intersection(prior_paths) or current_labels.intersection(prior_labels)):
                continue
            snapshot = self.db.scalar(select(RequirementMatchSnapshotRecord).where(RequirementMatchSnapshotRecord.pr_context_version_id == historical_version.id))
            if snapshot is None:
                continue
            rows = list(self.db.scalars(select(RequirementMatchRecord).where(RequirementMatchRecord.snapshot_id == snapshot.id, RequirementMatchRecord.status == "confirmed")))
            for row in rows:
                entry = catalog.get(row.requirement_id.lower())
                if entry is None:
                    continue
                evidence = [{"type": "historical_match", "ref": f"requirement-match://{row.id}", "contentHash": row.match_hash}]
                result.append(self._candidate(entry, "history", 0.6, "candidate", "HISTORICAL_OVERLAP", "rule_history", evidence, True))
        return self._dedupe_candidates(result)

    def _ai_candidates(
        self,
        scope: ScmProjectScope,
        catalog: dict[str, RequirementCatalogEntry],
        payload: dict[str, Any],
        changed_files: list[dict[str, Any]],
        context: ServiceContext,
    ) -> tuple[list[RequirementMatchCandidate], list[dict[str, Any]]]:
        try:
            response = ModelGatewayTool(self.db).invoke_json(
                trace_id=UUID(str(context.trace_id)),
                execution_id=None,
                role=ModelRole.PRIMARY,
                prompt=(
                    "Suggest requirement IDs for this provider-neutral PR context. Return candidates only; "
                    "never confirm a match and do not make Gate or CI decisions."
                ),
                payload={
                    "schemaVersion": "phase8.requirement-match-ai-request.v1",
                    "projectId": str(scope.project.id),
                    "repositoryRef": scope.repository_ref,
                    "changedPaths": [item["path"] for item in changed_files[:200]],
                    "labels": self._labels(payload),
                    "allowedRequirementIds": [entry.requirement_id for entry in catalog.values()][:2000],
                },
                validator=RequirementMatchModelOutput,
                request_id=context.request_id,
            )
        except Exception as exc:
            write_audit_log(
                self.db,
                context.user.id,
                "scm.requirement_match.ai_unavailable",
                "project",
                str(scope.project.id),
                context.request_id,
                context.trace_id,
                details={
                    "repositoryRef": scope.repository_ref,
                    "errorType": type(exc).__name__,
                    "fallbackStatus": "unknown",
                    "aiMayConfirmMatch": False,
                    "gateDecisionCreated": False,
                },
            )
            return [], []
        invocation_id = str(response.get("modelInvocationId") or "")
        model_ref = {"type": "model_invocation", "ref": f"model-invocation://{invocation_id}", "contentHash": None} if invocation_id else None
        output = response.get("output")
        raw_items = output.get("candidates") if isinstance(output, dict) else None
        items: list[Any] = raw_items if isinstance(raw_items, list) else []
        result: list[RequirementMatchCandidate] = []
        for item in items[:50]:
            if not isinstance(item, dict):
                continue
            entry = catalog.get(str(item.get("requirementId") or "").strip().lower())
            if entry is None:
                continue
            confidence = min(max(float(item.get("confidence", 0.5)), 0.0), 0.79)
            evidence = [model_ref] if model_ref else []
            candidate = self._candidate(entry, "ai_suggestion", confidence, "candidate", "AI_SUGGESTION", "ai", evidence, True)
            candidate.modelInvocationRef = ScmRef.model_validate(model_ref) if model_ref else None
            result.append(candidate)
        return result, [model_ref] if model_ref else []

    def _persist_match_snapshot(
        self,
        version: ScmPrContextVersionRecord,
        candidates: list[RequirementMatchCandidate],
        unknown_refs: list[str],
        model_refs: list[dict[str, Any]],
        guardrail_refs: list[dict[str, Any]],
        context: ServiceContext,
    ) -> RequirementMatchSnapshotRecord:
        snapshot_id = uuid4()
        now = datetime.now(timezone.utc)
        match_contracts: list[RequirementMatch] = []
        match_rows: list[RequirementMatchRecord] = []
        for ordinal, candidate in enumerate(candidates, start=1):
            match_id = uuid4()
            match_hash = canonical_hash({"snapshotId": str(snapshot_id), "ordinal": ordinal, "candidate": candidate.model_dump(mode="json")})
            contract = RequirementMatch(
                schemaVersion="phase8.requirement-match.v1",
                matchId=match_id,
                prContextVersionId=version.id,
                candidate=candidate,
                matchHash=match_hash,
                createdAt=now,
            )
            match_contracts.append(contract)
            match_rows.append(
                RequirementMatchRecord(
                    id=match_id,
                    snapshot_id=snapshot_id,
                    ordinal=ordinal,
                    requirement_id=candidate.requirementId,
                    requirement_version_id=candidate.requirementVersionId,
                    source=candidate.source,
                    confidence=Decimal(str(candidate.confidence)),
                    status=candidate.status,
                    review_required=candidate.reviewRequired,
                    reasons=[item.model_dump(mode="json") for item in candidate.reasons],
                    evidence_refs=[item.model_dump(mode="json") for item in candidate.evidenceRefs],
                    model_invocation_ref=candidate.modelInvocationRef.model_dump(mode="json") if candidate.modelInvocationRef else None,
                    match_hash=match_hash,
                )
            )
        status = self._match_snapshot_status(candidates)
        review_required = status != "confirmed" or bool(unknown_refs) or any(item.reviewRequired for item in candidates)
        match_audit = write_audit_log(
            self.db,
            context.user.id,
            "scm.requirement_match.snapshot.create",
            "requirement_match_snapshot",
            str(snapshot_id),
            context.request_id,
            context.trace_id,
            details={
                "prContextVersionId": str(version.id),
                "algorithmVersion": REQUIREMENT_MATCH_ALGORITHM_VERSION,
                "status": status,
                "reviewRequired": review_required,
                "candidateCount": len(candidates),
                "explicitUnknownCount": len(unknown_refs),
                "aiMayConfirmMatch": False,
                "gateDecisionCreated": False,
                "executionCreated": False,
            },
        )
        audit_refs = [self._audit_ref(match_audit)]
        body = {
            "schemaVersion": "phase8.requirement-match-snapshot.v1",
            "snapshotId": snapshot_id,
            "prContextVersionId": version.id,
            "algorithmVersion": REQUIREMENT_MATCH_ALGORITHM_VERSION,
            "status": status,
            "matches": [item.model_dump(mode="json") for item in match_contracts],
            "explicitUnknownRefs": unknown_refs,
            "modelInvocationRefs": model_refs,
            "guardrailEventRefs": guardrail_refs,
            "auditRefs": audit_refs,
            "createdAt": now,
            "reviewRequired": review_required,
            "readOnly": True,
            "gateDecision": None,
            "executionCreated": False,
        }
        snapshot_hash = canonical_hash(body)
        RequirementMatchSnapshot.model_validate({**body, "snapshotHash": snapshot_hash})
        row = RequirementMatchSnapshotRecord(
            id=snapshot_id,
            pr_context_version_id=version.id,
            algorithm_version=REQUIREMENT_MATCH_ALGORITHM_VERSION,
            status=status,
            review_required=review_required,
            explicit_unknown_refs=unknown_refs,
            model_invocation_refs=model_refs,
            guardrail_event_refs=guardrail_refs,
            audit_refs=audit_refs,
            snapshot_hash=snapshot_hash,
            replay_snapshot={
                "schemaVersion": "phase8.requirement-match-replay.v1",
                "snapshotHash": snapshot_hash,
                "algorithmVersion": REQUIREMENT_MATCH_ALGORITHM_VERSION,
                "prContextVersionId": str(version.id),
                "prContextHash": version.context_hash,
                "modelInvocationRefs": model_refs,
                "matchHashes": [item.matchHash for item in match_contracts],
                "traceId": context.trace_id,
            },
            trace_id=UUID(str(context.trace_id)),
        )
        self.db.add(row)
        # RequirementMatch rows reference the immutable snapshot, and the
        # models do not define an ORM relationship that guarantees insert
        # order.  Persist the parent first within the same transaction.
        self.db.flush()
        self.db.add_all(match_rows)
        self.db.flush()
        return row

    @staticmethod
    def _skill_request(
        receipt: ScmWebhookReceipt,
        binding: SkillConnectorBinding,
        revision: PRRevision,
        changed_files: list[dict[str, Any]],
        payload: dict[str, Any],
        explicit_refs: list[str],
        context: ServiceContext,
    ) -> IntegrationSkillInput:
        return IntegrationSkillInput(
            skill="scm-pr-workflow",
            operation="build_pr_context",
            provider=receipt.provider,
            payload={
                "repository": receipt.repository_ref,
                "pullRequestId": str(receipt.pull_request_number),
                "revision": revision.model_dump(mode="json"),
                "changedFiles": changed_files,
                "labels": ScmPrContextService._labels(payload),
                "draft": ScmPrContextService._draft(payload),
                "state": ScmPrContextService._state(payload, receipt.action),
                "authorRef": ScmPrContextService._author_ref(receipt.provider, payload),
                "explicitRequirementRefs": explicit_refs,
            },
            metadata={
                "requestId": context.request_id,
                "traceId": context.trace_id,
                "webhookReceiptRef": f"scm-webhook-receipt://{receipt.id}",
                "bindingId": str(binding.id),
            },
        )

    def _fetch_provider_diff(
        self,
        binding: SkillConnectorBinding,
        scope: ScmProjectScope,
        envelope: WebhookEnvelope,
        skill_invocation_id: UUID | None,
        context: ServiceContext,
    ) -> tuple[str | None, list[dict[str, Any]], list[dict[str, Any]]]:
        validated_binding = self.credentials.validate_binding(
            connector_name=binding.connector_name,
            secret_ref=binding.secret_ref,
            credential_ref=binding.credential_ref,
            scope=dict(binding.scope or {}),
        )
        runtime_credentials = self.credentials.runtime_credentials_for_binding(
            validated_binding,
            prefer_credential=True,
        )
        if not runtime_credentials.get("token"):
            return None, [], []
        connector = GitHubReadOnlyConnector() if envelope.provider == "github" else GitLabReadOnlyConnector()
        result = connector.invoke(
            ConnectorOperationRequest(
                connector_name=envelope.provider,
                operation="fetch_diff",
                payload={
                    "repository": envelope.repository.fullName,
                    "pullNumber": envelope.pullRequestNumber,
                },
                binding_snapshot=scope.binding_snapshot,
                runtime_credentials=runtime_credentials,
                trace_id=context.trace_id,
                skill_invocation_id=str(skill_invocation_id) if skill_invocation_id else None,
            )
        )
        call_ref = {
            "type": "connector_call",
            "ref": result.connector_call_ref or f"{envelope.provider}://connector/fetch_diff/unavailable",
            "connector": envelope.provider,
            "operation": "fetch_diff",
            "succeeded": result.succeeded,
        }
        write_audit_log(
            self.db,
            context.user.id,
            "scm.connector.fetch_diff",
            "skill_connector_binding",
            str(binding.id),
            context.request_id,
            context.trace_id,
            details={
                "provider": envelope.provider,
                "repositoryRef": scope.repository_ref,
                "pullRequestNumber": envelope.pullRequestNumber,
                "operation": "fetch_diff",
                "succeeded": result.succeeded,
                "connectorCallRef": result.connector_call_ref,
                "writesGate": False,
                "createsExecution": False,
            },
        )
        if not result.succeeded:
            return None, [call_ref], []
        raw_diff: str | None = None
        if isinstance(result.data.get("diff"), str):
            raw_diff = str(result.data["diff"])
        elif isinstance(result.data.get("changes"), list):
            parts = [str(item.get("diff")) for item in result.data["changes"] if isinstance(item, dict) and item.get("diff")]
            raw_diff = "\n".join(parts) if parts else None
        evidence_refs = [
            {"type": "connector", "ref": str(item.get("ref")), "contentHash": None}
            for item in result.evidence_refs
            if isinstance(item, dict) and item.get("ref")
        ]
        return redact_sensitive_text(raw_diff) if raw_diff else None, [call_ref], evidence_refs

    @staticmethod
    def _changed_files_from_change_set(change_set: dict[str, Any]) -> list[dict[str, Any]]:
        change_types = {
            "add": "added",
            "update": "modified",
            "remove": "deleted",
            "rename": "renamed",
            "copy": "copied",
            "unknown": "unknown",
        }
        result: list[dict[str, Any]] = []
        for item in change_set.get("files") or []:
            if not isinstance(item, dict) or not item.get("path"):
                continue
            result.append(
                {
                    "path": str(item["path"]),
                    "changeType": change_types.get(str(item.get("changeType") or "unknown"), "unknown"),
                    "previousPath": str(item["oldPath"]) if item.get("oldPath") else None,
                }
            )
        return result

    def _ingest_change_set(
        self,
        scope: ScmProjectScope,
        receipt: ScmWebhookReceipt,
        revision: PRRevision,
        diff: str,
        context: ServiceContext,
    ) -> dict[str, Any]:
        try:
            return ChangeSetService(self.db).ingest_code(
                scope.project.id,
                CodeChangeSetIngestRequest(
                    sourceType="scm_webhook",
                    sourceId=f"{receipt.provider}://{receipt.repository_native_id}/pull/{receipt.pull_request_number}",
                    revision=revision.headSha,
                    repositoryRef=scope.repository_ref,
                    baseSha=revision.baseSha,
                    headSha=revision.headSha,
                    diff=diff,
                    sourceRefs=[
                        ChangeSourceRef(
                            type="scm_webhook_receipt",
                            ref=f"scm-webhook-receipt://{receipt.id}",
                            contentHash=receipt.payload_hash,
                        )
                    ],
                    forcePush=revision.forcePush,
                    baseReachable=not bool(scope.binding_snapshot.get("baseUnreachable", False)),
                ),
                context,
            )
        except ChangeSetError as exc:
            raise ScmPrContextError(exc.code, status_code=exc.status_code, field=exc.field) from exc

    def _resolve_binding_scope(self, binding: SkillConnectorBinding, envelope: WebhookEnvelope) -> ScmProjectScope:
        scope = dict(binding.scope or {})
        try:
            project_id = UUID(str(scope.get("projectId")))
        except (ValueError, TypeError) as exc:
            raise ScmPrContextError("SCM_PROJECT_BINDING_UNAVAILABLE", status_code=409) from exc
        project = self.db.get(Project, project_id)
        if project is None or project.status != "active":
            raise ScmPrContextError("SCM_PROJECT_BINDING_UNAVAILABLE", status_code=409)
        gate_context = project.metadata_json.get("gateContext")
        gate_context = gate_context if isinstance(gate_context, dict) else {}
        tenant_id = str(gate_context.get("tenantId") or "local-tenant").strip()
        workspace_id = str(gate_context.get("workspaceId") or f"project-{project.id}").strip()
        if scope.get("tenantId") not in {None, tenant_id} or scope.get("workspaceId") not in {None, workspace_id}:
            raise ScmPrContextError("SCM_CONNECTOR_SCOPE_MISMATCH", status_code=409)
        mappings = scope.get("repositoryBindings") or scope.get("repositories")
        if not isinstance(mappings, list):
            mappings = [scope] if scope.get("repositoryRef") else []
        match: dict[str, Any] | None = None
        for candidate in mappings:
            if not isinstance(candidate, dict):
                continue
            native_id = str(candidate.get("repositoryNativeId") or candidate.get("repositoryId") or "").strip()
            full_name = str(candidate.get("fullName") or candidate.get("repository") or "").strip()
            installation = str(candidate.get("installationRef") or candidate.get("installationId") or "").strip()
            repository_matches = (
                native_id == envelope.repository.nativeId if native_id else full_name.casefold() == envelope.repository.fullName.casefold()
            )
            if repository_matches and (not installation or installation == envelope.installationRef):
                match = candidate
                break
        if match is None:
            raise ScmPrContextError("SCM_REPOSITORY_BINDING_NOT_FOUND", status_code=404)
        repository_ref = str(match.get("repositoryRef") or match.get("ref") or "").strip()
        if not repository_ref or "://" not in repository_ref:
            raise ScmPrContextError("SCM_REPOSITORY_BINDING_INVALID", status_code=409)
        configured = project.metadata_json.get("repositories") or project.metadata_json.get("repositoryRefs")
        allowed = {
            str(item if isinstance(item, str) else item.get("ref") or item.get("repositoryRef") or "")
            for item in configured or []
            if isinstance(item, (str, dict))
        }
        if repository_ref not in allowed:
            raise ScmPrContextError("SCM_REPOSITORY_BINDING_NOT_FOUND", status_code=404)
        native_id = str(match.get("repositoryNativeId") or match.get("repositoryId") or envelope.repository.nativeId)
        binding_snapshot_body = {
            "connectorBindingId": str(binding.id),
            "connectorName": binding.connector_name,
            "tenantId": tenant_id,
            "workspaceId": workspace_id,
            "projectId": str(project.id),
            "repositoryRef": repository_ref,
            "repositoryNativeId": native_id,
            "installationRef": envelope.installationRef,
        }
        binding_snapshot = self.connector_snapshot_builder.build(
            {
                **binding_snapshot_body,
                "configurationHash": canonical_hash(binding_snapshot_body),
                "bindingRevision": 1,
                "scopeType": "project_repository",
            }
        )
        return ScmProjectScope(project, tenant_id, workspace_id, repository_ref, native_id, envelope.installationRef, binding_snapshot)

    def _require_read_scope(self, project_id: UUID, context: ServiceContext) -> tuple[str, str, Project]:
        if "pr.read" not in set(context.user.capabilities):
            raise ScmPrContextError("PR_READ_CAPABILITY_REQUIRED", status_code=403, field="pr.read")
        try:
            scope = ScopeAuthorizationService(self.db).resolve_project(project_id, context)
        except ScopeAuthorizationError as exc:
            raise ScmPrContextError(
                "PR_CONTEXT_PROJECT_NOT_FOUND" if exc.status_code == 404 else exc.code,
                status_code=exc.status_code,
                field=exc.field,
            ) from exc
        return scope.tenant_id, scope.workspace_id, scope.project

    def _minimal_payload_snapshot(self, envelope: WebhookEnvelope, project: Project) -> dict[str, Any]:
        payload = envelope.payloadSnapshot
        commit_refs = self._commit_requirement_refs(project, payload)
        if envelope.provider == "github":
            raw_pr = payload.get("pull_request")
            pr: dict[str, Any] = raw_pr if isinstance(raw_pr, dict) else {}
            raw_base = pr.get("base")
            base: dict[str, Any] = raw_base if isinstance(raw_base, dict) else {}
            raw_head = pr.get("head")
            head: dict[str, Any] = raw_head if isinstance(raw_head, dict) else {}
            snapshot = {
                "title": pr.get("title"),
                "body": pr.get("body"),
                "base": self._minimal_git_ref(base),
                "head": self._minimal_git_ref(head),
                "user": self._stable_user(pr.get("user")),
                "draft": pr.get("draft"),
                "state": pr.get("state"),
                "merged": pr.get("merged"),
                "labels": pr.get("labels"),
                "files": self._change_metadata_only(payload.get("files") or pr.get("files")),
                "commitRequirementRefs": commit_refs,
                "before": payload.get("before"),
                "forced": payload.get("forced"),
            }
        else:
            raw_attrs = payload.get("object_attributes")
            if not isinstance(raw_attrs, dict):
                raw_attrs = payload.get("merge_request")
            if not isinstance(raw_attrs, dict):
                raw_attrs = payload.get("pull_request")
            attrs: dict[str, Any] = raw_attrs if isinstance(raw_attrs, dict) else {}
            raw_last_commit = attrs.get("last_commit")
            last_commit: dict[str, Any] = raw_last_commit if isinstance(raw_last_commit, dict) else {}
            snapshot = {
                "title": attrs.get("title"),
                "body": attrs.get("description") or attrs.get("body"),
                "object_attributes": {
                    "iid": attrs.get("iid") or attrs.get("id"),
                    "target_branch": attrs.get("target_branch") or attrs.get("base_ref"),
                    "target_branch_sha": attrs.get("target_branch_sha") or attrs.get("base_sha") or attrs.get("oldrev"),
                    "source_branch": attrs.get("source_branch") or attrs.get("head_ref"),
                    "last_commit": {"id": last_commit.get("id")},
                    "last_commit_id": attrs.get("last_commit_id"),
                    "head_sha": attrs.get("head_sha"),
                    "draft": attrs.get("draft"),
                    "state": attrs.get("state"),
                    "oldrev": attrs.get("oldrev"),
                    "force_push": attrs.get("force_push"),
                },
                "user": self._stable_user(payload.get("user") or attrs.get("author")),
                "labels": payload.get("labels") or attrs.get("labels"),
                "changes": self._change_metadata_only(payload.get("changes")),
                "files": self._change_metadata_only(payload.get("files")),
                "commitRequirementRefs": commit_refs,
                "before": payload.get("before") or attrs.get("oldrev"),
                "forced": payload.get("forced") or attrs.get("force_push"),
            }
        return redact_sensitive_data(snapshot)

    @staticmethod
    def _minimal_git_ref(value: dict[str, Any]) -> dict[str, Any]:
        raw_repository = value.get("repo")
        repository: dict[str, Any] = raw_repository if isinstance(raw_repository, dict) else {}
        return {
            "ref": value.get("ref"),
            "sha": value.get("sha"),
            "repo": {"id": repository.get("id")},
        }

    @staticmethod
    def _stable_user(value: Any) -> dict[str, Any]:
        user = value if isinstance(value, dict) else {}
        return {"id": user.get("id") or user.get("user_id")}

    def _commit_requirement_refs(self, project: Project, payload: dict[str, Any]) -> list[dict[str, str]]:
        messages: list[str] = []
        commits = payload.get("commits")
        if isinstance(commits, list):
            for item in commits[:250]:
                message = item.get("message") if isinstance(item, dict) else item
                if isinstance(message, str) and message:
                    messages.append(redact_sensitive_text(message[:10_000]))
        head_commit = payload.get("head_commit")
        if isinstance(head_commit, dict) and isinstance(head_commit.get("message"), str):
            messages.append(redact_sensitive_text(head_commit["message"][:10_000]))

        catalog = self._requirement_catalog(project.id)
        prefixes = project.metadata_json.get("requirementIdPrefixes")
        prefixes = [str(item) for item in prefixes if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,15}", str(item))] if isinstance(prefixes, list) else ["REQ", "R"]
        results: dict[tuple[str, str], dict[str, str]] = {}
        for message in messages:
            content_hash = canonical_hash(message)
            for entry in catalog.values():
                if re.search(rf"(?<![A-Za-z0-9_-]){re.escape(entry.requirement_id)}(?![A-Za-z0-9_-])", message, flags=re.IGNORECASE):
                    results[(entry.requirement_id.lower(), content_hash)] = {
                        "id": entry.requirement_id,
                        "contentHash": content_hash,
                    }
            if prefixes:
                pattern = re.compile(rf"(?<![A-Za-z0-9_-])(?:{'|'.join(re.escape(item) for item in prefixes)})-\d+(?![A-Za-z0-9_-])", re.IGNORECASE)
                for matched in pattern.findall(message):
                    matched_entry = catalog.get(matched.lower())
                    requirement_id = matched_entry.requirement_id if matched_entry else matched.upper()
                    results[(requirement_id.lower(), content_hash)] = {
                        "id": requirement_id,
                        "contentHash": content_hash,
                    }
        return list(results.values())[:500]

    @staticmethod
    def _change_metadata_only(value: Any) -> list[dict[str, Any]] | None:
        if not isinstance(value, list):
            return None
        allowed = {
            "old_path",
            "new_path",
            "filename",
            "previous_filename",
            "path",
            "status",
            "renamed_file",
            "deleted_file",
            "new_file",
        }
        return [{key: item[key] for key in allowed if key in item} for item in value[:50_000] if isinstance(item, dict)]

    def _revision_from_snapshot(self, provider: str, payload: dict[str, Any]) -> PRRevision:
        if provider == "github":
            raw_base = payload.get("base")
            base: dict[str, Any] = raw_base if isinstance(raw_base, dict) else {}
            raw_head = payload.get("head")
            head: dict[str, Any] = raw_head if isinstance(raw_head, dict) else {}
            base_ref, base_sha = base.get("ref"), base.get("sha")
            head_ref, head_sha = head.get("ref"), head.get("sha")
        else:
            raw_attrs = payload.get("object_attributes")
            attrs: dict[str, Any] = raw_attrs if isinstance(raw_attrs, dict) else {}
            base_ref = attrs.get("target_branch") or attrs.get("base_ref")
            base_sha = attrs.get("target_branch_sha") or attrs.get("base_sha") or attrs.get("oldrev")
            head_ref = attrs.get("source_branch") or attrs.get("head_ref")
            raw_last_commit = attrs.get("last_commit")
            last_commit: dict[str, Any] = raw_last_commit if isinstance(raw_last_commit, dict) else {}
            head_sha = last_commit.get("id") or attrs.get("last_commit_id") or attrs.get("head_sha")
        try:
            return PRRevision(
                schemaVersion="phase8.pr-revision.v1",
                baseRef=str(base_ref or ""),
                baseSha=str(base_sha or ""),
                headRef=str(head_ref or ""),
                headSha=str(head_sha or ""),
                previousHeadSha=str(payload.get("before")) if payload.get("before") else None,
                forcePush=bool(payload.get("forced", False)),
            )
        except Exception as exc:
            raise ScmPrContextError("SCM_PR_REVISION_INCOMPLETE", status_code=422) from exc

    def _requirement_catalog(self, project_id: UUID) -> dict[str, RequirementCatalogEntry]:
        versions = list(
            self.db.scalars(
                select(RequirementVersion)
                .where(RequirementVersion.metadata_json["projectId"].as_string() == str(project_id))
                .order_by(RequirementVersion.version_no.desc(), RequirementVersion.created_at.desc())
            )
        )
        # SQLite and PostgreSQL JSON expressions above are supported by SQLAlchemy;
        # retain an in-process scope check as defense-in-depth.
        result: dict[str, RequirementCatalogEntry] = {}
        for version in versions:
            if str(version.metadata_json.get("projectId")) != str(project_id):
                continue
            metadata_items = version.metadata_json.get("requirementItems")
            raw_items = metadata_items if isinstance(metadata_items, list) else list(version.requirements or [])
            for index, item in enumerate(raw_items, start=1):
                if isinstance(item, dict):
                    requirement_id = str(item.get("id") or item.get("requirementId") or item.get("itemId") or "").strip()
                else:
                    requirement_id = str(version.metadata_json.get("requirementIds", {}).get(str(index)) or "").strip() if isinstance(version.metadata_json.get("requirementIds"), dict) else ""
                if not requirement_id:
                    continue
                result.setdefault(requirement_id.lower(), RequirementCatalogEntry(requirement_id, version.id, version.version_no, version.content_hash))
        return result

    def _extract_explicit_refs(
        self,
        project: Project,
        payload: dict[str, Any],
        catalog: dict[str, RequirementCatalogEntry],
    ) -> tuple[list[str], list[str], dict[str, list[dict[str, Any]]]]:
        texts: list[tuple[str, str]] = []
        for source, value in (("pr_template", payload.get("body")), ("pr_title", payload.get("title"))):
            if isinstance(value, str) and value:
                texts.append((source, value[:100_000]))
        prefixes = project.metadata_json.get("requirementIdPrefixes")
        prefixes = [str(item) for item in prefixes if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,15}", str(item))] if isinstance(prefixes, list) else ["REQ", "R"]
        observed: dict[str, str] = {}
        evidence: dict[str, list[dict[str, Any]]] = {}
        for item in payload.get("commitRequirementRefs") or []:
            if not isinstance(item, dict) or not item.get("id") or not item.get("contentHash"):
                continue
            requirement_id = str(item["id"])
            key = requirement_id.lower()
            catalog_entry = catalog.get(key)
            canonical = catalog_entry.requirement_id if catalog_entry is not None else requirement_id
            observed.setdefault(key, canonical)
            evidence.setdefault(canonical, []).append(
                {
                    "type": "commit_message",
                    "ref": f"scm-text-hash://{str(item['contentHash']).removeprefix('sha256:')}",
                    "contentHash": str(item["contentHash"]),
                }
            )
        for source, text in texts:
            text_hash = canonical_hash(text)
            for entry in catalog.values():
                if re.search(rf"(?<![A-Za-z0-9_-]){re.escape(entry.requirement_id)}(?![A-Za-z0-9_-])", text, flags=re.IGNORECASE):
                    observed.setdefault(entry.requirement_id.lower(), entry.requirement_id)
                    evidence.setdefault(entry.requirement_id, []).append({"type": source, "ref": f"scm-text-hash://{text_hash[7:]}", "contentHash": text_hash})
            if prefixes:
                pattern = re.compile(rf"(?<![A-Za-z0-9_-])(?:{'|'.join(re.escape(item) for item in prefixes)})-\d+(?![A-Za-z0-9_-])", re.IGNORECASE)
                for matched in pattern.findall(text):
                    key = matched.lower()
                    catalog_entry = catalog.get(key)
                    canonical = catalog_entry.requirement_id if catalog_entry is not None else matched.upper()
                    observed.setdefault(key, canonical)
                    evidence.setdefault(canonical, []).append({"type": source, "ref": f"scm-text-hash://{text_hash[7:]}", "contentHash": text_hash})
        confirmed = [value for key, value in observed.items() if key in catalog]
        unknown = [value for key, value in observed.items() if key not in catalog]
        return confirmed, unknown, evidence

    @staticmethod
    def _candidate(
        entry: RequirementCatalogEntry,
        source: str,
        confidence: float,
        status: str,
        reason_code: str,
        layer: str,
        evidence: list[dict[str, Any]],
        review_required: bool,
    ) -> RequirementMatchCandidate:
        refs = [ScmRef.model_validate(item) for item in evidence]
        return RequirementMatchCandidate.model_validate(
            {
                "requirementId": entry.requirement_id,
                "requirementVersionId": entry.version_id,
                "requirementVersion": entry.version_no,
                "source": source,
                "confidence": confidence,
                "status": status,
                "reasons": [
                    {
                        "code": reason_code,
                        "layer": layer,
                        "explanationKey": f"requirementMatch.reason.{reason_code.lower()}",
                        "evidenceRefs": refs,
                    }
                ],
                "evidenceRefs": refs,
                "modelInvocationRef": None,
                "reviewRequired": review_required,
            }
        )

    @staticmethod
    def _mapping_applies(mapping: dict[str, Any], labels: set[str], paths: list[str], payload: dict[str, Any]) -> bool:
        criteria_used = False
        if mapping.get("pullRequestNumber") is not None:
            criteria_used = True
            raw_attrs = payload.get("object_attributes")
            attrs: dict[str, Any] = raw_attrs if isinstance(raw_attrs, dict) else {}
            number = attrs.get("iid") or attrs.get("id") or payload.get("number")
            if str(number) != str(mapping["pullRequestNumber"]):
                return False
        label_values = mapping.get("labelsAny") or mapping.get("labels")
        if isinstance(label_values, list) and label_values:
            criteria_used = True
            if not labels.intersection({str(item) for item in label_values}):
                return False
        prefixes = mapping.get("pathPrefixes") or mapping.get("paths")
        if isinstance(prefixes, list) and prefixes:
            criteria_used = True
            if not any(any(path == str(prefix) or path.startswith(str(prefix).rstrip("/") + "/") for prefix in prefixes) for path in paths):
                return False
        return criteria_used or bool(mapping.get("appliesToAll", False))

    @staticmethod
    def _path_matches(path: str, pattern: str) -> bool:
        normalized = pattern.replace("\\", "/").lstrip("./")
        return fnmatch.fnmatch(path, normalized) or path == normalized or path.startswith(normalized.rstrip("/") + "/")

    @staticmethod
    def _node_matches_ref(node: CanonicalExecutionGraphNode, value: str) -> bool:
        if value in {node.node_ref, node.semantic_key, node.client_key}:
            return True
        return any(str(item.get("ref")) == value for item in node.external_refs if isinstance(item, dict))

    @staticmethod
    def _requirement_id_from_node(node: CanonicalExecutionGraphNode) -> str | None:
        for container in (node.attributes_json, node.display_metadata):
            for key in ("requirementId", "itemId", "id"):
                if container.get(key):
                    return str(container[key])
        for item in node.external_refs:
            if isinstance(item, dict) and item.get("ref"):
                return str(item["ref"]).rsplit("/", 1)[-1]
        return node.semantic_key

    @staticmethod
    def _dedupe_candidates(items: list[RequirementMatchCandidate]) -> list[RequirementMatchCandidate]:
        priority = {"explicit_reference": 0, "manual_mapping": 1, "verified_traceability": 2, "rule": 3, "history": 4, "ai_suggestion": 5}
        selected: dict[tuple[str, str], RequirementMatchCandidate] = {}
        for item in items:
            key = (item.requirementId.lower(), item.status)
            current = selected.get(key)
            if current is None or (priority[item.source], -item.confidence) < (priority[current.source], -current.confidence):
                selected[key] = item
        return sorted(selected.values(), key=lambda item: (priority[item.source], -item.confidence, item.requirementId))

    @staticmethod
    def _match_snapshot_status(candidates: list[RequirementMatchCandidate]) -> str:
        if any(item.status == "confirmed" for item in candidates):
            return "confirmed"
        candidates_only = [item for item in candidates if item.status == "candidate"]
        if not candidates_only:
            return "unknown"
        ordered = sorted(candidates_only, key=lambda item: item.confidence, reverse=True)
        if len(ordered) > 1 and ordered[0].requirementId != ordered[1].requirementId and abs(ordered[0].confidence - ordered[1].confidence) <= 0.05:
            return "conflict"
        return "candidate"

    @staticmethod
    def _changed_files(payload: dict[str, Any]) -> list[dict[str, Any]]:
        raw = payload.get("files") or payload.get("changes") or []
        result: list[dict[str, Any]] = []
        for item in raw if isinstance(raw, list) else []:
            if isinstance(item, str):
                path, change_type, previous = item, "unknown", None
            elif isinstance(item, dict):
                raw_path = item.get("filename") or item.get("new_path") or item.get("path")
                path = str(raw_path) if raw_path else ""
                previous = item.get("previous_filename") or item.get("old_path")
                native_status = str(item.get("status") or "unknown").lower()
                change_type = {"added": "added", "new": "added", "modified": "modified", "changed": "modified", "removed": "deleted", "deleted": "deleted", "renamed": "renamed", "copied": "copied"}.get(native_status, "renamed" if item.get("renamed_file") else "unknown")
            else:
                continue
            if not path:
                continue
            try:
                from agentic_qa.schemas.scm_pr import ChangedFile

                result.append(
                    ChangedFile.model_validate(
                        {
                            "path": str(path),
                            "changeType": change_type,
                            "previousPath": str(previous) if previous else None,
                        }
                    ).model_dump(mode="json")
                )
            except Exception:
                continue
        return result[:50_000]

    @staticmethod
    def _diff_from_snapshot(payload: dict[str, Any]) -> str | None:
        if isinstance(payload.get("diff"), str):
            return payload["diff"]
        changes = payload.get("changes")
        if isinstance(changes, list):
            parts = [str(item.get("diff")) for item in changes if isinstance(item, dict) and item.get("diff")]
            return "\n".join(parts) if parts else None
        return None

    @classmethod
    def _redacted_diff(cls, payload: dict[str, Any]) -> str | None:
        value = cls._diff_from_snapshot(payload)
        return redact_sensitive_text(value) if value else None

    def _load_diff_from_snapshot(self, payload: dict[str, Any]) -> str | None:
        artifact = payload.get("diffArtifact")
        if not isinstance(artifact, dict) or not artifact.get("storageRef"):
            return None
        try:
            encoded = self.storage.read_artifact(str(artifact["storageRef"]))
            if "sha256:" + hashlib.sha256(encoded).hexdigest() != artifact.get("contentHash"):
                raise ScmPrContextError("SCM_WEBHOOK_DIFF_ARTIFACT_HASH_MISMATCH", status_code=409)
            return encoded.decode("utf-8")
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise ScmPrContextError("SCM_WEBHOOK_DIFF_ARTIFACT_UNAVAILABLE", status_code=409) from exc

    @staticmethod
    def _labels(payload: dict[str, Any]) -> list[str]:
        result: list[str] = []
        for item in payload.get("labels") or []:
            value = item.get("name") or item.get("title") if isinstance(item, dict) else item
            if value:
                redacted = redact_sensitive_text(str(value))[:255]
                if redacted and redacted not in result:
                    result.append(redacted)
        return result[:200]

    @staticmethod
    def _draft(payload: dict[str, Any]) -> bool:
        raw_attrs = payload.get("object_attributes")
        attrs: dict[str, Any] = raw_attrs if isinstance(raw_attrs, dict) else {}
        return bool(payload.get("draft") or attrs.get("draft") or str(payload.get("title") or attrs.get("title") or "").lower().startswith(("draft:", "wip:")))

    @staticmethod
    def _state(payload: dict[str, Any], action: str) -> str:
        raw_attrs = payload.get("object_attributes")
        attrs: dict[str, Any] = raw_attrs if isinstance(raw_attrs, dict) else {}
        if bool(payload.get("merged")) or action == "merged" or attrs.get("state") == "merged":
            return "merged"
        value = str(payload.get("state") or attrs.get("state") or "unknown").lower()
        if action == "closed" or value == "closed":
            return "closed"
        if value in {"open", "opened", "reopened"} or action in {"opened", "reopened", "synchronize", "sync", "update"}:
            return "open"
        return "unknown"

    @staticmethod
    def _author_ref(provider: str, payload: dict[str, Any]) -> str:
        raw_user = payload.get("user")
        user: dict[str, Any] = raw_user if isinstance(raw_user, dict) else {}
        stable = user.get("id") or user.get("user_id")
        if stable:
            return f"{provider}://author/{stable}"
        login = str(user.get("username") or user.get("login") or "unknown")
        return f"{provider}://author-hash/{canonical_hash(login)[7:39]}"

    @staticmethod
    def _is_fork(payload: dict[str, Any]) -> bool:
        raw_base = payload.get("base")
        base: dict[str, Any] = raw_base if isinstance(raw_base, dict) else {}
        raw_head = payload.get("head")
        head: dict[str, Any] = raw_head if isinstance(raw_head, dict) else {}
        raw_base_repo = base.get("repo")
        base_repo: dict[str, Any] = raw_base_repo if isinstance(raw_base_repo, dict) else {}
        raw_head_repo = head.get("repo")
        head_repo: dict[str, Any] = raw_head_repo if isinstance(raw_head_repo, dict) else {}
        return bool(base_repo.get("id") and head_repo.get("id") and str(base_repo["id"]) != str(head_repo["id"]))

    def _record_webhook_preflight(
        self,
        scope: ScmProjectScope,
        binding: SkillConnectorBinding,
        envelope: WebhookEnvelope,
        context: ServiceContext,
    ) -> list[dict[str, Any]]:
        self.guardrails.record_result(
            GuardrailContext(
                trace_id=context.trace_id,
                request_id=context.request_id,
                actor_id=context.user.id,
                actor_roles=context.user.roles,
                resource_type="scm_webhook",
                resource_id=envelope.deliveryId,
                connector_binding_id=binding.id,
                payload={
                    "provider": envelope.provider,
                    "projectId": str(scope.project.id),
                    "repositoryRef": scope.repository_ref,
                    "payloadHash": envelope.payloadHash,
                    "signatureVerified": True,
                    "repositoryBindingVerified": True,
                    "tenantDerivedFromBinding": True,
                    "rawPayloadPersisted": False,
                    "writesGate": False,
                    "createsExecution": False,
                },
            ),
            GuardrailResult(
                rule_id="scm.webhook.preflight.v1",
                decision=GuardrailDecision.ALLOW,
                reason="Signature, time window, project scope, and repository binding were verified.",
                evidence=[f"scm-delivery://{envelope.provider}/{envelope.deliveryId}"],
                metadata={"backendAuthorization": True, "externalPayloadTrustedForScope": False},
            ),
        )
        self.db.flush()
        event = self.db.scalar(select(GuardrailEvent).where(GuardrailEvent.trace_id == UUID(str(context.trace_id))).order_by(GuardrailEvent.created_at.desc()))
        return [{"type": "guardrail_event", "ref": f"guardrail-event://{event.id}", "contentHash": None}] if event else []

    def _write_delivery_conflict_audit(self, receipt: ScmWebhookReceipt, context: ServiceContext, payload_hash: str) -> None:
        write_audit_log(
            self.db,
            context.user.id,
            "scm.webhook.delivery_conflict",
            "scm_webhook_receipt",
            str(receipt.id),
            context.request_id,
            context.trace_id,
            details={"deliveryId": receipt.delivery_id, "existingPayloadHash": receipt.payload_hash, "receivedPayloadHash": payload_hash},
        )

    def _recover_delivery_race(
        self,
        binding: SkillConnectorBinding,
        envelope: WebhookEnvelope,
        idempotency_key: str,
        diff_storage_ref: str | None,
        exc: IntegrityError,
    ) -> dict[str, Any]:
        self.db.rollback()
        if diff_storage_ref:
            try:
                self.storage.delete_artifact(diff_storage_ref)
            except (OSError, ValueError):
                pass
        recovered = self.db.scalar(
            select(ScmWebhookReceipt).where(
                ScmWebhookReceipt.connector_binding_id == binding.id,
                ScmWebhookReceipt.provider == envelope.provider,
                ScmWebhookReceipt.delivery_id == envelope.deliveryId,
            )
        )
        if (
            recovered is not None
            and recovered.payload_hash == envelope.payloadHash
            and recovered.idempotency_key == idempotency_key
        ):
            return self._receipt_projection(recovered, duplicate=True)
        raise ScmPrContextError("SCM_WEBHOOK_DELIVERY_CONFLICT", status_code=409) from exc

    def _fail_receipt(self, receipt: ScmWebhookReceipt, code: str) -> None:
        receipt.status = "failed"
        receipt.error_code = code
        self.db.commit()

    @staticmethod
    def _system_context(request_id: str, trace_id: str) -> ServiceContext:
        return ServiceContext(
            user=CurrentUser(
                id=DEMO_ADMIN_ID,
                name="scm-webhook-service",
                email="scm-webhook-service@example.invalid",
                roles=["system"],
                edition="enterprise",
                capabilities=["webhook.service", "change.create", "pr.read", "match.review"],
            ),
            request_id=request_id,
            trace_id=trace_id,
        )

    @staticmethod
    def _utc(value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    @staticmethod
    def _audit_ref(audit: AuditLog) -> dict[str, Any]:
        return {"type": "audit_log", "ref": f"audit-log://{audit.id}", "contentHash": None}

    @staticmethod
    def _receipt_projection(receipt: ScmWebhookReceipt, *, duplicate: bool) -> dict[str, Any]:
        return {
            "receiptId": str(receipt.id),
            "status": receipt.status,
            "provider": receipt.provider,
            "deliveryId": receipt.delivery_id,
            "projectId": str(receipt.project_id),
            "repositoryRef": receipt.repository_ref,
            "pullRequestNumber": receipt.pull_request_number,
            "headSha": receipt.head_sha,
            "prContextVersionId": str(receipt.pr_context_version_id) if receipt.pr_context_version_id else None,
            "duplicate": duplicate,
            "signatureVerified": True,
            "queued": receipt.status == "queued",
            "gateDecisionCreated": False,
            "executionCreated": False,
        }

    @staticmethod
    def _context_summary(row: ScmPrContextRecord) -> dict[str, Any]:
        return {
            "contextId": str(row.id),
            "projectId": str(row.project_id),
            "provider": row.provider,
            "repositoryRef": row.repository_ref,
            "repositoryNativeId": row.repository_native_id,
            "pullRequestNumber": row.pull_request_number,
            "state": row.state,
            "latestVersion": row.latest_version,
            "headSha": row.latest_head_sha,
            "providerEventAt": row.latest_provider_event_at.isoformat(),
            "updatedAt": row.updated_at.isoformat(),
            "readOnly": True,
        }

    def _detail_by_version(self, project_id: UUID, version_id: UUID) -> dict[str, Any]:
        version = self.db.get(ScmPrContextVersionRecord, version_id)
        if version is None:
            raise ScmPrContextError("PR_CONTEXT_VERSION_NOT_FOUND", status_code=404)
        context = self.db.get(ScmPrContextRecord, version.context_id)
        if context is None or context.project_id != project_id:
            raise ScmPrContextError("PR_CONTEXT_VERSION_NOT_FOUND", status_code=404)
        return self._detail_projection(version)

    def _detail_projection(self, version: ScmPrContextVersionRecord) -> dict[str, Any]:
        snapshot = self.db.scalar(select(RequirementMatchSnapshotRecord).where(RequirementMatchSnapshotRecord.pr_context_version_id == version.id))
        match_projection = None
        if snapshot is not None:
            rows = list(self.db.scalars(select(RequirementMatchRecord).where(RequirementMatchRecord.snapshot_id == snapshot.id).order_by(RequirementMatchRecord.ordinal)))
            matches = []
            for row in rows:
                version_row = self.db.get(RequirementVersion, row.requirement_version_id) if row.requirement_version_id else None
                candidate = RequirementMatchCandidate.model_validate(
                    {
                        "requirementId": row.requirement_id,
                        "requirementVersionId": row.requirement_version_id,
                        "requirementVersion": version_row.version_no if version_row else None,
                        "source": row.source,
                        "confidence": float(row.confidence),
                        "status": row.status,
                        "reasons": row.reasons,
                        "evidenceRefs": row.evidence_refs,
                        "modelInvocationRef": row.model_invocation_ref,
                        "reviewRequired": row.review_required,
                    }
                )
                matches.append(RequirementMatch(schemaVersion="phase8.requirement-match.v1", matchId=row.id, prContextVersionId=version.id, candidate=candidate, matchHash=row.match_hash, createdAt=row.created_at).model_dump(mode="json"))
            match_projection = RequirementMatchSnapshot.model_validate(
                {
                    "schemaVersion": "phase8.requirement-match-snapshot.v1",
                    "snapshotId": snapshot.id,
                    "prContextVersionId": version.id,
                    "algorithmVersion": REQUIREMENT_MATCH_ALGORITHM_VERSION,
                    "status": snapshot.status,
                    "matches": matches,
                    "explicitUnknownRefs": snapshot.explicit_unknown_refs,
                    "modelInvocationRefs": snapshot.model_invocation_refs,
                    "guardrailEventRefs": snapshot.guardrail_event_refs,
                    "auditRefs": snapshot.audit_refs,
                    "snapshotHash": snapshot.snapshot_hash,
                    "createdAt": snapshot.created_at,
                    "reviewRequired": snapshot.review_required,
                    "readOnly": True,
                    "gateDecision": None,
                    "executionCreated": False,
                }
            ).model_dump(mode="json")
        return {
            "context": dict(version.context_snapshot),
            "requirementMatch": match_projection,
            "p21Input": {
                "prContextVersionRef": {"type": "pr_context_version", "ref": f"pr-context-version://{version.id}", "contentHash": version.context_hash},
                "requirementMatchSnapshotRef": {"type": "requirement_match_snapshot", "ref": f"requirement-match-snapshot://{snapshot.id}", "contentHash": snapshot.snapshot_hash} if snapshot else None,
                "changeSetRef": version.context_snapshot.get("changeSetRef"),
                "baseSha": version.base_sha,
                "headSha": version.head_sha,
            },
            "readOnly": True,
            "admissionImplemented": True,
            "gateDecisionCreated": False,
            "executionCreated": False,
        }


__all__ = ["ScmPrContextError", "ScmPrContextService"]
