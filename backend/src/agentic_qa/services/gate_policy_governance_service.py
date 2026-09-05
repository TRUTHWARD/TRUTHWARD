# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from agentic_qa.domain.enums import ApprovalStatus, GatePolicyStatus
from agentic_qa.domain.models import (
    Approval,
    AuditLog,
    GatePolicy,
    GatePolicyGovernanceRequest,
    GatePolicyVersion,
    GuardrailEvent,
    Project,
)
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.result import GuardrailViolationError
from agentic_qa.guardrails.runtime.audit import RuntimeGuardrailEngine
from agentic_qa.guardrails.runtime.gate_policy import GatePolicyMutationGuard
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.trace import traced_operation
from agentic_qa.schemas.gate_policy import validate_gate_policy_document
from agentic_qa.schemas.gate_policy_governance import (
    CreateGatePolicyDraftRequest,
    GatePolicyLifecycleRequest,
    GatePolicyListProjection,
    GatePolicyProjection,
    GatePolicyReviewDecisionRequest,
    GatePolicyValidationProjection,
    GatePolicyVersionProjection,
    SubmitGatePolicyReviewRequest,
    UpdateGatePolicyDraftRequest,
)
from agentic_qa.services.approval_service import ApprovalConflictError, ApprovalService
from agentic_qa.services.common import ServiceContext, acquire_transaction_advisory_lock, canonical_hash
from agentic_qa.services.gate_policy_repository import GatePolicyRepository
from agentic_qa.services.gate_policy_import_service import GatePolicyImportService
from agentic_qa.services.gate_policy_service import GatePolicyDataError, GatePolicyService
from agentic_qa.services.scope_service import ScopeAuthorizationError, ScopeAuthorizationService


CAPABILITY_READ = "gate_policy.read"
CAPABILITY_DRAFT_WRITE = "gate_policy.draft.write"
CAPABILITY_SUBMIT = "gate_policy.submit"
CAPABILITY_REVIEW = "gate_policy.review"
CAPABILITY_LIFECYCLE = "gate_policy.lifecycle.manage"

PENDING_GOVERNANCE_STATES = frozenset({"review_pending", "transition_pending"})
LIFECYCLE_TRANSITIONS: dict[str, frozenset[str]] = {
    "draft": frozenset({"archived"}),
    "active": frozenset({"disabled", "deprecated"}),
    "disabled": frozenset({"deprecated", "archived"}),
    "deprecated": frozenset({"archived"}),
    "archived": frozenset(),
}


class GatePolicyGovernanceError(ValueError):
    """Stable API-safe error emitted by the Gate Policy governance boundary."""

    def __init__(
        self,
        code: str,
        *,
        status_code: int,
        field: str | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        self.code = code
        self.status_code = status_code
        self.field = field
        self.details = details or {}
        super().__init__(code)

    def as_dict(self) -> dict[str, object]:
        return {"errorCode": self.code, "field": self.field, "details": dict(self.details)}


class GatePolicyGovernanceService:
    """Project-scoped, capability-enforced Gate Policy governance workflow.

    The service manages declarative policy drafts and review/lifecycle facts. It
    never evaluates Gate inputs, creates Skill Invocations, activates a policy,
    rewrites Replay snapshots, or writes Gate decisions.
    """

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repository = GatePolicyRepository(db)
        self.data_service = GatePolicyService(db, self.repository)

    def list_policies(
        self,
        *,
        project_id: UUID,
        page: int,
        page_size: int,
        status_filter: str | None,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_READ)
        _project, tenant_id, workspace_id = self._project_scope(project_id, context, write=False)
        if status_filter is not None and status_filter not in {item.value for item in GatePolicyStatus}:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_STATUS_INVALID",
                status_code=422,
                field="status",
            )
        policies = self.repository.list_policies_for_project(
            tenant_id,
            workspace_id,
            project_id,
            status=status_filter,
        )
        start = (page - 1) * page_size
        projection = GatePolicyListProjection(
            items=[
                GatePolicyProjection.model_validate(
                    self._policy_projection(item, include_document=False)
                )
                for item in policies[start : start + page_size]
            ],
            total=len(policies),
            page=page,
            pageSize=page_size,
            readOnly=CAPABILITY_DRAFT_WRITE not in set(context.user.capabilities),
            executesGate=False,
        )
        return projection.model_dump(mode="json")

    def get_policy(
        self,
        *,
        project_id: UUID,
        policy_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_READ)
        policy, _tenant_id, _workspace_id = self._scoped_policy(project_id, policy_id, context, write=False)
        return self._policy_projection(policy, include_document=False)

    def get_version(
        self,
        *,
        project_id: UUID,
        policy_id: UUID,
        version_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_READ)
        version = self._scoped_version(project_id, policy_id, version_id, context, write=False)
        return self._version_projection(version, include_document=True)

    def get_validation(
        self,
        *,
        project_id: UUID,
        policy_id: UUID,
        version_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_READ)
        version = self._scoped_version(project_id, policy_id, version_id, context, write=False)
        return self._validation_projection(version)

    def preview_import(
        self,
        *,
        project_id: UUID,
        content: bytes,
        format_hint: str,
        policy_id: UUID | None,
        version_id: UUID | None,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_DRAFT_WRITE)
        _project, tenant_id, workspace_id = self._project_scope(project_id, context, write=True)
        baseline: dict[str, Any] | None = None
        resource_id = project_id
        if (policy_id is None) != (version_id is None):
            raise GatePolicyGovernanceError("GATE_POLICY_IMPORT_BASELINE_INCOMPLETE", status_code=422)
        if policy_id is not None and version_id is not None:
            version = self._scoped_version(project_id, policy_id, version_id, context, write=False)
            baseline = version.policy_snapshot
            resource_id = version.id
        self._preflight(
            context,
            action="preview_import",
            resource_type="gate_policy_version" if version_id else "project",
            resource_id=resource_id,
            payload={"format": format_hint, "byteSize": len(content)},
        )
        with self._trace(
            context,
            "gate_policy.import.preview",
            {"projectId": str(project_id), "format": format_hint, "byteSize": len(content)},
        ):
            preview = GatePolicyImportService().parse_and_validate(
                content,
                format_hint=format_hint,
                baseline=baseline,
            )
            write_audit_log(
                self.db,
                context.user.id,
                "gate_policy.import.preview",
                "gate_policy_version" if version_id else "project",
                str(resource_id),
                context.request_id,
                context.trace_id,
                details={
                    "actorId": str(context.user.id),
                    "projectId": str(project_id),
                    "tenantId": tenant_id,
                    "workspaceId": workspace_id,
                    "format": preview["format"],
                    "byteSize": len(content),
                    "contentHash": preview["contentHash"],
                    "valid": preview["valid"],
                    "validationIssueCount": len(preview["validationIssues"]),
                    "result": "previewed",
                },
            )
        self.db.commit()
        return preview

    def create_draft(
        self,
        *,
        project_id: UUID,
        payload: CreateGatePolicyDraftRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_DRAFT_WRITE)
        _project, tenant_id, workspace_id = self._project_scope(project_id, context, write=True)
        normalized = self._validate_candidate(payload.document)
        identity = normalized["identity"]
        version_identity = normalized["version"]
        policy_id = self._uuid(identity["policyId"], "document.identity.policyId")
        version_id = self._uuid(version_identity["versionId"], "document.version.versionId")
        self._require_document_scope(normalized, tenant_id, workspace_id)
        content_hash = canonical_hash(normalized)
        if payload.expectedContentHash is not None and payload.expectedContentHash != content_hash:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_HASH_MISMATCH",
                status_code=409,
                field="expectedContentHash",
            )
        idempotency_key = self._idempotency_key(payload.idempotencyKey)
        request_hash = canonical_hash(
            {
                "projectId": str(project_id),
                "document": normalized,
                "expectedContentHash": payload.expectedContentHash,
            }
        )
        acquire_transaction_advisory_lock(
            self.db,
            "gate-policy-governance",
            f"{tenant_id}:{workspace_id}:create_draft:{idempotency_key}",
        )
        existing_request = self.repository.find_governance_request(
            tenant_id,
            workspace_id,
            "create_draft",
            idempotency_key,
        )
        if existing_request is not None:
            self._require_same_idempotent_request(existing_request, request_hash, str(policy_id))
            policy = self.repository.find_policy_for_project(
                tenant_id,
                workspace_id,
                project_id,
                policy_id,
            )
            if policy is None:
                raise GatePolicyGovernanceError("GATE_POLICY_IDEMPOTENCY_RECORD_INVALID", status_code=409)
            return {**self._policy_projection(policy, include_document=False), "deduplicated": True}

        self._preflight(
            context,
            action="create_draft",
            resource_type="gate_policy_version",
            resource_id=version_id,
            payload={"documentStatus": normalized.get("status"), "contentHash": content_hash},
        )
        try:
            with self._trace(
                context,
                "gate_policy.create_draft",
                {"projectId": str(project_id), "policyId": str(policy_id), "versionId": str(version_id)},
            ):
                policy = self.data_service.create_policy(
                    tenant_id=tenant_id,
                    workspace_id=workspace_id,
                    project_id=project_id,
                    policy_key=str(identity["policyKey"]),
                    name=str(identity["name"]),
                    description=identity.get("description"),
                    actor_id=context.user.id,
                    policy_id=policy_id,
                    commit=False,
                )
                version = self.data_service.create_version(
                    tenant_id=tenant_id,
                    workspace_id=workspace_id,
                    policy_id=policy.id,
                    document=normalized,
                    expected_content_hash=content_hash,
                    actor_id=context.user.id,
                    commit=False,
                )
                self.repository.add(
                    self._governance_request(
                        tenant_id=tenant_id,
                        workspace_id=workspace_id,
                        project_id=project_id,
                        operation="create_draft",
                        idempotency_key=idempotency_key,
                        request_hash=request_hash,
                        resource_type="gate_policy",
                        resource_id=policy.id,
                        context=context,
                    )
                )
                self._audit_version_mutation(
                    action="gate_policy.draft.create",
                    project_id=project_id,
                    version=version,
                    before_hash=None,
                    after_hash=version.content_hash,
                    before_version=None,
                    after_version=version.lock_version,
                    before_status=None,
                    after_status=version.status.value,
                    approval_ids=[],
                    result="created",
                    context=context,
                )
            self.db.commit()
            return self._policy_projection(policy, include_document=False)
        except GatePolicyDataError as exc:
            self.db.rollback()
            raise self._from_data_error(exc) from exc
        except (IntegrityError, StaleDataError) as exc:
            self.db.rollback()
            raise GatePolicyGovernanceError("GATE_POLICY_CONFLICT", status_code=409) from exc
        except Exception:
            self.db.rollback()
            raise

    def update_draft(
        self,
        *,
        project_id: UUID,
        policy_id: UUID,
        version_id: UUID,
        payload: UpdateGatePolicyDraftRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_DRAFT_WRITE)
        policy, tenant_id, workspace_id = self._scoped_policy(project_id, policy_id, context, write=True)
        version = self.repository.find_version_for_policy(
            tenant_id,
            workspace_id,
            policy.id,
            version_id,
            for_update=True,
        )
        if version is None:
            raise GatePolicyGovernanceError("GATE_POLICY_VERSION_NOT_FOUND", status_code=404)
        self._require_lock(version, payload.expectedVersion)
        if version.status != GatePolicyStatus.DRAFT:
            raise GatePolicyGovernanceError("GATE_POLICY_VERSION_IMMUTABLE", status_code=409)
        if self._effective_governance_status(version) in PENDING_GOVERNANCE_STATES:
            raise GatePolicyGovernanceError("GATE_POLICY_REVIEW_PENDING", status_code=409)
        normalized = self._validate_candidate(payload.document)
        self._require_document_scope(normalized, tenant_id, workspace_id)
        self._preflight(
            context,
            action="update_draft",
            resource_type="gate_policy_version",
            resource_id=version.id,
            payload={"documentStatus": normalized.get("status"), "contentHash": canonical_hash(normalized)},
        )
        before_hash = version.content_hash
        before_version = version.lock_version
        try:
            with self._trace(
                context,
                "gate_policy.update_draft",
                {"projectId": str(project_id), "policyId": str(policy.id), "versionId": str(version.id)},
            ):
                version = self.data_service.update_draft_version(
                    tenant_id=tenant_id,
                    workspace_id=workspace_id,
                    version_id=version.id,
                    expected_lock_version=payload.expectedVersion,
                    document=normalized,
                    expected_content_hash=payload.expectedContentHash,
                    actor_id=context.user.id,
                    commit=False,
                )
                self._audit_version_mutation(
                    action="gate_policy.draft.update",
                    project_id=project_id,
                    version=version,
                    before_hash=before_hash,
                    after_hash=version.content_hash,
                    before_version=before_version,
                    after_version=version.lock_version,
                    before_status=GatePolicyStatus.DRAFT.value,
                    after_status=version.status.value,
                    approval_ids=[],
                    result="updated",
                    context=context,
                )
            self.db.commit()
            return self._version_projection(version, include_document=True)
        except GatePolicyDataError as exc:
            self.db.rollback()
            raise self._from_data_error(exc) from exc
        except Exception:
            self.db.rollback()
            raise

    def validate_draft(
        self,
        *,
        project_id: UUID,
        policy_id: UUID,
        version_id: UUID,
        expected_version: int,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_DRAFT_WRITE)
        policy, tenant_id, workspace_id = self._scoped_policy(project_id, policy_id, context, write=True)
        version = self.repository.find_version_for_policy(
            tenant_id,
            workspace_id,
            policy.id,
            version_id,
            for_update=True,
        )
        if version is None:
            raise GatePolicyGovernanceError("GATE_POLICY_VERSION_NOT_FOUND", status_code=404)
        self._require_lock(version, expected_version)
        if version.status != GatePolicyStatus.DRAFT:
            raise GatePolicyGovernanceError("GATE_POLICY_VERSION_IMMUTABLE", status_code=409)
        if self._effective_governance_status(version) in PENDING_GOVERNANCE_STATES:
            raise GatePolicyGovernanceError("GATE_POLICY_REVIEW_PENDING", status_code=409)
        self._preflight(
            context,
            action="validate",
            resource_type="gate_policy_version",
            resource_id=version.id,
            payload={"contentHash": version.content_hash},
        )
        now = datetime.now(timezone.utc)
        issues: list[dict[str, object]] = []
        try:
            normalized = validate_gate_policy_document(version.policy_snapshot)
            if canonical_hash(normalized) != version.content_hash:
                issues.append(
                    {
                        "errorCode": "GATE_POLICY_HASH_MISMATCH",
                        "field": "contentHash",
                        "issueType": "integrity_error",
                    }
                )
        except ValidationError as exc:
            first = exc.errors(include_url=False, include_input=False)[0]
            issues.append(
                {
                    "errorCode": "GATE_POLICY_SCHEMA_INVALID",
                    "field": ".".join(str(item) for item in first.get("loc", ())) or None,
                    "issueType": str(first.get("type") or "validation_error"),
                }
            )
        validation_status = "invalid" if issues else "valid"
        before_version = version.lock_version
        try:
            with self._trace(
                context,
                "gate_policy.validate",
                {"projectId": str(project_id), "policyId": str(policy.id), "versionId": str(version.id)},
            ):
                version.validation_status = validation_status
                version.validated_at = now
                version.validated_by = context.user.id
                version.validation_report = {
                    "schemaVersion": "phase8.gate-policy-validation.v1",
                    "status": validation_status,
                    "contentHash": version.content_hash,
                    "validatedAt": now.isoformat(),
                    "validatedBy": str(context.user.id),
                    "errors": issues,
                    "warnings": [],
                    "writesGateDecision": False,
                }
                version.updated_by = context.user.id
                self.db.flush()
                self._audit_version_mutation(
                    action="gate_policy.draft.validate",
                    project_id=project_id,
                    version=version,
                    before_hash=version.content_hash,
                    after_hash=version.content_hash,
                    before_version=before_version,
                    after_version=version.lock_version,
                    before_status=version.status.value,
                    after_status=version.status.value,
                    approval_ids=[],
                    result=validation_status,
                    context=context,
                )
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        projection = self._validation_projection(version)
        if issues:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_VALIDATION_FAILED",
                status_code=422,
                details={"validation": projection},
            )
        return projection

    def submit_review(
        self,
        *,
        project_id: UUID,
        policy_id: UUID,
        version_id: UUID,
        payload: SubmitGatePolicyReviewRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_SUBMIT)
        policy, tenant_id, workspace_id = self._scoped_policy(project_id, policy_id, context, write=True)
        version = self.repository.find_version_for_policy(
            tenant_id,
            workspace_id,
            policy.id,
            version_id,
            for_update=True,
        )
        if version is None:
            raise GatePolicyGovernanceError("GATE_POLICY_VERSION_NOT_FOUND", status_code=404)
        idempotency_key = self._idempotency_key(payload.idempotencyKey)
        request_hash = canonical_hash(
            {"versionId": str(version.id), "contentHash": version.content_hash, "reason": payload.reason}
        )
        acquire_transaction_advisory_lock(
            self.db,
            "gate-policy-governance",
            f"{tenant_id}:{workspace_id}:submit_review:{idempotency_key}",
        )
        existing_request = self.repository.find_governance_request(
            tenant_id,
            workspace_id,
            "submit_review",
            idempotency_key,
        )
        if existing_request is not None:
            self._require_same_idempotent_request(existing_request, request_hash, str(version.id))
            return {**self._version_projection(version, include_document=False), "deduplicated": True}
        self._require_lock(version, payload.expectedVersion)
        if version.status != GatePolicyStatus.DRAFT:
            raise GatePolicyGovernanceError("GATE_POLICY_VERSION_IMMUTABLE", status_code=409)
        if version.validation_status != "valid" or version.validation_report.get("contentHash") != version.content_hash:
            raise GatePolicyGovernanceError("GATE_POLICY_VALIDATION_REQUIRED", status_code=422)
        if self._effective_governance_status(version) in PENDING_GOVERNANCE_STATES:
            raise GatePolicyGovernanceError("GATE_POLICY_REVIEW_PENDING", status_code=409)
        self._preflight(
            context,
            action="submit_review",
            resource_type="gate_policy_version",
            resource_id=version.id,
            payload={"contentHash": version.content_hash},
        )
        before_version = version.lock_version
        try:
            with self._trace(
                context,
                "gate_policy.submit_review",
                {"projectId": str(project_id), "policyId": str(policy.id), "versionId": str(version.id)},
            ):
                approval_result = ApprovalService(self.db).request_gate_policy_review(
                    project_id=project_id,
                    tenant_id=tenant_id,
                    workspace_id=workspace_id,
                    policy_id=policy.id,
                    version_id=version.id,
                    content_hash=version.content_hash,
                    reason=payload.reason,
                    context=context,
                    commit=False,
                )
                approval_id = UUID(str(approval_result["approvalId"]))
                version.governance_status = "review_pending"
                version.current_approval_id = approval_id
                version.submitted_at = datetime.now(timezone.utc)
                version.submitted_by = context.user.id
                version.updated_by = context.user.id
                request_record = self._governance_request(
                    tenant_id=tenant_id,
                    workspace_id=workspace_id,
                    project_id=project_id,
                    operation="submit_review",
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    resource_type="gate_policy_version",
                    resource_id=version.id,
                    context=context,
                    approval_id=approval_id,
                )
                self.repository.add(request_record)
                self.db.flush()
                self._audit_version_mutation(
                    action="gate_policy.review.submit",
                    project_id=project_id,
                    version=version,
                    before_hash=version.content_hash,
                    after_hash=version.content_hash,
                    before_version=before_version,
                    after_version=version.lock_version,
                    before_status="draft",
                    after_status="review_pending",
                    approval_ids=[approval_id],
                    result="pending",
                    context=context,
                )
            self.db.commit()
            return self._version_projection(version, include_document=False)
        except (ApprovalConflictError, IntegrityError, StaleDataError) as exc:
            self.db.rollback()
            raise GatePolicyGovernanceError("GATE_POLICY_REVIEW_CONFLICT", status_code=409) from exc
        except Exception:
            self.db.rollback()
            raise

    def decide_review(
        self,
        *,
        project_id: UUID,
        policy_id: UUID,
        version_id: UUID,
        payload: GatePolicyReviewDecisionRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_REVIEW)
        version = self._scoped_version(project_id, policy_id, version_id, context, write=True, for_update=True)
        self._require_lock(version, payload.expectedVersion)
        if version.current_approval_id != payload.approvalId:
            raise GatePolicyGovernanceError("GATE_POLICY_APPROVAL_MISMATCH", status_code=409)
        approval = self.db.get(Approval, payload.approvalId)
        if approval is None or approval.resource_id != str(version.id) or approval.resource_type not in {
            "gate_policy_version_review",
            "gate_policy_version_lifecycle",
        }:
            raise GatePolicyGovernanceError("GATE_POLICY_APPROVAL_NOT_FOUND", status_code=404)
        if approval.status != ApprovalStatus.PENDING:
            raise GatePolicyGovernanceError("GATE_POLICY_APPROVAL_NOT_PENDING", status_code=409)
        self._preflight(
            context,
            action="review_decision",
            resource_type="gate_policy_version",
            resource_id=version.id,
            payload={"approvalId": str(approval.id), "decision": payload.decision},
        )
        approval_service = ApprovalService(self.db)
        try:
            with self._trace(
                context,
                "gate_policy.review_decision",
                {"projectId": str(project_id), "versionId": str(version.id), "decision": payload.decision},
            ):
                if payload.decision == "approve":
                    approval_result = approval_service.approve(approval.id, payload.comment, context)
                else:
                    approval_result = approval_service.reject(approval.id, payload.comment, context)
                    version.governance_status = (
                        "review_rejected"
                        if approval.resource_type == "gate_policy_version_review"
                        else "transition_rejected"
                    )
                    version.updated_by = context.user.id
                    self.db.flush()
                    self._audit_version_mutation(
                        action="gate_policy.review.reject",
                        project_id=project_id,
                        version=version,
                        before_hash=version.content_hash,
                        after_hash=version.content_hash,
                        before_version=payload.expectedVersion,
                        after_version=version.lock_version,
                        before_status="pending",
                        after_status=version.governance_status,
                        approval_ids=[approval.id],
                        result="rejected",
                        context=context,
                    )
                    self.db.commit()
            self.db.commit()
            refreshed = self._scoped_version(project_id, policy_id, version_id, context, write=True)
            return {
                "version": self._version_projection(refreshed, include_document=False),
                "approval": approval_result,
                "activatesProduction": False,
            }
        except GatePolicyGovernanceError:
            self.db.rollback()
            raise
        except ApprovalConflictError as exc:
            self.db.rollback()
            raise GatePolicyGovernanceError("GATE_POLICY_REVIEW_CONFLICT", status_code=409) from exc
        except Exception:
            self.db.rollback()
            raise

    def request_lifecycle_transition(
        self,
        *,
        project_id: UUID,
        policy_id: UUID,
        version_id: UUID,
        payload: GatePolicyLifecycleRequest,
        context: ServiceContext,
    ) -> dict[str, object]:
        self._require_capability(context, CAPABILITY_LIFECYCLE)
        policy, tenant_id, workspace_id = self._scoped_policy(project_id, policy_id, context, write=True)
        version = self.repository.find_version_for_policy(
            tenant_id,
            workspace_id,
            policy.id,
            version_id,
            for_update=True,
        )
        if version is None:
            raise GatePolicyGovernanceError("GATE_POLICY_VERSION_NOT_FOUND", status_code=404)
        idempotency_key = self._idempotency_key(payload.idempotencyKey)
        request_hash = canonical_hash(
            {
                "versionId": str(version.id),
                "contentHash": version.content_hash,
                "currentStatus": version.status.value,
                "targetStatus": payload.targetStatus,
                "reason": payload.reason,
            }
        )
        acquire_transaction_advisory_lock(
            self.db,
            "gate-policy-governance",
            f"{tenant_id}:{workspace_id}:lifecycle_transition:{idempotency_key}",
        )
        existing_request = self.repository.find_governance_request(
            tenant_id,
            workspace_id,
            "lifecycle_transition",
            idempotency_key,
        )
        if existing_request is not None:
            self._require_same_idempotent_request(existing_request, request_hash, str(version.id))
            return {**self._version_projection(version, include_document=False), "deduplicated": True}
        self._require_lock(version, payload.expectedVersion)
        self._require_lifecycle_transition(version.status.value, payload.targetStatus)
        if self._effective_governance_status(version) in PENDING_GOVERNANCE_STATES:
            raise GatePolicyGovernanceError("GATE_POLICY_REVIEW_PENDING", status_code=409)
        self._preflight(
            context,
            action="lifecycle_transition",
            resource_type="gate_policy_version",
            resource_id=version.id,
            payload={"currentStatus": version.status.value, "targetStatus": payload.targetStatus},
        )
        before_version = version.lock_version
        try:
            with self._trace(
                context,
                "gate_policy.lifecycle_request",
                {
                    "projectId": str(project_id),
                    "versionId": str(version.id),
                    "targetStatus": payload.targetStatus,
                },
            ):
                approval_result = ApprovalService(self.db).request_gate_policy_lifecycle(
                    project_id=project_id,
                    tenant_id=tenant_id,
                    workspace_id=workspace_id,
                    policy_id=policy.id,
                    version_id=version.id,
                    content_hash=version.content_hash,
                    current_status=version.status.value,
                    target_status=payload.targetStatus,
                    reason=payload.reason,
                    context=context,
                    commit=False,
                )
                approval_id = UUID(str(approval_result["approvalId"]))
                version.governance_status = "transition_pending"
                version.current_approval_id = approval_id
                version.submitted_at = datetime.now(timezone.utc)
                version.submitted_by = context.user.id
                version.updated_by = context.user.id
                self.repository.add(
                    self._governance_request(
                        tenant_id=tenant_id,
                        workspace_id=workspace_id,
                        project_id=project_id,
                        operation="lifecycle_transition",
                        idempotency_key=idempotency_key,
                        request_hash=request_hash,
                        resource_type="gate_policy_version",
                        resource_id=version.id,
                        context=context,
                        approval_id=approval_id,
                    )
                )
                self.db.flush()
                self._audit_version_mutation(
                    action="gate_policy.lifecycle.submit",
                    project_id=project_id,
                    version=version,
                    before_hash=version.content_hash,
                    after_hash=version.content_hash,
                    before_version=before_version,
                    after_version=version.lock_version,
                    before_status=version.status.value,
                    after_status="transition_pending",
                    approval_ids=[approval_id],
                    result="pending",
                    context=context,
                )
            self.db.commit()
            return self._version_projection(version, include_document=False)
        except (ApprovalConflictError, IntegrityError, StaleDataError) as exc:
            self.db.rollback()
            raise GatePolicyGovernanceError("GATE_POLICY_LIFECYCLE_CONFLICT", status_code=409) from exc
        except Exception:
            self.db.rollback()
            raise

    def execute_approved_review(
        self,
        *,
        approval_payload: dict[str, object],
        approval_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        version, project_id = self._approved_target(approval_payload, approval_id)
        self._preflight(
            context,
            action="review_decision",
            resource_type="gate_policy_version",
            resource_id=version.id,
            payload={"approvalId": str(approval_id), "decision": "approve"},
        )
        if version.status != GatePolicyStatus.DRAFT:
            raise GatePolicyGovernanceError("GATE_POLICY_VERSION_IMMUTABLE", status_code=409)
        if version.validation_status != "valid" or version.validation_report.get("contentHash") != version.content_hash:
            raise GatePolicyGovernanceError("GATE_POLICY_VALIDATION_REQUIRED", status_code=422)
        before_version = version.lock_version
        version.governance_status = "review_approved"
        version.updated_by = context.user.id
        self.db.flush()
        self._audit_version_mutation(
            action="gate_policy.review.approve",
            project_id=project_id,
            version=version,
            before_hash=version.content_hash,
            after_hash=version.content_hash,
            before_version=before_version,
            after_version=version.lock_version,
            before_status="review_pending",
            after_status="review_approved",
            approval_ids=[approval_id],
            result="approved_not_active",
            context=context,
        )
        return {
            "versionId": str(version.id),
            "governanceStatus": version.governance_status,
            "status": version.status.value,
            "activatesProduction": False,
        }

    def execute_approved_lifecycle(
        self,
        *,
        approval_payload: dict[str, object],
        approval_id: UUID,
        context: ServiceContext,
    ) -> dict[str, object]:
        version, project_id = self._approved_target(approval_payload, approval_id)
        target_status = str(approval_payload.get("targetStatus") or "")
        self._require_lifecycle_transition(version.status.value, target_status)
        self._preflight(
            context,
            action="review_decision",
            resource_type="gate_policy_version",
            resource_id=version.id,
            payload={"approvalId": str(approval_id), "decision": "approve", "targetStatus": target_status},
        )
        before_status = version.status.value
        before_version = version.lock_version
        version.status = GatePolicyStatus(target_status)
        version.governance_status = "transition_applied"
        version.updated_by = context.user.id
        self.db.flush()
        self._audit_version_mutation(
            action=f"gate_policy.lifecycle.{target_status}",
            project_id=project_id,
            version=version,
            before_hash=version.content_hash,
            after_hash=version.content_hash,
            before_version=before_version,
            after_version=version.lock_version,
            before_status=before_status,
            after_status=target_status,
            approval_ids=[approval_id],
            result="applied",
            context=context,
        )
        return {
            "versionId": str(version.id),
            "governanceStatus": version.governance_status,
            "status": version.status.value,
            "activatesProduction": False,
        }

    def _project_scope(
        self,
        project_id: UUID,
        context: ServiceContext,
        *,
        write: bool,
    ) -> tuple[Project, str, str]:
        try:
            scope = ScopeAuthorizationService(self.db).resolve_project(
                project_id,
                context,
                write=write,
            )
        except ScopeAuthorizationError as exc:
            if exc.status_code == 409:
                code = "GATE_POLICY_SCOPE_INVALID"
            elif exc.status_code == 403:
                code = "GATE_POLICY_PROJECT_WRITE_FORBIDDEN"
            else:
                code = "GATE_POLICY_PROJECT_NOT_FOUND"
            raise GatePolicyGovernanceError(code, status_code=exc.status_code, field=exc.field) from exc
        return scope.project, scope.tenant_id, scope.workspace_id

    def _scoped_policy(
        self,
        project_id: UUID,
        policy_id: UUID,
        context: ServiceContext,
        *,
        write: bool,
    ) -> tuple[GatePolicy, str, str]:
        _project, tenant_id, workspace_id = self._project_scope(project_id, context, write=write)
        policy = self.repository.find_policy_for_project(
            tenant_id,
            workspace_id,
            project_id,
            policy_id,
            for_update=write,
        )
        if policy is None:
            raise GatePolicyGovernanceError("GATE_POLICY_NOT_FOUND", status_code=404)
        return policy, tenant_id, workspace_id

    def _scoped_version(
        self,
        project_id: UUID,
        policy_id: UUID,
        version_id: UUID,
        context: ServiceContext,
        *,
        write: bool,
        for_update: bool = False,
    ) -> GatePolicyVersion:
        policy, tenant_id, workspace_id = self._scoped_policy(project_id, policy_id, context, write=write)
        version = self.repository.find_version_for_policy(
            tenant_id,
            workspace_id,
            policy.id,
            version_id,
            for_update=for_update,
        )
        if version is None:
            raise GatePolicyGovernanceError("GATE_POLICY_VERSION_NOT_FOUND", status_code=404)
        return version

    def _approved_target(
        self,
        approval_payload: dict[str, object],
        approval_id: UUID,
    ) -> tuple[GatePolicyVersion, UUID]:
        try:
            project_id = UUID(str(approval_payload["projectId"]))
            policy_id = UUID(str(approval_payload["policyId"]))
            version_id = UUID(str(approval_payload["versionId"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise GatePolicyGovernanceError("GATE_POLICY_APPROVAL_PAYLOAD_INVALID", status_code=409) from exc
        tenant_id = str(approval_payload.get("tenantId") or "")
        workspace_id = str(approval_payload.get("workspaceId") or "")
        policy = self.repository.find_policy_for_project(
            tenant_id,
            workspace_id,
            project_id,
            policy_id,
            for_update=True,
        )
        if policy is None:
            raise GatePolicyGovernanceError("GATE_POLICY_APPROVAL_SCOPE_MISMATCH", status_code=409)
        version = self.repository.find_version_for_policy(
            tenant_id,
            workspace_id,
            policy.id,
            version_id,
            for_update=True,
        )
        if version is None or version.current_approval_id != approval_id:
            raise GatePolicyGovernanceError("GATE_POLICY_APPROVAL_MISMATCH", status_code=409)
        if str(approval_payload.get("contentHash") or "") != version.content_hash:
            raise GatePolicyGovernanceError("GATE_POLICY_APPROVAL_STALE", status_code=409)
        return version, project_id

    def _policy_projection(self, policy: GatePolicy, *, include_document: bool) -> dict[str, object]:
        if policy.project_id is None:
            raise GatePolicyGovernanceError("GATE_POLICY_PROJECT_SCOPE_MISSING", status_code=409)
        versions = self.repository.list_versions(policy.tenant_id, policy.workspace_id, policy.id)
        projection = GatePolicyProjection(
            policyId=policy.id,
            policyRef=policy.policy_ref,
            projectId=policy.project_id,
            tenantId=policy.tenant_id,
            workspaceId=policy.workspace_id,
            policyKey=policy.policy_key,
            name=policy.name,
            description=policy.description,
            status=policy.status.value,
            lockVersion=policy.lock_version,
            versions=[
                GatePolicyVersionProjection.model_validate(
                    self._version_projection(item, include_document=include_document)
                )
                for item in versions
            ],
            createdAt=policy.created_at,
            updatedAt=policy.updated_at,
            executesGate=False,
            activatesProduction=False,
        )
        return projection.model_dump(mode="json")

    def _version_projection(self, version: GatePolicyVersion, *, include_document: bool) -> dict[str, object]:
        approvals = list(
            self.db.scalars(
                select(Approval)
                .where(
                    Approval.resource_id == str(version.id),
                    Approval.resource_type.in_(("gate_policy_version_review", "gate_policy_version_lifecycle")),
                )
                .order_by(Approval.created_at.asc(), Approval.id.asc())
            )
        )
        current = next((item for item in reversed(approvals) if item.id == version.current_approval_id), None)
        audit_logs = list(
            self.db.scalars(
                select(AuditLog)
                .where(AuditLog.resource_type == "gate_policy_version", AuditLog.resource_id == str(version.id))
                .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
            )
        )
        guardrail_events = [
            event
            for event in self.db.scalars(
                select(GuardrailEvent)
                .where(GuardrailEvent.rule_id == GatePolicyMutationGuard.rule_id)
                .order_by(GuardrailEvent.created_at.asc(), GuardrailEvent.id.asc())
            )
            if str((event.payload or {}).get("resourceId") or "") == str(version.id)
        ]
        payload = {
            "versionId": version.id,
            "versionRef": version.version_ref,
            "versionNumber": version.version_number,
            "schemaVersion": version.schema_version,
            "status": version.status.value,
            "governanceStatus": self._effective_governance_status(version, current),
            "contentHash": version.content_hash,
            "lockVersion": version.lock_version,
            "validation": self._validation_projection(version),
            "currentApproval": self._approval_projection(current) if current else None,
            "approvalRefs": [
                {"type": "approval", "id": str(item.id), "status": item.status.value}
                for item in approvals
            ],
            "guardrailRefs": [
                {
                    "type": "guardrail_event",
                    "id": str(item.id),
                    "ruleId": item.rule_id,
                    "decision": item.decision.value,
                }
                for item in guardrail_events
            ],
            "auditRefs": [
                {
                    "type": "audit",
                    "id": str(item.id),
                    "action": item.action,
                    "requestId": item.request_id,
                    "traceId": str(item.trace_id) if item.trace_id else None,
                }
                for item in audit_logs
            ],
            "traceRefs": list(dict.fromkeys(str(item.trace_id) for item in audit_logs if item.trace_id)),
            "document": version.policy_snapshot if include_document else None,
            "createdAt": version.created_at,
            "updatedAt": version.updated_at,
        }
        from agentic_qa.schemas.gate_policy_governance import GatePolicyVersionProjection

        return GatePolicyVersionProjection.model_validate(payload).model_dump(mode="json")

    def _validation_projection(self, version: GatePolicyVersion) -> dict[str, object]:
        report = version.validation_report or {}
        if report.get("contentHash") != version.content_hash:
            report = {}
        payload = {
            "schemaVersion": "phase8.gate-policy-validation.v1",
            "status": report.get("status") or "not_validated",
            "contentHash": version.content_hash,
            "validatedAt": report.get("validatedAt") or version.validated_at,
            "validatedBy": report.get("validatedBy") or version.validated_by,
            "errors": list(report.get("errors") or []),
            "warnings": list(report.get("warnings") or []),
            "writesGateDecision": False,
        }
        return GatePolicyValidationProjection.model_validate(payload).model_dump(mode="json")

    @staticmethod
    def _approval_projection(approval: Approval) -> dict[str, object]:
        action = str(approval.payload.get("action") or "")
        return {
            "approvalId": str(approval.id),
            "resourceType": approval.resource_type,
            "action": action,
            "status": approval.status.value,
            "targetStatus": approval.payload.get("targetStatus"),
            "requestedBy": str(approval.requested_by) if approval.requested_by else None,
            "decidedBy": str(approval.decided_by) if approval.decided_by else None,
            "createdAt": approval.created_at.isoformat(),
            "decidedAt": approval.decided_at.isoformat() if approval.decided_at else None,
        }

    def _effective_governance_status(
        self,
        version: GatePolicyVersion,
        current: Approval | None = None,
    ) -> str:
        if current is None and version.current_approval_id is not None:
            current = self.db.get(Approval, version.current_approval_id)
        if current is None:
            return version.governance_status
        action = str(current.payload.get("action") or "")
        prefix = "review" if action == "gate_policy.review" else "transition"
        mapping = {
            ApprovalStatus.PENDING: f"{prefix}_pending",
            ApprovalStatus.APPROVED: "review_approved" if prefix == "review" else "transition_applied",
            ApprovalStatus.REJECTED: f"{prefix}_rejected",
            ApprovalStatus.CANCELLED: f"{prefix}_cancelled",
            ApprovalStatus.EXPIRED: f"{prefix}_expired",
        }
        return mapping[current.status]

    def _preflight(
        self,
        context: ServiceContext,
        *,
        action: str,
        resource_type: str,
        resource_id: UUID,
        payload: dict[str, object],
    ) -> None:
        guardrail_context = GuardrailContext(
            trace_id=context.trace_id,
            request_id=context.request_id,
            actor_id=context.user.id,
            actor_roles=list(context.user.roles),
            resource_type=resource_type,
            resource_id=str(resource_id),
            payload=payload,
            metadata={"action": action},
        )
        try:
            RuntimeGuardrailEngine(self.db).enforce(guardrail_context, [GatePolicyMutationGuard()])
        except GuardrailViolationError as exc:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_GUARDRAIL_BLOCKED",
                status_code=403,
                details={"ruleId": exc.result.rule_id, "decision": exc.result.decision.value},
            ) from exc

    def _audit_version_mutation(
        self,
        *,
        action: str,
        project_id: UUID,
        version: GatePolicyVersion,
        before_hash: str | None,
        after_hash: str | None,
        before_version: int | None,
        after_version: int | None,
        before_status: str | None,
        after_status: str | None,
        approval_ids: list[UUID],
        result: str,
        context: ServiceContext,
    ) -> None:
        write_audit_log(
            self.db,
            context.user.id,
            action,
            "gate_policy_version",
            str(version.id),
            context.request_id,
            context.trace_id,
            details={
                "actorId": str(context.user.id),
                "projectId": str(project_id),
                "tenantId": version.tenant_id,
                "workspaceId": version.workspace_id,
                "policyId": str(version.policy_id),
                "versionId": str(version.id),
                "beforeHash": before_hash,
                "afterHash": after_hash,
                "beforeVersion": before_version,
                "afterVersion": after_version,
                "beforeStatus": before_status,
                "afterStatus": after_status,
                "approvalRefs": [str(item) for item in approval_ids],
                "result": result,
            },
        )

    def _trace(self, context: ServiceContext, span_name: str, attributes: dict[str, object]):
        return traced_operation(
            self.db,
            trace_id=context.trace_id,
            execution_id=None,
            root_span_name="gate_policy.governance",
            span_name=span_name,
            service_name="orchestrator-service",
            attributes=attributes,
            parent_span_id=context.parent_span_id,
        )

    def _governance_request(
        self,
        *,
        tenant_id: str,
        workspace_id: str,
        project_id: UUID,
        operation: str,
        idempotency_key: str,
        request_hash: str,
        resource_type: str,
        resource_id: UUID,
        context: ServiceContext,
        approval_id: UUID | None = None,
    ) -> GatePolicyGovernanceRequest:
        return GatePolicyGovernanceRequest(
            id=uuid4(),
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            project_id=project_id,
            operation=operation,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            resource_type=resource_type,
            resource_id=str(resource_id),
            approval_id=approval_id,
            trace_id=UUID(context.trace_id),
            created_by=context.user.id,
        )

    @staticmethod
    def _validate_candidate(document: dict[str, Any]) -> dict[str, Any]:
        try:
            return validate_gate_policy_document(document)
        except ValidationError as exc:
            first = exc.errors(include_url=False, include_input=False)[0]
            raise GatePolicyGovernanceError(
                "GATE_POLICY_SCHEMA_INVALID",
                status_code=422,
                field=".".join(str(item) for item in first.get("loc", ())) or None,
                details={"issueType": str(first.get("type") or "validation_error")},
            ) from exc
        except (TypeError, ValueError) as exc:
            raise GatePolicyGovernanceError("GATE_POLICY_SCHEMA_INVALID", status_code=422) from exc

    @staticmethod
    def _require_document_scope(document: dict[str, Any], tenant_id: str, workspace_id: str) -> None:
        scope = document.get("scope") or {}
        if scope.get("tenantId") != tenant_id or scope.get("workspaceId") != workspace_id:
            raise GatePolicyGovernanceError("GATE_POLICY_SCOPE_MISMATCH", status_code=409, field="document.scope")

    @staticmethod
    def _require_capability(context: ServiceContext, capability: str) -> None:
        if capability not in set(context.user.capabilities):
            raise GatePolicyGovernanceError(
                "CAPABILITY_REQUIRED",
                status_code=403,
                details={"capability": capability},
            )

    @staticmethod
    def _require_lock(version: GatePolicyVersion, expected_version: int) -> None:
        if expected_version < 1 or version.lock_version != expected_version:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_LOCK_CONFLICT",
                status_code=409,
                field="expectedVersion",
                details={"expectedVersion": expected_version},
            )

    @staticmethod
    def _require_lifecycle_transition(current: str, target: str) -> None:
        if target not in LIFECYCLE_TRANSITIONS.get(current, frozenset()):
            raise GatePolicyGovernanceError(
                "GATE_POLICY_STATE_TRANSITION_INVALID",
                status_code=409,
                details={"currentStatus": current, "targetStatus": target},
            )

    @staticmethod
    def _require_same_idempotent_request(
        record: GatePolicyGovernanceRequest,
        request_hash: str,
        resource_id: str,
    ) -> None:
        if record.request_hash != request_hash or record.resource_id != resource_id:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_IDEMPOTENCY_CONFLICT",
                status_code=409,
                field="idempotencyKey",
            )

    @staticmethod
    def _idempotency_key(value: str) -> str:
        normalized = value.strip()
        if not normalized or len(normalized) > 255:
            raise GatePolicyGovernanceError(
                "GATE_POLICY_IDEMPOTENCY_KEY_INVALID",
                status_code=422,
                field="idempotencyKey",
            )
        return normalized

    @staticmethod
    def _uuid(value: object, field: str) -> UUID:
        try:
            return UUID(str(value))
        except (TypeError, ValueError, AttributeError) as exc:
            raise GatePolicyGovernanceError("GATE_POLICY_ID_INVALID", status_code=422, field=field) from exc

    @staticmethod
    def _from_data_error(exc: GatePolicyDataError) -> GatePolicyGovernanceError:
        if exc.code.endswith("NOT_FOUND"):
            status_code = 404
        elif exc.code in {
            "GATE_POLICY_SCHEMA_INVALID",
            "GATE_POLICY_KEY_INVALID",
            "GATE_POLICY_NAME_INVALID",
            "GATE_POLICY_DESCRIPTION_INVALID",
            "GATE_POLICY_ID_INVALID",
        }:
            status_code = 422
        else:
            status_code = 409
        return GatePolicyGovernanceError(
            exc.code,
            status_code=status_code,
            field=exc.field,
            details=exc.details,
        )
