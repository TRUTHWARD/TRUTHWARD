# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Literal, Protocol
from uuid import UUID

from sqlalchemy.orm import Session

from agentic_qa.domain.models import Execution, SkillVersion, TestPlan
from agentic_qa.infra.safe_projection import ConnectorBindingSafeProjectionBuilder
from agentic_qa.runtime.qa_harness.context_builder import (
    AUTHORIZED_CONTEXT_REDACTION_POLICY_VERSION,
    AUTHORIZED_CONTEXT_SCHEMA_VERSION,
    MAX_CONTEXT_BYTES,
    MAX_CONTEXT_DEPTH,
    MAX_CONTEXT_NODES,
    MAX_CONTEXT_TOKENS,
    canonical_content_hash,
    context_envelope_hash,
    project_safe_context_content,
    validate_context_envelope,
)
from agentic_qa.runtime.qa_harness.contracts import HarnessContextBlock, HarnessEvidenceRef
from agentic_qa.schemas.skills import SkillContextEnvelope
from agentic_qa.services.common import ServiceContext
from agentic_qa.services.scope_service import ScopeAuthorizationService, ScopeContext


SKILL_CONTEXT_REQUIRED_UNAVAILABLE = "SKILL_CONTEXT_REQUIRED_UNAVAILABLE"
SKILL_CONTEXT_OPTIONAL_UNAVAILABLE = "SKILL_CONTEXT_OPTIONAL_UNAVAILABLE"
SKILL_CONTEXT_SOURCE_MISSING = "SKILL_CONTEXT_SOURCE_MISSING"
SKILL_CONTEXT_ACCESS_NOT_DECLARED = "SKILL_CONTEXT_ACCESS_NOT_DECLARED"
SKILL_CONTEXT_CAPABILITY_REQUIRED = "SKILL_CONTEXT_CAPABILITY_REQUIRED"
SKILL_CONTEXT_SCOPE_NOT_ALLOWED = "SKILL_CONTEXT_SCOPE_NOT_ALLOWED"
SKILL_CONTEXT_RAW_CONTENT_NOT_ALLOWED = "SKILL_CONTEXT_RAW_CONTENT_NOT_ALLOWED"
SKILL_CONTEXT_EVIDENCE_REQUIRED = "SKILL_CONTEXT_EVIDENCE_REQUIRED"
SKILL_CONTEXT_STALE = "SKILL_CONTEXT_STALE"
SKILL_CONTEXT_FRESHNESS_UNAVAILABLE = "SKILL_CONTEXT_FRESHNESS_UNAVAILABLE"
SKILL_CONTEXT_CONTENT_HASH_MISMATCH = "SKILL_CONTEXT_CONTENT_HASH_MISMATCH"
SKILL_CONTEXT_SOURCE_VERSION_MISSING = "SKILL_CONTEXT_SOURCE_VERSION_MISSING"
SKILL_CONTEXT_UNSAFE = "SKILL_CONTEXT_UNSAFE"
SKILL_CONTEXT_SIZE_LIMIT_EXCEEDED = "SKILL_CONTEXT_SIZE_LIMIT_EXCEEDED"

EXTERNAL_CONTEXT_TYPES = frozenset(
    {
        "requirement_document",
        "scm_diff",
        "execution_log",
        "external_evidence",
        "web_content",
    }
)


class SkillContextError(ValueError):
    def __init__(self, code: str, *, context_type: str | None = None) -> None:
        message = code if context_type is None else f"{code}:{context_type}"
        super().__init__(message)
        self.code = code
        self.context_type = context_type


class SkillContextUnavailableError(SkillContextError):
    pass


@dataclass(frozen=True, slots=True)
class ContextRequirement:
    context_type: str
    required: bool
    access_allowed: bool
    allowed_scopes: frozenset[str]
    allow_raw_content: bool
    max_age_seconds: int | None
    require_evidence_ref: bool
    required_capability: str | None


@dataclass(frozen=True, slots=True)
class SkillContextAccessPolicy:
    requirements: tuple[ContextRequirement, ...]
    allowed_scopes: frozenset[str]
    allow_raw_content: bool
    max_context_bytes: int
    max_context_tokens: int
    max_depth: int
    max_nodes: int

    @classmethod
    def from_version(cls, version: SkillVersion) -> "SkillContextAccessPolicy":
        data_policy = (
            version.data_access_policy if isinstance(version.data_access_policy, dict) else {}
        )
        compatibility = version.compatibility if isinstance(version.compatibility, dict) else {}
        capabilities = version.capabilities if isinstance(version.capabilities, dict) else {}
        configured = data_policy.get("authorizedContext") or data_policy.get("context") or {}
        if configured in (None, {}):
            configured = {}
        if not isinstance(configured, dict):
            raise SkillContextError("SKILL_CONTEXT_POLICY_INVALID")

        required_types = _string_list(
            configured.get("requiredContextTypes") or configured.get("requiredTypes")
        )
        optional_types = _string_list(
            configured.get("optionalContextTypes") or configured.get("optionalTypes")
        )
        compatibility_required = _string_list(compatibility.get("requiredContextTypes"))
        capability_required = _string_list(capabilities.get("requiredContextTypes"))
        compatibility_optional = _string_list(compatibility.get("optionalContextTypes"))
        capability_optional = _string_list(capabilities.get("optionalContextTypes"))
        required_types = _dedupe([*required_types, *compatibility_required, *capability_required])
        optional_types = _dedupe(
            [
                item
                for item in [*optional_types, *compatibility_optional, *capability_optional]
                if item not in required_types
            ]
        )
        allowed_types = set(
            _string_list(configured.get("allowedContextTypes"))
            or [*required_types, *optional_types]
        )
        allowed_scopes = frozenset(_string_list(configured.get("allowedScopes")) or ["project"])
        if not allowed_scopes.issubset(
            {"global", "workspace", "project", "environment", "stage", "domain"}
        ):
            raise SkillContextError("SKILL_CONTEXT_POLICY_SCOPE_INVALID")

        default_allow_raw = _strict_bool(configured.get("allowRawContent"), default=False)
        default_require_evidence = _strict_bool(configured.get("requireEvidenceRef"), default=False)
        freshness = configured.get("freshnessSeconds")
        capability_map = configured.get("requiredCapabilities") or {}
        if not isinstance(capability_map, dict):
            raise SkillContextError("SKILL_CONTEXT_POLICY_CAPABILITY_INVALID")
        definitions = configured.get("contexts") or []
        if not isinstance(definitions, list):
            raise SkillContextError("SKILL_CONTEXT_POLICY_INVALID")
        definition_by_type: dict[str, dict[str, object]] = {}
        for item in definitions:
            if not isinstance(item, dict) or not isinstance(item.get("type"), str):
                raise SkillContextError("SKILL_CONTEXT_POLICY_INVALID")
            context_type = str(item["type"]).strip()
            if not context_type or context_type in definition_by_type:
                raise SkillContextError("SKILL_CONTEXT_POLICY_INVALID")
            definition_by_type[context_type] = item
            if _strict_bool(item.get("required"), default=False):
                if context_type not in required_types:
                    required_types.append(context_type)
                optional_types = [value for value in optional_types if value != context_type]
            elif context_type not in required_types and context_type not in optional_types:
                optional_types.append(context_type)
            allowed_types.add(context_type)

        requirements: list[ContextRequirement] = []
        for context_type, required in [
            *((item, True) for item in required_types),
            *((item, False) for item in optional_types),
        ]:
            definition = definition_by_type.get(context_type, {})
            requirement_scopes = frozenset(
                _string_list(definition.get("allowedScopes")) or allowed_scopes
            )
            required_capability = definition.get("requiredCapability")
            if required_capability is None:
                required_capability = capability_map.get(context_type)
            if required_capability is not None and not isinstance(required_capability, str):
                raise SkillContextError("SKILL_CONTEXT_POLICY_CAPABILITY_INVALID")
            requirements.append(
                ContextRequirement(
                    context_type=context_type,
                    required=required,
                    access_allowed=context_type in allowed_types and bool(configured),
                    allowed_scopes=requirement_scopes,
                    allow_raw_content=_strict_bool(
                        definition.get("allowRawContent"), default=default_allow_raw
                    ),
                    max_age_seconds=_freshness_for(
                        context_type,
                        definition.get("maxAgeSeconds", freshness),
                    ),
                    require_evidence_ref=_strict_bool(
                        definition.get("requireEvidenceRef"),
                        default=default_require_evidence,
                    ),
                    required_capability=str(required_capability).strip()
                    if required_capability
                    else None,
                )
            )

        return cls(
            requirements=tuple(requirements),
            allowed_scopes=allowed_scopes,
            allow_raw_content=default_allow_raw,
            max_context_bytes=_bounded_positive_int(
                configured.get("maxContextBytes"),
                default=64 * 1024,
                hard_limit=MAX_CONTEXT_BYTES,
            ),
            max_context_tokens=_bounded_positive_int(
                configured.get("maxContextTokens"),
                default=16 * 1024,
                hard_limit=MAX_CONTEXT_TOKENS,
            ),
            max_depth=_bounded_positive_int(
                configured.get("maxDepth"),
                default=12,
                hard_limit=MAX_CONTEXT_DEPTH,
            ),
            max_nodes=_bounded_positive_int(
                configured.get("maxNodes"),
                default=5_000,
                hard_limit=MAX_CONTEXT_NODES,
            ),
        )


@dataclass(frozen=True, slots=True)
class ContextProviderResult:
    source_ref: str
    source_version: str | int | None
    revision: str | int | None
    scope_snapshot: dict[str, object]
    content: object | None
    updated_at: datetime | None
    expected_content_hash: str | None
    evidence_refs: tuple[dict[str, object], ...]
    raw_content: bool
    trust_boundary: Literal[
        "platform_authority",
        "service_authorized",
        "service_observation",
        "external_untrusted",
    ]
    redaction_status: str = "not_required"
    unavailable_reason: str | None = None
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ContextProviderRequest:
    db: Session
    scope_context: ScopeContext
    execution_id: UUID | None
    connector_binding_snapshot: Mapping[str, object] | None
    provided_contexts: Mapping[str, object]
    connector_snapshot_builder: ConnectorBindingSafeProjectionBuilder


class SkillContextProvider(Protocol):
    context_type: str
    scope_type: str
    required_capability: str | None

    def provide(self, request: ContextProviderRequest) -> ContextProviderResult: ...


class _ProjectProfileProvider:
    context_type = "project_profile"
    scope_type = "project"
    required_capability: str | None = "governance.read"

    def provide(self, request: ContextProviderRequest) -> ContextProviderResult:
        project = request.scope_context.project
        updated_at = _as_utc(project.updated_at or project.created_at)
        return ContextProviderResult(
            source_ref=f"project://{project.id}",
            source_version=updated_at.isoformat() if updated_at else "project.v1",
            revision=None,
            scope_snapshot=_scope_projection(request.scope_context),
            content={
                "projectId": str(project.id),
                "key": project.key,
                "name": project.name,
                "status": project.status,
            },
            updated_at=updated_at,
            expected_content_hash=None,
            evidence_refs=({"type": "project", "ref": f"project://{project.id}"},),
            raw_content=False,
            trust_boundary="platform_authority",
        )


class _EnvironmentProfileProvider:
    context_type = "environment_profile"
    scope_type = "environment"
    required_capability: str | None = "governance.read"

    def provide(self, request: ContextProviderRequest) -> ContextProviderResult:
        environment = request.scope_context.environment
        if environment is None:
            return _missing_provider_result(self.context_type, request.scope_context)
        updated_at = _as_utc(environment.updated_at or environment.created_at)
        return ContextProviderResult(
            source_ref=f"project-environment://{environment.id}",
            source_version=updated_at.isoformat() if updated_at else "environment.v1",
            revision=None,
            scope_snapshot=_scope_projection(request.scope_context),
            content={
                "environmentId": str(environment.id),
                "projectId": str(environment.project_id),
                "key": environment.key,
                "name": environment.name,
                "status": environment.status,
            },
            updated_at=updated_at,
            expected_content_hash=None,
            evidence_refs=(
                {"type": "environment", "ref": f"project-environment://{environment.id}"},
            ),
            raw_content=False,
            trust_boundary="platform_authority",
        )


class _ExecutionSummaryProvider:
    context_type = "execution_summary"
    scope_type = "project"
    required_capability: str | None = "replay.read"

    def provide(self, request: ContextProviderRequest) -> ContextProviderResult:
        if request.execution_id is None:
            return _missing_provider_result(self.context_type, request.scope_context)
        execution = request.db.get(Execution, request.execution_id)
        if execution is None:
            return _missing_provider_result(self.context_type, request.scope_context)
        plan = request.db.get(TestPlan, execution.plan_id)
        if plan is None or plan.project_id != request.scope_context.project.id:
            raise SkillContextError(
                "SKILL_CONTEXT_SOURCE_SCOPE_MISMATCH", context_type=self.context_type
            )
        updated_at = _as_utc(execution.updated_at or execution.created_at)
        return ContextProviderResult(
            source_ref=f"execution://{execution.id}",
            source_version=updated_at.isoformat() if updated_at else "execution.v1",
            revision=None,
            scope_snapshot=_scope_projection(request.scope_context),
            content={
                "executionId": str(execution.id),
                "planRef": f"test-plan://{plan.id}",
                "status": execution.status.value,
                "stage": execution.stage.value,
                "environment": execution.environment,
                "triggerSource": execution.trigger_source,
                "startedAt": execution.started_at.isoformat() if execution.started_at else None,
                "endedAt": execution.ended_at.isoformat() if execution.ended_at else None,
            },
            updated_at=updated_at,
            expected_content_hash=None,
            evidence_refs=({"type": "execution", "ref": f"execution://{execution.id}"},),
            raw_content=False,
            trust_boundary="service_authorized",
        )


class _ConnectorBindingProvider:
    context_type = "connector_binding"
    scope_type = "project"
    required_capability: str | None = "capability_bindings.read"

    def provide(self, request: ContextProviderRequest) -> ContextProviderResult:
        if not request.connector_binding_snapshot:
            return _missing_provider_result(self.context_type, request.scope_context)
        connector_source = dict(request.connector_binding_snapshot or {})
        authoritative_scope = _scope_projection(request.scope_context)
        for key in ("tenantId", "workspaceId", "projectId", "environmentId"):
            if connector_source.get(key) is None and authoritative_scope.get(key) is not None:
                connector_source[key] = authoritative_scope[key]
        projection = request.connector_snapshot_builder.build(connector_source)
        if not projection:
            return _missing_provider_result(self.context_type, request.scope_context)
        source_ref = (
            f"connector-binding://{projection.get('connectorBindingId', 'safe-projection')}"
        )
        return ContextProviderResult(
            source_ref=source_ref,
            source_version=projection.get("bindingVersion")
            or projection.get("bindingRevision")
            or "safe-projection.v1",
            revision=projection.get("bindingRevision"),
            scope_snapshot={
                key: projection.get(key)
                for key in ("tenantId", "workspaceId", "projectId", "environmentId")
                if projection.get(key) is not None
            },
            content=projection,
            updated_at=_parse_datetime(projection.get("createdAt")),
            expected_content_hash=canonical_content_hash(projection),
            evidence_refs=({"type": "connector_binding", "ref": source_ref},),
            raw_content=False,
            trust_boundary="external_untrusted",
            redaction_status="redacted",
            limitations=("UNTRUSTED_CONNECTOR_CONTEXT_DATA_ONLY",),
        )


class _ProvidedProjectionProvider:
    scope_type = "project"
    required_capability: str | None

    def __init__(self, context_type: str, required_capability: str) -> None:
        self.context_type = context_type
        self.required_capability = required_capability

    def provide(self, request: ContextProviderRequest) -> ContextProviderResult:
        raw_descriptor = request.provided_contexts.get(self.context_type)
        if raw_descriptor is None:
            return _missing_provider_result(self.context_type, request.scope_context)
        if not isinstance(raw_descriptor, Mapping):
            raise SkillContextError(SKILL_CONTEXT_UNSAFE, context_type=self.context_type)
        descriptor = dict(raw_descriptor)
        available = descriptor.get("available", True)
        if available is not True:
            reason = str(descriptor.get("unavailableReason") or SKILL_CONTEXT_SOURCE_MISSING)
            return ContextProviderResult(
                source_ref=str(descriptor.get("sourceRef") or f"unavailable://{self.context_type}"),
                source_version=descriptor.get("sourceVersion"),
                revision=descriptor.get("revision"),
                scope_snapshot=dict(descriptor.get("scopeSnapshot") or {}),
                content=None,
                updated_at=_parse_datetime(descriptor.get("updatedAt")),
                expected_content_hash=None,
                evidence_refs=(),
                raw_content=True,
                trust_boundary="external_untrusted",
                redaction_status="unavailable",
                unavailable_reason=reason,
                limitations=("UNTRUSTED_EXTERNAL_CONTEXT_DATA_ONLY",),
            )
        source_ref = descriptor.get("sourceRef")
        if not isinstance(source_ref, str) or not source_ref.strip():
            raise SkillContextError(SKILL_CONTEXT_UNSAFE, context_type=self.context_type)
        evidence_refs = descriptor.get("evidenceRefs") or []
        if not isinstance(evidence_refs, list):
            raise SkillContextError(SKILL_CONTEXT_UNSAFE, context_type=self.context_type)
        scope_snapshot = descriptor.get("scopeSnapshot")
        if not isinstance(scope_snapshot, dict):
            raise SkillContextError(
                "SKILL_CONTEXT_SOURCE_SCOPE_MISSING", context_type=self.context_type
            )
        expected_hash = descriptor.get("contentHash")
        if expected_hash is not None and not isinstance(expected_hash, str):
            raise SkillContextError(
                SKILL_CONTEXT_CONTENT_HASH_MISMATCH, context_type=self.context_type
            )
        return ContextProviderResult(
            source_ref=source_ref,
            source_version=descriptor.get("sourceVersion"),
            revision=descriptor.get("revision"),
            scope_snapshot=dict(scope_snapshot),
            content=descriptor.get("content"),
            updated_at=_parse_datetime(descriptor.get("updatedAt")),
            expected_content_hash=expected_hash,
            evidence_refs=tuple(dict(item) for item in evidence_refs if isinstance(item, dict)),
            raw_content=_strict_bool(descriptor.get("rawContent"), default=True),
            trust_boundary="external_untrusted",
            redaction_status=str(descriptor.get("redactionStatus") or "not_required"),
            limitations=("UNTRUSTED_EXTERNAL_CONTEXT_DATA_ONLY",),
        )


class AuthorizedSkillContextBuilder:
    """Service-owned authorization and safe-projection boundary for Skill context."""

    def __init__(
        self,
        db: Session,
        *,
        scope_authorization: ScopeAuthorizationService | None = None,
        connector_snapshot_builder: ConnectorBindingSafeProjectionBuilder | None = None,
        providers: tuple[SkillContextProvider, ...] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.db = db
        self.scope_authorization = scope_authorization or ScopeAuthorizationService(db)
        self.connector_snapshot_builder = (
            connector_snapshot_builder or ConnectorBindingSafeProjectionBuilder()
        )
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        defaults: list[SkillContextProvider] = [
            _ProjectProfileProvider(),
            _EnvironmentProfileProvider(),
            _ExecutionSummaryProvider(),
            _ConnectorBindingProvider(),
            _ProvidedProjectionProvider("requirement_document", "requirements.read"),
            _ProvidedProjectionProvider("scm_diff", "change.read"),
            _ProvidedProjectionProvider("execution_log", "audit.logs.read"),
            _ProvidedProjectionProvider("external_evidence", "evidence.read"),
            _ProvidedProjectionProvider("web_content", "evidence.read"),
        ]
        self.providers = {
            provider.context_type: provider for provider in [*defaults, *(providers or ())]
        }

    @property
    def supported_context_types(self) -> tuple[str, ...]:
        return tuple(sorted(self.providers))

    def validate_policy(self, version: SkillVersion) -> SkillContextAccessPolicy:
        policy = SkillContextAccessPolicy.from_version(version)
        for requirement in policy.requirements:
            if requirement.context_type not in self.providers:
                raise SkillContextError(
                    "SKILL_CONTEXT_PROVIDER_NOT_REGISTERED",
                    context_type=requirement.context_type,
                )
        return policy

    def build(
        self,
        *,
        version: SkillVersion,
        extension_point_id: str,
        context: ServiceContext,
        scope: Mapping[str, object],
        execution_id: UUID | None,
        connector_binding_snapshot: Mapping[str, object] | None,
        provided_contexts: Mapping[str, object] | None,
    ) -> SkillContextEnvelope:
        policy = self.validate_policy(version)
        if not policy.requirements:
            return self._envelope(
                version=version,
                extension_point_id=extension_point_id,
                scope_snapshot={"contextAccess": "not_declared"},
                blocks=[],
                total_bytes=0,
                total_tokens=0,
                limitations=["SKILL_CONTEXT_ACCESS_NOT_DECLARED"],
            )

        scope_context = self._authorize_scope(scope, context)
        scope_snapshot = _scope_projection(scope_context)
        provider_request = ContextProviderRequest(
            db=self.db,
            scope_context=scope_context,
            execution_id=execution_id,
            connector_binding_snapshot=connector_binding_snapshot,
            provided_contexts=provided_contexts or {},
            connector_snapshot_builder=self.connector_snapshot_builder,
        )
        blocks: list[HarnessContextBlock] = []
        limitations: list[str] = []
        total_bytes = 0
        total_tokens = 0
        capabilities = set(context.user.capabilities)
        for requirement in policy.requirements:
            provider = self.providers[requirement.context_type]
            unavailable_reason: str | None = None
            result: ContextProviderResult | None = None
            if not requirement.access_allowed:
                unavailable_reason = SKILL_CONTEXT_ACCESS_NOT_DECLARED
            elif (
                provider.scope_type not in policy.allowed_scopes
                or provider.scope_type not in requirement.allowed_scopes
            ):
                unavailable_reason = SKILL_CONTEXT_SCOPE_NOT_ALLOWED
            else:
                required_capability = (
                    requirement.required_capability or provider.required_capability
                )
                if required_capability and required_capability not in capabilities:
                    unavailable_reason = SKILL_CONTEXT_CAPABILITY_REQUIRED
            if unavailable_reason is None:
                result = provider.provide(provider_request)
                if result.unavailable_reason:
                    unavailable_reason = result.unavailable_reason
                else:
                    self._assert_source_scope(scope_context, result, requirement.context_type)
                    if result.source_version is None and result.revision is None:
                        unavailable_reason = SKILL_CONTEXT_SOURCE_VERSION_MISSING
                    elif result.raw_content and not requirement.allow_raw_content:
                        unavailable_reason = SKILL_CONTEXT_RAW_CONTENT_NOT_ALLOWED
                    elif requirement.require_evidence_ref and not result.evidence_refs:
                        unavailable_reason = SKILL_CONTEXT_EVIDENCE_REQUIRED
                    else:
                        unavailable_reason = self._freshness_reason(
                            result.updated_at,
                            requirement.max_age_seconds,
                        )

            if unavailable_reason is not None:
                block = self._unavailable_block(
                    requirement,
                    result=result,
                    scope_snapshot=scope_snapshot,
                    reason=unavailable_reason,
                )
                blocks.append(block)
                limitations.append(
                    f"{SKILL_CONTEXT_REQUIRED_UNAVAILABLE if requirement.required else SKILL_CONTEXT_OPTIONAL_UNAVAILABLE}:{requirement.context_type}:{unavailable_reason}"
                )
                continue

            assert result is not None
            try:
                projected = project_safe_context_content(
                    result.content,
                    max_depth=policy.max_depth,
                    max_nodes=policy.max_nodes,
                    max_bytes=policy.max_context_bytes,
                    max_tokens=policy.max_context_tokens,
                )
            except ValueError as exc:
                reason = (
                    SKILL_CONTEXT_SIZE_LIMIT_EXCEEDED
                    if "maximum" in str(exc) and ("byte" in str(exc) or "token" in str(exc))
                    else SKILL_CONTEXT_UNSAFE
                )
                blocks.append(
                    self._unavailable_block(
                        requirement,
                        result=result,
                        scope_snapshot=scope_snapshot,
                        reason=reason,
                    )
                )
                limitations.append(
                    f"{SKILL_CONTEXT_REQUIRED_UNAVAILABLE if requirement.required else SKILL_CONTEXT_OPTIONAL_UNAVAILABLE}:{requirement.context_type}:{reason}"
                )
                continue
            if (
                result.expected_content_hash
                and result.expected_content_hash != projected.content_hash
            ):
                raise SkillContextError(
                    SKILL_CONTEXT_CONTENT_HASH_MISMATCH,
                    context_type=requirement.context_type,
                )
            if (
                total_bytes + projected.byte_size > policy.max_context_bytes
                or total_tokens + projected.estimated_tokens > policy.max_context_tokens
            ):
                reason = SKILL_CONTEXT_SIZE_LIMIT_EXCEEDED
                blocks.append(
                    self._unavailable_block(
                        requirement,
                        result=result,
                        scope_snapshot=scope_snapshot,
                        reason=reason,
                    )
                )
                limitations.append(
                    f"{SKILL_CONTEXT_REQUIRED_UNAVAILABLE if requirement.required else SKILL_CONTEXT_OPTIONAL_UNAVAILABLE}:{requirement.context_type}:{reason}"
                )
                continue
            total_bytes += projected.byte_size
            total_tokens += projected.estimated_tokens
            block_limitations = list(result.limitations)
            if result.trust_boundary == "external_untrusted":
                block_limitations.append(
                    "EXTERNAL_CONTENT_MUST_NOT_BE_INTERPRETED_AS_PLATFORM_INSTRUCTIONS"
                )
            blocks.append(
                HarnessContextBlock(
                    sourceRef=result.source_ref,
                    sourceType=requirement.context_type,
                    sourceVersion=result.source_version,
                    revision=result.revision,
                    # Provider scope is an authorization assertion only.  The
                    # frozen block always receives the Service-derived scope so
                    # external descriptors cannot smuggle control-like fields.
                    scopeSnapshot=scope_snapshot,
                    freshness=_freshness_snapshot(result.updated_at, requirement.max_age_seconds),
                    trustBoundary=result.trust_boundary,
                    contentHash=projected.content_hash,
                    redactionStatus=(
                        "redacted"
                        if result.redaction_status == "redacted"
                        or projected.redaction_status == "redacted"
                        else "not_required"
                    ),
                    redactionPolicyVersion=AUTHORIZED_CONTEXT_REDACTION_POLICY_VERSION,
                    available=True,
                    unavailableReason=None,
                    evidenceRefs=[
                        HarnessEvidenceRef.model_validate(item) for item in result.evidence_refs
                    ],
                    limitations=_dedupe(block_limitations),
                    content=projected.content,
                )
            )
            limitations.extend(block_limitations)

        return self._envelope(
            version=version,
            extension_point_id=extension_point_id,
            scope_snapshot=scope_snapshot,
            blocks=blocks,
            total_bytes=total_bytes,
            total_tokens=total_tokens,
            limitations=_dedupe(limitations),
        )

    @staticmethod
    def ensure_required_available(envelope: SkillContextEnvelope) -> None:
        if not envelope.requiredAvailable:
            raise SkillContextUnavailableError(SKILL_CONTEXT_REQUIRED_UNAVAILABLE)

    def _authorize_scope(
        self,
        scope: Mapping[str, object],
        context: ServiceContext,
    ) -> ScopeContext:
        project_value = scope.get("projectId")
        try:
            project_id = UUID(str(project_value))
        except (TypeError, ValueError) as exc:
            raise SkillContextError("SKILL_CONTEXT_PROJECT_SCOPE_REQUIRED") from exc
        environment_value = scope.get("environmentId") or scope.get("environment")
        environment_id: UUID | None = None
        if environment_value:
            try:
                environment_id = UUID(str(environment_value))
            except (TypeError, ValueError) as exc:
                raise SkillContextError("SKILL_CONTEXT_ENVIRONMENT_SCOPE_INVALID") from exc
        resolved = self.scope_authorization.resolve_project(
            project_id,
            context,
            environment_id=environment_id,
        )
        if scope.get("tenantId") is not None and str(scope["tenantId"]) != resolved.tenant_id:
            raise SkillContextError("SKILL_CONTEXT_TENANT_SCOPE_MISMATCH")
        if (
            scope.get("workspaceId") is not None
            and str(scope["workspaceId"]) != resolved.workspace_id
        ):
            raise SkillContextError("SKILL_CONTEXT_WORKSPACE_SCOPE_MISMATCH")
        return resolved

    @staticmethod
    def _assert_source_scope(
        scope_context: ScopeContext,
        result: ContextProviderResult,
        context_type: str,
    ) -> None:
        expected = _scope_projection(scope_context)
        actual = result.scope_snapshot
        for key in ("tenantId", "workspaceId", "projectId"):
            if str(actual.get(key) or "") != str(expected.get(key) or ""):
                raise SkillContextError(
                    "SKILL_CONTEXT_SOURCE_SCOPE_MISMATCH", context_type=context_type
                )
        actual_environment = actual.get("environmentId")
        expected_environment = expected.get("environmentId")
        if actual_environment is not None and str(actual_environment) != str(
            expected_environment or ""
        ):
            raise SkillContextError(
                "SKILL_CONTEXT_SOURCE_SCOPE_MISMATCH", context_type=context_type
            )

    def _freshness_reason(
        self,
        updated_at: datetime | None,
        max_age_seconds: int | None,
    ) -> str | None:
        if max_age_seconds is None:
            return None
        if updated_at is None:
            return SKILL_CONTEXT_FRESHNESS_UNAVAILABLE
        if self.clock() >= updated_at + timedelta(seconds=max_age_seconds):
            return SKILL_CONTEXT_STALE
        return None

    @staticmethod
    def _unavailable_block(
        requirement: ContextRequirement,
        *,
        result: ContextProviderResult | None,
        scope_snapshot: dict[str, object],
        reason: str,
    ) -> HarnessContextBlock:
        return HarnessContextBlock(
            sourceRef=(
                result.source_ref if result else f"unavailable://{requirement.context_type}"
            ),
            sourceType=requirement.context_type,
            sourceVersion=result.source_version if result else None,
            revision=result.revision if result else None,
            scopeSnapshot=scope_snapshot,
            freshness=_freshness_snapshot(
                result.updated_at if result else None,
                requirement.max_age_seconds,
                status="unavailable",
            ),
            trustBoundary=(result.trust_boundary if result else "service_authorized"),
            contentHash=canonical_content_hash(None),
            redactionStatus="unavailable",
            redactionPolicyVersion=AUTHORIZED_CONTEXT_REDACTION_POLICY_VERSION,
            available=False,
            unavailableReason=reason,
            evidenceRefs=[],
            limitations=[reason],
            content=None,
        )

    @staticmethod
    def _envelope(
        *,
        version: SkillVersion,
        extension_point_id: str,
        scope_snapshot: dict[str, object],
        blocks: list[HarnessContextBlock],
        total_bytes: int,
        total_tokens: int,
        limitations: list[str],
    ) -> SkillContextEnvelope:
        required_available = not any(
            limitation.startswith(f"{SKILL_CONTEXT_REQUIRED_UNAVAILABLE}:")
            for limitation in limitations
        )
        payload: dict[str, object] = {
            "schemaVersion": AUTHORIZED_CONTEXT_SCHEMA_VERSION,
            "extensionPointId": extension_point_id,
            "skillVersionId": str(version.id),
            "manifestHash": version.manifest_hash,
            "scopeSnapshot": scope_snapshot,
            "blocks": [block.model_dump(mode="json") for block in blocks],
            "totalBytes": total_bytes,
            "estimatedUnits": total_tokens,
            "requiredAvailable": required_available,
            "limitations": limitations,
            "platformControls": {
                "contextTreatment": "untrusted_data_not_instructions",
                "platformControlsMutable": False,
                "protectedFields": [
                    "allowedExtensionPoints",
                    "approval",
                    "authorization",
                    "providerRouting",
                    "guardrail",
                ],
            },
        }
        payload["envelopeHash"] = context_envelope_hash(payload)
        envelope = SkillContextEnvelope.model_validate(payload)
        safe_payload = validate_context_envelope(envelope.model_dump(mode="json"))
        return SkillContextEnvelope.model_validate(safe_payload)


def _scope_projection(scope_context: ScopeContext) -> dict[str, object]:
    return {
        "schemaVersion": "phase8.skill-context-scope.v1",
        "tenantId": scope_context.tenant_id,
        "workspaceId": scope_context.workspace_id,
        "projectId": str(scope_context.project.id),
        "environmentId": str(scope_context.environment.id) if scope_context.environment else None,
        "decisionRef": scope_context.decision_ref,
        "serverDerived": True,
    }


def _missing_provider_result(
    context_type: str,
    scope_context: ScopeContext,
) -> ContextProviderResult:
    return ContextProviderResult(
        source_ref=f"unavailable://{context_type}",
        source_version=None,
        revision=None,
        scope_snapshot=_scope_projection(scope_context),
        content=None,
        updated_at=None,
        expected_content_hash=None,
        evidence_refs=(),
        raw_content=False,
        trust_boundary="service_authorized",
        redaction_status="unavailable",
        unavailable_reason=SKILL_CONTEXT_SOURCE_MISSING,
    )


def _freshness_snapshot(
    updated_at: datetime | None,
    max_age_seconds: int | None,
    *,
    status: str | None = None,
) -> dict[str, object]:
    normalized = _as_utc(updated_at)
    return {
        "status": status or ("not_required" if max_age_seconds is None else "fresh"),
        "sourceUpdatedAt": normalized.isoformat() if normalized else None,
        "maxAgeSeconds": max_age_seconds,
        "expiresAt": (
            (normalized + timedelta(seconds=max_age_seconds)).isoformat()
            if normalized and max_age_seconds is not None
            else None
        ),
    }


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return _as_utc(value)
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return _as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None


def _string_list(value: object) -> list[str]:
    if value in (None, []):
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise SkillContextError("SKILL_CONTEXT_POLICY_INVALID")
    normalized = [item.strip() for item in value]
    if any(not item for item in normalized):
        raise SkillContextError("SKILL_CONTEXT_POLICY_INVALID")
    return _dedupe(normalized)


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _strict_bool(value: object, *, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise SkillContextError("SKILL_CONTEXT_POLICY_INVALID")
    return value


def _bounded_positive_int(value: object, *, default: int, hard_limit: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SkillContextError("SKILL_CONTEXT_POLICY_LIMIT_INVALID")
    return min(value, hard_limit)


def _freshness_for(context_type: str, value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, dict):
        value = value.get(context_type)
        if value is None:
            return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SkillContextError("SKILL_CONTEXT_POLICY_FRESHNESS_INVALID")
    return value


__all__ = [
    "AuthorizedSkillContextBuilder",
    "ContextProviderRequest",
    "ContextProviderResult",
    "ContextRequirement",
    "EXTERNAL_CONTEXT_TYPES",
    "SkillContextAccessPolicy",
    "SkillContextError",
    "SkillContextProvider",
    "SkillContextUnavailableError",
    "SKILL_CONTEXT_REQUIRED_UNAVAILABLE",
]
