# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Literal, cast
from uuid import UUID, uuid4

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from agentic_qa.agents.base import AgentResult
from agentic_qa.agents.generator import GeneratorAgent
from agentic_qa.agents.planner_v2 import PlannerAgent
from agentic_qa.connectors import GITHUB_CONNECTOR_CONTRACT, MCP_CONNECTOR_CONTRACT
from agentic_qa.connectors.contracts import ConnectorRuntimeContract
from agentic_qa.domain.enums import (
    AgentRunStatus,
    HealthStatus,
    JobStatus,
    ModelRole,
    PlanStatus,
)
from agentic_qa.domain.models import (
    AgentRun,
    Execution,
    ExecutionArtifact,
    ExecutionTask,
    Finding,
    Job,
    Model,
    ModelInvocation,
    ModelRoleBinding,
    Project,
    ProjectEnvironment,
    Skill,
    SkillInvocation,
    SkillVersion,
    TestPlan,
    TestPlanDomain,
)
from agentic_qa.guardrails.base import GuardrailContext
from agentic_qa.guardrails.result import GuardrailViolationError
from agentic_qa.guardrails.runtime import AgentOutputGuard, RuntimeGuardrailEngine
from agentic_qa.infra.audit import write_audit_log
from agentic_qa.infra.trace import ensure_trace, record_span, traced_operation
from agentic_qa.runtime.qa_harness import (
    AgentStepResult,
    AuthorizedContextBuilder,
    BuiltinQaProfileCatalog,
    ExtensionDescriptor,
    ExtensionDescriptorProjector,
    ExtensionHealthStatus,
    ExtensionKind,
    HarnessContextBlock,
    HarnessEvidenceRef,
    HarnessRunContext,
    HarnessRunSpec,
    Observation,
    ObservationUsage,
    QaHarnessRuntime,
    QaProfile,
    QaProfileExtensionSelection,
    QaProfileRequirement,
    QaProfileResolutionSnapshot,
    QaProfileResolver,
    ServiceCapabilityError,
    SkillIntent,
    StopReason,
)
from agentic_qa.runtime.qa_harness.context_builder import canonical_content_hash
from agentic_qa.runtime.qa_harness.trajectory_events import TrajectoryEvent
from agentic_qa.schemas.contracts import validate_contract
from agentic_qa.schemas.admission import SandboxProfile
from agentic_qa.schemas.model_outputs import GeneratorModelOutput, PlannerModelOutput
from agentic_qa.schemas.requirement_scope import normalize_requirement_scope
from agentic_qa.services.common import ServiceContext, canonical_hash, paginate_query, paginate_result
from agentic_qa.services.requirement_scope_service import RequirementScopeService
from agentic_qa.services.skill_runtime import ManagedSkillRuntimeRegistry
from agentic_qa.services.skill_service import ExtensionInvocationCompletion, SkillService
from agentic_qa.services.scope_service import ScopeAuthorizationError, ScopeAuthorizationService
from agentic_qa.tools.model_gateway import ModelGatewayTool
from agentic_qa.tools.runner_registry import RunnerRegistry


class TestPlanService:
    def __init__(
        self,
        db: Session,
        runtime_registry: ManagedSkillRuntimeRegistry | None = None,
    ) -> None:
        self.db = db
        self.planner = PlannerAgent()
        self.generator = GeneratorAgent()
        self.model_tool = ModelGatewayTool(db)
        self.guardrail_engine = RuntimeGuardrailEngine(db)
        self.skill_service = SkillService(db, runtime_registry=runtime_registry)
        self.qa_profiles = BuiltinQaProfileCatalog()
        self.qa_profile_resolver = QaProfileResolver()
        self.runner_registry = RunnerRegistry()

    def create_plan(self, payload, context: ServiceContext) -> dict[str, object]:
        project_id = self._optional_project_id(getattr(payload, "projectId", None))
        if project_id is not None:
            ScopeAuthorizationService(self.db).resolve_project(project_id, context, write=True)
        elif not {"admin", "system"}.intersection(context.user.roles):
            raise ValueError("project-scoped plan required")
        environment_id = self._optional_environment_id(getattr(payload, "environmentId", None), project_id)
        input_payload = dict(payload.input or {})
        requirement_version_id = self._requirement_version_id_from_payload(payload, input_payload)
        requirement_scope = self._requirement_scope_from_payload(payload, input_payload, requirement_version_id)
        if requirement_scope:
            requirement_scope = RequirementScopeService(self.db).persist(requirement_scope, context)
        if requirement_version_id is not None:
            input_payload["requirementVersionId"] = str(requirement_version_id)
        if requirement_scope:
            input_payload["requirementScope"] = requirement_scope
        plan = TestPlan(
            id=uuid4(),
            name=payload.name,
            source_type=payload.sourceType,
            source_ref=payload.sourceRef,
            environment=payload.environment,
            project_id=project_id,
            environment_id=environment_id,
            risk_level=payload.riskLevel,
            input_payload=input_payload,
            requirement_version_id=requirement_version_id,
            requirement_scope=requirement_scope,
            requirement_scope_id=str(requirement_scope.get("scopeId")) if requirement_scope else None,
            status=PlanStatus.DRAFT,
            created_by=context.user.id,
        )
        self.db.add(plan)
        self.db.flush()
        for domain in payload.domains:
            domain_key = domain.value
            self.db.add(
                TestPlanDomain(
                    id=uuid4(),
                    plan_id=plan.id,
                    domain=domain,
                    enabled=True,
                    config=dict(payload.domainConfig.get(domain_key, {})),
                )
            )
        write_audit_log(self.db, str(context.user.id), "test_plan.create", "test_plan", str(plan.id), context.request_id, context.trace_id)
        self.db.commit()
        return {"id": str(plan.id), "status": plan.status.value}

    def list_plans(self, page: int, page_size: int, context: ServiceContext) -> dict[str, object]:
        statement = select(TestPlan).order_by(TestPlan.created_at.desc())
        if not {"admin", "system"}.intersection(context.user.roles):
            project_ids = ScopeAuthorizationService(self.db).authorized_project_ids(context)
            statement = statement.where(TestPlan.project_id.in_(project_ids))
        plans, total = paginate_query(self.db, statement, page, page_size)
        domain_lookup = self._plan_domains_map([plan.id for plan in plans])
        items = [self.serialize_plan(plan, domain_lookup=domain_lookup) for plan in plans]
        return paginate_result(items, total, page, page_size)

    def get_plan(self, plan_id: UUID, context: ServiceContext) -> dict[str, object]:
        plan = self._require_plan(plan_id)
        self._authorize_plan(plan, context)
        return self.serialize_plan(plan)

    def analyze_coverage(self, plan_id: UUID, context: ServiceContext) -> dict[str, object]:
        plan = self._require_plan(plan_id)
        self._authorize_plan(plan, context)
        requirements = [str(item) for item in plan.input_payload.get("requirements", []) if str(item).strip()]
        generated_plan = plan.generated_plan or {}
        test_points = self._coverage_test_points(generated_plan)
        test_cases = self._coverage_test_cases(generated_plan)
        execution_rows = list(self.db.scalars(select(Execution).where(Execution.plan_id == plan.id)))
        execution_ids = [row.id for row in execution_rows]
        task_rows: list[ExecutionTask] = []
        artifact_rows: list[ExecutionArtifact] = []
        finding_rows: list[Finding] = []
        if execution_ids:
            task_rows = list(self.db.scalars(select(ExecutionTask).where(ExecutionTask.execution_id.in_(execution_ids))))
            artifact_rows = list(self.db.scalars(select(ExecutionArtifact).where(ExecutionArtifact.execution_id.in_(execution_ids))))
            finding_rows = list(self.db.scalars(select(Finding).where(Finding.execution_id.in_(execution_ids))))

        uncovered_requirements = [
            {"requirement": requirement, "reason": "no matching test point or case"}
            for requirement in requirements
            if not self._requirement_is_covered(requirement, test_points, test_cases)
        ]
        weak_areas = [
            {"area": item["requirement"], "reason": "requirement is not covered"}
            for item in uncovered_requirements
        ]
        completed_tasks = len([task for task in task_rows if task.status.value == "completed"])
        findings_with_evidence = len([finding for finding in finding_rows if finding.evidence])
        evidence_denominator = len(finding_rows) or len(task_rows)
        evidence_numerator = findings_with_evidence if finding_rows else len(artifact_rows)

        return validate_contract(
            "coverage-map",
            {
                "schemaVersion": "phase8.coverage-map.v1",
                "requirementCoverage": self._ratio(len(requirements) - len(uncovered_requirements), len(requirements), default=1.0),
                "testPointCoverage": self._ratio(len(test_points), len(requirements), default=1.0),
                "testCaseCoverage": self._ratio(len(test_cases), len(test_points), default=1.0),
                "executionCoverage": self._ratio(completed_tasks, len(task_rows), default=0.0),
                "evidenceCoverage": self._ratio(evidence_numerator, evidence_denominator, default=0.0),
                "regressionCoverage": 1.0 if generated_plan.get("regressionPlan") or generated_plan.get("regression") else 0.0,
                "uncoveredRequirements": uncovered_requirements,
                "weakCoverageAreas": weak_areas,
                "duplicateCoverageAreas": self._duplicate_coverage_areas(test_cases),
                "coverageConfidence": 0.5 if not requirements else self._ratio(len(requirements) - len(uncovered_requirements), len(requirements), default=1.0),
                "evidenceRefs": [
                    {"type": "artifact", "id": str(artifact.id), "executionId": str(artifact.execution_id)}
                    for artifact in artifact_rows
                ],
                "metadata": {
                    "planId": str(plan.id),
                    "requirementCount": len(requirements),
                    "testPointCount": len(test_points),
                    "testCaseCount": len(test_cases),
                    "executionCount": len(execution_rows),
                },
            },
        )

    def update_plan(self, plan_id: UUID, payload, context: ServiceContext) -> dict[str, object]:
        plan = self._require_plan(plan_id)
        self._authorize_plan(plan, context, write=True)
        if payload.name is not None:
            plan.name = payload.name
        if payload.environment is not None:
            plan.environment = payload.environment
        if payload.projectId is not None:
            next_project_id = self._optional_project_id(payload.projectId)
            if next_project_id is not None:
                ScopeAuthorizationService(self.db).resolve_project(
                    next_project_id, context, write=True
                )
            plan.project_id = next_project_id
        if payload.environmentId is not None:
            plan.environment_id = self._optional_environment_id(payload.environmentId, plan.project_id)
        if payload.riskLevel is not None:
            plan.risk_level = payload.riskLevel
        if getattr(payload, "requirementVersionId", None) is not None:
            plan.requirement_version_id = payload.requirementVersionId
        if getattr(payload, "requirementScope", None) is not None:
            raw_scope = payload.requirementScope.model_dump(mode="json") if hasattr(payload.requirementScope, "model_dump") else dict(payload.requirementScope)
            plan.requirement_scope = RequirementScopeService(self.db).persist(
                self._normalize_scope_payload(raw_scope, plan.requirement_version_id), context
            )
            plan.requirement_scope_id = str(plan.requirement_scope["scopeId"])
        if payload.input is not None:
            input_payload = dict(payload.input or {})
            requirement_version_id = self._requirement_version_id_from_payload(payload, input_payload) or plan.requirement_version_id
            requirement_scope = self._requirement_scope_from_payload(payload, input_payload, requirement_version_id) or plan.requirement_scope
            if requirement_version_id is not None:
                plan.requirement_version_id = requirement_version_id
                input_payload["requirementVersionId"] = str(requirement_version_id)
            if requirement_scope:
                plan.requirement_scope = RequirementScopeService(self.db).persist(requirement_scope, context)
                plan.requirement_scope_id = str(plan.requirement_scope["scopeId"])
                input_payload["requirementScope"] = plan.requirement_scope
            plan.input_payload = input_payload
        if payload.status is not None:
            plan.status = payload.status
        if payload.domains is not None:
            self.db.execute(delete(TestPlanDomain).where(TestPlanDomain.plan_id == plan.id))
            for domain in payload.domains:
                domain_key = domain.value
                self.db.add(
                    TestPlanDomain(
                        id=uuid4(),
                        plan_id=plan.id,
                        domain=domain,
                        enabled=True,
                        config=dict((payload.domainConfig or {}).get(domain_key, {})),
                    )
                )
        elif payload.domainConfig is not None:
            for domain_row in self.db.scalars(select(TestPlanDomain).where(TestPlanDomain.plan_id == plan.id)):
                domain_row.config = dict(payload.domainConfig.get(domain_row.domain.value, domain_row.config))
        write_audit_log(self.db, str(context.user.id), "test_plan.update", "test_plan", str(plan.id), context.request_id, context.trace_id)
        self.db.commit()
        self.db.refresh(plan)
        return self.serialize_plan(plan)

    def delete_plan(self, plan_id: UUID, context: ServiceContext) -> dict[str, object]:
        plan = self._require_plan(plan_id)
        self._authorize_plan(plan, context, write=True)
        self.db.execute(delete(TestPlanDomain).where(TestPlanDomain.plan_id == plan.id))
        self.db.delete(plan)
        write_audit_log(self.db, str(context.user.id), "test_plan.delete", "test_plan", str(plan_id), context.request_id, context.trace_id)
        self.db.commit()
        return {"id": str(plan_id)}

    def generate_plan(self, plan_id: UUID, context: ServiceContext) -> dict[str, object]:
        self._authorize_plan(self._require_plan(plan_id), context, write=True)
        job = self.prepare_generate_plan_job(plan_id)
        self.db.commit()
        from agentic_qa.infra.queue import enqueue_task

        queue_task = enqueue_task(
            "plan.generate",
            str(job.id),
            str(plan_id),
            str(context.user.id),
            context.user.roles,
            context.request_id,
            context.trace_id,
        )
        job.payload = {**job.payload, "queueTaskId": str(queue_task.id)}
        self.db.commit()
        return {
            "jobId": str(job.id),
            "queueTaskId": str(queue_task.id),
            "planId": str(plan_id),
            "status": "queued",
        }

    def _authorize_plan(
        self,
        plan: TestPlan,
        context: ServiceContext,
        *,
        write: bool = False,
    ) -> None:
        if plan.project_id is None:
            if {"admin", "system"}.intersection(context.user.roles):
                return
            raise ValueError("test plan not found")
        try:
            ScopeAuthorizationService(self.db).resolve_project(
                plan.project_id,
                context,
                environment_id=plan.environment_id,
                write=write,
            )
        except ScopeAuthorizationError as exc:
            raise ValueError("test plan not found") from exc

    def prepare_generate_plan_job(self, plan_id: UUID) -> Job:
        plan = self._require_plan(plan_id)
        job = Job(
            id=uuid4(),
            job_type="plan.generate",
            status=JobStatus.QUEUED,
            payload={"planId": str(plan.id)},
            progress=0,
        )
        self.db.add(job)
        self.db.flush()
        return job

    def run_generate_plan_job(self, job_id: UUID, plan_id: UUID, context: ServiceContext) -> dict[str, object]:
        job = self._require_job(job_id)
        plan = self._require_plan(plan_id)
        if job.status == JobStatus.COMPLETED:
            return {
                "jobId": str(job.id),
                "planId": str(plan.id),
                "status": job.status.value,
                "deduplicated": True,
            }
        try:
            job.status = JobStatus.RUNNING
            job.progress = 15
            job.started_at = datetime.now(timezone.utc)
            ensure_trace(
                self.db,
                execution_id=None,
                root_span_name="plan.generate",
                trace_id=context.trace_id,
            )
            self.db.flush()
            safe_input = self._minimal_harness_input(plan)
            spec = self._plan_harness_spec(plan, job, safe_input)
            input_block = HarnessContextBlock(
                sourceRef=f"test-plan-input://{plan.id}",
                sourceType="test_plan_input",
                trustBoundary="service_authorized",
                contentHash=canonical_content_hash(safe_input),
                redactionStatus="redacted",
                available=True,
                content=safe_input,
            )
            terminal_capability_errors: list[Exception] = []
            service_context = context

            def execute_service_capability(
                intent: SkillIntent,
                context: HarnessRunContext,
                blocks: list[HarnessContextBlock],
            ) -> Observation | list[Observation]:
                try:
                    return self._execute_plan_harness_intent(
                        plan=plan,
                        job=job,
                        spec=spec,
                        intent=intent,
                        run_context=context,
                        blocks=blocks,
                        context=service_context,
                    )
                except ServiceCapabilityError as exc:
                    cause = exc.__cause__
                    if isinstance(cause, GuardrailViolationError):
                        terminal_capability_errors.append(cause)
                    raise

            harness = QaHarnessRuntime(
                context_builder=AuthorizedContextBuilder([input_block]),
                agent_runtime=lambda run_spec, run_context, blocks: self._plan_harness_agent_step(
                    plan,
                    run_spec,
                    run_context,
                    blocks,
                ),
                service_capability=execute_service_capability,
                trajectory_sink=lambda event: self._record_harness_trajectory(event, context),
                cancellation_probe=lambda: job.status == JobStatus.CANCELLED,
            )
            harness_result = harness.run(spec)
            if terminal_capability_errors:
                raise terminal_capability_errors[0]
            compatibility_error = next(
                (
                    item
                    for item in harness_result.limitations
                    if item.startswith("MODEL_FALLBACK_DISABLED:")
                ),
                None,
            )
            if compatibility_error:
                raise ValueError(compatibility_error)
            if (
                harness_result.status.value not in {"completed", "degraded", "needs_review"}
                or (
                    harness_result.status.value == "degraded"
                    and harness_result.stopReason != StopReason.COMPLETED_VALID_RESULT
                )
            ):
                raise ValueError(f"QA_HARNESS_STOPPED:{harness_result.stopReason.value}")
            if not harness_result.result:
                raise ValueError("QA_HARNESS_STOPPED:AGENT_OUTPUT_INVALID")
            frozen_refs = dict(harness_result.metadata.get("frozenRefs") or {})
            skill_refs = [
                str(item).rsplit("/", 1)[-1]
                for item in frozen_refs.get("skillInvocationRefs", [])
            ]
            plan.generated_plan = {
                **harness_result.result,
                "skillInvocationRefs": skill_refs,
                "harnessRun": harness_result.model_dump(mode="json"),
            }
            plan.status = PlanStatus.READY
            job.status = JobStatus.COMPLETED
            job.progress = 100
            job.result_ref = str(plan.id)
            job.result_payload = {
                "planId": str(plan.id),
                "status": plan.status.value,
                "harnessRunId": spec.runId,
                "harnessStatus": harness_result.status.value,
                "stopReason": harness_result.stopReason.value,
                "reviewStatus": (
                    "needs_review"
                    if harness_result.status.value == "needs_review"
                    else "completed"
                ),
            }
            job.ended_at = datetime.now(timezone.utc)
            write_audit_log(
                self.db,
                str(context.user.id),
                "test_plan.generate",
                "test_plan",
                str(plan.id),
                context.request_id,
                context.trace_id,
                details={
                    "harnessRunId": spec.runId,
                    "harnessStatus": harness_result.status.value,
                    "stopReason": harness_result.stopReason.value,
                    "budget": {
                        "turnsUsed": harness_result.turnsUsed,
                        "modelCallsUsed": harness_result.modelCallsUsed,
                        "skillInvocationsUsed": harness_result.skillInvocationsUsed,
                        "toolCallsUsed": harness_result.toolCallsUsed,
                    },
                    "trajectoryRefs": harness_result.trajectoryRefs,
                    "skillInvocationRefs": skill_refs,
                    "qaProfileRef": spec.metadata.get("qaProfileRef"),
                    "profileHash": spec.profileSnapshot.get("profileHash"),
                    "profileResolutionHash": spec.metadata.get(
                        "profileResolutionHash"
                    ),
                },
            )
            self.db.commit()
            return {
                "jobId": str(job.id),
                "planId": str(plan.id),
                "status": job.status.value,
                "harnessStatus": harness_result.status.value,
                "stopReason": harness_result.stopReason.value,
            }
        except Exception as exc:
            self.db.rollback()
            self.skill_service.reconcile_extension_failures_after_rollback()
            job = self._require_job(job_id)
            job.status = JobStatus.FAILED
            job.progress = 100
            job.error_message = str(exc)
            job.ended_at = datetime.now(timezone.utc)
            self.db.commit()
            raise

    def _plan_harness_spec(
        self,
        plan: TestPlan,
        job: Job,
        safe_input: dict[str, object],
    ) -> HarnessRunSpec:
        input_refs = self._harness_evidence_refs(self._authoritative_plan_evidence(plan))
        profile = self.qa_profiles.get("web-regression")
        profile_scope = self._plan_profile_scope(plan)
        profile_resolution = self._resolve_plan_profile(
            profile,
            scope=profile_scope,
            requested_domains=self._plan_domains(plan.id),
        )
        if profile_resolution.resolutionStatus == "unavailable":
            reason_codes = ",".join(profile_resolution.limitations)
            raise ValueError(f"QA_PROFILE_RESOLUTION_UNAVAILABLE:{reason_codes}")
        profile_snapshot = {
            "schemaVersion": "qa-profile-snapshot.v1",
            "profileId": profile.profileId,
            "profileVersion": profile.version,
            "profileHash": profile.profileHash,
            "profile": profile.model_dump(mode="json"),
            "extensionResolutionSnapshot": profile_resolution.model_dump(mode="json"),
            "resolutionStatus": profile_resolution.resolutionStatus,
            "publicConfigurable": False,
        }
        policy_snapshot = {
            "schemaVersion": "qa-harness-policy.v1",
            "workflow": "plan.generate",
            "lifecycleStage": "PREPARE",
            "allowDeterministicFallback": safe_input.get("allowDeterministicFallback", True),
            "coverageThreshold": 0.9,
            "maxCoverageRevisions": 1,
            "serviceOwnsBinding": True,
            "serviceOwnsAcceptance": True,
            "qaProfileRef": f"qa-profile://{profile.profileId}/{profile.version}",
            "qaProfileHash": profile.profileHash,
            "extensionResolutionHash": profile_resolution.resolutionHash,
            "profileCannotOverrideControls": True,
        }
        allowed_extension_points = [
            str(item.extensionPointId)
            for item in profile.extensionPointRequirements
            if item.extensionPointId
        ]
        budgets = profile.budgetDefaults
        return HarnessRunSpec(
            runId=str(job.id),
            workflow="plan.generate",
            lifecycleStage="PREPARE",
            objective=f"Generate a bounded test plan and test cases for test-plan://{plan.id}",
            inputRefs=input_refs,
            allowedExtensionPoints=allowed_extension_points,
            policySnapshot=policy_snapshot,
            profileSnapshot=profile_snapshot,
            maxTurns=budgets.maxTurns,
            maxModelCalls=budgets.maxModelCalls,
            maxSkillInvocations=budgets.maxSkillInvocations,
            maxToolCalls=budgets.maxToolCalls,
            timeoutSeconds=budgets.timeoutSeconds,
            stopConditions=profile.stopConditions,
            metadata={
                "agentRef": "agent-runtime://prepare-plan-coordinator.v1",
                "planRef": f"test-plan://{plan.id}",
                "inputSnapshotHash": canonical_content_hash(safe_input),
                "qaProfileRef": f"qa-profile://{profile.profileId}/{profile.version}",
                "profileResolutionHash": profile_resolution.resolutionHash,
            },
        )

    def _resolve_plan_profile(
        self,
        profile: QaProfile,
        *,
        scope: dict[str, object],
        requested_domains: list[str],
    ) -> QaProfileResolutionSnapshot:
        catalog: dict[str, ExtensionDescriptor] = {}
        selections: dict[str, QaProfileExtensionSelection] = {}
        for requirement in profile.all_requirements():
            descriptor: ExtensionDescriptor | None
            selection: QaProfileExtensionSelection | None
            if requirement.kind == ExtensionKind.SKILL:
                descriptor, selection = self._resolve_profile_skill(requirement, scope)
            else:
                descriptor, selection = self._resolve_profile_extension(requirement, scope)
            if descriptor is not None:
                catalog[descriptor.extensionId] = descriptor
            if selection is not None:
                selections[requirement.requirementId] = selection
        return self.qa_profile_resolver.resolve(
            profile,
            scope=scope,
            catalog=catalog,
            selections=selections,
            requested_domains=requested_domains,
        )

    def _resolve_profile_skill(
        self,
        requirement: QaProfileRequirement,
        scope: dict[str, object],
    ) -> tuple[ExtensionDescriptor, QaProfileExtensionSelection]:
        if not requirement.extensionPointId:
            raise ValueError("QA Profile Skill requirement has no extensionPointId")
        resolution = self.skill_service.resolve_binding(
            requirement.extensionPointId,
            scope=scope,
        )
        version = self.db.get(SkillVersion, UUID(str(resolution["skillVersionId"])))
        if version is None:
            raise ValueError("QA Profile resolved Skill Version is unavailable")
        skill = self.db.get(Skill, version.skill_ref_id)
        if skill is None:
            raise ValueError("QA Profile resolved Skill is unavailable")
        compatibility = {
            **dict(version.compatibility or {}),
            "runtimeAdapter": resolution.get("runtimeAdapter"),
            "runtimeResultKind": resolution.get("runtimeResultKind"),
        }
        descriptor = ExtensionDescriptorProjector.skill(
            {
                "skillId": skill.skill_id,
                "displayName": skill.display_name,
                "skillStatus": skill.status,
                "skillVersionId": str(version.id),
                "version": version.version,
                "governanceStatus": version.governance_status,
                "manifestHash": version.manifest_hash,
                "capabilities": dict(version.capabilities or {}),
                "allowedTools": list(version.allowed_tools or []),
                "allowedConnectors": list(version.allowed_connectors or []),
                "riskProfile": dict(version.risk_profile or {}),
                "dataAccessPolicy": dict(version.data_access_policy or {}),
                "replayPolicy": dict(version.replay_policy or {}),
                "extensionPoints": list(version.extension_points or []),
                "compatibility": compatibility,
            }
        )
        binding_id = resolution.get("bindingId")
        return descriptor, QaProfileExtensionSelection(
            requirementId=requirement.requirementId,
            extensionId=descriptor.extensionId,
            extensionRef=f"skill-version://{version.id}",
            bindingRef=(
                f"capability-binding://{binding_id}" if binding_id else None
            ),
            fallbackReason=(
                str(resolution["fallbackReason"])
                if resolution.get("fallbackReason")
                else None
            ),
            authorityScope=dict(scope),
            metadata={
                "extensionPointId": requirement.extensionPointId,
                "source": resolution.get("source"),
                "manifestHash": version.manifest_hash,
            },
        )

    def _resolve_profile_extension(
        self,
        requirement: QaProfileRequirement,
        scope: dict[str, object],
    ) -> tuple[ExtensionDescriptor | None, QaProfileExtensionSelection | None]:
        if not requirement.extensionId:
            return None, None
        descriptor: ExtensionDescriptor | None = None
        extension_ref = f"extension://{requirement.extensionId}"
        if requirement.kind == ExtensionKind.MODEL_ADAPTER:
            descriptor = self._model_role_descriptor(requirement)
            extension_ref = f"model-role://{requirement.modelRole}"
        elif requirement.kind == ExtensionKind.TOOL_ADAPTER:
            try:
                runner = self.runner_registry.get(requirement.extensionId)
            except ValueError:
                runner = None
            if runner is not None:
                descriptor = ExtensionDescriptorProjector.tool_adapter(
                    {
                        "runnerId": runner.runner_id,
                        "domain": runner.domain.value,
                        "supportsParallelism": runner.supports_parallelism,
                        "defaultTimeoutSeconds": runner.default_timeout_seconds,
                        "capabilities": {
                            "domain": runner.domain.value,
                            "registered": True,
                        },
                        "healthStatus": "healthy",
                    }
                )
                extension_ref = f"runner://{runner.runner_id}"
        elif requirement.kind == ExtensionKind.CONNECTOR:
            contract = self._profile_connector_contract(requirement.extensionId)
            if contract is not None:
                descriptor = ExtensionDescriptorProjector.connector(
                    {
                        "connectorName": contract.connector_name,
                        "protocol": contract.protocol,
                        "capabilities": [
                            {
                                "name": item.name,
                                "readOnly": item.read_only,
                                "riskLevel": item.risk_level,
                            }
                            for item in contract.capabilities
                        ],
                        "credentialSchemes": list(contract.credential_schemes),
                        "healthStatus": "unknown",
                    }
                )
                extension_ref = f"connector-contract://{contract.connector_name}"
        elif requirement.kind == ExtensionKind.SANDBOX_ADAPTER:
            sandbox = SandboxProfile().model_dump(mode="json")
            if sandbox["profileId"] == requirement.extensionId:
                descriptor = ExtensionDescriptorProjector.sandbox_adapter(
                    {**sandbox, "healthStatus": "healthy"}
                )
                extension_ref = f"sandbox-profile://{sandbox['profileId']}"
        elif requirement.kind == ExtensionKind.STORAGE_ADAPTER:
            storage_authority = self._storage_descriptor_authority(
                requirement.extensionId
            )
            if storage_authority is not None:
                descriptor = ExtensionDescriptorProjector.storage_adapter(
                    storage_authority
                )
                extension_ref = f"storage-adapter://{requirement.extensionId}"
        elif requirement.kind == ExtensionKind.EVALUATOR:
            descriptor = ExtensionDescriptorProjector.evaluator(
                {
                    "evaluatorId": requirement.extensionId,
                    "version": "1.0.0",
                    "capabilities": {
                        "deterministic": requirement.extensionId
                        == "coverage-review.v1",
                        "evidenceOnly": True,
                    },
                    "healthStatus": "healthy",
                }
            )
            extension_ref = f"evaluator://{requirement.extensionId}"
        if descriptor is None:
            return None, None
        return descriptor, QaProfileExtensionSelection(
            requirementId=requirement.requirementId,
            extensionId=descriptor.extensionId,
            extensionRef=extension_ref,
            authorityScope=dict(scope),
            metadata={"projectionOnly": True},
        )

    def _model_role_descriptor(
        self,
        requirement: QaProfileRequirement,
    ) -> ExtensionDescriptor:
        role = ModelRole(str(requirement.modelRole or ModelRole.PRIMARY.value))
        role_models = list(
            self.db.scalars(
                select(Model)
                .join(ModelRoleBinding, Model.id == ModelRoleBinding.model_id)
                .where(Model.enabled.is_(True))
                .where(ModelRoleBinding.enabled.is_(True))
                .where(ModelRoleBinding.role == role)
                .where(Model.health_status != HealthStatus.UNAVAILABLE)
            )
        )
        candidates = role_models or list(
            self.db.scalars(
                select(Model)
                .where(Model.enabled.is_(True))
                .where(Model.health_status != HealthStatus.UNAVAILABLE)
            )
        )
        capability_keys = {
            str(key)
            for model in candidates
            for key in dict(model.capabilities or {})
        }
        capabilities = {
            key: any(bool(dict(model.capabilities or {}).get(key)) for model in candidates)
            for key in sorted(capability_keys)
        }
        # This descriptor represents the registered model-gateway adapter, not
        # a claim that a live provider is configured.  The gateway always owns
        # the structured-JSON contract and can return its explicit degraded
        # stub/fallback result; provider availability remains a runtime fact.
        capabilities["json"] = True
        health_status = ExtensionHealthStatus.UNKNOWN
        if candidates:
            statuses = {model.health_status for model in candidates}
            if HealthStatus.HEALTHY in statuses:
                health_status = ExtensionHealthStatus.HEALTHY
            elif HealthStatus.UNKNOWN in statuses:
                health_status = ExtensionHealthStatus.UNKNOWN
            else:
                health_status = ExtensionHealthStatus.DEGRADED
        return ExtensionDescriptorProjector.model_adapter(
            {
                "adapterId": requirement.extensionId,
                "displayName": f"Model Gateway {role.value} role",
                "modelRole": role.value,
                "providerSelectionDeferred": True,
                "enabled": True,
                "healthStatus": health_status.value,
                "capabilities": capabilities,
                "candidateModelRefs": [
                    f"model://{model.id}" for model in sorted(candidates, key=lambda item: str(item.id))
                ],
                "limitations": (
                    []
                    if candidates
                    else ["MODEL_ROLE_CANDIDATE_UNAVAILABLE"]
                ),
            }
        )

    def _storage_descriptor_authority(
        self,
        extension_id: str,
    ) -> dict[str, object] | None:
        if extension_id == "artifact-storage.local":
            return {
                "adapterId": extension_id,
                "sourceAuthority": "ArtifactStorageAdapter",
                "capabilities": {
                    "contentHash": True,
                    "stableRefs": True,
                    "local": True,
                },
                "healthStatus": "healthy",
            }
        if extension_id == "replay-storage.local":
            return {
                "adapterId": extension_id,
                "sourceAuthority": "ReplayStorageAdapter",
                "capabilities": {
                    "contentHash": True,
                    "stableRefs": True,
                    "local": True,
                },
                "healthStatus": "healthy",
            }
        return None

    def _profile_connector_contract(
        self,
        connector_name: str,
    ) -> ConnectorRuntimeContract | None:
        contracts = {
            GITHUB_CONNECTOR_CONTRACT.connector_name: GITHUB_CONNECTOR_CONTRACT,
            MCP_CONNECTOR_CONTRACT.connector_name: MCP_CONNECTOR_CONTRACT,
        }
        return contracts.get(connector_name)

    def _plan_profile_scope(self, plan: TestPlan) -> dict[str, object]:
        project = self.db.get(Project, plan.project_id) if plan.project_id else None
        if project is not None:
            tenant_id, workspace_id = ScopeAuthorizationService.project_authority(project)
        else:
            tenant_id = "local-tenant"
            workspace_id = f"unscoped-plan-{plan.id}"
        return {
            "tenantId": tenant_id,
            "workspaceId": workspace_id,
            "projectId": str(plan.project_id) if plan.project_id else plan.source_ref,
            "environmentId": str(plan.environment_id) if plan.environment_id else None,
            "environment": plan.environment,
            "stage": "PREPARE",
        }

    def _harness_profile_request_refs(
        self,
        spec: HarnessRunSpec,
    ) -> dict[str, object]:
        resolution = spec.profileSnapshot.get("extensionResolutionSnapshot")
        resolution = resolution if isinstance(resolution, dict) else {}
        return {
            "qaProfileRef": (
                f"qa-profile://{spec.profileSnapshot.get('profileId')}/"
                f"{spec.profileSnapshot.get('profileVersion')}"
            ),
            "profileHash": spec.profileSnapshot.get("profileHash"),
            "profileResolutionHash": resolution.get("resolutionHash"),
        }

    def _plan_harness_agent_step(
        self,
        plan: TestPlan,
        spec: HarnessRunSpec,
        run_context: HarnessRunContext,
        blocks: list[HarnessContextBlock],
    ) -> AgentStepResult:
        del blocks
        planner_observations = [
            item for item in run_context.observations if item.kind == "planner_result"
        ]
        generator_observations = [
            item for item in run_context.observations if item.kind == "generator_result"
        ]
        coverage_observations = [
            item for item in run_context.observations if item.kind == "coverage_review"
        ]
        evidence = self._harness_step_evidence(spec, run_context)
        if not planner_observations:
            return AgentStepResult(
                result={},
                confidence=1.0,
                evidence=evidence,
                limitations=[],
                skillIntents=[
                    SkillIntent(
                        intentId="planner-1",
                        extensionPointId="PREPARE.test_plan",
                        request={
                            **self._harness_profile_request_refs(spec),
                            "operation": "generate_test_plan",
                            "payload": {
                                "planRef": f"test-plan://{plan.id}",
                                "inputRef": f"test-plan-input://{plan.id}",
                            },
                        },
                        inputRefs=spec.inputRefs,
                        expectedModelCalls=1,
                        expectedSkillInvocations=1,
                        expectedToolCalls=0,
                        metadata={"agent": self.planner.name, "revision": 0},
                    )
                ],
                status="continue",
                metadata={"coordinator": "prepare-plan.v1"},
            )
        if not generator_observations:
            planner_observation = planner_observations[-1]
            return AgentStepResult(
                result=dict(planner_observation.result),
                confidence=float(planner_observation.metadata.get("confidence", 0.0)),
                evidence=evidence,
                limitations=list(planner_observation.limitations),
                skillIntents=[
                    SkillIntent(
                        intentId="generator-1",
                        extensionPointId="PREPARE.test_case",
                        request={
                            **self._harness_profile_request_refs(spec),
                            "operation": "generate_test_cases",
                            "payload": {
                                "planRef": f"test-plan://{plan.id}",
                                "plannerObservationRef": planner_observation.observationRef,
                                "revision": 0,
                            },
                        },
                        inputRefs=[
                            *spec.inputRefs,
                            HarnessEvidenceRef(
                                type="observation",
                                ref=planner_observation.observationRef,
                            ),
                        ],
                        expectedModelCalls=1,
                        expectedSkillInvocations=1,
                        expectedToolCalls=0,
                        metadata={"agent": self.generator.name, "revision": 0},
                    )
                ],
                status="continue",
                fallbackUsed=planner_observation.status == "degraded",
                fallbackReason=planner_observation.metadata.get("fallbackReason"),
                metadata={"coordinator": "prepare-plan.v1"},
            )
        if not coverage_observations:
            return AgentStepResult(
                result=self._harness_candidate(planner_observations[-1], generator_observations[-1], None),
                confidence=0.0,
                evidence=evidence,
                limitations=["COVERAGE_OBSERVATION_MISSING"],
                status="needs_review",
                metadata={"reasonCode": StopReason.INSUFFICIENT_EVIDENCE.value},
            )
        coverage = coverage_observations[-1]
        candidate = self._harness_candidate(
            planner_observations[-1],
            generator_observations[-1],
            coverage,
        )
        fallback_observations = [
            item
            for item in [*planner_observations, *generator_observations]
            if item.status == "degraded"
        ]
        fallback_reason = next(
            (
                str(item.metadata.get("fallbackReason"))
                for item in fallback_observations
                if item.metadata.get("fallbackReason")
            ),
            None,
        )
        confidence = min(
            float(planner_observations[-1].metadata.get("confidence", 0.0)),
            float(generator_observations[-1].metadata.get("confidence", 0.0)),
            float(coverage.result.get("coverageConfidence", 0.0)),
        )
        if coverage.result.get("status") == "approved":
            return AgentStepResult(
                result=candidate,
                confidence=confidence,
                evidence=evidence,
                limitations=list(
                    dict.fromkeys(
                        limitation
                        for item in [*planner_observations, *generator_observations, coverage]
                        for limitation in item.limitations
                    )
                ),
                status="degraded" if fallback_observations else "completed",
                fallbackUsed=bool(fallback_observations),
                fallbackReason=fallback_reason,
                metadata={"coverageStatus": "approved"},
            )
        if len(generator_observations) < 2:
            return AgentStepResult(
                result=candidate,
                confidence=confidence,
                evidence=evidence,
                limitations=["COVERAGE_REVISION_REQUIRED"],
                skillIntents=[
                    SkillIntent(
                        intentId="generator-revision-1",
                        extensionPointId="PREPARE.test_case",
                        request={
                            **self._harness_profile_request_refs(spec),
                            "operation": "revise_test_cases",
                            "payload": {
                                "planRef": f"test-plan://{plan.id}",
                                "plannerObservationRef": planner_observations[-1].observationRef,
                                "coverageObservationRef": coverage.observationRef,
                                "revision": 1,
                            },
                        },
                        inputRefs=[
                            *spec.inputRefs,
                            HarnessEvidenceRef(type="observation", ref=coverage.observationRef),
                        ],
                        expectedModelCalls=1,
                        expectedSkillInvocations=1,
                        expectedToolCalls=0,
                        metadata={"agent": self.generator.name, "revision": 1},
                    )
                ],
                status="continue",
                fallbackUsed=bool(fallback_observations),
                fallbackReason=fallback_reason,
                metadata={"coverageStatus": "needs_review", "revision": 1},
            )
        return AgentStepResult(
            result=candidate,
            confidence=confidence,
            evidence=evidence,
            limitations=list(
                dict.fromkeys(
                    [
                        *coverage.limitations,
                        "COVERAGE_REMAINED_INSUFFICIENT_AFTER_BOUNDED_REVISION",
                    ]
                )
            ),
            status="needs_review",
            fallbackUsed=bool(fallback_observations),
            fallbackReason=fallback_reason,
            metadata={"reasonCode": StopReason.INSUFFICIENT_EVIDENCE.value},
        )

    def _execute_plan_harness_intent(
        self,
        *,
        plan: TestPlan,
        job: Job,
        spec: HarnessRunSpec,
        intent: SkillIntent,
        run_context: HarnessRunContext,
        blocks: list[HarnessContextBlock],
        context: ServiceContext,
    ) -> Observation | list[Observation]:
        del blocks
        if intent.extensionPointId not in {"PREPARE.test_plan", "PREPARE.test_case"}:
            raise ServiceCapabilityError(StopReason.CAPABILITY_UNAVAILABLE)
        planner_observations = [
            item for item in run_context.observations if item.kind == "planner_result"
        ]
        if intent.extensionPointId == "PREPARE.test_case" and not planner_observations:
            raise ServiceCapabilityError(StopReason.SERVICE_CAPABILITY_FAILED)
        agent = self.planner if intent.extensionPointId == "PREPARE.test_plan" else self.generator
        validator = PlannerModelOutput if agent is self.planner else GeneratorModelOutput
        revision = int(intent.metadata.get("revision", 0))
        safe_input = self._minimal_harness_input(plan)
        planner_result = (
            AgentResult(
                result=dict(planner_observations[-1].result),
                confidence=float(planner_observations[-1].metadata.get("confidence", 0.0)),
                evidence=[item.model_dump(mode="json") for item in planner_observations[-1].evidenceRefs],
                limitations=list(planner_observations[-1].limitations),
                metadata=dict(planner_observations[-1].metadata),
            )
            if planner_observations
            else None
        )
        invocation: SkillInvocation | None = None
        model_response: dict[str, object] | None = None
        try:
            def execute_agent(_runtime_context, _runtime_request):
                nonlocal model_response
                prompt = self._harness_model_prompt(plan, agent.name, revision)
                model_payload: dict[str, object] = {
                    **safe_input,
                    "taskType": (
                        "plan.generate"
                        if agent is self.planner
                        else "plan.generate.cases"
                    ),
                    "agent": agent.name,
                    "planName": plan.name,
                    "revision": revision,
                }
                if planner_result is not None:
                    model_payload["generatedPlan"] = planner_result.payload
                latest_coverage = next(
                    (
                        item
                        for item in reversed(run_context.observations)
                        if item.kind == "coverage_review"
                    ),
                    None,
                )
                if latest_coverage is not None:
                    model_payload["coverageObservation"] = latest_coverage.result
                with traced_operation(
                    self.db,
                    trace_id=context.trace_id,
                    execution_id=None,
                    root_span_name="plan.generate",
                    span_name="model.select-and-invoke",
                    service_name="orchestrator-service",
                    attributes={
                        "planId": str(plan.id),
                        "agent": agent.name,
                        "harnessRunId": str(job.id),
                        "turn": run_context.currentTurn,
                        "revision": revision,
                    },
                ):
                    model_response = self.model_tool.invoke_json(
                        trace_id=UUID(context.trace_id),
                        execution_id=None,
                        role=ModelRole.PRIMARY,
                        prompt=prompt,
                        payload=model_payload,
                        validator=validator,
                        request_id=context.request_id,
                        timeout_seconds=_runtime_context.remaining_seconds(),
                        max_provider_retries=0,
                    )
                if agent is self.planner:
                    return self._planner_result(plan, model_response)
                if planner_result is None:
                    raise ValueError("planner Observation is required")
                return self._generator_result(plan, planner_result, model_response)

            def accept_agent_result(
                runtime_result: object,
                selected_invocation: SkillInvocation,
            ) -> ExtensionInvocationCompletion:
                if not isinstance(runtime_result, AgentResult):
                    raise ValueError("managed Skill runtime returned an incompatible AgentResult")
                self.guardrail_engine.enforce(
                    GuardrailContext(
                        trace_id=context.trace_id,
                        request_id=context.request_id,
                        actor_id=context.user.id,
                        actor_roles=context.user.roles,
                        resource_type="test_plan",
                        resource_id=str(plan.id),
                        skill_invocation_id=selected_invocation.id,
                        payload={"agentName": agent.name, "agentResult": runtime_result},
                    ),
                    [AgentOutputGuard()],
                )
                return ExtensionInvocationCompletion(
                    output_snapshot=self._skill_result(
                        result=runtime_result.payload,
                        confidence=runtime_result.confidence,
                        evidence=self._skill_evidence(plan, runtime_result, model_response),
                        metadata=self._skill_metadata(agent.name, runtime_result, model_response),
                    ),
                    status=self._skill_invocation_status(runtime_result),
                )

            with traced_operation(
                self.db,
                trace_id=context.trace_id,
                execution_id=None,
                root_span_name="plan.generate",
                span_name=(
                    "planner.run" if agent is self.planner else "generator.run"
                ),
                service_name="agent-service",
                attributes={
                    "planId": str(plan.id),
                    "harnessRunId": str(job.id),
                    "turn": run_context.currentTurn,
                    "revision": revision,
                },
            ):
                extension_result = self.skill_service.invoke_extension(
                    extension_point_id=intent.extensionPointId,
                    source_workflow="plan.generate",
                    context=context,
                    request=intent.request,
                    scope={
                        **self._plan_profile_scope(plan),
                        "domain": "test_plan" if agent is self.planner else "test_case",
                    },
                    policy_snapshot={
                        "workflow": "plan.generate",
                        "stage": "PREPARE",
                        "harnessRunId": str(job.id),
                        "intentId": intent.intentId,
                        "revision": revision,
                        "qaProfileSnapshot": spec.profileSnapshot,
                        "extensionResolutionHash": spec.metadata.get(
                            "profileResolutionHash"
                        ),
                        "parentBudget": {
                            "remainingModelCalls": max(
                                0, spec.maxModelCalls - run_context.modelCallsUsed
                            ),
                            "remainingSkillInvocations": max(
                                0,
                                spec.maxSkillInvocations
                                - run_context.skillInvocationsUsed,
                            ),
                            "remainingToolCalls": max(
                                0, spec.maxToolCalls - run_context.toolCallsUsed
                            ),
                        },
                    },
                    deadline_at=run_context.deadlineAt,
                    cancellation_probe=lambda: (
                        run_context.cancellationState == "cancelled"
                    ),
                    idempotency_key=f"qa-harness:{job.id}:{intent.intentId}",
                    capabilities={"execute": execute_agent},
                    resolution_metadata=self._harness_profile_request_refs(spec),
                    result_acceptor=accept_agent_result,
                )
                if not isinstance(extension_result.runtime_result, AgentResult):
                    raise ValueError("managed Skill runtime returned an incompatible AgentResult")
                agent_result = extension_result.runtime_result
            invocation = self.db.get(SkillInvocation, extension_result.invocation_id)
            if invocation is None:
                raise ValueError("managed Skill invocation was not persisted")
            agent_run_id = self._persist_harness_agent_run(
                plan=plan,
                agent_name=agent.name,
                input_payload=safe_input,
                result=agent_result,
                model_response=model_response,
                context=context,
            )
            invocation.agent_run_id = agent_run_id
            self._link_model_invocation(model_response, agent_run_id)
            self.db.flush()
            observation = self._agent_observation(
                plan=plan,
                job=job,
                intent=intent,
                invocation=invocation,
                agent_run_id=agent_run_id,
                result=agent_result,
                model_response=model_response,
                kind="planner_result" if agent is self.planner else "generator_result",
            )
            if agent is self.planner:
                job.progress = max(job.progress, 45)
                return observation
            job.progress = max(job.progress, 75 if revision == 0 else 90)
            candidate = self._harness_candidate(planner_observations[-1], observation, None)
            coverage = self._coverage_observation(
                plan=plan,
                job=job,
                intent=intent,
                invocation=invocation,
                generated_plan=candidate,
                revision=revision,
            )
            return [observation, coverage]
        except GuardrailViolationError as exc:
            raise ServiceCapabilityError(StopReason.GUARDRAIL_BLOCKED) from exc
        except ServiceCapabilityError:
            raise
        except Exception as exc:
            reason = self._capability_stop_reason(exc)
            message = (
                str(exc)
                if str(exc).startswith("MODEL_FALLBACK_DISABLED:")
                else reason.value
            )
            raise ServiceCapabilityError(reason, message) from exc

    def _agent_observation(
        self,
        *,
        plan: TestPlan,
        job: Job,
        intent: SkillIntent,
        invocation: SkillInvocation,
        agent_run_id: UUID,
        result: AgentResult,
        model_response: dict[str, object] | None,
        kind: str,
    ) -> Observation:
        evidence = self._harness_evidence_refs(
            self._skill_evidence(plan, result, model_response)
        )
        status: Literal["completed", "degraded"] = (
            "degraded" if result.metadata.get("status") == "degraded" else "completed"
        )
        return Observation(
            observationId=f"{intent.intentId}:agent-result",
            observationRef=f"harness-observation://{job.id}/{intent.intentId}/agent-result",
            intentId=intent.intentId,
            extensionPointId=intent.extensionPointId,
            source="service",
            kind=kind,
            status=status,
            available=True,
            result=result.payload,
            evidenceRefs=evidence,
            limitations=list(result.limitations),
            usage=ObservationUsage(modelCalls=1, skillInvocations=1, toolCalls=0),
            skillInvocationRef=f"skill-invocation://{invocation.id}",
            modelInvocationRef=self._model_invocation_ref(model_response),
            agentRunRef=f"agent-run://{agent_run_id}",
            traceRefs=[f"trace://{invocation.trace_id}"],
            redactionStatus="redacted",
            metadata={
                "confidence": result.confidence,
                "fallbackUsed": bool(result.metadata.get("fallbackUsed", False)),
                "fallbackReason": result.metadata.get("fallbackReason"),
                "modelStatus": model_response.get("status") if model_response else None,
                "bindingResolution": self._frozen_binding_resolution(invocation),
                "generationMetadata": self._generation_metadata(result, model_response),
            },
        )

    def _coverage_observation(
        self,
        *,
        plan: TestPlan,
        job: Job,
        intent: SkillIntent,
        invocation: SkillInvocation,
        generated_plan: dict[str, object],
        revision: int,
    ) -> Observation:
        coverage = self._generation_coverage_review(plan, generated_plan)
        evidence = self._harness_evidence_refs(
            [
                *self._authoritative_plan_evidence(plan),
                {"type": "skill_invocation", "ref": f"skill-invocation://{invocation.id}"},
            ]
        )
        return Observation(
            observationId=f"{intent.intentId}:coverage-review",
            observationRef=f"harness-observation://{job.id}/{intent.intentId}/coverage-review",
            intentId=intent.intentId,
            extensionPointId=intent.extensionPointId,
            source="service",
            kind="coverage_review",
            status="completed",
            available=True,
            result=coverage,
            evidenceRefs=evidence,
            limitations=(
                []
                if coverage["status"] == "approved"
                else ["COVERAGE_REVIEW_NEEDS_REVISION"]
            ),
            usage=ObservationUsage(),
            skillInvocationRef=f"skill-invocation://{invocation.id}",
            traceRefs=[f"trace://{invocation.trace_id}"],
            redactionStatus="not_required",
            metadata={
                "revision": revision,
                "deterministic": True,
                "authoritativeDecision": False,
            },
        )

    def _generation_coverage_review(
        self,
        plan: TestPlan,
        generated_plan: dict[str, object],
    ) -> dict[str, object]:
        requirements = [
            str(item)
            for item in plan.input_payload.get("requirements", [])
            if str(item).strip()
        ]
        test_points = self._coverage_test_points(generated_plan)
        test_cases = self._coverage_test_cases(generated_plan)
        uncovered = [
            {"requirement": requirement, "reason": "no matching test point or case"}
            for requirement in requirements
            if not self._requirement_is_covered(requirement, test_points, test_cases)
        ]
        weak = [
            {"area": item["requirement"], "reason": "requirement is not covered"}
            for item in uncovered
        ]
        duplicates = self._duplicate_coverage_areas(test_cases)
        requirement_coverage = self._ratio(
            len(requirements) - len(uncovered),
            len(requirements),
            default=1.0,
        )
        approved = requirement_coverage >= 0.9 and not weak and not duplicates and bool(test_cases)
        return {
            "schemaVersion": "qa-harness-coverage-observation.v1",
            "status": "approved" if approved else "needs_review",
            "requirementCoverage": requirement_coverage,
            "testPointCoverage": self._ratio(len(test_points), len(requirements), default=1.0),
            "testCaseCoverage": self._ratio(len(test_cases), len(test_points), default=1.0),
            "coverageConfidence": (
                0.5
                if not requirements
                else self._ratio(
                    len(requirements) - len(uncovered),
                    len(requirements),
                    default=1.0,
                )
            ),
            "uncoveredRequirements": uncovered,
            "weakCoverageAreas": weak,
            "duplicateCoverageAreas": duplicates,
            "testCaseCount": len(test_cases),
            "authoritative": False,
        }

    def _harness_candidate(
        self,
        planner: Observation,
        generator: Observation,
        coverage: Observation | None,
    ) -> dict[str, object]:
        return {
            **dict(planner.result),
            **dict(generator.result),
            "coverageReview": dict(coverage.result) if coverage is not None else None,
            "generationMetadata": {
                "planner": dict(planner.metadata.get("generationMetadata") or {}),
                "generator": dict(generator.metadata.get("generationMetadata") or {}),
            },
        }

    def _persist_harness_agent_run(
        self,
        *,
        plan: TestPlan,
        agent_name: str,
        input_payload: dict[str, object],
        result: AgentResult,
        model_response: dict[str, object] | None,
        context: ServiceContext,
    ) -> UUID:
        now = datetime.now(timezone.utc)
        agent_run_id = uuid4()
        self.db.add(
            AgentRun(
                id=agent_run_id,
                execution_id=None,
                task_id=None,
                trace_id=UUID(context.trace_id),
                agent_name=agent_name,
                status=AgentRunStatus.COMPLETED,
                input_payload={
                    "planRef": f"test-plan://{plan.id}",
                    "inputHash": canonical_hash(input_payload),
                },
                output_payload=result.to_contract(),
                model_id=self._parse_model_id(model_response),
                started_at=now,
                ended_at=now,
            )
        )
        self.db.flush()
        return agent_run_id

    def _record_harness_trajectory(
        self,
        event: TrajectoryEvent,
        context: ServiceContext,
    ) -> str:
        span = record_span(
            self.db,
            trace_id=context.trace_id,
            span_name=f"qa_harness.{event.state.value.lower()}",
            service_name="orchestrator-service",
            status=(
                "error"
                if event.state.value in {"FAILED", "BLOCKED", "CANCELLED"}
                else "ok"
            ),
            attributes={
                "runId": event.runId,
                "turn": event.turn,
                "state": event.state.value,
                "agentRef": event.agentRef,
                "modelInvocationRef": event.modelInvocationRef,
                "skillIntentRef": event.skillIntentRef,
                "skillInvocationRef": event.skillInvocationRef,
                "observationRefs": event.observationRefs,
                "stopReason": event.stopReason.value if event.stopReason else None,
                "budgetSnapshot": event.budgetSnapshot.model_dump(mode="json"),
            },
        )
        self.db.flush()
        return f"trace-span://{span.id}"

    def _harness_model_prompt(self, plan: TestPlan, agent_name: str, revision: int) -> str:
        if agent_name == self.planner.name:
            return (
                f"Generate test plan for {plan.name}. Return only PlannerModelOutput JSON with "
                "result.functional.scenarios, result.performance.targets, result.security.checks, "
                "confidence, evidence, limitations, and metadata."
            )
        revision_instruction = (
            " Revise the cases once to address the supplied coverage Observation."
            if revision
            else ""
        )
        return (
            f"Generate executable cases for {plan.name}. Return only GeneratorModelOutput JSON with "
            "result.generatedCases for functional/performance/security, result.summary, confidence, "
            f"evidence, limitations, and metadata.{revision_instruction}"
        )

    def _minimal_harness_input(self, plan: TestPlan) -> dict[str, object]:
        allowed = {
            "acceptanceCriteria",
            "allowDeterministicFallback",
            "diffSummary",
            "domains",
            "requirementScope",
            "requirements",
            "requirementVersionId",
            "riskHints",
        }
        source = {
            key: value
            for key, value in dict(plan.input_payload).items()
            if key in allowed
        }
        if plan.requirement_scope:
            source["requirementScope"] = plan.requirement_scope
        return cast(dict[str, object], self._minimal_json_value(source))

    def _minimal_json_value(self, value: object) -> object:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, list):
            return [self._minimal_json_value(item) for item in value[:500]]
        if isinstance(value, tuple):
            return [self._minimal_json_value(item) for item in value[:500]]
        if isinstance(value, dict):
            safe: dict[str, object] = {}
            for key, item in value.items():
                normalized = "".join(character for character in str(key).lower() if character.isalnum())
                if any(
                    marker in normalized
                    for marker in (
                        "authorization",
                        "cookie",
                        "credential",
                        "password",
                        "rawconnectorconfig",
                        "rawproviderresponse",
                        "secret",
                        "sourcecode",
                        "token",
                    )
                ) or normalized in {"diff", "patch"}:
                    continue
                safe[str(key)] = self._minimal_json_value(item)
            return safe
        raise ValueError("test plan input contains a non-JSON value")

    def _harness_evidence_refs(
        self,
        evidence: list[dict[str, object]],
    ) -> list[HarnessEvidenceRef]:
        refs: list[HarnessEvidenceRef] = []
        seen: set[str] = set()
        for item in evidence:
            evidence_type = str(item.get("type") or "evidence")
            raw_ref = item.get("ref") or item.get("id")
            if raw_ref is None:
                continue
            ref = str(raw_ref)
            if "://" not in ref:
                ref = f"{evidence_type}://{ref}"
            content_hash = item.get("contentHash")
            key = f"{evidence_type}:{ref}:{content_hash or ''}"
            if key in seen:
                continue
            seen.add(key)
            refs.append(
                HarnessEvidenceRef(
                    type=evidence_type,
                    ref=ref,
                    contentHash=str(content_hash) if content_hash else None,
                )
            )
        return refs

    def _harness_step_evidence(
        self,
        spec: HarnessRunSpec,
        run_context: HarnessRunContext,
    ) -> list[HarnessEvidenceRef]:
        refs = [*spec.inputRefs, *run_context.evidenceRefs]
        for observation in run_context.observations:
            refs.append(
                HarnessEvidenceRef(type="observation", ref=observation.observationRef)
            )
        unique: list[HarnessEvidenceRef] = []
        seen: set[str] = set()
        for item in refs:
            key = f"{item.type}:{item.ref}:{item.contentHash or ''}"
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return unique

    def _frozen_binding_resolution(self, invocation: SkillInvocation) -> dict[str, object]:
        resolution = dict(invocation.resolution_snapshot or {})
        allowed = {
            "requestedExtensionPointId",
            "extensionPointId",
            "resolvedSkillId",
            "skillId",
            "skillVersionId",
            "version",
            "manifestHash",
            "bindingId",
            "scope",
            "source",
            "fallbackReason",
            "runtimeAdapter",
            "runtimeResultKind",
            "capabilityDecisionRefs",
            "licenseDecisionRefs",
            "approvalDecisionRefs",
            "qaProfileRef",
            "profileHash",
            "profileResolutionHash",
        }
        return {key: value for key, value in resolution.items() if key in allowed}

    def _capability_stop_reason(self, exc: Exception) -> StopReason:
        message = str(exc).upper()
        if "MODEL_INPUT_BLOCKED" in message or "PROMPT_INJECTION" in message:
            return StopReason.GUARDRAIL_BLOCKED
        if "MODEL_FALLBACK_DISABLED" in message:
            if "INVALID" in message or "SCHEMA" in message or "MALFORMED" in message:
                return StopReason.MODEL_OUTPUT_INVALID
            return StopReason.MODEL_UNAVAILABLE
        if "MODEL" in message and ("INVALID" in message or "SCHEMA" in message):
            return StopReason.MODEL_OUTPUT_INVALID
        if "MODEL" in message and ("UNAVAILABLE" in message or "FAILED" in message):
            return StopReason.MODEL_UNAVAILABLE
        if "APPROVAL" in message:
            return StopReason.APPROVAL_REQUIRED
        if "BINDING" in message:
            return StopReason.BINDING_UNAVAILABLE
        if "EXTENSION POINT" in message or "RUNTIME" in message or "CAPABILITY" in message:
            return StopReason.CAPABILITY_UNAVAILABLE
        return StopReason.SERVICE_CAPABILITY_FAILED

    def serialize_plan(self, plan: TestPlan, domain_lookup: dict[UUID, list[str]] | None = None) -> dict[str, object]:
        return {
            "id": str(plan.id),
            "name": plan.name,
            "status": plan.status.value,
            "domains": (domain_lookup or {}).get(plan.id, self._plan_domains(plan.id)),
            "domainConfig": self._plan_domain_config(plan.id),
            "riskLevel": plan.risk_level.value,
            "environment": plan.environment,
            "projectId": str(plan.project_id) if plan.project_id else None,
            "environmentId": str(plan.environment_id) if plan.environment_id else None,
            "sourceType": plan.source_type.value,
            "sourceRef": plan.source_ref,
            "requirementVersionId": str(plan.requirement_version_id) if plan.requirement_version_id else None,
            "requirementScope": plan.requirement_scope,
            "input": plan.input_payload,
            "generatedPlan": plan.generated_plan,
            "createdAt": plan.created_at.isoformat(),
            "updatedAt": plan.updated_at.isoformat(),
        }

    def _plan_domains(self, plan_id: UUID) -> list[str]:
        statement = select(TestPlanDomain).where(TestPlanDomain.plan_id == plan_id)
        return [row.domain.value for row in self.db.scalars(statement)]

    def _plan_domain_config(self, plan_id: UUID) -> dict[str, dict[str, object]]:
        rows = self.db.scalars(select(TestPlanDomain).where(TestPlanDomain.plan_id == plan_id))
        return {row.domain.value: row.config for row in rows}

    def _plan_domains_map(self, plan_ids: list[UUID]) -> dict[UUID, list[str]]:
        if not plan_ids:
            return {}
        domain_lookup = {plan_id: [] for plan_id in plan_ids}
        rows = self.db.scalars(select(TestPlanDomain).where(TestPlanDomain.plan_id.in_(plan_ids)))
        for row in rows:
            domain_lookup[row.plan_id].append(row.domain.value)
        return domain_lookup

    def _optional_project_id(self, project_id: UUID | None) -> UUID | None:
        if project_id is None:
            return None
        if self.db.get(Project, project_id) is None:
            raise ValueError("project not found")
        return project_id

    def _optional_environment_id(self, environment_id: UUID | None, project_id: UUID | None) -> UUID | None:
        if environment_id is None:
            return None
        environment = self.db.get(ProjectEnvironment, environment_id)
        if environment is None:
            raise ValueError("environment not found")
        if project_id is not None and environment.project_id != project_id:
            raise ValueError("environment does not belong to project")
        return environment_id

    def _require_plan(self, plan_id: UUID) -> TestPlan:
        plan = self.db.get(TestPlan, plan_id)
        if plan is None:
            raise ValueError("test plan not found")
        return plan

    def _requirement_version_id_from_payload(self, payload, input_payload: dict[str, object]) -> UUID | None:
        raw_id = getattr(payload, "requirementVersionId", None) or input_payload.get("requirementVersionId")
        raw_scope = getattr(payload, "requirementScope", None) or input_payload.get("requirementScope")
        if raw_id is None and raw_scope is not None:
            scope_payload = raw_scope.model_dump(mode="json") if hasattr(raw_scope, "model_dump") else dict(raw_scope)
            raw_id = scope_payload.get("requirementVersionId")
        if raw_id is None:
            return None
        return UUID(str(raw_id))

    def _requirement_scope_from_payload(
        self,
        payload,
        input_payload: dict[str, object],
        requirement_version_id: UUID | None,
    ) -> dict[str, object]:
        raw_scope = getattr(payload, "requirementScope", None) or input_payload.get("requirementScope")
        if raw_scope is not None:
            scope_payload = raw_scope.model_dump(mode="json") if hasattr(raw_scope, "model_dump") else dict(raw_scope)
            return self._normalize_scope_payload(scope_payload, requirement_version_id)
        if requirement_version_id is None:
            return {}
        return normalize_requirement_scope(
            requirement_version_id=requirement_version_id,
            filters={"source": "test_plan"},
            metadata={"selectionMode": "requirement_version", "defaulted": True},
        )

    def _normalize_scope_payload(
        self,
        scope_payload: dict[str, object],
        requirement_version_id: UUID | None,
    ) -> dict[str, object]:
        scope_requirement_version_id = UUID(str(scope_payload.get("requirementVersionId") or requirement_version_id))
        if requirement_version_id is not None and scope_requirement_version_id != requirement_version_id:
            raise ValueError("requirementScope.requirementVersionId must match requirementVersionId")
        return normalize_requirement_scope(
            requirement_version_id=scope_requirement_version_id,
            selected_requirement_item_ids=[str(item) for item in scope_payload.get("selectedRequirementItemIds") or []],
            requirement_version_ids=[str(item) for item in scope_payload.get("requirementVersionIds") or []] or None,
            requirement_item_refs=list(scope_payload.get("requirementItemRefs") or []),
            filters=dict(scope_payload.get("filters") or {}),
            metadata=dict(scope_payload.get("metadata") or {}),
            force_v2=str(scope_payload.get("schemaVersion")) == "phase8.requirement-scope.v2",
        )

    def _require_job(self, job_id: UUID) -> Job:
        job = self.db.get(Job, job_id)
        if job is None:
            raise ValueError("job not found")
        return job

    def _parse_model_id(self, model_response: dict[str, object] | None) -> UUID | None:
        if not model_response:
            return None
        model_id = model_response.get("modelId")
        if not model_id:
            return None
        return UUID(str(model_id))

    def _planner_result(
        self,
        plan: TestPlan,
        model_response: dict[str, object],
    ) -> AgentResult:
        return self._model_result_or_fallback(
            plan=plan,
            model_response=model_response,
            fallback=lambda: self.planner.run(plan.input_payload),
        )

    def _generator_result(
        self,
        plan: TestPlan,
        planner_result: AgentResult,
        model_response: dict[str, object],
    ) -> AgentResult:
        return self._model_result_or_fallback(
            plan=plan,
            model_response=model_response,
            fallback=lambda: self.generator.run(
                {"planName": plan.name, "generatedPlan": planner_result.payload}
            ),
        )

    def _model_result_or_fallback(
        self,
        *,
        plan: TestPlan,
        model_response: dict[str, object],
        fallback: Callable[[], AgentResult],
    ) -> AgentResult:
        output = model_response.get("output")
        if (
            model_response.get("status") == "completed"
            and model_response.get("success") is True
            and isinstance(output, dict)
            and isinstance(output.get("result"), dict)
        ):
            model_evidence = [
                dict(item)
                for item in output.get("evidence", [])
                if isinstance(item, dict)
            ]
            return AgentResult(
                result=dict(output["result"]),
                confidence=float(output.get("confidence", 0.0)),
                evidence=cast(
                    list[str | dict[str, Any]],
                    [*self._authoritative_plan_evidence(plan), *model_evidence],
                ),
                limitations=[str(item) for item in output.get("limitations", [])],
                metadata={
                    **dict(output.get("metadata") or {}),
                    "status": "completed",
                    "executionMode": "model",
                    "modelInvocationRef": self._model_invocation_ref(model_response),
                    "modelStatus": model_response.get("status"),
                    "modelMode": model_response.get("mode"),
                    "provider": model_response.get("provider"),
                    "fallbackUsed": False,
                    "fallbackReason": None,
                },
            )

        fallback_reason = self._model_fallback_reason(model_response)
        if fallback_reason == "MODEL_INPUT_PROMPT_INJECTION_BLOCKED":
            raise ValueError(f"MODEL_INPUT_BLOCKED:{fallback_reason}")
        if plan.input_payload.get("allowDeterministicFallback") is False:
            raise ValueError(f"MODEL_FALLBACK_DISABLED:{fallback_reason}")
        deterministic = fallback()
        return AgentResult(
            result=deterministic.payload,
            confidence=min(max(float(deterministic.confidence), 0.0), 0.45),
            evidence=cast(
                list[str | dict[str, Any]],
                self._authoritative_plan_evidence(plan),
            ),
            limitations=list(
                dict.fromkeys(
                    [
                        *[str(item) for item in model_response.get("limitations", [])],
                        "DETERMINISTIC_FALLBACK_USED",
                    ]
                )
            ),
            metadata={
                **dict(deterministic.metadata),
                "status": "degraded",
                "executionMode": "deterministic_fallback",
                "modelInvocationRef": self._model_invocation_ref(model_response),
                "modelStatus": model_response.get("status"),
                "modelMode": model_response.get("mode"),
                "provider": model_response.get("provider"),
                "fallbackUsed": True,
                "fallbackReason": fallback_reason,
            },
        )

    def _authoritative_plan_evidence(self, plan: TestPlan) -> list[dict[str, Any]]:
        refs: list[dict[str, Any]] = [
            {
                "type": "test_plan",
                "ref": f"test-plan://{plan.id}",
            },
            {
                "type": "test_plan_input",
                "ref": f"test-plan-input://{plan.id}",
                "contentHash": canonical_hash(plan.input_payload),
            },
        ]
        if plan.requirement_version_id is not None:
            refs.append(
                {
                    "type": "requirement_version",
                    "ref": f"requirement-version://{plan.requirement_version_id}",
                }
            )
        if plan.requirement_scope_id:
            refs.append(
                {
                    "type": "requirement_scope",
                    "ref": f"requirement-scope://{plan.requirement_scope_id}",
                }
            )
        return refs

    def _model_fallback_reason(self, model_response: dict[str, object]) -> str:
        explicit = model_response.get("fallbackReason")
        if explicit:
            return str(explicit)
        limitations = model_response.get("limitations")
        if isinstance(limitations, list) and limitations:
            return str(limitations[0])
        status = str(model_response.get("status") or "failed").upper()
        return f"MODEL_{status}"

    def _model_invocation_ref(self, model_response: dict[str, object] | None) -> str | None:
        invocation_id = model_response.get("modelInvocationId") if model_response else None
        return f"model-invocation://{invocation_id}" if invocation_id else None

    def _skill_evidence(
        self,
        plan: TestPlan,
        result: AgentResult,
        model_response: dict[str, object] | None,
    ) -> list[dict[str, object]]:
        evidence = [*self._authoritative_plan_evidence(plan)]
        for item in result.evidence:
            if isinstance(item, dict) and item.get("type") and (item.get("ref") or item.get("id")):
                evidence.append(dict(item))
        model_ref = self._model_invocation_ref(model_response)
        if model_ref:
            evidence.append({"type": "model_invocation", "ref": model_ref})
        unique: list[dict[str, object]] = []
        seen: set[str] = set()
        for item in evidence:
            key = canonical_hash(item)
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return unique

    def _skill_metadata(
        self,
        agent_name: str,
        result: AgentResult,
        model_response: dict[str, object] | None,
    ) -> dict[str, object]:
        return {
            "agent": agent_name,
            "sourceWorkflow": "plan.generate",
            "status": result.metadata.get("status", "completed"),
            "executionMode": result.metadata.get("executionMode", "managed_runtime"),
            "modelInvocationRef": self._model_invocation_ref(model_response),
            "modelStatus": model_response.get("status") if model_response else None,
            "fallbackUsed": bool(result.metadata.get("fallbackUsed", False)),
            "fallbackReason": result.metadata.get("fallbackReason"),
            "limitations": list(result.limitations),
        }

    def _skill_invocation_status(self, result: AgentResult) -> str:
        return "degraded" if result.metadata.get("status") == "degraded" else "completed"

    def _generation_metadata(
        self,
        result: AgentResult,
        model_response: dict[str, object] | None,
    ) -> dict[str, object]:
        return {
            "status": result.metadata.get("status", "completed"),
            "executionMode": result.metadata.get("executionMode", "managed_runtime"),
            "modelInvocationRef": self._model_invocation_ref(model_response),
            "modelStatus": model_response.get("status") if model_response else None,
            "fallbackUsed": bool(result.metadata.get("fallbackUsed", False)),
            "fallbackReason": result.metadata.get("fallbackReason"),
            "confidence": result.confidence,
            "limitations": list(result.limitations),
        }

    def _link_model_invocation(
        self,
        model_response: dict[str, object] | None,
        agent_run_id: UUID,
    ) -> None:
        if not model_response or not model_response.get("modelInvocationId"):
            return
        invocation = self.db.get(ModelInvocation, UUID(str(model_response["modelInvocationId"])))
        if invocation is not None:
            invocation.agent_run_id = agent_run_id

    def _skill_result(
        self,
        *,
        result: dict[str, object],
        confidence: float,
        evidence: list[dict[str, object]],
        metadata: dict[str, object],
    ) -> dict[str, object]:
        return {
            "result": result,
            "confidence": float(confidence),
            "evidence": evidence,
            "artifactRefs": [],
            "rawFindingRefs": [],
            "findingCandidates": [],
            "metadata": metadata,
        }

    def _coverage_test_points(self, generated_plan: dict[str, object]) -> list[dict[str, str]]:
        points: list[dict[str, str]] = []
        for domain, key in (("functional", "scenarios"), ("performance", "targets"), ("security", "checks")):
            section = generated_plan.get(domain)
            values = section.get(key, []) if isinstance(section, dict) else []
            points.extend({"domain": domain, "text": str(value)} for value in values)
        return points

    def _coverage_test_cases(self, generated_plan: dict[str, object]) -> list[dict[str, str]]:
        cases: list[dict[str, str]] = []
        generated_cases = generated_plan.get("generatedCases", {})
        if not isinstance(generated_cases, dict):
            return cases
        for domain, rows in generated_cases.items():
            if not isinstance(rows, list):
                continue
            for row in rows:
                if isinstance(row, dict):
                    cases.append({"domain": str(domain), "name": str(row.get("name", "")), "goal": str(row.get("goal", ""))})
        return cases

    def _requirement_is_covered(self, requirement: str, test_points: list[dict[str, str]], test_cases: list[dict[str, str]]) -> bool:
        normalized = requirement.strip().lower()
        haystack = " ".join([item["text"] for item in test_points] + [item["goal"] for item in test_cases]).lower()
        return bool(normalized and normalized in haystack)

    def _duplicate_coverage_areas(self, test_cases: list[dict[str, str]]) -> list[dict[str, object]]:
        seen: dict[str, int] = {}
        for test_case in test_cases:
            key = test_case["goal"].strip().lower()
            if key:
                seen[key] = seen.get(key, 0) + 1
        return [
            {"goal": goal, "count": count, "reason": "duplicate test case goal"}
            for goal, count in seen.items()
            if count > 1
        ]

    def _ratio(self, numerator: int, denominator: int, *, default: float) -> float:
        if denominator <= 0:
            return default
        return max(0.0, min(1.0, numerator / denominator))
