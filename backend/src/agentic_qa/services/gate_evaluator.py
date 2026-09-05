# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import ValidationError

from agentic_qa.schemas.gate_evaluator import (
    DomainInputStateContract,
    GateAuthorityRefContract,
    GateCompletenessSummaryContract,
    GateDecisionValue,
    GateDomainResultContract,
    GateDomainValue,
    GateInputContract,
    GateInputEvaluationSummaryContract,
    GateMetricEvaluationContract,
    GatePolicyEvaluationSummaryContract,
    GateResultContract,
)
from agentic_qa.schemas.gate_policy import (
    GatePolicyContract,
    GatePolicyResolutionSnapshotContract,
)
from agentic_qa.services.common import canonical_hash
from agentic_qa.services.gate_policy_resolver import (
    GatePolicyResolutionError,
    GatePolicyResolutionSnapshotBuilder,
)


GATE_EVALUATOR_VERSION = "phase8.gate-evaluator.v1"
DOMAIN_ORDER: tuple[GateDomainValue, ...] = ("functional", "performance", "security")
SYSTEM_HARD_RULE_PREFIX = "SYSTEM_"

LEGACY_REASON_TEXT = {
    "FUNCTIONAL_BLOCKING_FINDING_OPEN": "functional blocking canonical finding is still open",
    "FUNCTIONAL_FINDINGS_REQUIRE_FOLLOWUP": "functional canonical findings need triage follow-up",
    "PERFORMANCE_THRESHOLD_EXCEEDED_20_PERCENT": "performance threshold exceeded by more than 20%",
    "PERFORMANCE_THRESHOLD_EXCEEDED": "performance threshold exceeded",
    "SECURITY_HIGH_FINDING_OPEN": "security finding severity=high",
    "SECURITY_FINDINGS_REMAIN_OPEN": "security findings remain open",
}


def compute_gate_input_fingerprint(payload: GateInputContract | dict[str, Any]) -> str:
    """Hash only material Gate inputs; request/trace correlation is non-authoritative."""

    normalized = (
        payload.model_dump(mode="json")
        if isinstance(payload, GateInputContract)
        else dict(payload)
    )
    normalized.pop("inputFingerprint", None)
    evaluation_context = dict(normalized.get("evaluationContext") or {})
    for field_name in ("evaluationId", "traceId", "requestId"):
        evaluation_context.pop(field_name, None)
    normalized["evaluationContext"] = evaluation_context
    return canonical_hash(normalized)


@dataclass(frozen=True)
class EvaluationSignal:
    decision: GateDecisionValue
    reason_code: str
    priority: int
    domain: GateDomainValue | None = None
    rule_id: str | None = None
    refs: tuple[GateAuthorityRefContract, ...] = ()
    hard_rule: bool = False
    metric_evaluations: tuple[GateMetricEvaluationContract, ...] = ()


@dataclass(frozen=True)
class CompletenessEvaluation:
    signals: tuple[EvaluationSignal, ...]
    summary: GateCompletenessSummaryContract


@dataclass(frozen=True)
class AggregatedGateEvaluation:
    decision: GateDecisionValue
    domain_results: tuple[GateDomainResultContract, ...]
    reason_codes: tuple[str, ...]
    reasons: tuple[str, ...]
    matched_rules: tuple[str, ...]
    blocking_refs: tuple[GateAuthorityRefContract, ...]
    warning_refs: tuple[GateAuthorityRefContract, ...]
    metric_evaluations: tuple[GateMetricEvaluationContract, ...]
    completeness: GateCompletenessSummaryContract
    confidence: float


class DomainApplicabilityResolver:
    """Resolve domain scope only from Service-owned execution authorities."""

    def resolve(
        self,
        *,
        task_domains: dict[str, dict[str, Any]],
        plan_domain_states: dict[str, bool],
        execution_plan_domains: set[str],
        execution_scope_is_authoritative: bool,
        input_availability: dict[str, str],
        required_domains: dict[str, bool],
        authority_refs: dict[str, list[dict[str, str]]],
    ) -> list[dict[str, object]]:
        states: list[dict[str, object]] = []
        for domain in DOMAIN_ORDER:
            task = task_domains.get(domain)
            explicitly_enabled = plan_domain_states.get(domain) is True or domain in execution_plan_domains
            explicitly_disabled = plan_domain_states.get(domain) is False
            refs = list(authority_refs.get(domain, []))

            if task is not None and explicitly_disabled:
                applicability = "unknown"
            elif task is not None or explicitly_enabled:
                applicability = "applicable"
            elif explicitly_disabled or execution_scope_is_authoritative:
                applicability = "not_applicable"
            else:
                applicability = "unknown"

            required = bool(required_domains.get(domain, False)) if applicability == "applicable" else False
            input_type = "metrics" if domain == "performance" else "normalizedFindings"
            availability = (
                str(input_availability.get(domain, "unavailable"))
                if applicability == "applicable"
                else "unavailable"
            )
            states.append(
                {
                    "domain": domain,
                    "applicability": applicability,
                    "availability": availability,
                    "required": required,
                    "requiredInputTypes": [input_type],
                    "authorityRefs": refs,
                    "inputRefs": [],
                    "missingInputs": [input_type] if applicability == "applicable" and availability == "missing" else [],
                    "invalidInputs": [input_type] if applicability == "applicable" and availability == "invalid" else [],
                    "unavailableInputs": [input_type] if applicability == "applicable" and availability == "unavailable" else [],
                }
            )
        return states


class CompletenessEvaluator:
    def evaluate(self, gate_input: GateInputContract, policy: GatePolicyContract | None) -> CompletenessEvaluation:
        signals: list[EvaluationSignal] = []
        applicable_count = 0
        evaluated_count = 0
        excluded_count = 0
        required_missing_count = 0
        optional_missing_count = 0
        optional_decision: GateDecisionValue = (
            policy.completeness.missingInputDecision if policy is not None else "blocked"
        )

        for state in gate_input.domainInputStates:
            refs = tuple(state.authorityRefs)
            if state.applicability == "not_applicable":
                excluded_count += 1
                signals.append(
                    EvaluationSignal(
                        decision="pass",
                        reason_code="DOMAIN_NOT_APPLICABLE",
                        priority=10,
                        domain=state.domain,
                        refs=refs,
                    )
                )
                continue
            if state.applicability == "applicable":
                applicable_count += 1
                if state.availability == "available":
                    evaluated_count += 1
                elif state.required:
                    required_missing_count += 1
                else:
                    optional_missing_count += 1
                    signals.append(
                        EvaluationSignal(
                            decision=optional_decision,
                            reason_code=f"OPTIONAL_INPUT_{state.availability.upper()}",
                            priority=100,
                            domain=state.domain,
                            refs=refs,
                        )
                    )

        if required_missing_count:
            status: Literal["complete", "partial", "incomplete", "unknown"] = "incomplete"
        elif any(state.applicability == "unknown" for state in gate_input.domainInputStates):
            status = "unknown"
        elif optional_missing_count:
            status = "partial"
        else:
            status = "complete"
        return CompletenessEvaluation(
            signals=tuple(signals),
            summary=GateCompletenessSummaryContract(
                status=status,
                applicableDomainCount=applicable_count,
                evaluatedDomainCount=evaluated_count,
                excludedDomainCount=excluded_count,
                requiredMissingCount=required_missing_count,
                optionalMissingCount=optional_missing_count,
            ),
        )


class HardRuleEvaluator:
    """System rules are evaluated before Policy and can never be weakened by it."""

    def evaluate(self, gate_input: GateInputContract) -> tuple[EvaluationSignal, ...]:
        signals: list[EvaluationSignal] = []
        execution_refs = tuple(gate_input.executionContext.authorityRefs)

        if gate_input.normalizationState.status != "completed" or gate_input.normalizationState.unresolvedRawFindingCount:
            signals.append(self._block("NORMALIZE_NOT_COMPLETED", refs=tuple(gate_input.normalizationState.authorityRefs)))

        if gate_input.evidenceIntegrity.status != "valid":
            code = {
                "missing": "EVIDENCE_INTEGRITY_MISSING",
                "invalid": "EVIDENCE_INTEGRITY_FAILED",
                "unknown": "EVIDENCE_INTEGRITY_UNKNOWN",
            }.get(gate_input.evidenceIntegrity.status, "EVIDENCE_INTEGRITY_FAILED")
            refs = tuple(
                [
                    *gate_input.evidenceIntegrity.authorityRefs,
                    *gate_input.evidenceIntegrity.missingRefs,
                    *gate_input.evidenceIntegrity.invalidRefs,
                ]
            )
            signals.append(self._block(code, refs=refs))

        policy_code = self._policy_integrity_reason(gate_input)
        if policy_code is not None:
            signals.append(self._block(policy_code, refs=execution_refs))

        expected_fingerprint = compute_gate_input_fingerprint(gate_input)
        if expected_fingerprint != gate_input.inputFingerprint:
            signals.append(self._block("INPUT_FINGERPRINT_MISMATCH", refs=execution_refs))

        if gate_input.executionContext.riskLevel == "high":
            approved = any(
                item.status == "approved"
                and item.resourceType == "execution"
                and item.resourceId == gate_input.executionContext.executionId
                for item in gate_input.approvalState
            )
            if not approved:
                approval_refs = tuple(
                    GateAuthorityRefContract(type="approval", id=item.id, source="approval_flow")
                    for item in gate_input.approvalState
                )
                signals.append(
                    self._block(
                        "HIGH_RISK_APPROVAL_NOT_SATISFIED",
                        refs=approval_refs or execution_refs,
                    )
                )

        for state in gate_input.domainInputStates:
            refs = tuple(state.authorityRefs)
            if state.applicability == "unknown":
                signals.append(
                    self._block(
                        "DOMAIN_APPLICABILITY_UNKNOWN",
                        domain=state.domain,
                        refs=refs,
                    )
                )
            elif state.applicability == "applicable" and state.availability != "available" and state.required:
                signals.append(
                    self._block(
                        f"REQUIRED_INPUT_{state.availability.upper()}",
                        domain=state.domain,
                        refs=refs,
                    )
                )
        return tuple(signals)

    @staticmethod
    def _block(
        reason_code: str,
        *,
        domain: GateDomainValue | None = None,
        refs: tuple[GateAuthorityRefContract, ...] = (),
    ) -> EvaluationSignal:
        return EvaluationSignal(
            decision="blocked",
            reason_code=reason_code,
            priority=1_000_000,
            domain=domain,
            refs=refs,
            hard_rule=True,
        )

    @staticmethod
    def _policy_integrity_reason(gate_input: GateInputContract) -> str | None:
        if gate_input.policySnapshot is None or gate_input.policySnapshotHash is None:
            return "POLICY_SNAPSHOT_MISSING"
        if canonical_hash(gate_input.policySnapshot) != gate_input.policySnapshotHash:
            return "POLICY_SNAPSHOT_HASH_MISMATCH"
        raw_request = gate_input.policySnapshot.get("request")
        raw_policy = gate_input.policySnapshot.get("policy")
        raw_scope = raw_policy.get("scope") if isinstance(raw_policy, dict) else None
        context = gate_input.executionContext
        for ownership in (raw_request, raw_scope):
            if not isinstance(ownership, dict):
                continue
            if (
                ownership.get("tenantId") != context.tenantId
                or ownership.get("workspaceId") != context.workspaceId
            ):
                return "CROSS_TENANT_POLICY_SNAPSHOT"
        if (
            isinstance(raw_request, dict)
            and raw_request.get("projectId") is not None
            and raw_request.get("projectId") != context.projectId
        ):
            return "POLICY_SCOPE_MISMATCH"
        try:
            snapshot = GatePolicyResolutionSnapshotContract.model_validate(gate_input.policySnapshot)
            GatePolicyResolutionSnapshotBuilder().verify(
                snapshot.model_dump(mode="json"),
                gate_input.policySnapshotHash,
            )
        except GatePolicyResolutionError as exc:
            if exc.code == "GATE_POLICY_HASH_MISMATCH":
                return "POLICY_VERSION_HASH_MISMATCH"
            return "POLICY_SNAPSHOT_INVALID"
        except ValidationError:
            return "POLICY_SNAPSHOT_INVALID"
        request = snapshot.request
        if request.tenantId != context.tenantId or request.workspaceId != context.workspaceId:
            return "CROSS_TENANT_POLICY_SNAPSHOT"
        if request.projectId is not None and request.projectId != context.projectId:
            return "POLICY_SCOPE_MISMATCH"
        return None


class PolicyRuleEvaluator:
    def evaluate(
        self,
        gate_input: GateInputContract,
        policy: GatePolicyContract | None,
    ) -> tuple[EvaluationSignal, ...]:
        if policy is None:
            return ()
        signals: list[EvaluationSignal] = list(self._global_policy_signals(gate_input, policy))
        ordered_rules = sorted(policy.rules, key=lambda item: (-item.priority, item.ruleId))

        for domain in ("functional", "security"):
            findings = [
                finding
                for finding in gate_input.normalizedFindings
                if finding.domain == domain and finding.status == "open"
            ]
            for rule in (item for item in ordered_rules if item.category == domain):
                candidates = [
                    finding
                    for finding in findings
                    if rule.severity is None or finding.severity == rule.severity
                ]
                matched = bool(candidates) if rule.operator == "exists" else not candidates if rule.operator == "not_exists" else False
                if not matched:
                    continue
                refs = tuple(
                    GateAuthorityRefContract(type="normalized_finding", id=item.id, source="NORMALIZE")
                    for item in candidates
                )
                requirement_signals = self._requirement_signals(
                    gate_input,
                    policy,
                    rule,
                    refs=refs,
                    evidence_types=self._evidence_types_for_findings(candidates),
                    confidences=[item.confidence for item in candidates],
                    domain=domain,  # type: ignore[arg-type]
                )
                if requirement_signals:
                    signals.extend(requirement_signals)
                    continue
                signals.append(
                    EvaluationSignal(
                        decision=rule.decision,
                        reason_code=rule.reasonCode,
                        priority=rule.priority,
                        domain=domain,  # type: ignore[arg-type]
                        rule_id=rule.ruleId,
                        refs=refs,
                    )
                )

        performance_rules = [item for item in ordered_rules if item.category == "performance"]
        for metric in (item for item in gate_input.metrics if item.domain == "performance"):
            metric_ref = GateAuthorityRefContract(type="metric", id=metric.id, source="execution_metric")
            if metric.threshold is None:
                metric_evaluation = GateMetricEvaluationContract(
                    metricRef=metric.id,
                    domain="performance",
                    ruleId=None,
                    value=metric.value,
                    threshold=None,
                    comparisonValue=None,
                    outcome="ignored",
                    decision="pass",
                    reasonCode="METRIC_THRESHOLD_NOT_CONFIGURED",
                )
                signals.append(
                    EvaluationSignal(
                        decision="pass",
                        reason_code="METRIC_THRESHOLD_NOT_CONFIGURED",
                        priority=1,
                        domain="performance",
                        refs=(metric_ref,),
                        metric_evaluations=(metric_evaluation,),
                    )
                )
                continue
            if metric.threshold == 0:
                metric_evaluation = GateMetricEvaluationContract(
                    metricRef=metric.id,
                    domain="performance",
                    ruleId=None,
                    value=metric.value,
                    threshold=metric.threshold,
                    comparisonValue=None,
                    outcome="invalid",
                    decision="blocked",
                    reasonCode="METRIC_COMPARISON_INVALID",
                )
                signals.append(
                    EvaluationSignal(
                        decision="blocked",
                        reason_code="METRIC_COMPARISON_INVALID",
                        priority=900_000,
                        domain="performance",
                        refs=(metric_ref,),
                        metric_evaluations=(metric_evaluation,),
                    )
                )
                continue

            comparison_value = metric.value / metric.threshold
            matched_rule = next(
                (
                    rule
                    for rule in performance_rules
                    if rule.metric in {"*", metric.name}
                    and self._matches(comparison_value, rule.operator, rule.threshold)
                ),
                None,
            )
            if matched_rule is None:
                evaluation = GateMetricEvaluationContract(
                    metricRef=metric.id,
                    domain="performance",
                    ruleId=None,
                    value=metric.value,
                    threshold=metric.threshold,
                    comparisonValue=comparison_value,
                    outcome="not_matched",
                    decision="pass",
                    reasonCode=None,
                )
                signals.append(
                    EvaluationSignal(
                        decision="pass",
                        reason_code="METRIC_WITHIN_POLICY_THRESHOLD",
                        priority=0,
                        domain="performance",
                        refs=(metric_ref,),
                        metric_evaluations=(evaluation,),
                    )
                )
                continue
            evaluation = GateMetricEvaluationContract(
                metricRef=metric.id,
                domain="performance",
                ruleId=matched_rule.ruleId,
                value=metric.value,
                threshold=metric.threshold,
                comparisonValue=comparison_value,
                outcome="matched",
                decision=matched_rule.decision,
                reasonCode=matched_rule.reasonCode,
            )
            requirement_signals = self._requirement_signals(
                gate_input,
                policy,
                matched_rule,
                refs=(metric_ref,),
                evidence_types={
                    "metric",
                    *(
                        self._canonical_evidence_type(item.type)
                        for item in metric.evidenceRefs
                    ),
                },
                confidences=[],
                domain="performance",
            )
            if requirement_signals:
                signals.extend(requirement_signals)
                continue
            signals.append(
                EvaluationSignal(
                    decision=matched_rule.decision,
                    reason_code=matched_rule.reasonCode,
                    priority=matched_rule.priority,
                    domain="performance",
                    rule_id=matched_rule.ruleId,
                    refs=(metric_ref,),
                    metric_evaluations=(evaluation,),
                )
            )
        return tuple(signals)

    def _global_policy_signals(
        self,
        gate_input: GateInputContract,
        policy: GatePolicyContract,
    ) -> tuple[EvaluationSignal, ...]:
        signals: list[EvaluationSignal] = []
        evidence_types = self._all_evidence_types(gate_input)
        evidence_count = gate_input.evidenceIntegrity.checkedRefCount
        if (
            evidence_count < policy.evidence.minimumCount
            or not set(policy.evidence.requiredTypes).issubset(evidence_types)
        ):
            signals.append(
                EvaluationSignal(
                    decision=policy.evidence.missingEvidenceDecision,
                    reason_code="POLICY_EVIDENCE_REQUIREMENT_NOT_MET",
                    priority=800_000,
                    refs=tuple(gate_input.evidenceIntegrity.authorityRefs),
                )
            )

        confidence = min(
            (item.confidence for item in gate_input.normalizedFindings),
            default=1.0,
        )
        if confidence < policy.confidence.minimum:
            signals.append(
                EvaluationSignal(
                    decision=policy.confidence.belowThresholdDecision,
                    reason_code="POLICY_CONFIDENCE_REQUIREMENT_NOT_MET",
                    priority=700_000,
                    refs=tuple(
                        GateAuthorityRefContract(
                            type="normalized_finding",
                            id=item.id,
                            source="NORMALIZE",
                        )
                        for item in gate_input.normalizedFindings
                        if item.confidence == confidence
                    ),
                )
            )

        completeness_values: dict[str, object] = {
            "completeness": sum(
                1
                for state in gate_input.domainInputStates
                if state.applicability == "unknown"
                or (state.applicability == "applicable" and state.availability != "available")
            ),
            "confidence": confidence,
            "evidence": evidence_count,
        }
        for rule in policy.rules:
            if rule.category not in completeness_values:
                continue
            if self._matches(completeness_values[rule.category], rule.operator, rule.threshold):
                signals.append(
                    EvaluationSignal(
                        decision=rule.decision,
                        reason_code=rule.reasonCode,
                        priority=rule.priority,
                        rule_id=rule.ruleId,
                        refs=tuple(gate_input.executionContext.authorityRefs),
                    )
                )
        return tuple(signals)

    def _requirement_signals(
        self,
        gate_input: GateInputContract,
        policy: GatePolicyContract,
        rule: Any,
        *,
        refs: tuple[GateAuthorityRefContract, ...],
        evidence_types: set[str],
        confidences: list[float],
        domain: GateDomainValue,
    ) -> tuple[EvaluationSignal, ...]:
        signals: list[EvaluationSignal] = []
        evidence_requirement = rule.evidenceRequirement
        if evidence_requirement is not None and (
            len(refs) < evidence_requirement.minimumCount
            or not set(evidence_requirement.requiredTypes).issubset(evidence_types)
        ):
            signals.append(
                EvaluationSignal(
                    decision=policy.evidence.missingEvidenceDecision,
                    reason_code="RULE_EVIDENCE_REQUIREMENT_NOT_MET",
                    priority=rule.priority,
                    domain=domain,
                    rule_id=rule.ruleId,
                    refs=refs,
                )
            )
        confidence_requirement = rule.confidenceRequirement
        if confidence_requirement is not None and (
            not confidences or min(confidences) < confidence_requirement.minimum
        ):
            signals.append(
                EvaluationSignal(
                    decision=confidence_requirement.missingDecision,
                    reason_code="RULE_CONFIDENCE_REQUIREMENT_NOT_MET",
                    priority=rule.priority,
                    domain=domain,
                    rule_id=rule.ruleId,
                    refs=refs,
                )
            )
        approval_requirement = rule.approvalRequirement
        if approval_requirement is not None and approval_requirement.required:
            approved = any(
                approval.status == "approved"
                and approval.type in approval_requirement.approvalTypes
                and approval.resourceType == "execution"
                and approval.resourceId == gate_input.executionContext.executionId
                for approval in gate_input.approvalState
            )
            if not approved:
                signals.append(
                    EvaluationSignal(
                        decision="blocked",
                        reason_code="RULE_APPROVAL_REQUIREMENT_NOT_MET",
                        priority=rule.priority,
                        domain=domain,
                        rule_id=rule.ruleId,
                        refs=refs,
                    )
                )
        return tuple(signals)

    @staticmethod
    def _evidence_types_for_findings(findings: list[Any]) -> set[str]:
        evidence_types = {"finding"} if findings else set()
        for finding in findings:
            evidence_types.update(
                PolicyRuleEvaluator._canonical_evidence_type(item.type)
                for item in finding.evidenceRefs
            )
        return evidence_types

    @staticmethod
    def _all_evidence_types(gate_input: GateInputContract) -> set[str]:
        evidence_types: set[str] = set()
        if gate_input.normalizedFindings:
            evidence_types.add("finding")
        if gate_input.metrics:
            evidence_types.add("metric")
        if gate_input.approvalState:
            evidence_types.add("approval")
        if gate_input.evaluationContext.traceId:
            evidence_types.add("trace")
        for finding in gate_input.normalizedFindings:
            evidence_types.update(
                PolicyRuleEvaluator._canonical_evidence_type(item.type)
                for item in finding.evidenceRefs
            )
        for metric in gate_input.metrics:
            evidence_types.update(
                PolicyRuleEvaluator._canonical_evidence_type(item.type)
                for item in metric.evidenceRefs
            )
        return evidence_types

    @staticmethod
    def _canonical_evidence_type(value: str) -> str:
        return {
            "artifact_ref": "artifact",
            "normalized_finding": "finding",
            "execution_metric": "metric",
            "audit_log": "trace",
        }.get(value, value)

    @staticmethod
    def _matches(value: object, operator: str, threshold: object) -> bool:
        if operator == "exists":
            return value is not None
        if operator == "not_exists":
            return value is None
        if operator == "eq":
            return value == threshold
        if operator == "ne":
            return value != threshold
        if operator == "in":
            return isinstance(threshold, list) and value in threshold
        if operator == "not_in":
            return isinstance(threshold, list) and value not in threshold
        if not isinstance(value, (int, float)) or not isinstance(threshold, (int, float)):
            return False
        return {
            "gt": value > threshold,
            "gte": value >= threshold,
            "lt": value < threshold,
            "lte": value <= threshold,
        }.get(operator, False)


class Aggregator:
    def aggregate(
        self,
        gate_input: GateInputContract,
        policy: GatePolicyContract | None,
        hard_signals: tuple[EvaluationSignal, ...],
        completeness: CompletenessEvaluation,
        policy_signals: tuple[EvaluationSignal, ...],
    ) -> AggregatedGateEvaluation:
        decision_order = (
            list(policy.aggregation.decisionOrder)
            if policy is not None
            else ["pass", "warn", "fail", "blocked"]
        )
        rank = {decision: index for index, decision in enumerate(decision_order)}
        default_decision: GateDecisionValue = policy.aggregation.defaultDecision if policy is not None else "blocked"
        all_signals = (*hard_signals, *completeness.signals, *policy_signals)
        global_signals = [signal for signal in all_signals if signal.domain is None]
        domain_results: list[GateDomainResultContract] = []

        for domain in DOMAIN_ORDER:
            state = next(item for item in gate_input.domainInputStates if item.domain == domain)
            signals = [signal for signal in all_signals if signal.domain == domain]
            hard_blocks = [signal for signal in signals if signal.hard_rule and signal.decision == "blocked"]
            decision: GateDecisionValue = (
                "blocked"
                if hard_blocks
                else self._highest_decision(signals, rank, default_decision)
            )
            selected = [signal for signal in signals if signal.decision == decision]
            selected.sort(key=lambda item: (-item.priority, item.reason_code))
            reason_codes = self._unique([signal.reason_code for signal in selected])
            matched_rules = self._unique([signal.rule_id for signal in selected if signal.rule_id])
            metric_evaluations = [evaluation for signal in signals for evaluation in signal.metric_evaluations]
            blocking_refs = self._unique_refs(
                [ref for signal in signals if signal.decision in {"fail", "blocked"} for ref in signal.refs]
            )
            warning_refs = self._unique_refs(
                [ref for signal in signals if signal.decision == "warn" for ref in signal.refs]
            )
            domain_results.append(
                GateDomainResultContract(
                    domain=domain,
                    applicability=state.applicability,
                    availability=state.availability,
                    decision=decision,
                    reasonCodes=reason_codes,
                    matchedRules=matched_rules,
                    blockingRefs=blocking_refs,
                    warningRefs=warning_refs,
                    metricEvaluations=metric_evaluations,
                    completeness=self._domain_completeness(state),
                    confidence=self._domain_confidence(gate_input, state),
                    authorityRefs=state.authorityRefs,
                )
            )

        overall = self._highest_decision(
            [
                *global_signals,
                *[
                    EvaluationSignal(
                        decision=item.decision,
                        reason_code=(item.reasonCodes[0] if item.reasonCodes else f"{item.domain.upper()}_DEFAULT"),
                        priority=0,
                        domain=item.domain,
                    )
                    for item in domain_results
                    if item.applicability != "not_applicable"
                ],
            ],
            rank,
            default_decision,
        )
        compatibility = (
            policy.metadata.get("compatibility", {})
            if policy is not None and isinstance(policy.metadata.get("compatibility"), dict)
            else {}
        )
        security = next(item for item in domain_results if item.domain == "security")
        if security.applicability == "applicable" and security.decision == "fail" and compatibility:
            overall_config = compatibility.get("overall")
            configured = overall_config.get("securityFail") if isinstance(overall_config, dict) else None
            if configured in {"pass", "warn", "fail", "blocked"}:
                overall = configured  # type: ignore[assignment]
        if any(signal.hard_rule and signal.decision == "blocked" for signal in all_signals):
            overall = "blocked"

        ordered_signals = [
            *sorted(global_signals, key=lambda item: (-item.priority, item.reason_code)),
            *[
                signal
                for domain in DOMAIN_ORDER
                for signal in sorted(
                    [candidate for candidate in all_signals if candidate.domain == domain],
                    key=lambda item: (-item.priority, item.reason_code),
                )
            ],
        ]
        selected_reason_codes: list[str] = []
        selected_rules: list[str] = []
        for signal in ordered_signals:
            if signal.domain is None:
                selected_reason_codes.append(signal.reason_code)
                if signal.rule_id:
                    selected_rules.append(signal.rule_id)
                continue
            domain_result = next(item for item in domain_results if item.domain == signal.domain)
            if signal.reason_code in domain_result.reasonCodes:
                selected_reason_codes.append(signal.reason_code)
                if signal.rule_id:
                    selected_rules.append(signal.rule_id)

        reason_codes = self._unique(selected_reason_codes)
        reasons = self._unique([LEGACY_REASON_TEXT[code] for code in reason_codes if code in LEGACY_REASON_TEXT])
        blocking_refs = self._unique_refs(
            [ref for signal in all_signals if signal.decision in {"fail", "blocked"} for ref in signal.refs]
        )
        warning_refs = self._unique_refs(
            [ref for signal in all_signals if signal.decision == "warn" for ref in signal.refs]
        )
        metric_evaluations = [
            evaluation for signal in all_signals for evaluation in signal.metric_evaluations
        ]
        confidence = min((item.confidence for item in domain_results if item.applicability == "applicable"), default=1.0)
        if completeness.summary.status == "partial":
            confidence = min(confidence, 0.75)
        elif completeness.summary.status in {"incomplete", "unknown"}:
            confidence = 0.0
        return AggregatedGateEvaluation(
            decision=overall,
            domain_results=tuple(domain_results),
            reason_codes=tuple(reason_codes),
            reasons=tuple(reasons),
            matched_rules=tuple(self._unique(selected_rules)),
            blocking_refs=tuple(blocking_refs),
            warning_refs=tuple(warning_refs),
            metric_evaluations=tuple(metric_evaluations),
            completeness=completeness.summary,
            confidence=confidence,
        )

    @staticmethod
    def _highest_decision(
        signals: list[EvaluationSignal],
        rank: dict[str, int],
        default: GateDecisionValue,
    ) -> GateDecisionValue:
        if not signals:
            return default
        return max(signals, key=lambda item: (rank.get(item.decision, 10_000), item.priority)).decision

    @staticmethod
    def _domain_completeness(
        state: DomainInputStateContract,
    ) -> Literal["complete", "partial", "incomplete", "not_applicable", "unknown"]:
        if state.applicability == "not_applicable":
            return "not_applicable"
        if state.applicability == "unknown":
            return "unknown"
        if state.availability == "available":
            return "complete"
        return "incomplete" if state.required else "partial"

    @staticmethod
    def _domain_confidence(gate_input: GateInputContract, state: DomainInputStateContract) -> float:
        if state.applicability == "not_applicable":
            return 1.0
        if state.applicability == "unknown" or state.availability != "available":
            return 0.0 if state.required else 0.75
        confidences = [item.confidence for item in gate_input.normalizedFindings if item.domain == state.domain]
        return min(confidences, default=1.0)

    @staticmethod
    def _unique(values: list[str]) -> list[str]:
        return list(dict.fromkeys(values))

    @staticmethod
    def _unique_refs(values: list[GateAuthorityRefContract]) -> list[GateAuthorityRefContract]:
        unique: dict[tuple[str, str, str], GateAuthorityRefContract] = {}
        for value in values:
            unique[(value.type, value.id, value.source)] = value
        return list(unique.values())


class DecisionSnapshotBuilder:
    def build(
        self,
        gate_input: GateInputContract,
        evaluation: AggregatedGateEvaluation,
        policy_summary: GatePolicyEvaluationSummaryContract,
        input_summary: GateInputEvaluationSummaryContract,
    ) -> tuple[dict[str, Any], str]:
        snapshot = {
            "schemaVersion": "phase8.gate-decision-snapshot.v1",
            "evaluatorVersion": GATE_EVALUATOR_VERSION,
            "evaluationId": gate_input.evaluationContext.evaluationId,
            "evaluationTime": gate_input.evaluationContext.evaluationTime.isoformat(),
            "executionId": gate_input.executionContext.executionId,
            "decision": evaluation.decision,
            "domainResults": [item.model_dump(mode="json") for item in evaluation.domain_results],
            "reasonCodes": list(evaluation.reason_codes),
            "matchedRules": list(evaluation.matched_rules),
            "blockingRefs": [item.model_dump(mode="json") for item in evaluation.blocking_refs],
            "warningRefs": [item.model_dump(mode="json") for item in evaluation.warning_refs],
            "metricEvaluations": [item.model_dump(mode="json") for item in evaluation.metric_evaluations],
            "completeness": evaluation.completeness.model_dump(mode="json"),
            "confidence": evaluation.confidence,
            "policy": policy_summary.model_dump(mode="json"),
            "input": input_summary.model_dump(mode="json"),
        }
        return snapshot, canonical_hash(snapshot)


class GateEvaluator:
    """The only authoritative Gate calculation entrypoint."""

    def __init__(
        self,
        *,
        hard_rule_evaluator: HardRuleEvaluator | None = None,
        completeness_evaluator: CompletenessEvaluator | None = None,
        policy_rule_evaluator: PolicyRuleEvaluator | None = None,
        aggregator: Aggregator | None = None,
        snapshot_builder: DecisionSnapshotBuilder | None = None,
    ) -> None:
        self.hard_rule_evaluator = hard_rule_evaluator or HardRuleEvaluator()
        self.completeness_evaluator = completeness_evaluator or CompletenessEvaluator()
        self.policy_rule_evaluator = policy_rule_evaluator or PolicyRuleEvaluator()
        self.aggregator = aggregator or Aggregator()
        self.snapshot_builder = snapshot_builder or DecisionSnapshotBuilder()

    def evaluate(self, gate_input: GateInputContract | dict[str, Any]) -> GateResultContract:
        normalized_input = GateInputContract.model_validate(gate_input)
        policy = self._validated_policy(normalized_input)
        hard_signals = self.hard_rule_evaluator.evaluate(normalized_input)
        completeness = self.completeness_evaluator.evaluate(normalized_input, policy)
        policy_signals = self.policy_rule_evaluator.evaluate(normalized_input, policy)
        aggregated = self.aggregator.aggregate(
            normalized_input,
            policy,
            hard_signals,
            completeness,
            policy_signals,
        )
        policy_summary = self._policy_summary(normalized_input)
        input_summary = GateInputEvaluationSummaryContract(
            fingerprint=normalized_input.inputFingerprint,
            snapshotRef=(
                f"gate-input://{normalized_input.executionContext.executionId}/"
                f"{normalized_input.inputFingerprint.removeprefix('sha256:')}"
            ),
            normalizedFindingRefs=[item.id for item in normalized_input.normalizedFindings],
            metricRefs=[item.id for item in normalized_input.metrics],
            approvalRefs=[item.id for item in normalized_input.approvalState],
        )
        decision_snapshot, decision_snapshot_hash = self.snapshot_builder.build(
            normalized_input,
            aggregated,
            policy_summary,
            input_summary,
        )
        return GateResultContract(
            schemaVersion="phase8.gate-result.v1",
            evaluatorVersion=GATE_EVALUATOR_VERSION,
            evaluationId=normalized_input.evaluationContext.evaluationId,
            executionId=normalized_input.executionContext.executionId,
            decision=aggregated.decision,
            domainResults=list(aggregated.domain_results),
            reasonCodes=list(aggregated.reason_codes),
            reasons=list(aggregated.reasons),
            matchedRules=list(aggregated.matched_rules),
            blockingRefs=list(aggregated.blocking_refs),
            warningRefs=list(aggregated.warning_refs),
            metricEvaluations=list(aggregated.metric_evaluations),
            completeness=aggregated.completeness,
            confidence=aggregated.confidence,
            policy=policy_summary,
            input=input_summary,
            decisionSnapshot=decision_snapshot,
            decisionSnapshotHash=decision_snapshot_hash,
            writesGateDecision=False,
        )

    @staticmethod
    def _validated_policy(gate_input: GateInputContract) -> GatePolicyContract | None:
        if gate_input.policySnapshot is None:
            return None
        try:
            return GatePolicyResolutionSnapshotContract.model_validate(gate_input.policySnapshot).policy
        except ValidationError:
            return None

    @staticmethod
    def _policy_summary(gate_input: GateInputContract) -> GatePolicyEvaluationSummaryContract:
        snapshot = gate_input.policySnapshot or {}
        raw_binding = snapshot.get("binding")
        binding: dict[str, Any] = raw_binding if isinstance(raw_binding, dict) else {}
        raw_scope = snapshot.get("resolvedScope")
        resolved_scope: dict[str, Any] = raw_scope if isinstance(raw_scope, dict) else {}
        return GatePolicyEvaluationSummaryContract(
            policyId=str(snapshot.get("policyId")) if snapshot.get("policyId") else None,
            policyVersionId=str(snapshot.get("policyVersionId")) if snapshot.get("policyVersionId") else None,
            policyVersionHash=(
                str(snapshot.get("policyVersionHash")) if snapshot.get("policyVersionHash") else None
            ),
            bindingRef=str(binding.get("bindingRef")) if binding.get("bindingRef") else None,
            resolvedScope=resolved_scope,
            snapshotHash=gate_input.policySnapshotHash,
        )
