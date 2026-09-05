/* SPDX-License-Identifier: Apache-2.0 */
import { useState } from "react";

import { SectionCard } from "../components/SectionCard";
import { Locale, t } from "../i18n";
import type { ObservabilityMetric, QualityDashboard, StructuredLogItem } from "../lib/api";
import { redactSnapshotValue } from "../lib/redaction";
import {
  displayEventKind,
  displayFindingTitle,
  displayLogLevel,
  displayMetricLabel,
  displaySignalLabel,
  displayStatus,
} from "../lib/presentation";
import {
  ApprovalItem,
  ExecutionItem,
  GuardrailEventItem,
  GuardrailPolicyItem,
  ReplayItem,
  SkillInvocationItem,
  SkillItem,
} from "../store/platform";

type GateSnapshot = {
  overall: string;
  functional: string;
  performance: string;
  security: string;
  reasons?: string[];
} | null;

type FindingItem = {
  id: string;
  severity: string;
  source: string;
  title: string;
  summary: string;
};

type GateDashboardPageProps = {
  locale: Locale;
  executions: ExecutionItem[];
  selectedExecutionId: string | null;
  onSelectExecution: (executionId: string) => void;
  gate: GateSnapshot;
  findings: FindingItem[];
  replay: ReplayItem | null;
  policies: GuardrailPolicyItem[];
  guardrailEvents: GuardrailEventItem[];
  approvals: ApprovalItem[];
  skills: SkillItem[];
  skillInvocations: SkillInvocationItem[];
  metrics: ObservabilityMetric[];
  qualityDashboard: QualityDashboard | null;
  structuredLogs: StructuredLogItem[];
  guardrailSummary: { allow: number; warn: number; block: number };
};

const decisions = ["allow", "warn", "block"] as const;

export function GateDashboardPage({
  locale,
  executions,
  selectedExecutionId,
  onSelectExecution,
  gate,
  findings,
  replay,
  policies,
  guardrailEvents,
  approvals,
  skills,
  skillInvocations,
  metrics,
  qualityDashboard,
  structuredLogs,
  guardrailSummary,
}: GateDashboardPageProps) {
  const [selectedSkillInvocationId, setSelectedSkillInvocationId] = useState<string | null>(null);
  const selectedExecution = executions.find((execution) => execution.id === selectedExecutionId) ?? executions[0] ?? null;
  const executionGuardrails = selectedExecution
    ? guardrailEvents.filter((event) => event.executionId === selectedExecution.id)
    : guardrailEvents;
  const visualApprovals = selectedExecution
    ? approvals.filter((approval) => approval.type === "visual_action" && approval.resourceId === selectedExecution.id)
    : approvals.filter((approval) => approval.type === "visual_action");
  const visibleSkillInvocations = replay?.skillInvocations.length
    ? replay.skillInvocations
    : selectedExecution
      ? skillInvocations.filter((invocation) => invocation.executionId === selectedExecution.id)
      : skillInvocations;
  const selectedSkillInvocation =
    visibleSkillInvocations.find((invocation) => invocation.id === selectedSkillInvocationId)
    ?? visibleSkillInvocations[0]
    ?? null;
  const primaryMetrics = [
    "Execution Success Rate",
    "Task Success Rate",
    "Evidence Link Rate",
    "Model Cost Total",
    "Model Latency P95",
    "Gate Pass Rate",
  ]
    .map((name) => metrics.find((metric) => metric.name === name))
    .filter((metric): metric is ObservabilityMetric => Boolean(metric));
  const qualitySignals = qualityDashboard?.qualitySignals ?? [];
  const skillQuality = qualityDashboard?.skillQuality ?? [];
  const modelQuality = qualityDashboard?.modelQuality ?? [];
  const decisionLabels = {
    allow: t(locale, "decisionAllow"),
    warn: t(locale, "decisionWarn"),
    block: t(locale, "decisionBlock"),
  } satisfies Record<(typeof decisions)[number], string>;

  return (
    <div className="page-shell" data-route="/gate-dashboard">
      <div className="page-columns">
        <SectionCard title={t(locale, "gateDashboard")} eyebrow={t(locale, "outcomes")}>
          <div className="stack-list">
            {executions.map((execution) => (
              <button
                className={`stack-row stack-row--button ${execution.id === selectedExecution?.id ? "stack-row--selected" : ""}`}
                key={execution.id}
                onClick={() => onSelectExecution(execution.id)}
                type="button"
              >
                <div>
                  <strong>{execution.id.slice(0, 8)}</strong>
                  <p>{execution.environment}</p>
                </div>
                <span>{displayStatus(locale, execution.summary.security ?? execution.status)}</span>
              </button>
            ))}
          </div>
        </SectionCard>

        <SectionCard title={selectedExecution ? `${t(locale, "gatePrefix")} ${selectedExecution.id.slice(0, 8)}` : t(locale, "gateDecisions")} eyebrow={t(locale, "decision")}>
          {selectedExecution ? (
            <div className="detail-stack">
              <div className="stats-grid stats-grid--compact">
                <div className="stat-tile">
                  <span>{t(locale, "overall")}</span>
                  <strong>{displayStatus(locale, gate?.overall ?? "pending")}</strong>
                </div>
                <div className="stat-tile">
                  <span>{t(locale, "functional")}</span>
                  <strong>{displayStatus(locale, gate?.functional ?? "pending")}</strong>
                </div>
                <div className="stat-tile">
                  <span>{t(locale, "performance")}</span>
                  <strong>{displayStatus(locale, gate?.performance ?? "pending")}</strong>
                </div>
                <div className="stat-tile">
                  <span>{t(locale, "security")}</span>
                  <strong>{displayStatus(locale, gate?.security ?? "pending")}</strong>
                </div>
              </div>

              <div className="detail-grid">
                <div>
                  <h3>{t(locale, "gateReasons")}</h3>
                  <div className="stack-list">
                    {(gate?.reasons ?? []).map((reason) => (
                      <div className="stack-row stack-row--dense" key={reason}>
                        <strong>{displayFindingTitle(locale, reason)}</strong>
                      </div>
                    ))}
                    {(gate?.reasons ?? []).length === 0 ? <p className="empty-copy">{t(locale, "noGateReasons")}</p> : null}
                  </div>
                </div>

                <div>
                  <h3>{t(locale, "normalizedFindings")}</h3>
                  <div className="stack-list">
                    {findings.slice(0, 6).map((finding) => (
                      <div className="stack-row stack-row--dense" key={finding.id}>
                        <div>
                          <strong>{displayFindingTitle(locale, finding.title)}</strong>
                          <p>{finding.source}</p>
                        </div>
                        <span>{displayStatus(locale, finding.severity)}</span>
                      </div>
                    ))}
                    {findings.length === 0 ? <p className="empty-copy">{t(locale, "noNormalizedFindingsSelected")}</p> : null}
                  </div>
                </div>
              </div>

              <div className="guardrail-summary-grid">
                <div className="summary-pill">
                  <strong>{guardrailSummary.allow}</strong>
                  <span>{decisionLabels.allow}</span>
                </div>
                <div className="summary-pill summary-pill--warn">
                  <strong>{guardrailSummary.warn}</strong>
                  <span>{decisionLabels.warn}</span>
                </div>
                <div className="summary-pill summary-pill--block">
                  <strong>{guardrailSummary.block}</strong>
                  <span>{decisionLabels.block}</span>
                </div>
              </div>

              <div>
                <h3>{t(locale, "observabilityMetrics")}</h3>
                <div className="observability-metric-grid">
                  {primaryMetrics.map((metric) => (
                    <div className="observability-metric" key={metric.name}>
                      <span>{displayMetricLabel(locale, metric.name)}</span>
                      <strong>{formatMetricValue(metric, locale)}</strong>
                      <small>{displayStatus(locale, metric.status)}</small>
                    </div>
                  ))}
                  {primaryMetrics.length === 0 ? <p className="empty-copy">{t(locale, "noMetricsForExecution")}</p> : null}
                </div>
              </div>

              <div className="detail-grid">
                <div>
                  <h3>{t(locale, "qualitySignals")}</h3>
                  <div className="stack-list">
                    {qualitySignals.slice(0, 6).map((signal) => (
                      <div className="stack-row stack-row--dense" key={`${String(signal.signal)}-${String(signal.severity)}`}>
                        <div>
                          <strong>{displaySignalLabel(locale, signal.signal ?? t(locale, "signal"))}</strong>
                          <p>{displayStatus(locale, signal.severity ?? "info")}</p>
                        </div>
                        <span>{formatUnknown(signal.value, locale)}</span>
                      </div>
                    ))}
                    {qualitySignals.length === 0 ? <p className="empty-copy">{t(locale, "noQualitySignals")}</p> : null}
                  </div>
                </div>

                <div>
                  <h3>{t(locale, "structuredLogs")}</h3>
                  <div className="timeline-list">
                    {structuredLogs.slice(0, 6).map((log) => (
                      <div className={`timeline-item timeline-item--${log.source}`} key={log.id}>
                        <strong>{log.message}</strong>
                        <span>{displayLogLevel(locale, log.level)}</span>
                        <span>{log.component}</span>
                      </div>
                    ))}
                    {structuredLogs.length === 0 ? <p className="empty-copy">{t(locale, "noStructuredLogs")}</p> : null}
                  </div>
                </div>
              </div>

              <div className="detail-grid">
                <div>
                  <h3>{t(locale, "executionGuardrails")}</h3>
                  <div className="timeline-list">
                    {executionGuardrails.slice(0, 6).map((event) => (
                      <div className="timeline-item timeline-item--guardrail" key={event.id}>
                        <strong>{event.ruleId}</strong>
                        <span>{displayStatus(locale, event.decision)}</span>
                        <span>{event.reason}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h3>{t(locale, "replaySnapshot")}</h3>
                  <div className="timeline-list">
                    {(replay?.timeline ?? []).slice(0, 5).map((event, index) => (
                      <div className={`timeline-item timeline-item--${event.kind}`} key={`${event.timestamp}-${event.label}-${index}`}>
                        <strong>{event.label}</strong>
                        <span>{displayEventKind(locale, event.kind)}</span>
                        <span>{displayStatus(locale, event.status)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="detail-grid">
                <div>
                  <h3>{t(locale, "skillInvocations")}</h3>
                  <div className="timeline-list">
                    {visibleSkillInvocations.slice(0, 6).map((invocation) => (
                      <button
                        className={`timeline-item timeline-item--skill_invocation ${selectedSkillInvocation?.id === invocation.id ? "stack-row--selected" : ""}`}
                        key={invocation.id}
                        onClick={() => setSelectedSkillInvocationId(invocation.id)}
                        type="button"
                      >
                        <strong>{invocation.skillId}</strong>
                        <span>{displayStatus(locale, invocation.status)}</span>
                        <span>{invocation.manifestHash.slice(0, 18)}</span>
                      </button>
                    ))}
                    {visibleSkillInvocations.length === 0 ? <p className="empty-copy">{t(locale, "noSkillInvocationsForExecution")}</p> : null}
                  </div>
                </div>

                <div>
                  <h3>{t(locale, "skillSnapshot")}</h3>
                  {selectedSkillInvocation ? (
                    <div className="stack-list">
                      <div className="stack-row stack-row--dense">
                        <div>
                          <strong>{selectedSkillInvocation.skillId}</strong>
                          <p>{selectedSkillInvocation.manifestHash}</p>
                        </div>
                        <span>{selectedSkillInvocation.version}</span>
                      </div>
                      <SnapshotBlock locale={locale} title={t(locale, "input")} value={selectedSkillInvocation.inputSnapshot ?? {}} />
                      <SnapshotBlock locale={locale} title={t(locale, "output")} value={selectedSkillInvocation.outputSnapshot ?? {}} />
                      <SnapshotBlock locale={locale} title={t(locale, "policy")} value={selectedSkillInvocation.policySnapshot ?? {}} />
                      <SnapshotBlock locale={locale} title={t(locale, "connector")} value={selectedSkillInvocation.connectorBindingSnapshot} />
                    </div>
                  ) : (
                    <p className="empty-copy">{t(locale, "noSkillSnapshot")}</p>
                  )}
                </div>
              </div>

              <div className="detail-grid">
                <div>
                  <h3>{t(locale, "skillQuality")}</h3>
                  <div className="stack-list">
                    {skillQuality.slice(0, 5).map((skill) => (
                      <div className="stack-row stack-row--dense" key={String(skill.skillId)}>
                        <div>
                          <strong>{String(skill.skillId)}</strong>
                          <p>{Number(skill.invocations ?? 0)} {t(locale, "invocations")}</p>
                        </div>
                        <span>{formatRate(skill.successRate, locale)}</span>
                      </div>
                    ))}
                    {skillQuality.length === 0 ? <p className="empty-copy">{t(locale, "noSkillQuality")}</p> : null}
                  </div>
                </div>

                <div>
                  <h3>{t(locale, "modelCost")}</h3>
                  <div className="stack-list">
                    {modelQuality.slice(0, 5).map((model) => (
                      <div className="stack-row stack-row--dense" key={String(model.model)}>
                        <div>
                          <strong>{String(model.model)}</strong>
                          <p>{String(model.provider ?? t(locale, "providerUnknown"))}</p>
                        </div>
                        <span>{formatCurrency(model.totalCost)}</span>
                      </div>
                    ))}
                    {modelQuality.length === 0 ? <p className="empty-copy">{t(locale, "noModelQuality")}</p> : null}
                  </div>
                </div>
              </div>

              <div>
                <h3>{t(locale, "skillCatalog")}</h3>
                <div className="stack-list">
                  {skills.slice(0, 5).map((skill) => (
                    <div className="stack-row stack-row--dense" key={skill.id}>
                      <div>
                        <strong>{skill.displayName}</strong>
                        <p>{skill.skillId}</p>
                      </div>
                      <span>{skill.allowedConnectors.length} {t(locale, "connectors")}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <h3>{t(locale, "visualEvidence")}</h3>
                {replay?.visualGroundingAttempts.length ? (
                  <div className="visual-grounding-strip">
                    {replay.visualGroundingAttempts.slice(0, 4).map((attempt) => (
                      <div className="visual-grounding-item" key={attempt.id}>
                        <strong>{attempt.actionId}</strong>
                        <span>{String(attempt.chosenLocator.kind ?? t(locale, "unknown"))}</span>
                        <span>{attempt.confidence === null ? t(locale, "notApplicable") : `${Math.round(attempt.confidence * 100)}%`}</span>
                        <span>{displayStatus(locale, attempt.guardrailDecision ?? attempt.status)}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="empty-copy">{t(locale, "noVisualAttempts")}</p>
                )}
                {replay?.visualGroundingAttempts.length ? (
                  <div className="detail-grid">
                    {replay.visualGroundingAttempts.slice(0, 2).map((attempt) => (
                      <div className="stack-row stack-row--dense" key={`${attempt.id}-evidence`}>
                        <div>
                          <strong>{displayStatus(locale, attempt.verificationStatus ?? attempt.status)}</strong>
                          <p>
                            {attempt.artifactRefs.length} {t(locale, "artifacts")} | {t(locale, "click")}{" "}
                            {attempt.coordinateClickAllowed ? t(locale, "allowed") : t(locale, "blocked")}
                          </p>
                        </div>
                        <span>{displayStatus(locale, attempt.redactionStatus)}</span>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>

              <div>
                <h3>{t(locale, "visualApprovals")}</h3>
                <div className="stack-list">
                  {visualApprovals.slice(0, 4).map((approval) => (
                    <div className="stack-row stack-row--dense" key={approval.id}>
                      <div>
                        <strong>{String(approval.payload.actionId ?? approval.id.slice(0, 8))}</strong>
                        <p>{String(approval.payload.reason ?? approval.summary)}</p>
                      </div>
                      <span>{displayStatus(locale, approval.status)}</span>
                    </div>
                  ))}
                  {visualApprovals.length === 0 ? <p className="empty-copy">{t(locale, "noVisualApprovals")}</p> : null}
                </div>
              </div>

              <div className="policy-list">
                {policies.map((policy) => (
                  <PolicyCard key={policy.ruleId} policy={policy} />
                ))}
              </div>
            </div>
          ) : (
            <p className="empty-copy">{t(locale, "selectExecutionForGate")}</p>
          )}
        </SectionCard>
      </div>
    </div>
  );
}

function SnapshotBlock({ locale, title, value }: { locale: Locale; title: string; value: Record<string, unknown> }) {
  const redactedValue = redactSnapshotValue(value);
  return (
    <div className="stack-row stack-row--dense">
      <div>
        <strong>{title}</strong>
        <p>{t(locale, "maskedCredentialRefs")}</p>
        <pre className="snapshot-json">{JSON.stringify(redactedValue, null, 2)}</pre>
      </div>
    </div>
  );
}

function formatMetricValue(metric: ObservabilityMetric, locale: Locale) {
  if (metric.value === null) {
    return t(locale, "pending");
  }
  if (metric.name.toLowerCase().includes("rate")) {
    return `${Math.round(metric.value * 100)}%`;
  }
  if (metric.name.toLowerCase().includes("cost")) {
    return formatCurrency(metric.value);
  }
  if (metric.name.toLowerCase().includes("latency")) {
    return `${Math.round(metric.value)} ms`;
  }
  return Number.isInteger(metric.value) ? String(metric.value) : metric.value.toFixed(2);
}

function formatRate(value: unknown, locale: Locale) {
  return typeof value === "number" ? `${Math.round(value * 100)}%` : t(locale, "notApplicable");
}

function formatCurrency(value: unknown) {
  return typeof value === "number" ? `$${value.toFixed(4)}` : "$0.0000";
}

function formatUnknown(value: unknown, locale: Locale) {
  if (typeof value === "number") {
    return value > 0 && value <= 1 ? `${Math.round(value * 100)}%` : value.toFixed(2);
  }
  if (typeof value === "string") {
    return value;
  }
  if (value === null || value === undefined) {
    return t(locale, "notApplicable");
  }
  return String(value);
}

function PolicyCard({
  policy,
}: {
  policy: GuardrailPolicyItem;
}) {
  return (
    <div className="policy-card">
      <div className="policy-card__header">
        <div>
          <strong>{policy.name}</strong>
          <p>{policy.ruleId}</p>
        </div>
      </div>
      <p className="policy-card__copy">{policy.description}</p>
      <div className="policy-matrix">
        {decisions.map((decision) => (
          <div className="policy-field" key={`${policy.ruleId}-${decision}`}>
            <span>{decision}</span>
            <strong>{policy.effectiveDecisions[decision] ?? decision}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}
