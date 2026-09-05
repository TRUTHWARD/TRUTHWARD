/* SPDX-License-Identifier: Apache-2.0 */
import { SectionCard } from "../components/SectionCard";
import { Locale, t } from "../i18n";
import type { ObservabilityMetric, QualityDashboard, StructuredLogItem, StructuredLogProjection } from "../lib/api";
import { displayEventKind, displayLogLevel, displayMetricLabel, displaySignalLabel, displayStatus } from "../lib/presentation";

type TraceItem = {
  id: string;
  executionId: string | null;
  rootSpanName: string | null;
  spanCount: number;
  modelInvocationCount: number;
  agentRunCount: number;
  guardrailEventCount: number;
  createdAt: string;
};

type ReplayItem = {
  executionId: string;
  traceCount: number;
  timeline: Array<{ kind: string; label: string; status: string; timestamp: string }>;
  findings: Array<{ id: string; severity: string; title: string }>;
  visualGroundingAttempts: Array<{
    id: string;
    actionId: string;
    actionType: string;
    status: string;
    verificationStatus: string | null;
    confidence: number | null;
    chosenLocator: Record<string, unknown>;
    coordinateClickAllowed: boolean;
    riskLevel: string;
    guardrailDecision: string | null;
    redactionStatus: string;
    artifactRefs: Array<Record<string, unknown>>;
    verificationResult: Record<string, unknown>;
  }>;
  verificationResults: Array<{
    id: string;
    verificationType: string;
    status: string;
    confidence: number | null;
    normalizedFindingId: string | null;
  }>;
  guardrailEvents: Array<{ id: string; ruleId: string; decision: string; reason: string; createdAt: string }>;
  gate: { overall: string; reasons: string[] } | null;
};

type GuardrailPolicyItem = {
  ruleId: string;
  name: string;
  description: string;
  owner: string;
  enabled: boolean;
  decisionOverrides: Record<string, string>;
  effectiveDecisions: Record<string, string>;
  updatedAt: string | null;
};

type GuardrailEventItem = {
  id: string;
  traceId: string | null;
  executionId: string | null;
  resourceType: string;
  resourceId: string;
  ruleId: string;
  decision: string;
  reason: string;
  evidence: string[];
  createdAt: string;
};

type ObservabilityPageProps = {
  locale: Locale;
  traces: TraceItem[];
  replay: ReplayItem | null;
  metrics: ObservabilityMetric[];
  qualityDashboard: QualityDashboard | null;
  structuredLogProjection: StructuredLogProjection | null;
  structuredLogs: StructuredLogItem[];
  logsAccessState: "loading" | "ready" | "access-restricted" | "error";
  logsError: string | null;
  canReadStructuredLogs: boolean;
  policies: GuardrailPolicyItem[];
  guardrailEvents: GuardrailEventItem[];
  guardrailSummary: { allow: number; warn: number; block: number };
};

const decisions = ["allow", "warn", "block"] as const;

export function ObservabilityPage({
  locale,
  traces,
  replay,
  metrics,
  qualityDashboard,
  structuredLogProjection,
  structuredLogs,
  logsAccessState,
  logsError,
  canReadStructuredLogs,
  policies,
  guardrailEvents,
  guardrailSummary,
}: ObservabilityPageProps) {
  const decisionLabels = {
    allow: t(locale, "decisionAllow"),
    warn: t(locale, "decisionWarn"),
    block: t(locale, "decisionBlock"),
  } satisfies Record<(typeof decisions)[number], string>;

  return (
    <div className="page-shell" data-route="/observability">
    <SectionCard title={t(locale, "observability")}>
      <div className="stack-list">
        {traces.slice(0, 4).map((trace) => (
          <div className="stack-row stack-row--dense" key={trace.id}>
            <div>
              <strong>{trace.rootSpanName ?? t(locale, "trace")}</strong>
              <p>{trace.executionId ? `${t(locale, "executionPrefix")} ${trace.executionId.slice(0, 8)}` : t(locale, "planLevel")}</p>
            </div>
            <div className="metric-cluster">
              <span>{trace.spanCount} {t(locale, "spans")}</span>
              <span>{trace.modelInvocationCount} {t(locale, "models")}</span>
              <span>{trace.agentRunCount} {t(locale, "agent")}</span>
              <span>{trace.guardrailEventCount} {t(locale, "guardrails")}</span>
            </div>
          </div>
        ))}
      </div>

      {replay ? (
        <div className="replay-panel">
          <div className="replay-summary">
            <strong>{t(locale, "latestReplay")}</strong>
            <span>{replay.traceCount} {t(locale, "tracesLinked")}</span>
            <span>{t(locale, "gate")}: {displayStatus(locale, replay.gate?.overall ?? "pending")}</span>
            <span>{replay.findings.length} {t(locale, "findings")}</span>
            <span>{replay.guardrailEvents.length} {t(locale, "guardrails")}</span>
            <span>{replay.visualGroundingAttempts.length} {t(locale, "visualAttempts")}</span>
          </div>
          {replay.visualGroundingAttempts.length > 0 ? (
            <div className="visual-grounding-strip">
              {replay.visualGroundingAttempts.slice(0, 3).map((attempt) => (
                <div className="visual-grounding-item" key={attempt.id}>
                  <strong>{attempt.actionId}</strong>
                  <span>{String(attempt.chosenLocator.kind ?? t(locale, "unknown"))}</span>
                  <span>{attempt.confidence === null ? t(locale, "notApplicable") : `${Math.round(attempt.confidence * 100)}%`}</span>
                  <span>{displayStatus(locale, attempt.guardrailDecision ?? attempt.status)}</span>
                </div>
              ))}
            </div>
          ) : null}
          <div className="timeline-list">
            {replay.timeline.slice(0, 5).map((event, index) => (
              <div className={`timeline-item timeline-item--${event.kind}`} key={`${event.timestamp}-${event.label}-${index}`}>
                <strong>{event.label}</strong>
                <span>{displayEventKind(locale, event.kind)}</span>
                <span>{displayStatus(locale, event.status)}</span>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <p className="empty-copy">{t(locale, "replayDataEmpty")}</p>
      )}

      <div className="detail-grid">
        <div>
          <h3>{t(locale, "observabilityMetrics")}</h3>
          <div className="observability-metric-grid">
            {metrics.slice(0, 8).map((metric) => (
              <div className="observability-metric" key={metric.name}>
                <span>{displayMetricLabel(locale, metric.name)}</span>
                <strong>{formatMetricValue(metric, locale)}</strong>
                <small>{displayStatus(locale, metric.status)}</small>
              </div>
            ))}
            {metrics.length === 0 ? <p className="empty-copy">{t(locale, "noMetricsForExecution")}</p> : null}
          </div>
        </div>

        <div>
          <h3>{t(locale, "structuredLogs")}</h3>
          {!canReadStructuredLogs || logsAccessState === "access-restricted" ? (
            <div className="empty-state">
              <strong>{t(locale, "accessRestricted")}</strong>
              <p>{t(locale, "protectedDataNotRequested")}</p>
            </div>
          ) : null}
          {logsAccessState === "loading" ? (
            <div className="empty-state">
              <strong>{t(locale, "loading")}</strong>
              <p>{t(locale, "loadingReadOnlyData")}</p>
            </div>
          ) : null}
          {logsAccessState === "error" ? (
            <div className="error-banner">
              <strong>{t(locale, "errorState")}</strong>
              <p>{logsError ?? t(locale, "auditLogsUnavailable")}</p>
            </div>
          ) : null}
          {logsAccessState === "ready" && canReadStructuredLogs ? (
            <div className="detail-stack">
              <div className="stats-grid stats-grid--compact">
                <MetricTile label={t(locale, "total")} value={String(structuredLogProjection?.summary.total ?? structuredLogs.length)} />
                <MetricTile label={t(locale, "auditSourceExecution")} value={String(structuredLogProjection?.summary.executionLogCount ?? 0)} />
                <MetricTile label={t(locale, "auditSourceAudit")} value={String(structuredLogProjection?.summary.auditLogCount ?? 0)} />
                <MetricTile label={t(locale, "evidenceOnly")} value={String(structuredLogProjection?.evidenceOnly ?? true)} />
                <MetricTile label={t(locale, "writesDecision")} value={String(structuredLogProjection?.writesDecision ?? false)} />
                <MetricTile label={t(locale, "capability")} value={structuredLogProjection?.capability.required ?? "audit.logs.read"} />
              </div>
              <div className="timeline-list">
                {structuredLogs.slice(0, 8).map((log) => (
                  <div className={`timeline-item timeline-item--${log.source}`} key={log.id}>
                    <strong>{log.message}</strong>
                    <span>{displayLogLevel(locale, log.level)}</span>
                    <span>{log.component}</span>
                  </div>
                ))}
                {structuredLogs.length === 0 ? <p className="empty-copy">{t(locale, "emptyReadOnlyResult")}</p> : null}
              </div>
            </div>
          ) : null}
        </div>
      </div>

      <div>
        <h3>{t(locale, "qualitySignals")}</h3>
        <div className="stack-list">
          {(qualityDashboard?.qualitySignals ?? []).slice(0, 6).map((signal) => (
            <div className="stack-row stack-row--dense" key={`${String(signal.signal)}-${String(signal.severity)}`}>
              <div>
                <strong>{displaySignalLabel(locale, signal.signal ?? t(locale, "signal"))}</strong>
                <p>{displayStatus(locale, signal.severity ?? "info")}</p>
              </div>
              <span>{formatUnknown(signal.value, locale)}</span>
            </div>
          ))}
          {(qualityDashboard?.qualitySignals ?? []).length === 0 ? <p className="empty-copy">{t(locale, "noQualitySignals")}</p> : null}
        </div>
      </div>

      <div className="guardrail-panel">
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

        <div className="guardrail-layout">
          <div className="guardrail-column">
            <h3>{t(locale, "recentGuardrails")}</h3>
            <div className="timeline-list">
              {guardrailEvents.slice(0, 6).map((event) => (
                <div className="timeline-item timeline-item--guardrail" key={event.id}>
                  <strong>{event.ruleId}</strong>
                  <span>{displayStatus(locale, event.decision)}</span>
                  <span>{event.resourceType}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="guardrail-column">
            <h3>{t(locale, "policySnapshot")}</h3>
            <div className="policy-list">
              {policies.map((policy) => (
                <div className="policy-card" key={policy.ruleId}>
                  <div className="policy-card__header">
                    <div>
                      <strong>{policy.name}</strong>
                      <p>{policy.ruleId}</p>
                    </div>
                  </div>
                  <p className="policy-card__copy">{policy.description}</p>
                  <div className="policy-matrix">
                    {decisions.map((sourceDecision) => (
                      <div className="policy-field" key={`${policy.ruleId}-${sourceDecision}`}>
                        <span>{sourceDecision}</span>
                        <strong>{policy.effectiveDecisions[sourceDecision] ?? sourceDecision}</strong>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </SectionCard>
    </div>
  );
}

function MetricTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="stat-tile">
      <span>{label}</span>
      <strong>{value}</strong>
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
    return `$${metric.value.toFixed(4)}`;
  }
  if (metric.name.toLowerCase().includes("latency")) {
    return `${Math.round(metric.value)} ms`;
  }
  return Number.isInteger(metric.value) ? String(metric.value) : metric.value.toFixed(2);
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
