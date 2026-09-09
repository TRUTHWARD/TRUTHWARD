/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useState } from "react";

import { SafeJsonViewer } from "../components/SafeJsonViewer";
import { SectionCard } from "../components/SectionCard";
import { Locale, t } from "../i18n";
import type { ObservabilityMetric, QualityDashboard, StructuredLogItem, StructuredLogProjection } from "../lib/api";
import { displayEventKind, displayLogLevel, displayMetricLabel, displaySignalLabel, displayStatus } from "../lib/presentation";

type TraceItem = {
  id: string;
  executionId: string | null;
  rootSpanName: string | null;
  metadata?: Record<string, unknown>;
  spanCount: number;
  modelInvocationCount: number;
  agentRunCount: number;
  skillInvocationCount: number;
  auditLogCount?: number;
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
  const [selectedTraceId, setSelectedTraceId] = useState<string | null>(traces[0]?.id ?? null);
  const [selectedLogId, setSelectedLogId] = useState<string | null>(structuredLogs[0]?.id ?? null);
  const [selectedGuardrailId, setSelectedGuardrailId] = useState<string | null>(guardrailEvents[0]?.id ?? null);
  const selectedTrace = traces.find((trace) => trace.id === selectedTraceId) ?? traces[0] ?? null;
  const selectedLog = structuredLogs.find((log) => log.id === selectedLogId) ?? structuredLogs[0] ?? null;
  const selectedGuardrail =
    guardrailEvents.find((event) => event.id === selectedGuardrailId) ?? guardrailEvents[0] ?? null;
  const relatedLogs = selectedTrace ? structuredLogs.filter((log) => log.traceId === selectedTrace.id) : [];

  useEffect(() => {
    if (traces.length > 0 && !traces.some((trace) => trace.id === selectedTraceId)) {
      setSelectedTraceId(traces[0].id);
    }
  }, [selectedTraceId, traces]);
  useEffect(() => {
    if (structuredLogs.length > 0 && !structuredLogs.some((log) => log.id === selectedLogId)) {
      setSelectedLogId(structuredLogs[0].id);
    }
  }, [selectedLogId, structuredLogs]);
  useEffect(() => {
    if (guardrailEvents.length > 0 && !guardrailEvents.some((event) => event.id === selectedGuardrailId)) {
      setSelectedGuardrailId(guardrailEvents[0].id);
    }
  }, [guardrailEvents, selectedGuardrailId]);

  return (
    <div className="page-shell observability-page" data-route="/observability">
    <SectionCard title={t(locale, "observability")}>
      <div className="page-columns observability-trace-layout">
        <div>
          <h3>{t(locale, "traceRecords")}</h3>
          <div className="stack-list">
            {traces.slice(0, 8).map((trace) => (
              <button
                aria-pressed={selectedTrace?.id === trace.id}
                className={`stack-row stack-row--dense stack-row--button observability-trace-item ${selectedTrace?.id === trace.id ? "stack-row--selected" : ""}`}
                key={trace.id}
                onClick={() => setSelectedTraceId(trace.id)}
                type="button"
              >
                <div>
                  <strong>{trace.rootSpanName ?? t(locale, "trace")}</strong>
                  <p>{trace.executionId ? `${t(locale, "executionPrefix")} ${trace.executionId.slice(0, 8)}` : t(locale, "planLevel")}</p>
                </div>
                <div className="metric-cluster">
                  <span>{trace.spanCount} {t(locale, "spans")}</span>
                  <span>{trace.skillInvocationCount} {t(locale, "skillInvocation")}</span>
                  <span>{trace.guardrailEventCount} {t(locale, "guardrails")}</span>
                </div>
              </button>
            ))}
            {traces.length === 0 ? <p className="empty-copy">{t(locale, "noTraceRecords")}</p> : null}
          </div>
        </div>

        <div>
          <h3>{t(locale, "traceDetails")}</h3>
          {selectedTrace ? (
            <div className="detail-stack observability-trace-detail">
              <div className="detail-grid">
                <DetailValue label={t(locale, "traceId")} value={selectedTrace.id} />
                <DetailValue label={t(locale, "execution")} value={selectedTrace.executionId} locale={locale} />
                <DetailValue label={t(locale, "createdAt")} value={formatTimestamp(selectedTrace.createdAt, locale)} />
                <DetailValue label={t(locale, "relatedLogs")} value={String(relatedLogs.length)} />
              </div>
              <div className="stats-grid stats-grid--compact observability-trace-stats">
                <MetricTile label={t(locale, "spans")} value={String(selectedTrace.spanCount)} />
                <MetricTile label={t(locale, "models")} value={String(selectedTrace.modelInvocationCount)} />
                <MetricTile label={t(locale, "agent")} value={String(selectedTrace.agentRunCount)} />
                <MetricTile label={t(locale, "skillInvocation")} value={String(selectedTrace.skillInvocationCount)} />
                <MetricTile label={t(locale, "guardrails")} value={String(selectedTrace.guardrailEventCount)} />
                <MetricTile label={t(locale, "auditSourceAudit")} value={String(selectedTrace.auditLogCount ?? 0)} />
              </div>
              {selectedTrace.metadata && Object.keys(selectedTrace.metadata).length > 0 ? (
                <div>
                  <h3>{t(locale, "recordedMetadata")}</h3>
                  <SafeJsonViewer locale={locale} value={selectedTrace.metadata} />
                </div>
              ) : null}
            </div>
          ) : (
            <p className="empty-copy">{t(locale, "noTraceRecords")}</p>
          )}
        </div>
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
                {Object.keys(metric.metadata).length > 0 ? (
                  <details>
                    <summary>{t(locale, "viewDetails")}</summary>
                    <SafeJsonViewer locale={locale} value={metric.metadata} limits={{ maxCharacters: 6000, maxNodes: 120 }} />
                  </details>
                ) : null}
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
                  <button
                    aria-pressed={selectedLog?.id === log.id}
                    className={`timeline-item timeline-item--${log.source} ${selectedLog?.id === log.id ? "stack-row--selected" : ""}`}
                    key={log.id}
                    onClick={() => setSelectedLogId(log.id)}
                    type="button"
                  >
                    <strong>{log.message}</strong>
                    <span>{displayLogLevel(locale, log.level)}</span>
                    <span>{log.component}</span>
                  </button>
                ))}
                {structuredLogs.length === 0 ? <p className="empty-copy">{t(locale, "emptyReadOnlyResult")}</p> : null}
              </div>
              {selectedLog ? (
                <div className="detail-stack">
                  <h3>{t(locale, "selectedLogDetails")}</h3>
                  <div className="detail-grid">
                    <DetailValue label={t(locale, "timestamp")} value={formatTimestamp(selectedLog.timestamp, locale)} />
                    <DetailValue label={t(locale, "source")} value={selectedLog.source} />
                    <DetailValue label={t(locale, "level")} value={displayLogLevel(locale, selectedLog.level)} />
                    <DetailValue label={t(locale, "component")} value={selectedLog.component} />
                    <DetailValue label={t(locale, "service")} value={selectedLog.service} />
                    <DetailValue label={t(locale, "traceId")} value={selectedLog.traceId} locale={locale} />
                    <DetailValue label={t(locale, "spanId")} value={selectedLog.spanId} locale={locale} />
                    <DetailValue label={t(locale, "execution")} value={selectedLog.executionId} locale={locale} />
                    <DetailValue label={t(locale, "requestId")} value={selectedLog.requestId} locale={locale} />
                    <DetailValue label={t(locale, "auditResourceType")} value={selectedLog.resourceType ?? null} locale={locale} />
                    <DetailValue label={t(locale, "auditResourceId")} value={selectedLog.resourceId ?? null} locale={locale} />
                  </div>
                  <div>
                    <h3>{t(locale, "recordedMetadata")}</h3>
                    {Object.keys(selectedLog.metadata).length > 0 ? (
                      <SafeJsonViewer locale={locale} value={selectedLog.metadata} limits={{ maxCharacters: 12000, maxNodes: 240 }} />
                    ) : (
                      <p className="empty-copy">{t(locale, "auditNoDetails")}</p>
                    )}
                  </div>
                </div>
              ) : null}
            </div>
          ) : null}
        </div>
      </div>

      <div>
        <h3>{t(locale, "qualitySignals")}</h3>
        <div className="stack-list">
          {(qualityDashboard?.qualitySignals ?? []).slice(0, 6).map((signal) => (
            <div className="stack-row stack-row--dense observability-quality-signal" key={`${String(signal.signal)}-${String(signal.severity)}`}>
              <div>
                <strong>{displaySignalLabel(locale, signal.signal ?? t(locale, "signal"))}</strong>
                <p>{displayStatus(locale, signal.severity ?? "info")}</p>
              </div>
              <span>{formatUnknown(signal.value, locale)}</span>
              <details>
                <summary>{t(locale, "viewDetails")}</summary>
                <SafeJsonViewer locale={locale} value={signal} limits={{ maxCharacters: 6000, maxNodes: 120 }} />
              </details>
            </div>
          ))}
          {(qualityDashboard?.qualitySignals ?? []).length === 0 ? <p className="empty-copy">{t(locale, "noQualitySignals")}</p> : null}
        </div>
        {qualityDashboard ? (
          <div className="detail-grid">
            <JsonProjection locale={locale} title={t(locale, "executionQuality")} value={qualityDashboard.executionQuality} />
            <JsonProjection locale={locale} title={t(locale, "skillQuality")} value={qualityDashboard.skillQuality} />
            <JsonProjection locale={locale} title={t(locale, "modelQuality")} value={qualityDashboard.modelQuality} />
            <JsonProjection
              locale={locale}
              title={t(locale, "costAndFailureSummary")}
              value={{ costSummary: qualityDashboard.costSummary, failureReasons: qualityDashboard.failureReasons }}
            />
          </div>
        ) : null}
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
                <button
                  aria-pressed={selectedGuardrail?.id === event.id}
                  className={`timeline-item timeline-item--guardrail ${selectedGuardrail?.id === event.id ? "stack-row--selected" : ""}`}
                  key={event.id}
                  onClick={() => setSelectedGuardrailId(event.id)}
                  type="button"
                >
                  <strong>{event.ruleId}</strong>
                  <span>{displayStatus(locale, event.decision)}</span>
                  <span>{event.resourceType}</span>
                </button>
              ))}
            </div>
            {selectedGuardrail ? (
              <div className="detail-stack">
                <h3>{t(locale, "guardrailDetails")}</h3>
                <div className="detail-grid">
                  <DetailValue label={t(locale, "reason")} value={selectedGuardrail.reason} />
                  <DetailValue label={t(locale, "traceId")} value={selectedGuardrail.traceId} locale={locale} />
                  <DetailValue label={t(locale, "execution")} value={selectedGuardrail.executionId} locale={locale} />
                  <DetailValue label={t(locale, "auditResourceId")} value={selectedGuardrail.resourceId} />
                  <DetailValue label={t(locale, "createdAt")} value={formatTimestamp(selectedGuardrail.createdAt, locale)} />
                </div>
                <div>
                  <strong>{t(locale, "evidenceRefs")}</strong>
                  <SafeJsonViewer locale={locale} value={selectedGuardrail.evidence} limits={{ maxCharacters: 6000, maxNodes: 120 }} />
                </div>
              </div>
            ) : null}
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

function DetailValue({ label, value, locale }: { label: string; value: string | null; locale?: Locale }) {
  return (
    <div className="stack-row stack-row--dense">
      <div>
        <strong>{label}</strong>
        <p className="technical-value">{value ?? (locale ? t(locale, "none") : "—")}</p>
      </div>
    </div>
  );
}

function JsonProjection({ locale, title, value }: { locale: Locale; title: string; value: unknown }) {
  return (
    <div>
      <h3>{title}</h3>
      <SafeJsonViewer locale={locale} value={value} limits={{ maxCharacters: 12000, maxNodes: 240 }} />
    </div>
  );
}

function formatTimestamp(value: string, locale: Locale) {
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.getTime()) ? value : timestamp.toLocaleString(locale);
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
