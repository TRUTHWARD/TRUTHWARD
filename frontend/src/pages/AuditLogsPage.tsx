/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useMemo, useState, type FormEvent } from "react";

import { Locale, t } from "../i18n";
import { SafeJsonViewer } from "../components/SafeJsonViewer";
import {
  fetchAuditRetentionPolicy,
  requestAuditRetentionAction,
  type AuditLogProjection,
  type AuditRetentionPolicy,
  type StructuredLogItem,
} from "../lib/api";
import { ExecutionItem } from "../store/platform";
import { displayStatus } from "../lib/presentation";

export type AuditLogsAccessState = "loading" | "ready" | "access-restricted" | "error";

type AuditLogsPageProps = {
  locale: Locale;
  executions: ExecutionItem[];
  selectedExecutionId: string | null;
  onSelectExecution: (executionId: string | null) => void;
  projection: AuditLogProjection | null;
  logs: StructuredLogItem[];
  accessState: AuditLogsAccessState;
  error: string | null;
  canReadAuditLogs: boolean;
  canManageAuditRetention: boolean;
};

type RetentionAction = "archive" | "purge" | "set_legal_hold" | "clear_legal_hold";

export function AuditLogsPage({
  locale,
  executions,
  selectedExecutionId,
  onSelectExecution,
  projection,
  logs,
  accessState,
  error,
  canReadAuditLogs,
  canManageAuditRetention,
}: AuditLogsPageProps) {
  const [retentionPolicy, setRetentionPolicy] = useState<AuditRetentionPolicy | null>(null);
  const [selectedAuditLogId, setSelectedAuditLogId] = useState<string>("");
  const [retentionAction, setRetentionAction] = useState<RetentionAction>("archive");
  const [retentionDryRun, setRetentionDryRun] = useState(true);
  const [retentionReason, setRetentionReason] = useState("");
  const [retentionBusy, setRetentionBusy] = useState(false);
  const [retentionNotice, setRetentionNotice] = useState<Record<string, unknown> | null>(null);
  const [retentionError, setRetentionError] = useState<string | null>(null);
  const selectedExecution = selectedExecutionId ? executions.find((execution) => execution.id === selectedExecutionId) ?? null : null;
  const summary = projection?.summary ?? null;
  const retentionProjection = projection?.retentionProjection ?? null;
  const auditLogItems = useMemo(() => logs.filter((log) => log.source === "audit_log"), [logs]);
  const selectedAuditLog = auditLogItems.find((log) => log.id === selectedAuditLogId) ?? auditLogItems[0] ?? null;
  const supportedActions = retentionPolicy?.supportedActions ?? ["archive", "purge", "set_legal_hold", "clear_legal_hold"];

  useEffect(() => {
    if (!selectedAuditLogId && auditLogItems[0]) {
      setSelectedAuditLogId(auditLogItems[0].id);
    }
    if (selectedAuditLogId && !auditLogItems.some((log) => log.id === selectedAuditLogId)) {
      setSelectedAuditLogId(auditLogItems[0]?.id ?? "");
    }
  }, [auditLogItems, selectedAuditLogId]);

  useEffect(() => {
    let cancelled = false;
    if (!canReadAuditLogs) {
      setRetentionPolicy(null);
      return;
    }
    fetchAuditRetentionPolicy()
      .then((policy) => {
        if (!cancelled) {
          setRetentionPolicy(policy);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setRetentionPolicy(null);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [canReadAuditLogs]);

  const submitRetentionAction = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!canManageAuditRetention || !selectedAuditLog) {
      return;
    }
    setRetentionBusy(true);
    setRetentionError(null);
    setRetentionNotice(null);
    try {
      const result = await requestAuditRetentionAction({
        auditLogId: selectedAuditLog.id,
        action: retentionAction,
        dryRun: retentionDryRun,
        reason: retentionReason.trim() || null,
        idempotencyKey: retentionDryRun ? null : `audit-retention-${selectedAuditLog.id}-${retentionAction}`,
      });
      setRetentionNotice(result);
    } catch (requestError) {
      setRetentionError(requestError instanceof Error ? requestError.message : t(locale, "retentionRequestFailed"));
    } finally {
      setRetentionBusy(false);
    }
  };

  return (
    <div className="page-shell" data-route="/audit-logs">
      <div className="page-toolbar">
        <div>
          <h1>{t(locale, "auditLogs")}</h1>
        </div>
      </div>

      <div className="page-columns">
        <section className="panel">
          <div className="panel__header">
            <span className="eyebrow">{t(locale, "scope")}</span>
            <h2>{t(locale, "authoritativeQueryContext")}</h2>
          </div>
          <div className="stack-list">
            <button
              className={`stack-row stack-row--button ${selectedExecutionId === null ? "stack-row--selected" : ""}`}
              onClick={() => onSelectExecution(null)}
              type="button"
            >
              <div>
                <strong>{t(locale, "allAuditScopes")}</strong>
                <p>{t(locale, "authoritativeQueryContext")}</p>
              </div>
            </button>
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
                <span>{execution.status}</span>
              </button>
            ))}
            {executions.length === 0 ? <div className="empty-state">{t(locale, "allAuditScopes")}</div> : null}
          </div>
        </section>

        <section className="panel">
          {!canReadAuditLogs || accessState === "access-restricted" ? (
            <StateBanner title={t(locale, "accessRestricted")} copy={t(locale, "protectedDataNotRequested")} />
          ) : null}
          {accessState === "loading" ? <StateBanner title={t(locale, "loading")} copy={t(locale, "loadingReadOnlyData")} /> : null}
          {accessState === "error" ? (
            <div className="error-banner">
              <strong>{t(locale, "errorState")}</strong>
              <p>{error ?? t(locale, "auditLogsUnavailable")}</p>
            </div>
          ) : null}
          {accessState === "ready" && canReadAuditLogs ? (
            <div className="detail-stack">
              <div className="stats-grid stats-grid--compact">
                <MetricTile label={t(locale, "auditLogs")} value={String(summary?.total ?? logs.length)} />
                <MetricTile label={t(locale, "auditSourceAudit")} value={String(summary?.auditLogCount ?? 0)} />
                <MetricTile label={t(locale, "auditSourceExecution")} value={String(summary?.executionLogCount ?? 0)} />
                <MetricTile label={t(locale, "selectedScope")} value={selectedExecution ? selectedExecution.id.slice(0, 8) : t(locale, "allAuditScopes")} />
                <MetricTile label={t(locale, "retentionDays")} value={retentionProjection ? String(retentionProjection.retentionDays) : t(locale, "none")} />
                <MetricTile label={t(locale, "capability")} value={projection?.capability.required ?? "audit.logs.read"} />
                <MetricTile label={t(locale, "retentionPolicy")} value={retentionPolicy?.retentionPolicy ?? retentionProjection?.policy ?? t(locale, "none")} />
              </div>

              {canManageAuditRetention ? (
                <form className="control-form" onSubmit={(event) => void submitRetentionAction(event)}>
                  <div className="control-grid">
                    <label className="search-box">
                      <span>{t(locale, "selectedAuditRecord")}</span>
                      <select
                        disabled={retentionBusy || auditLogItems.length === 0}
                        onChange={(event) => setSelectedAuditLogId(event.target.value)}
                        value={selectedAuditLog?.id ?? ""}
                      >
                        {auditLogItems.map((log) => (
                          <option key={log.id} value={log.id}>
                            {auditEventTitle(locale, log)} - {log.id.slice(0, 8)}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="search-box">
                      <span>{t(locale, "retentionAction")}</span>
                      <select
                        disabled={retentionBusy || !selectedAuditLog}
                        onChange={(event) => {
                          setRetentionAction(event.target.value as RetentionAction);
                          setRetentionDryRun(true);
                        }}
                        value={retentionAction}
                      >
                        {supportedActions.map((action) => (
                          <option key={action} value={action}>
                            {t(locale, retentionActionLabel(action))}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="search-box">
                      <span>{t(locale, "reason")}</span>
                      <input
                        className="text-input"
                        disabled={retentionBusy || !selectedAuditLog}
                        onChange={(event) => setRetentionReason(event.target.value)}
                        value={retentionReason}
                      />
                    </label>
                  </div>
                  <label className="check-row">
                    <input
                      checked={retentionDryRun}
                      disabled={retentionBusy || !selectedAuditLog}
                      onChange={(event) => setRetentionDryRun(event.target.checked)}
                      type="checkbox"
                    />
                    <span>{t(locale, "retentionDryRun")}</span>
                  </label>
                  <div className="button-row">
                    <button className="primary-button" disabled={retentionBusy || !selectedAuditLog} type="submit">
                      {retentionDryRun ? t(locale, "previewRetentionAction") : t(locale, "requestRetentionApproval")}
                    </button>
                  </div>
                  {retentionError ? (
                    <div className="error-banner">
                      <strong>{t(locale, "retentionRequestFailed")}</strong>
                      <p>{retentionError}</p>
                    </div>
                  ) : null}
                  {retentionNotice ? (
                    <div className="detail-banner">
                      <div>
                        <strong>{t(locale, "retentionRequestSubmitted")}</strong>
                        <pre className="snapshot-json">{JSON.stringify(retentionNotice, null, 2)}</pre>
                      </div>
                    </div>
                  ) : null}
                </form>
              ) : (
                <StateBanner title={t(locale, "readOnly")} copy={t(locale, "auditRetentionRestricted")} />
              )}

              <div className="table-wrap">
                <table className="data-table data-table--compact">
                  <thead>
                    <tr>
                      <th>{t(locale, "timestamp")}</th>
                      <th>{t(locale, "source")}</th>
                      <th>{t(locale, "level")}</th>
                      <th>{t(locale, "component")}</th>
                      <th>{t(locale, "service")}</th>
                      <th>{t(locale, "retentionState")}</th>
                      <th>{t(locale, "message")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs.map((log) => (
                      <tr key={log.id}>
                        <td>{new Date(log.timestamp).toLocaleString()}</td>
                        <td>{log.source === "audit_log" ? t(locale, "auditSourceAudit") : log.source === "execution_log" ? t(locale, "auditSourceExecution") : log.source}</td>
                        <td><span className={`status-pill status-pill--${log.level.toLowerCase()}`}>{log.level}</span></td>
                        <td>{log.component}</td>
                        <td>{log.service}</td>
                        <td>{String(log.retentionState?.retentionStatus ?? t(locale, "unknown"))}</td>
                        <td className="audit-event-cell"><AuditEventContent locale={locale} log={log} /></td>
                      </tr>
                    ))}
                    {logs.length === 0 ? (
                      <tr>
                        <td colSpan={7}>{t(locale, "emptyReadOnlyResult")}</td>
                      </tr>
                    ) : null}
                  </tbody>
                </table>
              </div>
            </div>
          ) : null}
        </section>
      </div>
    </div>
  );
}

function auditEventTitle(locale: Locale, log: StructuredLogItem): string {
  if (log.source !== "audit_log") return log.message;
  if (log.message === "skill.invoke") return t(locale, "auditEventSkillInvoke");
  if (log.message === "replay_export.persist") return t(locale, "auditEventReplayPersist");
  return log.message;
}

function AuditEventContent({ locale, log }: { locale: Locale; log: StructuredLogItem }) {
  const [expanded, setExpanded] = useState(false);
  const metadata = log.metadata ?? {};
  const detail = metadata.details && typeof metadata.details === "object" && !Array.isArray(metadata.details)
    ? metadata.details as Record<string, unknown> : {};
  const textValue = (value: unknown): string | null => (
    typeof value === "string" && value.trim() ? value : null
  );
  const resourceId = log.resourceId ?? textValue(metadata.resourceId);
  const resourceType = log.resourceType ?? textValue(metadata.resourceType);
  const status = textValue(detail.status);
  const description = [detail.summary, detail.reason, detail.message, detail.errorMessage]
    .map(textValue).find(Boolean);
  const references = [
    [t(locale, "auditRecordId"), log.id],
    [t(locale, "auditEventCode"), log.message],
    [t(locale, "auditActorId"), textValue(metadata.actorId)],
    [t(locale, "auditResourceType"), resourceType],
    [t(locale, "auditResourceId"), resourceId],
    [t(locale, "auditExecutionId"), log.executionId],
    [t(locale, "auditTraceId"), log.traceId],
    [t(locale, "auditRequestId"), log.requestId],
  ];
  return (
    <div className="audit-event">
      <strong>{auditEventTitle(locale, log)}</strong>
      {resourceId ? <p>{t(locale, "auditResourceId")}: {resourceId}</p> : null}
      {log.source === "audit_log" ? (
        <p>{t(locale, "status")}: {status ? displayStatus(locale, status) : t(locale, "auditNotRecorded")}</p>
      ) : null}
      {description ? <p className="audit-event__description">{description}</p> : null}
      <details onToggle={(event) => setExpanded(event.currentTarget.open)}>
        <summary>{t(locale, "auditViewEventDetails")}</summary>
        {expanded ? (
          <div className="audit-event__details">
            <dl className="audit-event__references">
              {references.map(([label, value]) => (
                <div key={label}><dt>{label}</dt><dd>{value ?? t(locale, "auditNotRecorded")}</dd></div>
              ))}
            </dl>
            <strong>{t(locale, "auditRecordedDetails")}</strong>
            <p>{t(locale, "auditRecordedDetailsNotice")}</p>
            {Object.keys(metadata).length ? (
              <SafeJsonViewer locale={locale} value={metadata} limits={{ maxCharacters: 16000, maxNodes: 300 }} />
            ) : <p>{t(locale, "auditNoDetails")}</p>}
          </div>
        ) : null}
      </details>
    </div>
  );
}

function StateBanner({ title, copy }: { title: string; copy: string }) {
  return (
    <div className="empty-state">
      <strong>{title}</strong>
      <p>{copy}</p>
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

function retentionActionLabel(action: RetentionAction): Parameters<typeof t>[1] {
  switch (action) {
    case "archive":
      return "retentionArchive";
    case "purge":
      return "retentionPurge";
    case "set_legal_hold":
      return "retentionSetLegalHold";
    case "clear_legal_hold":
      return "retentionClearLegalHold";
  }
}
