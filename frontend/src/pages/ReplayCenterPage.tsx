/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useState } from "react";

import type {
  ReplayExport,
  ReplayExportRecord,
} from "../lib/api";
import { Locale, t } from "../i18n";
import { displayEventKind, displayFindingTitle, displayStageLabel, displayStatus } from "../lib/presentation";
import { ExecutionItem, ReplayItem } from "../store/platform";

const TIMELINE_PAGE_SIZE = 20;
const FINDING_PAGE_SIZE = 8;

type ReplayCenterPageProps = {
  canCompare: boolean;
  issueTrackerSyncAvailable: boolean;
  loading?: boolean;
  locale: Locale;
  executions: ExecutionItem[];
  selectedExecutionId: string | null;
  onSelectExecution: (executionId: string) => void;
  replay: ReplayItem | null;
  replayExport: ReplayExport | null;
  replayExports: ReplayExportRecord[];
};

export function ReplayCenterPage({
  canCompare,
  loading = false,
  locale,
  executions,
  selectedExecutionId,
  onSelectExecution,
  replay,
  replayExport,
  replayExports,
}: ReplayCenterPageProps) {
  const [timelineLimit, setTimelineLimit] = useState(TIMELINE_PAGE_SIZE);
  const [findingLimit, setFindingLimit] = useState(FINDING_PAGE_SIZE);
  const selectedExecution = executions.find((execution) => execution.id === selectedExecutionId) ?? null;
  const timeline = replay?.timeline ?? [];
  const findings = replay?.findings ?? [];

  useEffect(() => {
    if (executions.length > 0 && !selectedExecution) {
      onSelectExecution(executions[0].id);
    }
  }, [executions, onSelectExecution, selectedExecution]);

  useEffect(() => {
    setTimelineLimit(TIMELINE_PAGE_SIZE);
    setFindingLimit(FINDING_PAGE_SIZE);
  }, [selectedExecutionId]);

  return (
    <div className="page-shell replay-center" data-route="/replay-center">
      <div className="page-toolbar">
        <div>
          <h1>{t(locale, "replayCenter")}</h1>
        </div>
      </div>

      {!canCompare ? (
        <div className="empty-state">{t(locale, "replayEnterpriseNotice")}</div>
      ) : null}

      <div className="work-grid work-grid--sidebar work-grid--replay-center">
        <section className="panel replay-center__source-panel">
          <div className="panel__header replay-center__section-heading">
            <div>
              <span className="eyebrow">{t(locale, "executions")}</span>
              <h2>{t(locale, "replaySource")}</h2>
            </div>
            <span className="status-pill">{executions.length}</span>
          </div>
          <div className="stack-list replay-center__source-list">
            {executions.map((execution) => {
              const isSelected = execution.id === selectedExecution?.id;
              return (
                <button
                  aria-pressed={isSelected}
                  className={`stack-row stack-row--button ${isSelected ? "stack-row--selected" : ""}`}
                  key={execution.id}
                  onClick={() => onSelectExecution(execution.id)}
                  type="button"
                >
                  <div>
                    <strong>{execution.id.slice(0, 8)}</strong>
                    <p>{execution.environment} / {displayStageLabel(locale, execution.stage)}</p>
                  </div>
                  <span>{displayStatus(locale, execution.status)}</span>
                </button>
              );
            })}
            {executions.length === 0 ? <p className="empty-copy">{t(locale, "noExecutions")}</p> : null}
          </div>
        </section>

        <section aria-busy={loading} className="panel replay-center__detail-panel">
          <div className="stats-grid stats-grid--compact">
            <MetricTile label={t(locale, "timeline")} value={String(timeline.length)} />
            <MetricTile label={t(locale, "findings")} value={String(findings.length)} />
            <MetricTile label={t(locale, "skillInvocations")} value={String(replay?.skillInvocations.length ?? 0)} />
            <MetricTile label={t(locale, "corrections")} value={String(replay?.correctionGovernance.length ?? 0)} />
            <MetricTile label={t(locale, "guardrails")} value={String(replay?.guardrailEvents.length ?? 0)} />
            <MetricTile label={t(locale, "gate")} value={displayStatus(locale, replay?.gate?.overall ?? "pending")} />
          </div>

          {loading ? <div className="empty-state" role="status">{t(locale, "loading")}</div> : null}
          {!loading && !selectedExecution ? <div className="empty-state">{t(locale, "selectExecution")}</div> : null}

          {!loading && selectedExecution ? <div className="replay-center__columns">
            <div className="replay-center__column">
              <section className="replay-center__section">
                <SectionHeading count={timeline.length} title={t(locale, "replayTimeline")} />
                <div className="timeline-list replay-center__timeline-list">
                  {timeline.slice(0, timelineLimit).map((event, index) => (
                    <div className={`timeline-item timeline-item--${event.kind}`} key={`${event.timestamp}-${event.label}-${index}`}>
                      <strong>{event.label}</strong>
                      <span>{displayEventKind(locale, event.kind)}</span>
                      <span>{displayStatus(locale, event.status)}</span>
                    </div>
                  ))}
                  {timeline.length === 0 ? <p className="empty-copy">{t(locale, "noData")}</p> : null}
                </div>
                <ListControls
                  collapse={() => setTimelineLimit(TIMELINE_PAGE_SIZE)}
                  expand={() => setTimelineLimit((current) => Math.min(current + TIMELINE_PAGE_SIZE, timeline.length))}
                  limit={timelineLimit}
                  locale={locale}
                  pageSize={TIMELINE_PAGE_SIZE}
                  total={timeline.length}
                />
              </section>

              <section className="replay-center__section">
                <SectionHeading count={findings.length} title={t(locale, "externalIssues")} />
                <div className="stack-list replay-center__finding-list">
                  {findings.slice(0, findingLimit).map((finding) => {
                    const link = finding.externalIssueLink;
                    return (
                      <div className="stack-row stack-row--dense" key={finding.id}>
                        <div>
                          <strong>{displayFindingTitle(locale, finding.title)}</strong>
                          <p>{displayStatus(locale, finding.severity)}</p>
                        </div>
                        {link?.externalIssueUrl ? (
                          <a className="link-button" href={link.externalIssueUrl} rel="noreferrer" target="_blank">
                            {link.externalIssueKey ?? link.externalIssueId ?? link.syncStatus}
                          </a>
                        ) : (
                          <span>{link?.externalIssueKey ?? link?.syncStatus ?? t(locale, "notSynced")}</span>
                        )}
                      </div>
                    );
                  })}
                  {findings.length === 0 ? <p className="empty-copy">{t(locale, "noNormalizedFindingsSelected")}</p> : null}
                </div>
                <ListControls
                  collapse={() => setFindingLimit(FINDING_PAGE_SIZE)}
                  expand={() => setFindingLimit((current) => Math.min(current + FINDING_PAGE_SIZE, findings.length))}
                  limit={findingLimit}
                  locale={locale}
                  pageSize={FINDING_PAGE_SIZE}
                  total={findings.length}
                />
              </section>

              <SnapshotCard locale={locale} title={t(locale, "gate")} value={replay?.gate ?? null} />
            </div>

            <div className="replay-center__column">
              <section className="replay-center__section">
                <SectionHeading title={t(locale, "replayExport")} />
                {replayExport ? (
                  <div className="detail-stack">
                    <div className="inline-status replay-center__latest-export">
                      <div>
                        <strong className="technical-value">{replayExport.exportHash}</strong>
                        <time dateTime={replayExport.exportedAt}>{formatTimestamp(replayExport.exportedAt, locale)}</time>
                      </div>
                      <span className="status-pill">{displayStatus(locale, replayExport.redactionStatus)}</span>
                    </div>
                    <SnapshotCard locale={locale} title={t(locale, "snapshot")} value={{
                      traceabilitySnapshotRef: replayExport.traceabilitySnapshotRef,
                      traceabilitySnapshotHash: replayExport.traceabilitySnapshotHash,
                      coverageSummarySnapshot: replayExport.coverageSummarySnapshot,
                      coverageMatrixSnapshotRef: replayExport.coverageMatrixSnapshotRef,
                    }} />
                  </div>
                ) : (
                  <p className="empty-copy">{t(locale, "replayExportUnavailable")}</p>
                )}
              </section>

              <section className="replay-center__section">
                <SectionHeading count={replayExports.length} title={t(locale, "persistedReplayExports")} />
                <div className="stack-list replay-center__export-list">
                  {replayExports.map((record) => (
                    <div className="replay-center__export-record" key={record.exportId}>
                      <div>
                        <strong className="technical-value">{record.exportId}</strong>
                        <p>{record.traceRefs.length} {t(locale, "traces")}</p>
                      </div>
                      <div className="replay-center__export-meta">
                        <span className="status-pill">{displayStatus(locale, record.redactionStatus)}</span>
                        <time dateTime={record.persistedAt}>{formatTimestamp(record.persistedAt, locale)}</time>
                      </div>
                    </div>
                  ))}
                  {replayExports.length === 0 ? <p className="empty-copy">{t(locale, "noPersistedReplayExports")}</p> : null}
                </div>
              </section>

              <SnapshotCard locale={locale} title={t(locale, "auditRefs")} value={replayExport?.auditRefs ?? []} />
            </div>
          </div> : null}
        </section>
      </div>
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

function SectionHeading({ count, title }: { count?: number; title: string }) {
  return (
    <div className="replay-center__section-heading">
      <h3>{title}</h3>
      {typeof count === "number" ? <span className="status-pill">{count}</span> : null}
    </div>
  );
}

function ListControls({
  collapse,
  expand,
  limit,
  locale,
  pageSize,
  total,
}: {
  collapse: () => void;
  expand: () => void;
  limit: number;
  locale: Locale;
  pageSize: number;
  total: number;
}) {
  if (total <= pageSize) {
    return null;
  }

  const visible = Math.min(limit, total);
  return (
    <div className="replay-center__list-controls">
      <span>{visible} / {total}</span>
      <div className="button-row">
        {visible < total ? (
          <button className="secondary-button" onClick={expand} type="button">
            {t(locale, "loadMore")} ({Math.min(pageSize, total - visible)})
          </button>
        ) : null}
        {visible > pageSize ? (
          <button className="secondary-button" onClick={collapse} type="button">{t(locale, "collapse")}</button>
        ) : null}
      </div>
    </div>
  );
}

function SnapshotCard({ locale, title, value }: { locale: Locale; title: string; value: unknown }) {
  return (
    <details className="replay-center__snapshot">
      <summary>
        <strong>{title}</strong>
        <span>{t(locale, "technicalDetails")}</span>
      </summary>
      <pre aria-label={title} className="snapshot-json" tabIndex={0}>
        {JSON.stringify(value, null, 2)}
      </pre>
    </details>
  );
}

function formatTimestamp(value: string, locale: Locale) {
  const timestamp = new Date(value);
  if (Number.isNaN(timestamp.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "medium" }).format(timestamp);
}
