/* SPDX-License-Identifier: Apache-2.0 */
import { useState } from "react";

import { Locale, t } from "../i18n";
import type { ExternalIssueLink } from "../lib/api";
import { ExecutionItem } from "../store/platform";

type FindingItem = {
  id: string;
  domain: string;
  severity: string;
  source: string;
  title: string;
  summary: string;
  confidence: number | null;
  externalIssueLink: ExternalIssueLink | null;
};

type FindingsPageProps = {
  canSyncIssueTracker: boolean;
  locale: Locale;
  executions: ExecutionItem[];
  selectedExecutionId: string | null;
  onSelectExecution: (executionId: string) => void;
  onSyncExternalIssue: (findingId: string) => Promise<void>;
  onRefreshExternalIssue: (findingId: string) => Promise<void>;
  findings: FindingItem[];
  issueTrackerBindingCount: number;
  loading: boolean;
  error: string | null;
  syncingFindingId: string | null;
};

export function FindingsPage({
  canSyncIssueTracker,
  locale,
  executions,
  selectedExecutionId,
  onSelectExecution,
  onSyncExternalIssue,
  onRefreshExternalIssue,
  findings,
  issueTrackerBindingCount,
  loading,
  error,
  syncingFindingId,
}: FindingsPageProps) {
  const [actionError, setActionError] = useState<string | null>(null);
  const selectedExecution = executions.find((execution) => execution.id === selectedExecutionId) ?? executions[0] ?? null;
  const hasStableContext = Boolean(selectedExecution);
  const canUseIssueTracker = canSyncIssueTracker && issueTrackerBindingCount > 0;

  const runIssueAction = async (action: () => Promise<void>) => {
    setActionError(null);
    try {
      await action();
    } catch (issueError) {
      setActionError(issueError instanceof Error ? issueError.message : t(locale, "issueTrackerSyncFailed"));
    }
  };

  return (
    <div className="page-shell" data-route="/findings">
      <div className="page-toolbar">
        <div>
          <h1>{t(locale, "findings")}</h1>
        </div>
        <div className="badge-row">
          <span className="status-pill">{t(locale, "readOnly")}</span>
          <span className="status-pill">{canUseIssueTracker ? t(locale, "issueTrackerReady") : t(locale, "issueTrackerReadOnly")}</span>
        </div>
      </div>

      <div className="page-columns">
        <section className="panel">
          <div className="panel__header">
            <span className="eyebrow">{t(locale, "scope")}</span>
            <h2>{t(locale, "executionContext")}</h2>
          </div>
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
                <span>{execution.status}</span>
              </button>
            ))}
            {executions.length === 0 ? <div className="empty-state">{t(locale, "unavailableExecutionContext")}</div> : null}
          </div>
        </section>

        <section className="panel">
          {!hasStableContext ? <StateBanner title={t(locale, "unavailableContext")} copy={t(locale, "selectExecutionContext")} /> : null}
          {loading ? <StateBanner title={t(locale, "loading")} copy={t(locale, "loadingReadOnlyData")} /> : null}
          {error ? (
            <div className="error-banner">
              <strong>{t(locale, "errorState")}</strong>
              <p>{error}</p>
            </div>
          ) : null}
          {actionError ? (
            <div className="error-banner">
              <strong>{t(locale, "issueTrackerSyncFailed")}</strong>
              <p>{actionError}</p>
            </div>
          ) : null}
          {hasStableContext && !canUseIssueTracker ? (
            <StateBanner
              title={t(locale, "issueTrackerReadOnly")}
              copy={canSyncIssueTracker ? t(locale, "issueTrackerBindingRequired") : t(locale, "issueTrackerSyncCapabilityRequired")}
            />
          ) : null}
          {hasStableContext && !loading && !error ? (
            <div className="detail-stack">
              <div className="stats-grid stats-grid--compact">
                <MetricTile label={t(locale, "findings")} value={String(findings.length)} />
                <MetricTile label={t(locale, "execution")} value={selectedExecution.id.slice(0, 8)} />
                <MetricTile label={t(locale, "status")} value={selectedExecution.status} />
              </div>
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>{t(locale, "title")}</th>
                      <th>{t(locale, "severity")}</th>
                      <th>{t(locale, "source")}</th>
                      <th>{t(locale, "domain")}</th>
                      <th>{t(locale, "confidence")}</th>
                      <th>{t(locale, "externalIssue")}</th>
                      <th>{t(locale, "actions")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((finding) => {
                      const link = finding.externalIssueLink;
                      const syncing = syncingFindingId === finding.id;
                      return (
                        <tr key={finding.id}>
                          <td>
                            <strong>{finding.title}</strong>
                            <p>{finding.summary}</p>
                          </td>
                          <td><span className={`status-pill status-pill--${finding.severity}`}>{finding.severity}</span></td>
                          <td>{finding.source}</td>
                          <td>{finding.domain}</td>
                          <td>{finding.confidence === null ? t(locale, "none") : `${Math.round(finding.confidence * 100)}%`}</td>
                          <td>
                            {link ? (
                              <div className="stack-list stack-list--compact">
                                {link.externalIssueUrl ? (
                                  <a className="link-button" href={link.externalIssueUrl} rel="noreferrer" target="_blank">
                                    {link.externalIssueKey ?? link.externalIssueId ?? t(locale, "externalIssue")}
                                  </a>
                                ) : (
                                  <strong>{link.externalIssueKey ?? link.externalIssueId ?? t(locale, "externalIssue")}</strong>
                                )}
                                <span className={`status-pill status-pill--${link.syncStatus}`}>{link.syncStatus}</span>
                                <span>{link.externalStatus ?? t(locale, "pending")}</span>
                              </div>
                            ) : (
                              <span className="muted-text">{t(locale, "notSynced")}</span>
                            )}
                          </td>
                          <td>
                            {canUseIssueTracker ? (
                              <div className="button-row">
                                <button
                                  className="secondary-button"
                                  disabled={syncing || loading}
                                  onClick={() => void runIssueAction(() => onSyncExternalIssue(finding.id))}
                                  type="button"
                                >
                                  {syncing ? t(locale, "syncing") : link ? t(locale, "updateExternalIssue") : t(locale, "syncToIssueTracker")}
                                </button>
                                <button
                                  className="secondary-button"
                                  disabled={syncing || loading || !link}
                                  onClick={() => void runIssueAction(() => onRefreshExternalIssue(finding.id))}
                                  type="button"
                                >
                                  {t(locale, "refreshExternalStatus")}
                                </button>
                              </div>
                            ) : (
                              <span className="status-pill">{t(locale, "issueTrackerReadOnly")}</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                    {findings.length === 0 ? (
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
