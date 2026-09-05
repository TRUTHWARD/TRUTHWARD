/* SPDX-License-Identifier: Apache-2.0 */
import { Locale, t } from "../i18n";
import { displayEventKind, displayFindingTitle, displayStageLabel, displayStatus } from "../lib/presentation";
import { ExecutionItem, ReplayItem } from "../store/platform";

type GateSnapshot = {
  overall: string;
  functional: string;
  performance: string;
  security: string;
  reasons?: string[];
} | null;

type GateDecisionsPageProps = {
  locale: Locale;
  executions: ExecutionItem[];
  selectedExecutionId: string | null;
  onSelectExecution: (executionId: string) => void;
  gate: GateSnapshot;
  replay: ReplayItem | null;
  loading: boolean;
  error: string | null;
};

export function GateDecisionsPage({
  locale,
  executions,
  selectedExecutionId,
  onSelectExecution,
  gate,
  replay,
  loading,
  error,
}: GateDecisionsPageProps) {
  const selectedExecution = executions.find((execution) => execution.id === selectedExecutionId) ?? executions[0] ?? null;
  const hasStableContext = Boolean(selectedExecution);
  const reasons = gate?.reasons ?? [];

  return (
    <div className="page-shell" data-route="/gate-decisions">
      <div className="page-toolbar">
        <div>
          <h1>{t(locale, "gateDecisions")}</h1>
        </div>
        <span className="status-pill">{t(locale, "readOnly")}</span>
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
                <span>{displayStageLabel(locale, execution.stage)}</span>
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
          {hasStableContext && !loading && !error ? (
            <div className="detail-stack">
              <div className="stats-grid stats-grid--compact">
                <MetricTile label={t(locale, "overall")} value={displayStatus(locale, gate?.overall ?? "pending")} />
                <MetricTile label={t(locale, "functional")} value={displayStatus(locale, gate?.functional ?? "pending")} />
                <MetricTile label={t(locale, "performance")} value={displayStatus(locale, gate?.performance ?? "pending")} />
                <MetricTile label={t(locale, "security")} value={displayStatus(locale, gate?.security ?? "pending")} />
              </div>

              <div className="detail-grid">
                <div>
                  <h3>{t(locale, "gateReasons")}</h3>
                  <div className="stack-list">
                    {reasons.map((reason) => (
                      <div className="stack-row stack-row--dense" key={reason}>
                        <strong>{displayFindingTitle(locale, reason)}</strong>
                      </div>
                    ))}
                    {reasons.length === 0 ? <p className="empty-copy">{t(locale, "emptyReadOnlyResult")}</p> : null}
                  </div>
                </div>

                <div>
                  <h3>{t(locale, "replaySnapshot")}</h3>
                  <div className="timeline-list">
                    {(replay?.timeline ?? []).slice(0, 6).map((event, index) => (
                      <div className={`timeline-item timeline-item--${event.kind}`} key={`${event.timestamp}-${event.label}-${index}`}>
                        <strong>{event.label}</strong>
                        <span>{displayEventKind(locale, event.kind)}</span>
                        <span>{displayStatus(locale, event.status)}</span>
                      </div>
                    ))}
                    {(replay?.timeline ?? []).length === 0 ? <p className="empty-copy">{t(locale, "emptyReadOnlyResult")}</p> : null}
                  </div>
                </div>
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
