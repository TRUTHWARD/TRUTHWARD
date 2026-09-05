/* SPDX-License-Identifier: Apache-2.0 */
import { Locale, t } from "../i18n";
import type { WorkflowRunAction, WorkflowRunProjection, WorkflowRunStageSummary } from "../lib/api";
import {
  displayStageLabel,
  displayReasonCode,
  displayStatus,
  displayStrategyLabel,
  displayWorkflowActionLabel,
  summarizeTechnicalRefs,
} from "../lib/presentation";

type WorkflowRunsPageProps = {
  detail: WorkflowRunProjection | null;
  error: string | null;
  loading: boolean;
  locale: Locale;
  onNavigateAction: (action: WorkflowRunAction, run: WorkflowRunProjection) => Promise<void>;
  onSelectRun: (runId: string) => Promise<void>;
  runs: WorkflowRunProjection[];
  selectedRunId: string | null;
};

const stageOrder: WorkflowRunStageSummary["stageKey"][] = [
  "requirement",
  "plan",
  "approval",
  "execution",
  "exploratory",
  "regression",
  "gate",
  "replay",
];

export function WorkflowRunsPage({
  detail,
  error,
  loading,
  locale,
  onNavigateAction,
  onSelectRun,
  runs,
  selectedRunId,
}: WorkflowRunsPageProps) {
  const selectedRun = detail ?? runs.find((run) => run.runId === selectedRunId) ?? runs[0] ?? null;
  const stageSummaries = stageOrder
    .map((stageKey) => selectedRun?.stageSummaries.find((stage) => stage.stageKey === stageKey))
    .filter((stage): stage is WorkflowRunStageSummary => Boolean(stage));

  return (
    <div className="page-shell" data-route="/workflow-runs">
      <div className="page-toolbar">
        <div>
          <h1>{t(locale, "workflowRuns")}</h1>
        </div>
      </div>

      {loading ? <StateBanner title={t(locale, "loading")} copy={t(locale, "workflowRunsLoading")} /> : null}
      {error ? (
        <div className="error-banner">
          <strong>{t(locale, "workflowErrorState")}</strong>
          <p>{error}</p>
        </div>
      ) : null}

      <div className="work-grid work-grid--sidebar">
        <section className="panel">
          <div className="panel__header">
            <span className="eyebrow">{t(locale, "runs")}</span>
            <h2>{t(locale, "workflowRunList")}</h2>
          </div>
          <div className="stack-list">
            {runs.map((run) => (
              <button
                className={`stack-row stack-row--button ${run.runId === selectedRun?.runId ? "stack-row--selected" : ""}`}
                key={run.runId}
                onClick={() => void onSelectRun(run.runId)}
                type="button"
              >
                <div>
                  <strong>{shortId(run.runId)}</strong>
                  <p>{run.source} / {run.triggerType}</p>
                </div>
                <span className={`status-pill status-pill--${run.currentState}`}>{displayStatus(locale, run.currentState)}</span>
              </button>
            ))}
            {runs.length === 0 ? <div className="empty-state">{t(locale, "noWorkflowRuns")}</div> : null}
          </div>
        </section>

        <section className="panel">
          {!selectedRun ? <StateBanner title={t(locale, "unavailableContext")} copy={t(locale, "selectWorkflowRun")} /> : null}
          {selectedRun ? (
            <div className="detail-stack">
              <div className="stats-grid stats-grid--compact">
                <MetricTile label={t(locale, "currentState")} value={displayStatus(locale, selectedRun.currentState)} />
                <MetricTile label={t(locale, "currentStep")} value={displayStatus(locale, selectedRun.currentStep)} />
                <MetricTile label={t(locale, "checkpointCount")} value={String(selectedRun.checkpointCount)} />
                <MetricTile
                  label={t(locale, "blockingReason")}
                  value={selectedRun.blockedReason ? displayReasonCode(locale, selectedRun.blockedReason) : t(locale, "none")}
                />
              </div>

              <div className="workflow-stage-track" aria-label={t(locale, "workflowStages")}>
                {stageSummaries.map((stage) => (
                  <div className={`workflow-stage workflow-stage--${stage.status}`} key={stage.stageKey}>
                    <span>{displayStageLabel(locale, stage.stageKey, stage.label)}</span>
                    <strong>{displayStatus(locale, stage.status)}</strong>
                    {stage.statusReason ? <small title={stage.statusReason}>{displayReasonCode(locale, stage.statusReason)}</small> : null}
                  </div>
                ))}
              </div>

              <div className="workflow-summary-columns">
                <div className="workflow-summary-column">
                  <section>
                    <h3>{t(locale, "linkedResources")}</h3>
                    <div className="inline-status-list">
                      <LinkedResource label={t(locale, "requirement")} value={selectedRun.linkedResources.requirement} idKey="requirementVersionId" />
                      <LinkedResource label={t(locale, "plan")} value={selectedRun.linkedResources.plan} idKey="planId" />
                      <LinkedResource label={t(locale, "approval")} value={selectedRun.linkedResources.approval} idKey="approvalId" />
                      <LinkedResource label={t(locale, "execution")} value={selectedRun.linkedResources.execution} idKey="executionId" />
                      <LinkedResource label={t(locale, "exploratorySessions")} value={selectedRun.linkedResources.exploratorySessions[0] ?? null} idKey="sessionId" />
                      <LinkedResource label={t(locale, "regression")} value={selectedRun.linkedResources.regressionPlan} idKey="recommendedCaseCount" />
                      <LinkedResource label={t(locale, "gate")} value={selectedRun.linkedResources.gate} idKey="gateDecisionId" />
                      <LinkedResource label={t(locale, "replay")} value={selectedRun.linkedResources.replay} idKey="exportHash" />
                    </div>
                  </section>
                  <section>
                    <h3>{t(locale, "testDomains")}</h3>
                    <div className="inline-status-list">
                      {selectedRun.testDomains.map((domain) => (
                        <div className="inline-status" key={domain.domain}>
                          <span>{domainLabel(locale, domain.domain)}</span>
                          <strong>{displayStatus(locale, domain.status)}</strong>
                        </div>
                      ))}
                    </div>
                  </section>
                  <section>
                    <h3>{t(locale, "governanceStatus")}</h3>
                    <div className="stats-grid stats-grid--compact">
                      <MetricTile label={t(locale, "activeSkillBindings")} value={String(selectedRun.governanceStatus.activeSkillBindings?.length ?? 0)} />
                      <MetricTile label={t(locale, "skillInvocationRefs")} value={String(selectedRun.governanceStatus.skillInvocationRefs?.length ?? 0)} />
                      <MetricTile label={t(locale, "guardrailRefs")} value={String(selectedRun.governanceStatus.guardrailEventRefs?.length ?? 0)} />
                      <MetricTile label={t(locale, "auditRefs")} value={String(selectedRun.governanceStatus.auditRefs?.length ?? 0)} />
                    </div>
                  </section>
                  <section>
                    <h3>{t(locale, "stageEvidence")}</h3>
                    <div className="table-wrap">
                      <table className="data-table data-table--compact">
                        <thead><tr><th>{t(locale, "stage")}</th><th>{t(locale, "status")}</th><th>{t(locale, "checkpointCount")}</th><th>{t(locale, "resource")}</th></tr></thead>
                        <tbody>
                          {stageSummaries.map((stage) => (
                            <tr key={stage.stageKey}>
                              <td>{displayStageLabel(locale, stage.stageKey, stage.label)}</td>
                              <td><span className={`status-pill status-pill--${stage.status}`}>{displayStatus(locale, stage.status)}</span></td>
                              <td>{stage.checkpointRefs.length}</td>
                              <td className="technical-value">{resourceSummary(stage.refs)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </section>
                </div>

                <div className="workflow-summary-column">
                  <section>
                    <h3>{t(locale, "nextActions")}</h3>
                    <div className="stack-list">
                      {selectedRun.nextActions.map((action) => (
                        <button className="stack-row stack-row--button" key={action.actionId} onClick={() => void onNavigateAction(action, selectedRun)} type="button">
                          <div><strong>{displayWorkflowActionLabel(locale, action.actionId, action.label)}</strong><p className="technical-value">{action.targetRoute}</p></div>
                          <span className="technical-value">{action.targetResourceType}</span>
                        </button>
                      ))}
                      {selectedRun.nextActions.length === 0 ? <p className="empty-copy">{t(locale, "noNextActions")}</p> : null}
                    </div>
                  </section>
                  <section>
                    <h3>{t(locale, "executionStrategies")}</h3>
                    <div className="inline-status-list">
                      {selectedRun.executionStrategies.map((strategy) => (
                        <div className="inline-status" key={strategy.strategy}>
                          <span>{displayStrategyLabel(locale, strategy.strategy)}</span>
                          <strong>{displayStatus(locale, strategy.status)}</strong>
                        </div>
                      ))}
                    </div>
                  </section>
                  <section>
                    <h3>{t(locale, "currentUserCapabilityState")}</h3>
                    <div className="inline-status-list">
                      {Object.entries(selectedRun.governanceStatus.currentUserCapabilityState ?? {}).map(([capability, state]) => (
                        <div className="inline-status" key={capability}>
                          <span className="technical-value">{capability}</span>
                          <strong>{displayStatus(locale, state)}</strong>
                        </div>
                      ))}
                    </div>
                  </section>
                  <section>
                    <h3>{t(locale, "projectionSnapshot")}</h3>
                    <pre className="snapshot-json">{JSON.stringify(selectedRun.resultSummary, null, 2)}</pre>
                  </section>
                </div>
              </div>

              <section>
                <h3>{t(locale, "checkpoints")}</h3>
                <div className="timeline-list">
                  {(selectedRun.checkpoints ?? []).map((checkpoint) => (
                    <div className="timeline-item timeline-item--orchestration_checkpoint" key={String(checkpoint.checkpointId)}>
                      <strong>{String(checkpoint.stepName ?? "-")}</strong>
                      <span>{displayStatus(locale, String(checkpoint.status ?? "-"))}</span>
                      <span>{String(checkpoint.createdAt ?? "-")}</span>
                    </div>
                  ))}
                  {(selectedRun.checkpoints ?? []).length === 0 ? <p className="empty-copy">{t(locale, "selectWorkflowRunForCheckpoints")}</p> : null}
                </div>
              </section>
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

function LinkedResource({ label, value, idKey }: { label: string; value: Record<string, unknown> | null; idKey: string }) {
  return (
    <div className="inline-status">
      <span>{label}</span>
      <strong>{value ? shortId(String(value[idKey] ?? "-")) : "-"}</strong>
    </div>
  );
}

function shortId(value: string) {
  return value.length > 12 ? value.slice(0, 12) : value;
}

function resourceSummary(refs: Record<string, unknown>) {
  return summarizeTechnicalRefs(refs);
}

function domainLabel(locale: Locale, domain: string) {
  if (domain === "functional" || domain === "performance" || domain === "security") {
    return t(locale, domain);
  }
  return domain;
}
