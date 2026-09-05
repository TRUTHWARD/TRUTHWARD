/* SPDX-License-Identifier: Apache-2.0 */
import { useState } from "react";
import { createRegressionPresentation, type RegressionPresentation } from "../lib/api";

import { SectionCard } from "../components/SectionCard";
import { Locale, t } from "../i18n";
import type { ExecutionTaskArtifact, ExecutionTaskLog, ExecutionTaskMetric, ExecutionTaskRecord, ExternalIssueLink } from "../lib/api";
import {
  displayArtifactLabel,
  displayDomainLabel,
  displayEventKind,
  displayFindingTitle,
  displayLogLevel,
  displayLogMessage,
  displayMetricLabel,
  displayRemediationLabel,
  displayRemediationSummary,
  displayStageLabel,
  displayStatus,
} from "../lib/presentation";
import { ExecutionItem, JobItem, ReplayItem } from "../store/platform";

type ExecutionProgress = {
  progress: number;
  currentTask: string | null;
  completedTasks: number;
  totalTasks: number;
} | null;

type FindingItem = {
  id: string;
  executionId: string;
  taskId: string | null;
  domain: string;
  severity: string;
  source: string;
  title: string;
  summary: string;
  externalIssueLink: ExternalIssueLink | null;
};

type HealingSuggestion = {
  taskId: string | null;
  type: string;
  summary: string;
};

type ExecutionsPageProps = {
  canGenerateRegressionPresentation?: boolean;
  locale: Locale;
  executions: ExecutionItem[];
  selectedExecutionId: string | null;
  onSelectExecution: (executionId: string) => void;
  progress: ExecutionProgress;
  tasks: ExecutionTaskRecord[];
  findings: FindingItem[];
  selectedTaskId: string | null;
  selectedTask: ExecutionTaskRecord | null;
  selectedTaskArtifacts: ExecutionTaskArtifact[];
  selectedTaskLogs: ExecutionTaskLog[];
  selectedTaskMetrics: ExecutionTaskMetric[];
  selectedTaskDetailLoading: boolean;
  selectedTaskDetailError: string | null;
  onSelectTask: (taskId: string) => void;
  canSyncIssueTracker: boolean;
  issueTrackerBindingCount: number;
  syncingFindingId: string | null;
  onSyncExternalIssue: (findingId: string) => Promise<void>;
  onRefreshExternalIssue: (findingId: string) => Promise<void>;
  healingSuggestions: HealingSuggestion[];
  replay: ReplayItem | null;
  relatedJobs: JobItem[];
};

export function ExecutionsPage({
  canGenerateRegressionPresentation = false,
  locale,
  executions,
  selectedExecutionId,
  onSelectExecution,
  progress,
  tasks,
  findings,
  selectedTaskId,
  selectedTask,
  selectedTaskArtifacts,
  selectedTaskLogs,
  selectedTaskMetrics,
  selectedTaskDetailLoading,
  selectedTaskDetailError,
  onSelectTask,
  canSyncIssueTracker,
  issueTrackerBindingCount,
  syncingFindingId,
  onSyncExternalIssue,
  onRefreshExternalIssue,
  healingSuggestions,
  replay,
  relatedJobs,
}: ExecutionsPageProps) {
  const [actionError, setActionError] = useState<string | null>(null);
  const [presentation, setPresentation] = useState<{ executionId: string; data: RegressionPresentation } | null>(null);
  const [presenting, setPresenting] = useState(false);
  const [presentationError, setPresentationError] = useState<string | null>(null);
  const selectedExecution = executions.find((execution) => execution.id === selectedExecutionId) ?? executions[0] ?? null;
  const separator = t(locale, "valueSeparator");
  const canUseIssueTracker = canSyncIssueTracker && issueTrackerBindingCount > 0;
  const selectedTaskFindings = selectedTaskId ? findings.filter((finding) => finding.taskId === selectedTaskId) : [];
  const runtime = selectedExecution?.runtime ?? null;
  const currentPresentation = presentation?.executionId === selectedExecution?.id ? presentation?.data : null;
  const generatePresentation = async () => {
    if (!selectedExecution || !canGenerateRegressionPresentation) return;
    const executionId = selectedExecution.id;
    setPresenting(true);
    setPresentationError(null);
    try {
      setPresentation({ executionId, data: await createRegressionPresentation(executionId) });
    } catch (error) {
      setPresentationError(error instanceof Error ? error.message : t(locale, "communityRegressionFailed"));
    } finally {
      setPresenting(false);
    }
  };
  const runIssueAction = async (action: () => Promise<void>) => {
    setActionError(null);
    try {
      await action();
    } catch (issueError) {
      setActionError(issueError instanceof Error ? issueError.message : t(locale, "issueTrackerSyncFailed"));
    }
  };

  return (
    <div className="page-shell" data-route="/executions">
      <div className="page-columns">
        <SectionCard title={t(locale, "executions")} eyebrow={t(locale, "runs")}>
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
                  <p>{execution.environment} {separator} {displayStatus(locale, execution.summary.functional ?? "queued")} {separator} {displayStatus(locale, execution.summary.performance ?? "queued")} {separator} {displayStatus(locale, execution.summary.security ?? "queued")}</p>
                </div>
                <span>{displayStatus(locale, execution.status)} {separator} {displayStageLabel(locale, execution.stage)}</span>
              </button>
            ))}
          </div>
        </SectionCard>

        <SectionCard title={selectedExecution ? `${t(locale, "executionPrefix")} ${selectedExecution.id.slice(0, 8)}` : t(locale, "executionDetail")} eyebrow={t(locale, "selectedRun")}>
          {selectedExecution ? (
            <div className="detail-stack">
              {canGenerateRegressionPresentation ? (
                <div className="section-card">
                  <button className="ghost-button" disabled={presenting} onClick={() => void generatePresentation()} type="button">
                    {t(locale, "communityRegressionGenerate")}
                  </button>
                  <p>{t(locale, "communityRegressionBoundary")}</p>
                  {presentationError ? <p role="alert">{presentationError}</p> : null}
                  {currentPresentation ? (
                    <div aria-live="polite">
                      <p>{t(locale, "communityRegressionSkill")}: {currentPresentation.metadata.resolvedSkillId}</p>
                      <p>{t(locale, "communityRegressionInvocation")}: {currentPresentation.metadata.skillInvocationId}</p>
                      <p>{t(locale, "regressionRecommendedCases")}: {currentPresentation.recommendedRegressionSuite.length}</p>
                      {currentPresentation.metadata.communityView?.groups.map((group) => (
                        <p key={group.label}>{group.label}: {group.count}{group.caseIds ? ` (${group.caseIds.join(", ")})` : ""}</p>
                      ))}
                    </div>
                  ) : null}
                </div>
              ) : null}
              {actionError ? (
                <div className="error-banner">
                  <strong>{t(locale, "issueTrackerSyncFailed")}</strong>
                  <p>{actionError}</p>
                </div>
              ) : null}
              <div className="detail-banner">
                <div>
                  <strong>{displayStatus(locale, selectedExecution.status)}</strong>
                  <p>{selectedExecution.environment} {separator} {t(locale, "stage")} {displayStageLabel(locale, selectedExecution.stage)}</p>
                </div>
                <div className="chip-row">
                  <span className="tag">{t(locale, "functional")} {displayStatus(locale, selectedExecution.summary.functional ?? "queued")}</span>
                  <span className="tag">{t(locale, "performance")} {displayStatus(locale, selectedExecution.summary.performance ?? "queued")}</span>
                  <span className="tag">{t(locale, "security")} {displayStatus(locale, selectedExecution.summary.security ?? "queued")}</span>
                </div>
              </div>

              {progress ? (
                <div className="progress-panel">
                  <div className="progress-meta">
                    <strong>{progress.progress}%</strong>
                    <span>{progress.completedTasks}/{progress.totalTasks} {t(locale, "taskCount")}</span>
                    <span>{progress.currentTask ?? t(locale, "waitingForNextTask")}</span>
                  </div>
                  <div className="progress-bar">
                    <div className="progress-bar__value" style={{ width: `${progress.progress}%` }} />
                  </div>
                </div>
              ) : null}

              {runtime ? (
                <div className="detail-grid">
                  <div>
                    <h3>{t(locale, "runtimeExecutionClosure")}</h3>
                    <div className="stats-grid stats-grid--compact">
                      <div className="stat-tile">
                        <span>{t(locale, "tasks")}</span>
                        <strong>{runtime.counts.completedTaskCount}/{runtime.counts.taskCount}</strong>
                      </div>
                      <div className="stat-tile">
                        <span>{t(locale, "artifactRefs")}</span>
                        <strong>{runtime.counts.artifactRefCount}</strong>
                      </div>
                      <div className="stat-tile">
                        <span>{t(locale, "metricEvidenceRefs")}</span>
                        <strong>{runtime.counts.rawMetricRefCount}</strong>
                      </div>
                      <div className="stat-tile">
                        <span>{t(locale, "findingIntakeRefs")}</span>
                        <strong>{runtime.counts.rawFindingRefCount}</strong>
                      </div>
                    </div>
                    <div className="inline-status-list">
                      <div className="inline-status">
                        <strong>{t(locale, "queueMode")}</strong>
                        <span>{runtime.queueMode}</span>
                      </div>
                      <div className="inline-status">
                        <strong>{t(locale, "normalizedFindings")}</strong>
                        <span>{runtime.counts.normalizedFindingRefCount}</span>
                      </div>
                      <div className="inline-status">
                        <strong>{t(locale, "gate")}</strong>
                        <span>{runtime.readiness.gateCompleted ? t(locale, "yes") : runtime.readiness.gateReady ? t(locale, "gateReady") : t(locale, "no")}</span>
                      </div>
                    </div>
                  </div>
                  <div>
                    <h3>{t(locale, "runtimeConsumerReadiness")}</h3>
                    <div className="inline-status-list">
                      <div className="inline-status">
                        <strong>{t(locale, "rawEvidencePersisted")}</strong>
                        <span>{runtime.readiness.rawEvidencePersisted ? t(locale, "yes") : t(locale, "no")}</span>
                      </div>
                      <div className="inline-status">
                        <strong>{t(locale, "normalizeCompleted")}</strong>
                        <span>{runtime.readiness.normalizeCompleted ? t(locale, "yes") : t(locale, "no")}</span>
                      </div>
                      <div className="inline-status">
                        <strong>{t(locale, "replayConsumable")}</strong>
                        <span>{runtime.readiness.replayConsumable ? t(locale, "yes") : t(locale, "no")}</span>
                      </div>
                      <div className="inline-status">
                        <strong>{t(locale, "replayExportConsumable")}</strong>
                        <span>{runtime.readiness.replayExportConsumable ? t(locale, "yes") : t(locale, "no")}</span>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <p className="empty-copy">{t(locale, "runtimeReadinessUnavailable")}</p>
              )}

              <div className="detail-grid">
                <div>
                  <h3>{t(locale, "tasks")}</h3>
                  <div className="stack-list">
                    {tasks.map((task) => (
                      <button
                        className={`stack-row stack-row--button stack-row--dense ${task.id === selectedTaskId ? "stack-row--selected" : ""}`}
                        key={task.id}
                        onClick={() => onSelectTask(task.id)}
                        type="button"
                      >
                        <div>
                          <strong>{displayDomainLabel(locale, task.domain)}</strong>
                          <p>{task.runner} {separator} {task.taskType}</p>
                        </div>
                        <span>{displayStatus(locale, task.status)}{task.retryCount > 0 ? ` ${separator} ${t(locale, "retry")} ${task.retryCount}` : ""}</span>
                      </button>
                    ))}
                    {tasks.length === 0 ? <p className="empty-copy">{t(locale, "noExecutionTask")}</p> : null}
                  </div>
                </div>

                <div>
                  <h3>{t(locale, "findings")}</h3>
                  <div className="stack-list">
                    {findings.slice(0, 6).map((finding) => (
                      <div className="stack-row stack-row--dense" key={finding.id}>
                        <div>
                          <strong>{displayFindingTitle(locale, finding.title)}</strong>
                          <p>
                            {finding.source} {separator} {displayDomainLabel(locale, finding.domain)}
                            {finding.externalIssueLink ? ` ${separator} ${finding.externalIssueLink.externalIssueKey ?? finding.externalIssueLink.externalIssueId ?? finding.externalIssueLink.syncStatus}` : ""}
                          </p>
                        </div>
                        <div className="button-row">
                          <span>{displayStatus(locale, finding.severity)}</span>
                          <button
                            className="secondary-button"
                            disabled={!canUseIssueTracker || syncingFindingId === finding.id}
                            onClick={() => void runIssueAction(() => onSyncExternalIssue(finding.id))}
                            type="button"
                          >
                            {syncingFindingId === finding.id ? t(locale, "syncing") : finding.externalIssueLink ? t(locale, "updateExternalIssue") : t(locale, "syncToIssueTracker")}
                          </button>
                          <button
                            className="secondary-button"
                            disabled={!canUseIssueTracker || syncingFindingId === finding.id || !finding.externalIssueLink}
                            onClick={() => void runIssueAction(() => onRefreshExternalIssue(finding.id))}
                            type="button"
                          >
                            {t(locale, "refreshExternalStatus")}
                          </button>
                        </div>
                      </div>
                    ))}
                    {findings.length === 0 ? <p className="empty-copy">{t(locale, "noNormalizedFindingsForExecution")}</p> : null}
                  </div>
                </div>
              </div>

              <div className="detail-grid">
                <div>
                  <h3>{t(locale, "executionTaskDetail")}</h3>
                  {selectedTaskDetailLoading ? <p className="empty-copy">{t(locale, "loading")}</p> : null}
                  {selectedTaskDetailError ? <p className="error-copy">{selectedTaskDetailError}</p> : null}
                  {selectedTask ? (
                    <div className="detail-stack">
                      <div className="detail-banner">
                        <div>
                          <strong>{selectedTask.taskType}</strong>
                          <p>{selectedTask.runner} {separator} {displayDomainLabel(locale, selectedTask.domain)} {separator} {displayStatus(locale, selectedTask.status)}</p>
                        </div>
                        <div className="chip-row">
                          <span className="tag">{t(locale, "stage")} {selectedTask.stage ? displayStageLabel(locale, selectedTask.stage) : t(locale, "none")}</span>
                          <span className="tag">{t(locale, "retry")} {selectedTask.retryCount}</span>
                        </div>
                      </div>
                      {selectedTask.errorMessage ? <p className="error-copy">{selectedTask.errorMessage}</p> : null}
                      <details className="json-block">
                        <summary>{t(locale, "taskResultPayload")}</summary>
                        <pre>{JSON.stringify(selectedTask.resultPayload, null, 2)}</pre>
                      </details>
                    </div>
                  ) : (
                    <p className="empty-copy">{t(locale, "selectExecutionTask")}</p>
                  )}
                </div>

                <div>
                  <h3>{t(locale, "linkedFindings")}</h3>
                  <div className="stack-list">
                    {selectedTaskFindings.map((finding) => (
                      <div className="stack-row stack-row--dense" key={finding.id}>
                        <div>
                          <strong>{displayFindingTitle(locale, finding.title)}</strong>
                          <p>{finding.source} {separator} {displayDomainLabel(locale, finding.domain)}</p>
                        </div>
                        <span>{displayStatus(locale, finding.severity)}</span>
                      </div>
                    ))}
                    {selectedTaskFindings.length === 0 ? <p className="empty-copy">{t(locale, "noTaskFindings")}</p> : null}
                  </div>
                </div>
              </div>

              <div className="detail-grid">
                <div>
                  <h3>{t(locale, "artifacts")}</h3>
                  <div className="stack-list">
                    {selectedTaskArtifacts.map((artifact) => (
                      <div className="stack-row stack-row--dense" key={artifact.id}>
                        <div>
                          <strong>{displayArtifactLabel(locale, artifact.artifactType)}</strong>
                          <p>{artifact.summary ?? artifact.uri}</p>
                        </div>
                        <span>{displayStatus(locale, artifact.redactionStatus)}</span>
                      </div>
                    ))}
                    {selectedTaskArtifacts.length === 0 ? <p className="empty-copy">{t(locale, "noTaskArtifacts")}</p> : null}
                  </div>
                </div>

                <div>
                  <h3>{t(locale, "metrics")}</h3>
                  <div className="stack-list">
                    {selectedTaskMetrics.map((metric) => (
                      <div className="stack-row stack-row--dense" key={metric.id}>
                        <div>
                          <strong>{displayMetricLabel(locale, metric.metricName)}</strong>
                          <p>{metric.metricUnit ?? t(locale, "none")}</p>
                        </div>
                        <span>{metric.metricValue}</span>
                      </div>
                    ))}
                    {selectedTaskMetrics.length === 0 ? <p className="empty-copy">{t(locale, "noTaskMetrics")}</p> : null}
                  </div>
                </div>
              </div>

              <div className="detail-grid">
                <div>
                  <h3>{t(locale, "logs")}</h3>
                  <div className="stack-list">
                    {selectedTaskLogs.slice(0, 8).map((log) => (
                      <div className="stack-row stack-row--dense" key={log.id}>
                        <div>
                          <strong>{displayLogLevel(locale, log.level)}</strong>
                          <p>{displayLogMessage(locale, log.message)}</p>
                        </div>
                        <span>{new Date(log.createdAt).toLocaleTimeString()}</span>
                      </div>
                    ))}
                    {selectedTaskLogs.length === 0 ? <p className="empty-copy">{t(locale, "noTaskLogs")}</p> : null}
                  </div>
                </div>
              </div>

              <div className="detail-grid">
                <div>
                  <h3>{t(locale, "replayTimeline")}</h3>
                  <div className="timeline-list">
                    {(replay?.timeline ?? []).slice(0, 8).map((event, index) => (
                      <div className={`timeline-item timeline-item--${event.kind}`} key={`${event.timestamp}-${event.label}-${index}`}>
                        <strong>{event.label}</strong>
                        <span>{displayEventKind(locale, event.kind)}</span>
                        <span>{displayStatus(locale, event.status)}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h3>{t(locale, "healingSuggestions")}</h3>
                  <div className="stack-list">
                    {healingSuggestions.slice(0, 5).map((suggestion, index) => (
                      <div className="stack-row stack-row--dense" key={`${suggestion.taskId ?? index}-${suggestion.type}`}>
                        <div>
                          <strong>{displayRemediationLabel(locale, suggestion.type)}</strong>
                          <p>{displayRemediationSummary(locale, suggestion.summary)}</p>
                        </div>
                      </div>
                    ))}
                    {healingSuggestions.length === 0 ? <p className="empty-copy">{t(locale, "noHealingSuggestions")}</p> : null}
                  </div>
                </div>
              </div>

              <div className="inline-status-list">
                {relatedJobs.slice(0, 4).map((job) => (
                  <div className="inline-status" key={job.id}>
                    <strong>{job.jobType}</strong>
                    <span>{displayStatus(locale, job.status)}</span>
                    <span>{job.progress}%</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <p className="empty-copy">{t(locale, "noExecutionCreated")}</p>
          )}
        </SectionCard>
      </div>
    </div>
  );
}
