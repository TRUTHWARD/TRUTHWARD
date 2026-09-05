/* SPDX-License-Identifier: Apache-2.0 */
import { SectionCard } from "../components/SectionCard";
import { Locale, t } from "../i18n";
import type { RuntimeReadiness, RuntimeReadinessStatus } from "../lib/api";
import { displayRuntimeItemLabel, displayRuntimeItemSummary, displayStatus } from "../lib/presentation";
import { JobItem } from "../store/platform";

type JobsPageProps = {
  locale: Locale;
  jobs: JobItem[];
  selectedJobId: string | null;
  onSelectJob: (jobId: string) => void;
  runtimeReadiness: RuntimeReadiness | null;
};

export function JobsPage({ locale, jobs, selectedJobId, onSelectJob, runtimeReadiness }: JobsPageProps) {
  const selectedJob = jobs.find((job) => job.id === selectedJobId) ?? jobs[0] ?? null;
  const activeJobs = jobs.filter((job) => job.status === "queued" || job.status === "running");
  const queueRuntime = runtimeReadiness?.categories.find((category) => category.id === "queue-runtime") ?? null;
  const separator = t(locale, "valueSeparator");

  return (
    <div className="page-shell" data-route="/queue-jobs">
      <div className="page-columns page-columns--queue-jobs">
        <SectionCard title={t(locale, "queueJobs")} eyebrow={t(locale, "asyncControl")}>
          <div className="stats-grid stats-grid--compact">
            <div className="stat-tile">
              <span>{t(locale, "total")}</span>
              <strong>{jobs.length}</strong>
            </div>
            <div className="stat-tile">
              <span>{t(locale, "activeJobs")}</span>
              <strong>{activeJobs.length}</strong>
            </div>
            <div className="stat-tile">
              <span>{t(locale, "failed")}</span>
              <strong>{jobs.filter((job) => job.status === "failed").length}</strong>
            </div>
          </div>

          <div className="detail-stack">
            <div className="inline-status">
              <strong>{t(locale, "queueRuntimeReadiness")}</strong>
              <span className={queueRuntime ? classForRuntimeReadinessStatus(queueRuntime.status) : "status-pill status-pill--unknown"}>
                {queueRuntime ? t(locale, labelForRuntimeReadinessStatus(queueRuntime.status)) : t(locale, "runtimeReadinessUnavailable")}
              </span>
            </div>
            <div className="stack-list">
              {(queueRuntime?.items ?? []).map((item) => (
                <div className="stack-row stack-row--dense" key={item.id}>
                  <div>
                    <strong>{displayRuntimeItemLabel(locale, item)}</strong>
                    <p>{displayRuntimeItemSummary(locale, item)}</p>
                  </div>
                  <span className={classForRuntimeReadinessStatus(item.status)}>{t(locale, labelForRuntimeReadinessStatus(item.status))}</span>
                </div>
              ))}
              {!queueRuntime ? <p className="empty-copy">{t(locale, "runtimeReadinessUnavailable")}</p> : null}
            </div>
          </div>

          <div className="stack-list">
            {jobs.map((job) => (
              <button
                className={`stack-row stack-row--button ${job.id === selectedJob?.id ? "stack-row--selected" : ""}`}
                key={job.id}
                onClick={() => onSelectJob(job.id)}
                type="button"
              >
                <div>
                  <strong>{job.jobType}</strong>
                  <p>{job.id.slice(0, 8)}</p>
                </div>
                <span>{displayStatus(locale, job.status)} {separator} {job.progress}%</span>
              </button>
            ))}
          </div>
        </SectionCard>

        <SectionCard title={selectedJob ? `${t(locale, "jobPrefix")} ${selectedJob.id.slice(0, 8)}` : t(locale, "jobDetail")} eyebrow={t(locale, "selectedJob")}>
          {selectedJob ? (
            <div className="detail-stack">
              <div className="detail-banner">
                <div>
                  <strong>{selectedJob.jobType}</strong>
                  <p>{displayStatus(locale, selectedJob.status)}</p>
                </div>
                <span>{selectedJob.progress}%</span>
              </div>

              <div className="progress-bar">
                <div className="progress-bar__value" style={{ width: `${selectedJob.progress}%` }} />
              </div>

              <div className="detail-grid">
                <div>
                  <h3>{t(locale, "payload")}</h3>
                  <pre className="json-preview">{JSON.stringify(selectedJob.payload, null, 2)}</pre>
                </div>
                <div>
                  <h3>{t(locale, "result")}</h3>
                  <pre className="json-preview">{JSON.stringify(selectedJob.result, null, 2)}</pre>
                </div>
              </div>

              <div className="inline-status-list">
                <div className="inline-status">
                  <strong>{t(locale, "resultRef")}</strong>
                  <span>{selectedJob.resultRef ?? t(locale, "none")}</span>
                </div>
                <div className="inline-status">
                  <strong>{t(locale, "started")}</strong>
                  <span>{selectedJob.startedAt ? new Date(selectedJob.startedAt).toLocaleString() : t(locale, "pending")}</span>
                </div>
                <div className="inline-status">
                  <strong>{t(locale, "ended")}</strong>
                  <span>{selectedJob.endedAt ? new Date(selectedJob.endedAt).toLocaleString() : t(locale, "pending")}</span>
                </div>
              </div>

              {selectedJob.errorMessage ? (
                <div className="error-banner">
                  <strong>{t(locale, "errorState")}</strong>
                  <p>{selectedJob.errorMessage}</p>
                </div>
              ) : null}
            </div>
          ) : (
            <p className="empty-copy">{t(locale, "noJobsRecorded")}</p>
          )}
        </SectionCard>
      </div>
    </div>
  );
}

function labelForRuntimeReadinessStatus(status: RuntimeReadinessStatus): Parameters<typeof t>[1] {
  if (status === "local_passed") {
    return "localPassed";
  }
  if (status === "deployment_specific_not_validated") {
    return "deploymentSpecificNotValidated";
  }
  if (status === "missing_dependency") {
    return "missingDependency";
  }
  if (status === "not_configured") {
    return "notConfigured";
  }
  if (status === "unavailable") {
    return "unavailable";
  }
  return "unknown";
}

function classForRuntimeReadinessStatus(status: RuntimeReadinessStatus) {
  if (status === "local_passed") {
    return "status-pill status-pill--covered";
  }
  if (status === "deployment_specific_not_validated" || status === "not_configured") {
    return "status-pill status-pill--partial";
  }
  return "status-pill status-pill--unknown";
}
