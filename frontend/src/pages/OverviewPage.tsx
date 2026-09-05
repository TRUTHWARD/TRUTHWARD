/* SPDX-License-Identifier: Apache-2.0 */
import { SectionCard } from "../components/SectionCard";
import { Locale, t } from "../i18n";
import { ExecutionItem, HealthItem, JobItem, ModelItem } from "../store/platform";

type OverviewPageProps = {
  locale: Locale;
  health: HealthItem[];
  models: ModelItem[];
  executions: ExecutionItem[];
  jobs: JobItem[];
  guardrailSummary: { allow: number; warn: number; block: number };
};

export function OverviewPage({ locale, health, models, executions, jobs, guardrailSummary }: OverviewPageProps) {
  const activeJobs = jobs.filter((job) => job.status === "queued" || job.status === "running");
  const blockedExecutions = executions.filter((execution) => execution.summary.security === "failed").length;
  const separator = t(locale, "valueSeparator");

  return (
    <div className="page-shell" data-route="/">
      <SectionCard title={t(locale, "programSnapshot")} eyebrow={t(locale, "overview")}>
        <div className="stats-grid">
          <div className="stat-tile">
            <span>{t(locale, "services")}</span>
            <strong>{health.length}</strong>
            <p>{health.filter((item) => item.status === "healthy").length} {t(locale, "healthyRightNow")}</p>
          </div>
          <div className="stat-tile">
            <span>{t(locale, "models")}</span>
            <strong>{models.length}</strong>
            <p>{models.filter((item) => item.enabled).length} {t(locale, "enabledForRouting")}</p>
          </div>
          <div className="stat-tile">
            <span>{t(locale, "executions")}</span>
            <strong>{executions.length}</strong>
            <p>{blockedExecutions} {t(locale, "blockingSecurityOutcome")}</p>
          </div>
          <div className="stat-tile">
            <span>{t(locale, "activeQueue")}</span>
            <strong>{activeJobs.length}</strong>
            <p>{guardrailSummary.block} {t(locale, "guardrailBlocksRecorded")}</p>
          </div>
        </div>
      </SectionCard>

      <div className="page-columns page-columns--overview">
        <SectionCard title={t(locale, "serviceHealth")} eyebrow={t(locale, "runtime")}>
          <div className="pill-grid">
            {health.map((item) => (
              <div className="pill" key={item.name}>
                <strong>{item.name}</strong>
                <span>{item.status}</span>
              </div>
            ))}
          </div>
        </SectionCard>

        <SectionCard title={t(locale, "activeQueue")} eyebrow={t(locale, "jobs")}>
          <div className="stack-list">
            {activeJobs.slice(0, 5).map((job) => (
              <div className="stack-row" key={job.id}>
                <div>
                  <strong>{job.jobType}</strong>
                  <p>{job.id.slice(0, 8)}</p>
                </div>
                <span>{job.status} {separator} {job.progress}%</span>
              </div>
            ))}
            {activeJobs.length === 0 ? <p className="empty-copy">{t(locale, "noActiveJobs")}</p> : null}
          </div>
        </SectionCard>
      </div>

      <SectionCard title={t(locale, "latestExecutions")} eyebrow={t(locale, "flow")}>
        <div className="stack-list">
          {executions.slice(0, 6).map((execution) => (
            <div className="stack-row" key={execution.id}>
              <div>
                <strong>{execution.id.slice(0, 8)}</strong>
                <p>{execution.environment} {separator} {execution.summary.functional ?? "queued"} {separator} {execution.summary.performance ?? "queued"} {separator} {execution.summary.security ?? "queued"}</p>
              </div>
              <span>{execution.status} {separator} {execution.stage}</span>
            </div>
          ))}
        </div>
      </SectionCard>
    </div>
  );
}
