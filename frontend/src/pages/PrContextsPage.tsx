/* SPDX-License-Identifier: Apache-2.0 */
import { SectionCard } from "../components/SectionCard";
import { useAdmissionRuns } from "../hooks/useAdmissionRuns";
import { usePrContexts } from "../hooks/usePrContexts";
import { type Locale, t } from "../i18n";
import type { CurrentUser } from "../lib/api";


type Props = {
  currentUser: CurrentUser | null;
  locale: Locale;
  projectId: string | null;
};

export function PrContextsPage({ currentUser, locale, projectId }: Props) {
  const canRead = currentUser?.capabilities.includes("pr.read") ?? false;
  const view = usePrContexts(projectId, canRead);
  const canReadAdmission = currentUser?.capabilities.includes("admission.read") ?? false;
  const admission = useAdmissionRuns(projectId, view.detail?.context.versionId ?? null, canReadAdmission);

  return <div className="page-shell" data-route="/pr-contexts">
    <div className="page-toolbar">
      <div><h1>{t(locale, "prContexts")}</h1><p>{t(locale, "prContextBoundary")}</p></div>
    </div>
    {view.state === "loading" ? <State text={t(locale, "loading")} /> : null}
    {view.state === "unavailable" ? <State text={t(locale, "prContextProjectUnavailable")} /> : null}
    {view.state === "restricted" ? <State text={t(locale, "prContextAccessRestricted")} /> : null}
    {view.state === "error" ? <State text={t(locale, "prContextLoadFailed")} /> : null}
    {view.state === "empty" ? <State text={t(locale, "prContextEmpty")} /> : null}
    {view.state === "ready" ? <div className="page-columns">
      <SectionCard title={t(locale, "prContextList")} eyebrow={t(locale, "prContextProviderNeutral")}>
        <div className="list-stack" role="listbox">
          {view.items.map((item) => <button aria-selected={item.contextId === view.selectedId} className="list-row" key={item.contextId} onClick={() => view.select(item.contextId)} role="option" type="button"><span><strong>{item.provider} #{item.pullRequestNumber}</strong><small>{item.repositoryRef}</small></span><span className="badge-row"><span className="status-pill">{item.state}</span><span>v{item.latestVersion}</span></span></button>)}
        </div>
      </SectionCard>
      <SectionCard title={t(locale, "prContextDetail")} eyebrow={view.detail?.context.contextHash ?? t(locale, "loading")}>
        {view.detail ? <div className="detail-stack">
          <div className="badge-row"><span className="status-pill">{view.detail.context.state}</span><span className="status-pill">{view.detail.context.draft ? t(locale, "prContextDraft") : t(locale, "prContextReady")}</span>{view.detail.context.fork ? <span className="status-pill">{t(locale, "prContextFork")}</span> : null}</div>
          <p className="technical-id">{view.detail.context.versionId}</p>
          <p>{view.detail.context.repositoryRef} #{view.detail.context.pullRequestNumber}</p>
          <p>{t(locale, "prContextRevision")}: <code>{view.detail.context.revision.baseSha}</code> -&gt; <code>{view.detail.context.revision.headSha}</code></p>
          <p>{t(locale, "prContextChangedFiles")}: {view.detail.context.changedFiles.length}</p>
          <h3>{t(locale, "requirementMatchStatus")}</h3>
          {view.detail.requirementMatch ? <div className="detail-stack">
            <div className="badge-row"><span className="status-pill">{view.detail.requirementMatch.status}</span>{view.detail.requirementMatch.reviewRequired ? <span className="status-pill">{t(locale, "requirementMatchReviewRequired")}</span> : null}</div>
            {view.detail.requirementMatch.explicitUnknownRefs.length ? <article className="notice notice--warning"><strong>{t(locale, "requirementMatchUnknownRefs")}</strong><p>{view.detail.requirementMatch.explicitUnknownRefs.join(", ")}</p></article> : null}
            {view.detail.requirementMatch.matches.map((match) => <article className={match.candidate.status === "confirmed" ? "notice notice--info" : "notice notice--warning"} key={match.matchId}><strong>{match.candidate.requirementId} {"\u00b7"} {match.candidate.status}</strong><p>{match.candidate.source} {"\u00b7"} {Math.round(match.candidate.confidence * 100)}%</p><small>{match.candidate.reasons.map((reason) => reason.code).join(", ")}</small></article>)}
          </div> : <State text={t(locale, "requirementMatchUnavailable")} />}
          <h3>{t(locale, "admissionEvidence")}</h3>
          {admission.state === "loading" ? <State text={t(locale, "loading")} /> : null}
          {admission.state === "restricted" ? <State text={t(locale, "admissionEvidenceRestricted")} /> : null}
          {admission.state === "error" ? <State text={t(locale, "admissionEvidenceLoadFailed")} /> : null}
          {admission.state === "empty" || admission.state === "unavailable" ? <State text={t(locale, "admissionEvidenceEmpty")} /> : null}
          {admission.state === "ready" ? <div className="detail-stack">
            {admission.items.map((run) => <article className={run.status === "completed" ? "notice notice--info" : "notice notice--warning"} key={run.admissionRunId}>
              <div className="badge-row"><strong>{t(locale, "admissionRun")}</strong><span className="status-pill">{run.mode}</span><span className="status-pill">{run.status}</span><span className="status-pill">{run.sandboxProfile.profileId}</span></div>
              <p>{t(locale, "admissionStaticScan")}: {run.staticScan?.status ?? t(locale, "unavailable")} {"·"} {t(locale, "admissionSmoke")}: {run.smokeResult?.status ?? t(locale, "unavailable")}</p>
              <small>{t(locale, "admissionNormalizedFindings")}: {(run.staticScan?.normalizedFindingRefs.length ?? 0) + (run.smokeResult?.normalizedFindingRefs.length ?? 0)} {"·"} {t(locale, "admissionArtifacts")}: {(run.staticScan?.artifactRefs.length ?? 0) + (run.smokeResult?.artifactRefs.length ?? 0)}</small>
            </article>)}
          </div> : null}
          <div className="notice notice--info">{t(locale, "prContextDecisionBoundary")}</div>
        </div> : <State text={t(locale, "loading")} />}
      </SectionCard>
    </div> : null}
  </div>;
}

function State({ text }: { text: string }) {
  return <div className="notice notice--info" role="status">{text}</div>;
}
