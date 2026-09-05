/* SPDX-License-Identifier: Apache-2.0 */
import { SectionCard } from "../components/SectionCard";
import { useSelectiveReplayPlans } from "../hooks/useSelectiveReplayPlans";
import { type Locale, t } from "../i18n";
import type { CurrentUser, ReplayPlanRef } from "../lib/api";


type Props = {
  currentUser: CurrentUser | null;
  locale: Locale;
  projectId: string | null;
};

export function SelectiveReplayPlansPage({ currentUser, locale, projectId }: Props) {
  const canRead = currentUser?.capabilities.includes("replay.plan.read") ?? false;
  const view = useSelectiveReplayPlans(projectId, canRead);

  return <div className="page-shell" data-route="/selective-replay-plans">
    <div className="page-toolbar">
      <div><h1>{t(locale, "selectiveReplayPlans")}</h1><p>{t(locale, "selectiveReplayBoundary")}</p></div>
    </div>
    {view.state === "loading" ? <State text={t(locale, "loading")} /> : null}
    {view.state === "unavailable" ? <State text={t(locale, "selectiveReplayProjectUnavailable")} /> : null}
    {view.state === "restricted" ? <State text={t(locale, "selectiveReplayAccessRestricted")} /> : null}
    {view.state === "error" ? <State text={t(locale, "selectiveReplayLoadFailed")} /> : null}
    {view.state === "empty" ? <State text={t(locale, "selectiveReplayEmpty")} /> : null}
    {view.state === "ready" ? <div className="page-columns">
      <SectionCard title={t(locale, "selectiveReplayPlanList")} eyebrow={t(locale, "selectiveReplayBackendAuthority")}>
        <div className="list-stack" role="listbox">
          {view.items.map((item) => <button aria-selected={item.planId === view.selectedId} className="list-row" key={item.planId} onClick={() => view.select(item.planId)} role="option" type="button"><span><strong>{item.status} · {item.riskSummary.overallRisk}</strong><small>{item.algorithmVersion} · {item.selectedTests.length} {t(locale, "selectiveReplayTests")}</small></span><span className="badge-row">{item.fallback.used ? <span className="status-pill">{t(locale, "selectiveReplayFallbackUsed")}</span> : null}<span>{item.validity.state}</span></span></button>)}
        </div>
      </SectionCard>
      <SectionCard title={t(locale, "selectiveReplayPlanDetail")} eyebrow={view.selected?.planHash ?? t(locale, "loading")}>
        {view.selected ? <div className="detail-stack">
          <div className="badge-row"><span className="status-pill">{view.selected.status}</span><span className="status-pill">{view.selected.riskSummary.overallRisk}</span><span className="status-pill">{view.selected.coverageSummary.status}</span></div>
          <p className="technical-id">{view.selected.planId}</p>
          <p>{t(locale, "selectiveReplayCost")}: {view.selected.estimatedCost.selectedTestCount} / {view.selected.estimatedCost.estimatedSeconds}s · {t(locale, "selectiveReplayWithinBudget")}: {String(view.selected.estimatedCost.withinBudget)}</p>
          <h3>{t(locale, "selectiveReplayReasons")}</h3>
          {view.selected.selectionReasons.map((reason) => <article className="notice notice--info" key={reason.code}><strong>{reason.code}</strong><p>{reason.category} · {reason.explanationKey}</p><RefSummary refs={reason.sourceRefs} locale={locale} /></article>)}
          <h3>{t(locale, "selectiveReplayPaths")}</h3>
          {view.selected.selectedPaths.length ? view.selected.selectedPaths.map((path) => <article className="notice notice--info" key={path.pathId}><strong>{path.name} · {path.riskLevel}</strong><p>{path.selectionReasonCodes.join(" · ")}</p></article>) : <p>{t(locale, "none")}</p>}
          <h3>{t(locale, "selectiveReplayTests")}</h3>
          {view.selected.selectedTests.map((test) => <article className="notice notice--info" key={test.testRef}><strong>{test.testRef} · {test.riskLevel}</strong><p>{test.domain} · {test.selectionReasonCodes.join(" · ")} · {test.estimatedSeconds}s</p></article>)}
          <h3>{t(locale, "selectiveReplayUnknown")}</h3>
          {view.selected.unknownAreas.length ? view.selected.unknownAreas.map((item) => <article className="notice notice--warning" key={`${item.code}-${item.areaRef ?? "unknown"}`}><strong>{item.code} · {item.riskLevel}</strong><p>{item.areaRef ?? t(locale, "unknown")}</p></article>) : <p>{t(locale, "none")}</p>}
          {view.selected.fallback.used ? <article className="notice notice--warning"><strong>{t(locale, "selectiveReplayFallbackUsed")}</strong><p>{view.selected.fallback.reasonCodes.join(" · ")}</p><small>{view.selected.fallback.strategy}</small></article> : null}
          <button className="button button--secondary" onClick={() => void view.loadConfirmation()} type="button">{t(locale, "selectiveReplayReviewHandoff")}</button>
          {view.confirmationState === "loading" ? <State text={t(locale, "loading")} /> : null}
          {view.confirmationState === "restricted" ? <State text={t(locale, "selectiveReplayAccessRestricted")} /> : null}
          {view.confirmationState === "error" ? <State text={t(locale, "selectiveReplayConfirmationFailed")} /> : null}
          {view.confirmation ? <article className={`notice ${view.confirmation.canContinue ? "notice--info" : "notice--warning"}`}><strong>{view.confirmation.canContinue ? t(locale, "selectiveReplayHandoffReady") : t(locale, "selectiveReplayHandoffBlocked")}</strong><p>{view.confirmation.nextBoundary} · {view.confirmation.requiredCapability}</p><small>{t(locale, "selectiveReplayConfirmationNoExecution")}</small></article> : null}
        </div> : <State text={t(locale, "loading")} />}
      </SectionCard>
    </div> : null}
  </div>;
}

function RefSummary({ refs, locale }: { refs: ReplayPlanRef[]; locale: Locale }) {
  return <small>{t(locale, "impactEvidenceRefs")}: {refs.map((item) => item.ref).join(", ") || t(locale, "none")}</small>;
}

function State({ text }: { text: string }) {
  return <div className="notice notice--info" role="status">{text}</div>;
}
