/* SPDX-License-Identifier: Apache-2.0 */
import { SectionCard } from "../components/SectionCard";
import { CoverageReadinessPanel } from "../components/CoverageReadinessPanel";
import { EvidenceReferenceList } from "../components/EvidenceReferenceList";
import { useSelectiveReplayPlans } from "../hooks/useSelectiveReplayPlans";
import { type Locale, t } from "../i18n";
import type { CurrentUser, ReplayPlanRef } from "../lib/api";
import { displayDomainLabel, displayReasonCode, displayStatus } from "../lib/presentation";


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
    {view.state === "error" ? <State text={t(locale, "selectiveReplayLoadFailed")} tone="error" /> : null}
    {view.state === "empty" ? <>
      <State text={t(locale, "selectiveReplayEmpty")} />
    </> : null}
    {view.state === "empty" || view.state === "ready" ? <CoverageReadinessPanel canRead={currentUser?.capabilities.includes("coverage.read") ?? false} focusStage="selective_replay" locale={locale} onMaterialized={view.reload} projectId={projectId} /> : null}
    {view.state === "ready" ? <div className="page-columns">
      <SectionCard title={t(locale, "selectiveReplayPlanList")} eyebrow={t(locale, "selectiveReplayBackendAuthority")}>
        <div className="list-stack" role="listbox">
          {view.items.map((item) => <button aria-selected={item.planId === view.selectedId} className="list-row" key={item.planId} onClick={() => view.select(item.planId)} role="option" type="button"><span><strong>{planStatus(locale, item.status)} · {displayStatus(locale, item.riskSummary.overallRisk)}</strong><small>{item.algorithmVersion} · {item.selectedTests.length} {t(locale, "selectiveReplayTests")}</small></span><span className="badge-row">{item.fallback.used ? <span className="status-pill">{t(locale, "selectiveReplayConservativeSelection")}</span> : null}<span>{displayStatus(locale, item.validity.state)}</span></span></button>)}
        </div>
      </SectionCard>
      <SectionCard title={t(locale, "selectiveReplayPlanDetail")} eyebrow={view.selected?.planHash ?? t(locale, "loading")}>
        {view.selected ? <div className="detail-stack">
          <div className="badge-row"><span className="status-pill">{planStatus(locale, view.selected.status)}</span><span className="status-pill">{displayStatus(locale, view.selected.riskSummary.overallRisk)}</span><span className="status-pill">{displayStatus(locale, view.selected.coverageSummary.status)}</span><span className="status-pill">{t(locale, "selectiveReplayNoExecution")}</span></div>
          {view.selected.validity.requiresRegeneration ? <div className="notice notice--warning">{t(locale, "selectiveReplayRegenerate")}</div> : null}
          <p className="technical-id">{view.selected.planId}</p>
          <p>{t(locale, "selectiveReplayCost")}: {view.selected.estimatedCost.selectedTestCount} / {view.selected.estimatedCost.estimatedSeconds}s · {t(locale, "selectiveReplayWithinBudget")}: {String(view.selected.estimatedCost.withinBudget)}</p>
          <h3>{t(locale, "selectiveReplayReasons")}</h3>
          {view.selected.selectionReasons.map((reason) => <article className="notice notice--info" key={reason.code}><strong>{displayReasonCode(locale, reason.code)}</strong><p>{selectionReasonExplanation(locale, reason.code)}</p><span className="status-pill">{displayStatus(locale, reason.category)}</span><RefSummary refs={reason.sourceRefs} locale={locale} /><details className="reason-technical-details"><summary>{t(locale, "technicalDetails")}</summary><dl><div><dt>{t(locale, "selectiveReplayReasonCode")}</dt><dd><code>{reason.code}</code></dd></div><div><dt>{t(locale, "selectiveReplayExplanationKey")}</dt><dd><code>{reason.explanationKey}</code></dd></div><div><dt>{t(locale, "category")}</dt><dd>{reason.category}</dd></div><div><dt>{t(locale, "priority")}</dt><dd>{reason.priority}</dd></div><div><dt>{t(locale, "evidenceRefs")}</dt><dd>{reason.sourceRefs.length}</dd></div></dl></details></article>)}
          <h3>{t(locale, "selectiveReplayPaths")}</h3>
          {view.selected.selectedPaths.length ? view.selected.selectedPaths.map((path) => <article className="notice notice--info" key={path.pathId}><strong>{path.name} · {displayStatus(locale, path.riskLevel)}</strong><p>{path.selectionReasonCodes.map((code) => displayReasonCode(locale, code)).join(" · ")}</p><EvidenceReferenceList refs={path.evidenceRefs} locale={locale} /></article>) : <p>{t(locale, "none")}</p>}
          <h3>{t(locale, "selectiveReplayTests")}</h3>
          {view.selected.selectedTests.map((test) => <article className="notice notice--info" key={test.testRef}><strong>{readableRef(test.testRef)} · {displayStatus(locale, test.riskLevel)}</strong><p>{displayDomainLabel(locale, test.domain)} · {test.selectionReasonCodes.map((code) => displayReasonCode(locale, code)).join(" · ")} · {test.estimatedSeconds}s</p><EvidenceReferenceList refs={test.evidenceRefs} locale={locale} /></article>)}
          <h3>{t(locale, "selectiveReplayUnknown")}</h3>
          {view.selected.unknownAreas.length ? view.selected.unknownAreas.map((item) => <article className="notice notice--warning" key={`${item.code}-${item.areaRef ?? "unknown"}`}><strong>{displayReasonCode(locale, item.code)} · {displayStatus(locale, item.riskLevel)}</strong><p>{item.areaRef ? readableRef(item.areaRef) : t(locale, "unknown")}</p><EvidenceReferenceList refs={item.sourceRefs} locale={locale} /></article>) : <p>{t(locale, "none")}</p>}
          {view.selected.fallback.used ? <article className="notice notice--warning"><strong>{t(locale, "selectiveReplayConservativeSelection")}</strong><p>{view.selected.fallback.reasonCodes.map((code) => displayReasonCode(locale, code)).join(" · ")}</p><small>{displayStatus(locale, view.selected.fallback.strategy)}</small>{view.selected.fallback.sourcePlanRef ? <EvidenceReferenceList refs={[view.selected.fallback.sourcePlanRef]} locale={locale} /> : null}</article> : null}
          {currentUser?.edition === "community" ? <div className="notice notice--info">{t(locale, "selectiveReplayOssExecutionUnavailable")}</div> : null}
          <button className="button button--secondary" onClick={() => void view.loadConfirmation()} type="button">{t(locale, "selectiveReplayReviewHandoff")}</button>
          {view.confirmationState === "loading" ? <State text={t(locale, "loading")} /> : null}
          {view.confirmationState === "restricted" ? <State text={t(locale, "selectiveReplayAccessRestricted")} /> : null}
          {view.confirmationState === "error" ? <State text={t(locale, "selectiveReplayConfirmationFailed")} tone="error" /> : null}
          {view.confirmation ? <article className={`notice ${view.confirmation.canContinue ? "notice--info" : "notice--warning"}`}><strong>{view.confirmation.canContinue ? t(locale, "selectiveReplayHandoffReady") : t(locale, "selectiveReplayHandoffBlocked")}</strong><p>{view.confirmation.nextBoundary} · {view.confirmation.requiredCapability}</p><small>{t(locale, "selectiveReplayConfirmationNoExecution")}</small></article> : null}
        </div> : <State text={t(locale, "loading")} />}
      </SectionCard>
    </div> : null}
  </div>;
}

function RefSummary({ refs, locale }: { refs: ReplayPlanRef[]; locale: Locale }) {
  return <EvidenceReferenceList label={t(locale, "impactEvidenceRefs")} refs={refs} locale={locale} />;
}

function planStatus(locale: Locale, status: "ready" | "fallback") {
  return status === "fallback" ? t(locale, "selectiveReplayConservativeSelection") : displayStatus(locale, status);
}

function selectionReasonExplanation(locale: Locale, code: string) {
  const keys: Record<string, Parameters<typeof t>[1]> = {
    DIRECT_IMPACT: "selectiveReplayReasonDirectImpact",
    DEPENDENCY_PROPAGATION: "selectiveReplayReasonDependencyPropagation",
    HIGH_RISK_NEIGHBORHOOD: "selectiveReplayReasonHighRiskNeighborhood",
    HISTORICAL_FAILURE: "selectiveReplayReasonHistoricalFailure",
    OPEN_FINDING: "selectiveReplayReasonOpenFinding",
    REQUIREMENT_CHANGE: "selectiveReplayReasonRequirementChange",
    SMOKE_BASELINE: "selectiveReplayReasonSmokeBaseline",
    CONSERVATIVE_FALLBACK: "selectiveReplayReasonConservativeFallback",
  };
  return keys[code] ? t(locale, keys[code]) : displayReasonCode(locale, code);
}

function readableRef(value: string) {
  const identifier = value.match(/^[a-z][a-z0-9+._-]*:\/\/(.+)$/i)?.[1] ?? value;
  return identifier.replaceAll("_", " ");
}

function State({ text, tone = "info" }: { text: string; tone?: "info" | "error" }) {
  return <div className={`notice notice--${tone}`} role={tone === "error" ? "alert" : "status"}>{text}</div>;
}
