/* SPDX-License-Identifier: Apache-2.0 */
import { SectionCard } from "../components/SectionCard";
import { useImpactResults } from "../hooks/useImpactResults";
import { type Locale, t } from "../i18n";
import type { CurrentUser, ImpactPropagationStep, ImpactRef } from "../lib/api";


type Props = {
  currentUser: CurrentUser | null;
  locale: Locale;
  projectId: string | null;
};

export function ImpactAnalysisPage({ currentUser, locale, projectId }: Props) {
  const canRead = currentUser?.capabilities.includes("impact.read") ?? false;
  const view = useImpactResults(projectId, canRead);

  return (
    <div className="page-shell" data-route="/impact-analysis">
      <div className="page-toolbar">
        <div>
          <h1>{t(locale, "impactAnalysis")}</h1>
          <p>{t(locale, "impactBoundary")}</p>
        </div>
        <div className="badge-row">
          <span className="status-pill">{t(locale, "impactEvidenceBacked")}</span>
          {view.backendComputed ? <span className="status-pill">{t(locale, "impactBackendOnly")}</span> : null}
        </div>
      </div>

      {view.state === "loading" ? <State text={t(locale, "loading")} /> : null}
      {view.state === "unavailable" ? <State text={t(locale, "impactProjectUnavailable")} /> : null}
      {view.state === "restricted" ? <State text={t(locale, "impactAccessRestricted")} /> : null}
      {view.state === "error" ? <State text={t(locale, "impactLoadFailed")} /> : null}
      {view.state === "empty" ? <State text={t(locale, "impactEmpty")} /> : null}

      {view.state === "ready" ? <div className="page-columns">
        <SectionCard title={t(locale, "impactResultList")} eyebrow={t(locale, "impactBackendOnly")}>
          <div className="list-stack" role="listbox">
            {view.items.map((item) => <button aria-selected={item.impactResultId === view.selectedId} className="list-row" key={item.impactResultId} onClick={() => view.select(item.impactResultId)} role="option" type="button"><span><strong>{item.status} · {item.riskLevel}</strong><small>{item.algorithmVersion} · {formatConfidence(item.confidence)}</small></span><span className="badge-row">{item.reviewRequired ? <span className="status-pill">{t(locale, "impactReviewRequired")}</span> : null}<span>{item.impactedCapabilities.length}/{item.impactedTests.length}</span></span></button>)}
          </div>
        </SectionCard>

        <SectionCard title={t(locale, "impactResultDetail")} eyebrow={view.selected?.graphStaleness ?? t(locale, "loading")}>
          {view.selected ? <div className="detail-stack">
            <div className="badge-row"><span className="status-pill">{view.selected.status}</span><span className="status-pill">{view.selected.riskLevel}</span><span className="status-pill">{formatConfidence(view.selected.confidence)}</span></div>
            <p className="technical-id">{view.selected.impactResultId}</p>
            <p>{t(locale, "impactGraphState")}: <code>{view.selected.graphStaleness}</code> · {t(locale, "impactVisitedNodes")}: {view.selected.visitedNodeCount}</p>
            <ProjectionGroup title={t(locale, "impactCapabilities")} items={view.selected.impactedCapabilities.map((item) => ({ key: item.entityRef, label: item.label ?? item.entityRef, meta: `${item.mappingSource} · ${item.riskLevel} · ${formatConfidence(item.confidence)}`, refs: item.evidenceRefs, path: item.propagationPath }))} locale={locale} />
            <ProjectionGroup title={t(locale, "impactPaths")} items={view.selected.impactedPaths.map((item) => ({ key: item.pathId, label: item.name, meta: `${item.riskLevel} · ${formatConfidence(item.confidence)}`, refs: item.evidenceRefs, path: item.propagationPath }))} locale={locale} />
            <ProjectionGroup title={t(locale, "impactTests")} items={view.selected.impactedTests.map((item) => ({ key: item.testRef, label: item.testRef, meta: `${item.testKind ?? t(locale, "unknown")} · ${item.riskLevel} · ${formatConfidence(item.confidence)}`, refs: item.evidenceRefs, path: item.propagationPath }))} locale={locale} />
            <h3>{t(locale, "impactUnknownAreas")}</h3>
            {view.selected.unknownAreas.length ? view.selected.unknownAreas.map((item) => <article className="notice notice--warning" key={`${item.code}-${item.areaRef ?? "unknown"}`}><strong>{item.code} · {item.riskLevel}</strong><p>{item.areaRef ?? t(locale, "unknown")}</p><RefSummary refs={item.evidenceRefs} locale={locale} /></article>) : <p>{t(locale, "none")}</p>}
            <h3>{t(locale, "impactFallbacks")}</h3>
            {view.selected.recommendedFallbacks.map((item) => <article className="notice notice--warning" key={item.code}><strong>{item.code}</strong><p>{item.reason}</p><small>{item.recommendedAction}</small></article>)}
            {view.selected.aiSuggestions.length ? <><h3>{t(locale, "impactAiSuggestions")}</h3>{view.selected.aiSuggestions.map((item) => <article className="notice notice--warning" key={`${item.sourceEntityRef}-${item.suggestedCapabilityRef}`}><strong>{t(locale, "impactSuggestionOnly")} · {formatConfidence(item.confidence)}</strong><p>{item.suggestedCapabilityRef}</p><small>{item.rationale}</small></article>)}</> : null}
          </div> : <State text={t(locale, "loading")} />}
        </SectionCard>
      </div> : null}
    </div>
  );
}

function ProjectionGroup({ title, items, locale }: { title: string; items: Array<{ key: string; label: string; meta: string; refs: ImpactRef[]; path: ImpactPropagationStep[] }>; locale: Locale }) {
  return <div><h3>{title}</h3>{items.length ? items.map((item) => <article className="notice notice--info" key={item.key}><strong>{item.label}</strong><p>{item.meta}</p><p>{t(locale, "impactPropagation")}: {item.path.map((step) => `${step.entityType}:${step.viaRelation ?? "seed"}`).join(" → ")}</p><RefSummary refs={item.refs} locale={locale} /></article>) : <p>{t(locale, "none")}</p>}</div>;
}

function RefSummary({ refs, locale }: { refs: ImpactRef[]; locale: Locale }) {
  return <small>{t(locale, "impactEvidenceRefs")}: {refs.map((item) => item.ref).join(", ") || t(locale, "none")}</small>;
}

function State({ text }: { text: string }) {
  return <div className="notice notice--info" role="status">{text}</div>;
}

function formatConfidence(value: number) {
  return `${Math.round(value * 100)}%`;
}
