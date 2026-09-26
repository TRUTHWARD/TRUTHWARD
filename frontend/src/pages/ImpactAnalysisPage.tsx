/* SPDX-License-Identifier: Apache-2.0 */
import { SectionCard } from "../components/SectionCard";
import { CoverageReadinessPanel } from "../components/CoverageReadinessPanel";
import { EvidenceReferenceList } from "../components/EvidenceReferenceList";
import { useImpactResults } from "../hooks/useImpactResults";
import { type Locale, t } from "../i18n";
import type { CurrentUser, ImpactPropagationStep, ImpactRef } from "../lib/api";
import { displayReasonCode, displayStatus } from "../lib/presentation";


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
      {view.state === "error" ? <State text={t(locale, "impactLoadFailed")} tone="error" /> : null}
      {view.state === "empty" ? <>
        <State text={t(locale, "impactEmpty")} />
      </> : null}
      {view.state === "empty" || view.state === "ready" ? <CoverageReadinessPanel canRead={currentUser?.capabilities.includes("coverage.read") ?? false} focusStage="impact" locale={locale} onMaterialized={view.reload} projectId={projectId} /> : null}

      {view.state === "ready" ? <div className="page-columns">
        <SectionCard title={t(locale, "impactResultList")} eyebrow={t(locale, "impactBackendOnly")}>
          <div className="list-stack" role="listbox">
            {view.items.map((item) => <button aria-selected={item.impactResultId === view.selectedId} className="list-row" key={item.impactResultId} onClick={() => view.select(item.impactResultId)} role="option" type="button"><span><strong>{displayStatus(locale, item.status)} · {displayStatus(locale, item.riskLevel)}</strong><small>{item.algorithmVersion} · {formatConfidence(item.confidence)}</small></span><span className="badge-row">{item.reviewRequired ? <span className="status-pill">{t(locale, "impactReviewRequired")}</span> : null}<span>{item.impactedCapabilities.length}/{item.impactedTests.length}</span></span></button>)}
          </div>
        </SectionCard>

        <SectionCard title={t(locale, "impactResultDetail")} eyebrow={view.selected ? displayStatus(locale, view.selected.graphStaleness) : t(locale, "loading")}>
          {view.selected ? <div className="detail-stack">
            <div className="badge-row"><span className={`status-pill status-pill--${view.selected.status}`}>{displayStatus(locale, view.selected.status)}</span><span className={`status-pill status-pill--${view.selected.riskLevel}`}>{displayStatus(locale, view.selected.riskLevel)}</span><span className="status-pill">{formatConfidence(view.selected.confidence)}</span></div>
            <p className="technical-id">{view.selected.impactResultId}</p>
            <p>{t(locale, "impactGraphState")}: {displayStatus(locale, view.selected.graphStaleness)} · {t(locale, "impactVisitedNodes")}: {view.selected.visitedNodeCount}</p>
            <EvidenceReferenceList label={t(locale, "evidenceSourceReferences")} refs={view.selected.changeSetRefs} locale={locale} />
            <ProjectionGroup title={t(locale, "impactCapabilities")} items={view.selected.impactedCapabilities.map((item) => ({ key: item.entityRef, label: item.label ?? readableRef(item.entityRef), meta: `${displayStatus(locale, item.mappingSource)} · ${displayStatus(locale, item.riskLevel)} · ${formatConfidence(item.confidence)}`, refs: item.evidenceRefs, path: item.propagationPath }))} locale={locale} />
            <ProjectionGroup title={t(locale, "impactPaths")} items={view.selected.impactedPaths.map((item) => ({ key: item.pathId, label: item.name, meta: `${displayStatus(locale, item.riskLevel)} · ${formatConfidence(item.confidence)}`, refs: item.evidenceRefs, path: item.propagationPath }))} locale={locale} />
            <ProjectionGroup title={t(locale, "impactTests")} items={view.selected.impactedTests.map((item) => ({ key: item.testRef, label: readableRef(item.testRef), meta: `${item.testKind ? displayStatus(locale, item.testKind) : t(locale, "unknown")} · ${displayStatus(locale, item.riskLevel)} · ${formatConfidence(item.confidence)}`, refs: item.evidenceRefs, path: item.propagationPath }))} locale={locale} />
            <h3>{t(locale, "impactUnknownAreas")}</h3>
            {view.selected.unknownAreas.length ? view.selected.unknownAreas.map((item) => <article className="notice notice--warning" key={`${item.code}-${item.areaRef ?? "unknown"}`}><strong>{displayReasonCode(locale, item.code)} · {displayStatus(locale, item.riskLevel)}</strong><p>{item.areaRef ? readableRef(item.areaRef) : t(locale, "unknown")}</p><RefSummary refs={item.evidenceRefs} locale={locale} /><details className="reason-technical-details"><summary>{t(locale, "technicalDetails")}</summary><code>{item.code}</code><code>{item.messageKey}</code></details></article>) : <p>{t(locale, "none")}</p>}
            <h3>{t(locale, "impactFallbacks")}</h3>
            {view.selected.recommendedFallbacks.map((item) => <article className="notice notice--warning" key={item.code}><strong>{displayReasonCode(locale, item.code)}</strong><p>{item.reason}</p><small>{displayReasonCode(locale, item.recommendedAction)}</small></article>)}
            {view.selected.aiSuggestions.length ? <><h3>{t(locale, "impactAiSuggestions")}</h3>{view.selected.aiSuggestions.map((item) => <article className="notice notice--warning" key={`${item.sourceEntityRef}-${item.suggestedCapabilityRef}`}><strong>{t(locale, "impactSuggestionOnly")} · {formatConfidence(item.confidence)}</strong><p>{item.suggestedCapabilityRef}</p><small>{item.rationale}</small></article>)}</> : null}
          </div> : <State text={t(locale, "loading")} />}
        </SectionCard>
      </div> : null}
    </div>
  );
}

function ProjectionGroup({ title, items, locale }: { title: string; items: Array<{ key: string; label: string; meta: string; refs: ImpactRef[]; path: ImpactPropagationStep[] }>; locale: Locale }) {
  return <div><h3>{title}</h3>{items.length ? items.map((item) => <article className="notice notice--info" key={item.key}><strong>{item.label}</strong><p>{item.meta}</p><p>{t(locale, "impactPropagation")}: {item.path.map((step) => formatPropagationStep(locale, step)).join(" → ")}</p><RefSummary refs={item.refs} locale={locale} /></article>) : <p>{t(locale, "none")}</p>}</div>;
}

function RefSummary({ refs, locale }: { refs: ImpactRef[]; locale: Locale }) {
  return <EvidenceReferenceList label={t(locale, "impactEvidenceRefs")} refs={refs} locale={locale} />;
}

function formatPropagationStep(locale: Locale, step: ImpactPropagationStep) {
  const zhTerms: Record<string, string> = { requirement: "需求", capability: "能力", path: "路径", test: "测试", seed: "起点", depends_on: "依赖", forward: "正向", reverse: "反向", mapping: "映射" };
  const entity = locale === "zh-CN" ? zhTerms[step.entityType] ?? step.entityType : displayStatus(locale, step.entityType);
  const relation = step.viaRelation ?? "seed";
  const relationLabel = locale === "zh-CN" ? zhTerms[relation] ?? relation : displayStatus(locale, relation);
  return `${entity} · ${relationLabel}`;
}

function readableRef(value: string) {
  return value.match(/^[a-z][a-z0-9+._-]*:\/\/(.+)$/i)?.[1] ?? value;
}

function State({ text, tone = "info" }: { text: string; tone?: "info" | "error" }) {
  return <div className={`notice notice--${tone}`} role={tone === "error" ? "alert" : "status"}>{text}</div>;
}

function formatConfidence(value: number) {
  return `${Math.round(value * 100)}%`;
}
