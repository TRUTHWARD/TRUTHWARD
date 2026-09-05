/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useMemo } from "react";

import { SectionCard } from "../components/SectionCard";
import { readCegDeepLink, useCegProjection, type CegDeepLink } from "../hooks/useCegProjection";
import { type Locale, t } from "../i18n";
import type { CegStableRef, CurrentUser } from "../lib/api";


type Props = {
  currentUser: CurrentUser | null;
  deepLink?: CegDeepLink;
  locale: Locale;
  onNavigateCorrections: () => void;
  projectId: string | null;
};

const VIRTUALIZE_THRESHOLD = 80;

function statusClass(status: string) {
  if (["fresh", "covered", "active", "available", "canonical"].includes(status)) return "ceg-badge ceg-badge--positive";
  if (["stale", "invalid", "uncovered", "restricted"].includes(status)) return "ceg-badge ceg-badge--negative";
  return "ceg-badge ceg-badge--neutral";
}

function identityKey(identity: string) {
  return identity === "canonical"
    ? "cegIdentityCanonical"
    : identity === "candidate"
      ? "cegIdentityCandidate"
      : "cegIdentityObserved";
}

function promotionLabelKey(promotionType: string | null, humanApproval: boolean | null) {
  if (promotionType === "policy_approved_auto_promotion") return "cegPromotionPolicyAutoValidated";
  if (humanApproval) return "cegPromotionHumanApproved";
  return "cegPromotionNotPerformed";
}

export function CegVisualizationPage({ currentUser, deepLink = readCegDeepLink(), locale, onNavigateCorrections, projectId }: Props) {
  const canRead = currentUser?.capabilities.includes("graph.correction.read") ?? false;
  const projection = useCegProjection(projectId, canRead, deepLink);
  const selectedGraph = projection.summary?.items.find((item) => item.graphId === projection.selectedGraphId) ?? null;
  const selectedPath = projection.paths?.items.find((item) => item.pathId === projection.selectedPathId) ?? null;
  const nodeById = useMemo(() => new Map(projection.detail?.nodes.map((item) => [item.nodeId, item]) ?? []), [projection.detail]);

  useEffect(() => {
    const query = new URLSearchParams(window.location.search);
    const setOrDelete = (key: string, value: string | null) => value ? query.set(key, value) : query.delete(key);
    setOrDelete("graphId", projection.selectedGraphId);
    setOrDelete("versionId", projection.selectedVersionId);
    setOrDelete("pathId", projection.selectedPathId);
    const next = `${window.location.pathname}${query.size ? `?${query.toString()}` : ""}`;
    if (`${window.location.pathname}${window.location.search}` !== next) window.history.replaceState(null, "", next);
  }, [projection.selectedGraphId, projection.selectedPathId, projection.selectedVersionId]);

  return (
    <div className="page-shell ceg-page" data-route="/ceg">
      <div className="page-toolbar">
        <div>
          <h1>{t(locale, "cegVisualization")}</h1>
          <p>{t(locale, "cegVisualizationBoundary")}</p>
        </div>
      </div>

      <div className="ceg-filter-bar" aria-label={t(locale, "cegFilters")}>
        <label>{t(locale, "search")}<input onChange={(event) => projection.setSearch(event.target.value)} placeholder={t(locale, "cegSearchPlaceholder")} type="search" value={projection.search} /></label>
        <label>{t(locale, "cegIdentity")}<select onChange={(event) => projection.setIdentity(event.target.value)} value={projection.identity}><option value="">{t(locale, "all")}</option><option value="observed">{t(locale, "cegIdentityObserved")}</option><option value="candidate">{t(locale, "cegIdentityCandidate")}</option><option value="canonical">{t(locale, "cegIdentityCanonical")}</option></select></label>
        <label>{t(locale, "riskLevel")}<select onChange={(event) => projection.setRiskLevel(event.target.value)} value={projection.riskLevel}><option value="">{t(locale, "all")}</option><option value="low">{t(locale, "cegRiskLow")}</option><option value="medium">{t(locale, "cegRiskMedium")}</option><option value="high">{t(locale, "cegRiskHigh")}</option></select></label>
        <label>{t(locale, "cegCoverage")}<select onChange={(event) => projection.setCoverageStatus(event.target.value)} value={projection.coverageStatus}><option value="">{t(locale, "all")}</option><option value="covered">{t(locale, "cegCoverageCovered")}</option><option value="partial">{t(locale, "cegCoveragePartial")}</option><option value="uncovered">{t(locale, "cegCoverageUncovered")}</option><option value="unknown">{t(locale, "cegCoverageUnknown")}</option></select></label>
      </div>

      {projection.state === "loading" ? <ProjectionState text={t(locale, "loading")} /> : null}
      {projection.state === "unavailable" ? <ProjectionState text={t(locale, "cegUnavailable")} /> : null}
      {projection.state === "restricted" ? <ProjectionState text={t(locale, "cegRestricted")} /> : null}
      {projection.state === "error" ? <ProjectionState text={t(locale, "cegLoadFailed")} /> : null}
      {projection.state === "empty" ? <ProjectionState text={t(locale, "cegEmpty")} /> : null}

      {projection.summary ? <div className="ceg-level-stack">
        <SectionCard title={t(locale, "cegLevel1Title")} eyebrow={t(locale, "cegLevel1Eyebrow")}>
          <div className="ceg-summary-grid" role="list">
            {projection.summary.items.map((graph) => <button aria-pressed={graph.graphId === projection.selectedGraphId} className={`ceg-summary-card ${graph.graphId === projection.selectedGraphId ? "ceg-summary-card--selected" : ""}`} disabled={!graph.graphVersionId} key={graph.graphId} onClick={() => graph.graphVersionId && projection.selectGraph(graph.graphId, graph.graphVersionId)} role="listitem" type="button">
              <span className="ceg-card-heading"><strong>{graph.name}</strong><span className={statusClass(graph.versionSource ?? "unknown")}>{graph.versionSource ? t(locale, identityKey(graph.versionSource)) : t(locale, "unknown")}</span></span>
              <span className="technical-id">{graph.graphId}</span>
              <span className="ceg-card-badges"><span className={statusClass(graph.status)}>{graph.status}</span><span className={statusClass(graph.staleness.status)}>{graph.staleness.status}</span><span className={statusClass(graph.coverage.status)}>{graph.coverage.status}</span></span>
              <span>{t(locale, "cegVersion")} {graph.versionNumber ?? "-"} · {graph.scopeType}</span>
              <span>{t(locale, "cegTopologyCounts")}: {graph.topology.paths} / {graph.topology.nodes} / {graph.topology.edges} / {graph.topology.steps}</span>
              <span>{t(locale, "graphLearningMode")}: {graph.learning.graphLearningMode}</span>
              <span>{t(locale, "graphAutonomyPaused")}: {graph.learning.autonomyPaused || graph.staleness.autonomySuspended ? t(locale, "yes") : t(locale, "no")}</span>
              <span>{t(locale, "cegUpdatedAt")}: <time dateTime={graph.updatedAt}>{graph.updatedAt}</time></span>
            </button>)}
          </div>
        </SectionCard>

        {selectedGraph && projection.paths ? <SectionCard title={t(locale, "cegLevel2Title")} eyebrow={`${selectedGraph.name} · v${selectedGraph.versionNumber ?? "-"}`}>
          <div className={`ceg-path-list ${projection.paths.items.length > VIRTUALIZE_THRESHOLD ? "ceg-path-list--virtualized" : ""}`} role="listbox" tabIndex={0}>
            {projection.paths.items.map((path) => <button aria-selected={path.pathId === projection.selectedPathId} className={`ceg-path-row ${path.pathId === projection.selectedPathId ? "ceg-path-row--selected" : ""}`} key={path.pathId} onClick={() => projection.selectPath(path.pathId)} role="option" type="button">
              <span className="ceg-card-heading"><strong>{path.name}</strong><span className={statusClass(path.identity)}>{t(locale, identityKey(path.identity))}</span></span>
              <span className="technical-id">{path.pathId}</span>
              <span className="ceg-card-badges"><span className={statusClass(path.riskLevel)}>{path.riskLevel}</span><span className={statusClass(path.applicabilityStatus)}>{path.applicabilityStatus}</span><span className={statusClass(path.coverage.status)}>{path.coverage.status}</span></span>
              <span>{t(locale, "cegStepCount")}: {path.stepCount} · {t(locale, "cegPromotionEligibility")}: {path.promotion.eligible === null ? t(locale, "unknown") : path.promotion.eligible ? t(locale, "yes") : t(locale, "no")}</span>
              <span>{t(locale, "cegCapabilityRefs")}: {path.capabilityRefs.length}</span>
              {path.promotion.reasonCodes.length ? <span>{t(locale, "cegReasonCodes")}: {path.promotion.reasonCodes.join(", ")}</span> : null}
              <span>{t(locale, promotionLabelKey(path.promotion.promotionType, path.promotion.humanApproval))}</span>
            </button>)}
          </div>
          {projection.paths.page.hasMore ? <button className="secondary-button" onClick={projection.loadMorePaths} type="button">{t(locale, "loadMore")}</button> : null}
        </SectionCard> : null}

        {selectedPath && projection.detail ? <SectionCard title={t(locale, "cegLevel3Title")} eyebrow={selectedPath.name}>
          {projection.detail.truncated ? <div className="notice notice--warning">{t(locale, "cegDetailTruncated")}</div> : null}
          {projection.detail.cycleDetected ? <div className="notice notice--warning">{t(locale, "cegCycleDetected")}</div> : null}
          {projection.detail.orphanNodeRefs.length ? <div className="notice notice--info">{t(locale, "cegOrphanNodes")}: {projection.detail.orphanNodeRefs.length}</div> : null}
          <ol className="ceg-step-list">
            {projection.detail.steps.map((step) => {
              const node = nodeById.get(step.nodeId);
              const edge = step.viaEdgeId ? projection.detail?.edges.find((item) => item.edgeId === step.viaEdgeId) : null;
              return <li className="ceg-step" key={step.stepId}>
                <span className="ceg-step__number" aria-hidden="true">{step.order}</span>
                <div><span className="ceg-card-heading"><strong>{node?.label ?? step.nodeId}</strong><span className={statusClass(node?.identity ?? "unknown")}>{node ? t(locale, identityKey(node.identity)) : t(locale, "unknown")}</span></span><p className="technical-id">{step.stepId}</p><p>{node?.nodeType ?? t(locale, "unknown")} · {edge?.edgeType ?? t(locale, "cegEntryStep")}</p><div className="ceg-card-badges"><span className={statusClass(step.verificationStatus ?? "unknown")}>{step.verificationStatus ?? "unknown"}</span><span className="ceg-badge ceg-badge--neutral">{t(locale, "cegRetries")}: {step.retryCount}</span><span className="ceg-badge ceg-badge--neutral">{t(locale, "cegFallback")}: {step.fallbackTypes.join(", ") || t(locale, "none")}</span></div>{step.conditions.length ? <p>{t(locale, "cegConditions")}: {JSON.stringify(step.conditions)}</p> : null}{step.exceptionRefs.length ? <p>{t(locale, "cegExceptions")}: {step.exceptionRefs.length}</p> : null}</div>
              </li>;
            })}
          </ol>
        </SectionCard> : null}

        {projection.evidence ? <SectionCard title={t(locale, "cegLevel4Title")} eyebrow={t(locale, "cegRedactedEvidence")}>
          <div className="ceg-evidence-layout">
            <div>
              <h3>{t(locale, "evidenceRefs")}</h3>
              <div className="ceg-reference-list">
                {projection.evidence.items.map((item) => <article className="ceg-reference" key={item.evidenceId}><span className="ceg-card-heading"><strong>{item.title}</strong><span className={statusClass(item.status)}>{item.status}</span></span><p className="technical-id">{item.ref ?? item.evidenceId}</p>{item.summary ? <p>{item.summary}</p> : null}{item.unavailableReason ? <p>{item.unavailableReason}</p> : null}</article>)}
              </div>
            </div>
            <div>
              <h3>{t(locale, "cegVersionHistory")}</h3>
              <ol className="ceg-version-list">{projection.evidence.versionHistory.map((version) => <li key={version.graphVersionId}><span className="ceg-card-heading"><strong>v{version.versionNumber}</strong><span className={statusClass(version.status)}>{version.status}</span></span><p>{t(locale, identityKey(version.identity))} · {t(locale, promotionLabelKey(version.promotionType, version.humanApproval))}</p><p className="technical-id">{version.graphVersionId}</p></li>)}</ol>
            </div>
          </div>
          <div className="ceg-governance-grid">
            <ProjectionRefs locale={locale} refs={projection.evidence.sourceRefs} title={t(locale, "cegSourceTrace")} />
            <GovernanceFacts locale={locale} title={t(locale, "cegPromotions")} values={projection.evidence.promotions} />
            <GovernanceFacts locale={locale} title={t(locale, "cegProposals")} values={projection.evidence.proposals} />
            <GovernanceFacts locale={locale} title={t(locale, "cegStalenessReviews")} values={projection.evidence.stalenessReviews} />
          </div>
          {projection.evidence.capabilities.proposeCorrection ? <button className="secondary-button" onClick={onNavigateCorrections} type="button">{t(locale, "cegOpenControlledCorrection")}</button> : <div className="notice notice--info">{t(locale, "cegCorrectionReadOnly")}</div>}
        </SectionCard> : null}
      </div> : null}
    </div>
  );
}

function ProjectionState({ text }: { text: string }) {
  return <div className="notice notice--info" role="status">{text}</div>;
}

function ProjectionRefs({ locale, refs, title }: { locale: Locale; refs: CegStableRef[]; title: string }) {
  return <div><h3>{title}</h3><ul className="ceg-ref-list">{refs.slice(0, 100).map((ref) => <li key={`${ref.type}:${ref.id}:${ref.ref ?? ""}`}><span>{ref.type}</span><code>{ref.ref ?? ref.id}</code>{!ref.available ? <small>{ref.unavailableReason ?? t(locale, "unavailable")}</small> : null}</li>)}</ul></div>;
}

function GovernanceFacts({ locale, title, values }: { locale: Locale; title: string; values: Array<Record<string, unknown>> }) {
  return <div><h3>{title}</h3>{values.length ? <ul className="ceg-fact-list">{values.map((value, index) => {
    const promotionType = typeof value.promotionType === "string" ? value.promotionType : null;
    const humanApproval = typeof value.humanApproval === "boolean" ? value.humanApproval : null;
    const label = promotionType ? t(locale, promotionLabelKey(promotionType, humanApproval)) : String(value.status ?? value.action ?? t(locale, "unknown"));
    return <li key={String(value.promotionId ?? value.proposalId ?? value.reviewId ?? index)}><strong>{label}</strong><code>{String(value.promotionId ?? value.proposalId ?? value.reviewId ?? "")}</code></li>;
  })}</ul> : <p className="empty-copy">{t(locale, "cegNoGovernanceFacts")}</p>}</div>;
}
