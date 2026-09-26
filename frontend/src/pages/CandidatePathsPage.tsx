/* SPDX-License-Identifier: Apache-2.0 */
import { useState } from "react";

import { SectionCard } from "../components/SectionCard";
import { EvidenceReferenceList, type EvidenceReferenceLike } from "../components/EvidenceReferenceList";
import { useCandidateBuilds } from "../hooks/useCandidateBuilds";
import { Locale, t, userFacingError } from "../i18n";
import { materializeCommunityCoverage, type CurrentUser } from "../lib/api";
import { displayReasonCode, displayStatus } from "../lib/presentation";


type CandidatePathsPageProps = {
  currentUser: CurrentUser | null;
  locale: Locale;
  projectId: string | null;
};

export function CandidatePathsPage({ currentUser, locale, projectId }: CandidatePathsPageProps) {
  const canRead = currentUser?.capabilities.includes("graph.candidate.read") ?? false;
  const { state, items, observationPolicy, reload, selectedId, select, detail, detailState } = useCandidateBuilds(projectId, canRead);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshMessage, setRefreshMessage] = useState<string | null>(null);
  const [refreshError, setRefreshError] = useState<string | null>(null);

  async function refreshObservation() {
    if (!projectId || !observationPolicy?.manualRefreshAvailable) return;
    setRefreshing(true);
    setRefreshMessage(null);
    setRefreshError(null);
    try {
      const result = await materializeCommunityCoverage(projectId);
      const candidate = result.candidateObservation;
      setRefreshMessage(t(locale, candidate.status === "ready"
        ? "candidateObservationReady"
        : candidate.status === "not_applicable"
          ? "candidateSemanticTraceMissing"
          : "candidateObservationFailed"));
      reload();
    } catch (error) {
      setRefreshError(userFacingError(locale, error, "candidateObservationFailed"));
    } finally {
      setRefreshing(false);
    }
  }

  const readinessKey = observationPolicy?.reasonCode === "CANDIDATE_EXECUTION_MISSING"
    ? "candidateExecutionMissing"
    : observationPolicy?.reasonCode === "CANDIDATE_SEMANTIC_TRACE_MISSING"
      ? "candidateSemanticTraceMissing"
      : observationPolicy?.reasonCode === "CANDIDATE_OBSERVATION_AVAILABLE"
        ? "candidateObservationAvailable"
        : "candidateObservationReady";

  return (
    <div className="page-shell" data-route="/candidate-paths">
      <div className="page-toolbar">
        <div>
          <h1>{t(locale, "candidatePaths")}</h1>
          <p>{t(locale, "candidatePathsBoundary")}</p>
        </div>
        {observationPolicy?.manualRefreshAvailable ? (
          <button disabled={refreshing} onClick={() => void refreshObservation()} type="button">
            {t(locale, refreshing ? "candidateObservationRefreshing" : "candidateObservationRefresh")}
          </button>
        ) : null}
      </div>

      {observationPolicy?.enabled ? <p className="empty-copy">{t(locale, readinessKey)}</p> : null}
      {refreshMessage ? <p className="empty-copy" role="status">{refreshMessage}</p> : null}
      {refreshError ? <p className="error-copy" role="alert">{refreshError}</p> : null}

      {state === "loading" ? <p className="empty-copy">{t(locale, "loading")}</p> : null}
      {state === "unavailable" ? <p className="empty-copy">{t(locale, "candidateProjectUnavailable")}</p> : null}
      {state === "restricted" ? <p className="empty-copy">{t(locale, "candidateAccessRestricted")}</p> : null}
      {state === "error" ? <p className="error-copy" role="alert">{t(locale, "candidateLoadFailed")}</p> : null}
      {state === "empty" ? <p className="empty-copy">{t(locale, "candidateNoBuilds")}</p> : null}

      {state === "ready" ? (
        <div className="page-columns">
          {items.map((item) => (
            <SectionCard key={item.buildId} title={`${t(locale, "candidateBuild")} ${item.buildId.slice(0, 8)}`} eyebrow={displayStatus(locale, item.outcome)}>
              <div className="detail-stack">
                <div className="badge-row">
                  <span className="status-pill">{t(locale, "candidateOnly")}</span>
                  <span className="status-pill">{t(locale, "promotionNotPerformed")}</span>
                  <span className="status-pill">{displayStatus(locale, item.modelSuggestionStatus)}</span>
                </div>
                <div className="stats-grid stats-grid--compact">
                  <Metric label={t(locale, "candidateIndependentRuns")} value={item.evidenceSummary.independentRunCount} />
                  <Metric label={t(locale, "candidateSuccessFailure")} value={`${item.evidenceSummary.successCount}/${item.evidenceSummary.failureCount}`} />
                  <Metric label={t(locale, "candidateVerificationCoverage")} value={`${Math.round(item.evidenceSummary.verificationCoverage * 100)}%`} />
                  <Metric label={t(locale, "candidateRetries")} value={item.evidenceSummary.retryCount} />
                  <Metric label={t(locale, "candidateCoordinateClicks")} value={item.evidenceSummary.coordinateClickCount} />
                  <Metric label={t(locale, "candidateAmbiguities")} value={item.ambiguityCount} />
                </div>
                <p>{`${t(locale, "candidateTransformer")}: ${item.transformerVersion}`}</p>
                <p>{`${t(locale, "candidateLastObserved")}: ${new Date(item.evidenceSummary.lastObservedAt).toLocaleString(locale)}`}</p>
                <p>{`${t(locale, "candidateFlakySignals")}: ${item.evidenceSummary.flakySignals.join(", ") || t(locale, "none")}`}</p>
                <button aria-expanded={selectedId === item.buildId} className="link-button" onClick={() => select(item.buildId)} type="button">{t(locale, "candidateSupportingEvidence")}</button>
                {selectedId === item.buildId && detailState === "loading" ? <p className="muted-text">{t(locale, "loading")}</p> : null}
                {selectedId === item.buildId && detailState === "restricted" ? <p className="error-copy">{t(locale, "candidateAccessRestricted")}</p> : null}
                {selectedId === item.buildId && detailState === "error" ? <p className="error-copy">{t(locale, "candidateEvidenceLoadFailed")}</p> : null}
                {selectedId === item.buildId && detail ? <CandidateEvidence detail={detail} locale={locale} /> : null}
              </div>
            </SectionCard>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function CandidateEvidence({ detail, locale }: { detail: NonNullable<ReturnType<typeof useCandidateBuilds>["detail"]>; locale: Locale }) {
  const sourceRefs = dedupeRefs([
    ...detail.observedTrace.sourceEventRefs,
    ...detail.observedTrace.traceRefs,
    ...detail.candidatePath.provenance.sourceEventRefs,
  ]);
  const evidenceRefs = dedupeRefs([
    ...detail.candidatePath.provenance.evidenceRefs,
    ...detail.observedTrace.toolCallRefs,
    ...detail.observedTrace.connectorCallRefs,
    ...detail.observedTrace.replayRefs,
    ...detail.guardrailEventRefs,
    ...detail.auditRefs,
  ]);
  return <div className="candidate-evidence-detail">
    <div className="badge-row"><span className="status-pill">{detail.candidatePath.pathKey}</span><span className="status-pill">{Math.round(detail.candidatePath.confidence * 100)}%</span></div>
    <EvidenceReferenceList label={t(locale, "evidenceSourceReferences")} refs={sourceRefs} locale={locale} />
    <EvidenceReferenceList label={t(locale, "candidateSupportingEvidence")} refs={evidenceRefs} locale={locale} />
    {detail.ambiguities.length ? <div><strong>{t(locale, "candidateAmbiguities")}</strong><ul className="evidence-issue-list">{detail.ambiguities.map((item) => <li key={`${item.code}:${item.entityRef ?? "unknown"}`}><strong>{displayReasonCode(locale, item.code)}</strong><span>{displayStatus(locale, item.severity)}</span></li>)}</ul></div> : null}
  </div>;
}

function dedupeRefs(refs: EvidenceReferenceLike[]) {
  const seen = new Set<string>();
  return refs.filter((item) => {
    const key = String(item.ref ?? item.id ?? "");
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function Metric({ label, value }: { label: string; value: number | string }) {
  return <div className="stat-tile"><span>{label}</span><strong>{value}</strong></div>;
}
