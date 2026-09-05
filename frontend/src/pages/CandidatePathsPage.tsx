/* SPDX-License-Identifier: Apache-2.0 */
import { SectionCard } from "../components/SectionCard";
import { useCandidateBuilds } from "../hooks/useCandidateBuilds";
import { Locale, t } from "../i18n";
import type { CurrentUser } from "../lib/api";


type CandidatePathsPageProps = {
  currentUser: CurrentUser | null;
  locale: Locale;
  projectId: string | null;
};

export function CandidatePathsPage({ currentUser, locale, projectId }: CandidatePathsPageProps) {
  const canRead = currentUser?.capabilities.includes("graph.candidate.read") ?? false;
  const { state, items } = useCandidateBuilds(projectId, canRead);

  return (
    <div className="page-shell" data-route="/candidate-paths">
      <div className="page-toolbar">
        <div>
          <h1>{t(locale, "candidatePaths")}</h1>
          <p>{t(locale, "candidatePathsBoundary")}</p>
        </div>
      </div>

      {state === "loading" ? <p className="empty-copy">{t(locale, "loading")}</p> : null}
      {state === "unavailable" ? <p className="empty-copy">{t(locale, "candidateProjectUnavailable")}</p> : null}
      {state === "restricted" ? <p className="empty-copy">{t(locale, "candidateAccessRestricted")}</p> : null}
      {state === "error" ? <p className="empty-copy">{t(locale, "candidateLoadFailed")}</p> : null}
      {state === "empty" ? <p className="empty-copy">{t(locale, "candidateNoBuilds")}</p> : null}

      {state === "ready" ? (
        <div className="page-columns">
          {items.map((item) => (
            <SectionCard key={item.buildId} title={`${t(locale, "candidateBuild")} ${item.buildId.slice(0, 8)}`} eyebrow={item.outcome}>
              <div className="detail-stack">
                <div className="badge-row">
                  <span className="status-pill">{t(locale, "candidateOnly")}</span>
                  <span className="status-pill">{t(locale, "promotionNotPerformed")}</span>
                  <span className="status-pill">{item.modelSuggestionStatus}</span>
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
              </div>
            </SectionCard>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number | string }) {
  return <div className="stat-tile"><span>{label}</span><strong>{value}</strong></div>;
}
