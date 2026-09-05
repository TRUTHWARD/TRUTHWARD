/* SPDX-License-Identifier: Apache-2.0 */
import type { CoverageProofBundle } from "../lib/api";
import { Locale, t } from "../i18n";
import { CoverageMatrixItem, CoverageMatrixRowItem, CoverageSummaryItem, PlanItem } from "../store/platform";

type CoverageMatrixPageProps = {
  locale: Locale;
  plans: PlanItem[];
  selectedPlanId: string | null;
  onSelectPlan: (planId: string) => void;
  coverageSummary: CoverageSummaryItem | null;
  coverageMatrix: CoverageMatrixItem | null;
  coverageProof: CoverageProofBundle | null;
  selectedRequirementItemId: string | null;
  proofLoading: boolean;
  proofError: string | null;
  onSelectRequirementItem: (requirementItemId: string) => void;
};

export function CoverageMatrixPage({
  locale,
  plans,
  selectedPlanId,
  onSelectPlan,
  coverageSummary,
  coverageMatrix,
  coverageProof,
  selectedRequirementItemId,
  proofLoading,
  proofError,
  onSelectRequirementItem,
}: CoverageMatrixPageProps) {
  const selectedPlan = plans.find((plan) => plan.id === selectedPlanId) ?? plans[0] ?? null;
  const rows = coverageMatrix?.rows ?? [];
  const scope = coverageMatrix?.scope ?? coverageSummary?.scope ?? selectedPlan?.requirementScope ?? null;
  const scopeRequirementVersionIds = scope
    ? normalizeStringList(scope.requirementVersionIds, scope.requirementVersionId ? [String(scope.requirementVersionId)] : [])
    : [];
  const scopeSelectedRequirementItemIds = scope ? normalizeStringList(scope.selectedRequirementItemIds) : [];

  return (
    <div className="page-shell" data-route="/coverage-matrix">
      <div className="page-toolbar">
        <div>
          <h1>{t(locale, "coverageMatrix")}</h1>
        </div>
        <div className="badge-row">
          <span className="status-pill">{coverageSummary?.status ?? t(locale, "unknown")}</span>
        </div>
      </div>

      <div className="work-grid work-grid--sidebar">
        <section className="panel">
          <div className="panel__header">
            <span className="eyebrow">{t(locale, "scope")}</span>
            <h2>{t(locale, "requirementVersion")}</h2>
          </div>
          {scope ? (
            <div className="notice-banner">
              <strong>{scope.scopeId}</strong>
              <p>
                {t(locale, "requirementVersions")}: {scopeRequirementVersionIds.join(", ")}
              </p>
              <p>
                {t(locale, "selectedRequirementItems")}: {scopeSelectedRequirementItemIds.length > 0 ? scopeSelectedRequirementItemIds.join(", ") : t(locale, "allActiveRequirementItems")}
              </p>
            </div>
          ) : null}
          <div className="stack-list">
            {plans.map((plan) => (
              <button
                className={`stack-row stack-row--button ${plan.id === selectedPlan?.id ? "stack-row--selected" : ""}`}
                key={plan.id}
                onClick={() => onSelectPlan(plan.id)}
                type="button"
              >
                <div>
                  <strong>{plan.name}</strong>
                  <p>{plan.requirementVersionId ?? t(locale, "noRequirementVersion")}</p>
                </div>
                <span>{plan.status}</span>
              </button>
            ))}
            {plans.length === 0 ? <div className="empty-state">{t(locale, "noData")}</div> : null}
          </div>
        </section>

        <section className="panel">
          <div className="stats-grid stats-grid--compact">
            <MetricTile label={t(locale, "requirement")} value={formatCoverage(coverageSummary?.requirementCoverage, t(locale, "notApplicable"))} />
            <MetricTile label={t(locale, "testPoint")} value={formatCoverage(coverageSummary?.testPointCoverage, t(locale, "notApplicable"))} />
            <MetricTile label={t(locale, "testCase")} value={formatCoverage(coverageSummary?.testCaseCoverage, t(locale, "notApplicable"))} />
            <MetricTile label={t(locale, "evidence")} value={formatCoverage(coverageSummary?.evidenceCoverage, t(locale, "notApplicable"))} />
            <MetricTile label={t(locale, "findingTrace")} value={formatCoverage(coverageSummary?.findingTraceCoverage, t(locale, "notApplicable"))} />
            <MetricTile label={t(locale, "gateImpact")} value={formatCoverage(coverageSummary?.gateImpactCoverage, t(locale, "notApplicable"))} />
          </div>

          <div className="table-wrap">
            <table className="data-table data-table--compact">
              <thead>
                <tr>
                  <th>{t(locale, "requirement")}</th>
                  <th>{t(locale, "testPoints")}</th>
                  <th>{t(locale, "testCases")}</th>
                  <th>{t(locale, "executions")}</th>
                  <th>{t(locale, "evidence")}</th>
                  <th>{t(locale, "findings")}</th>
                  <th>{t(locale, "gate")}</th>
                  <th>{t(locale, "status")}</th>
                  <th>{t(locale, "risk")}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const requirementItemId = getRequirementItemId(row);
                  const missingLinks = row.missingLinks ?? [];
                  return (
                    <tr
                      className={requirementItemId === selectedRequirementItemId ? "data-table__row--selected" : ""}
                      key={requirementItemId}
                    >
                      <td>
                        <button className="link-button" onClick={() => onSelectRequirementItem(requirementItemId)} type="button">
                          {row.requirement}
                        </button>
                        {missingLinks.length > 0 ? <p>{missingLinks.map((link) => link.code).join(", ")}</p> : null}
                      </td>
                      <td>{(row.testPoints ?? []).length}</td>
                      <td>{(row.testCases ?? []).length}</td>
                      <td>{(row.executionTasks ?? []).length}</td>
                      <td>{(row.evidenceArtifacts ?? []).length}</td>
                      <td>{(row.normalizedFindings ?? []).length}</td>
                      <td>{(row.gateImpact ?? []).length}</td>
                      <td><span className={`status-pill status-pill--${row.coverageStatus}`}>{row.coverageStatus}</span></td>
                      <td><span className={`status-pill status-pill--${row.riskStatus}`}>{row.riskStatus}</span></td>
                    </tr>
                  );
                })}
                {rows.length === 0 ? (
                  <tr>
                    <td colSpan={9}>{coverageMatrix ? t(locale, "noActiveRequirementItems") : t(locale, "selectPlanWithRequirementVersion")}</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      <CoverageProofDrawer
        locale={locale}
        proof={coverageProof}
        proofError={proofError}
        proofLoading={proofLoading}
        selectedRequirementItemId={selectedRequirementItemId}
      />
    </div>
  );
}

function CoverageProofDrawer({
  locale,
  proof,
  proofLoading,
  proofError,
  selectedRequirementItemId,
}: {
  locale: Locale;
  proof: CoverageProofBundle | null;
  proofLoading: boolean;
  proofError: string | null;
  selectedRequirementItemId: string | null;
}) {
  return (
    <section className="drawer-panel">
      <div className="panel__header">
        <span className="eyebrow">{t(locale, "coverageProof")}</span>
        <h2>{selectedRequirementItemId ?? t(locale, "selectRequirement")}</h2>
      </div>
      {proofLoading ? <div className="empty-state">{t(locale, "loading")}</div> : null}
      {proofError ? (
        <div className="error-banner">
          <strong>{t(locale, "coverageProofUnavailable")}</strong>
          <p>{proofError}</p>
        </div>
      ) : null}
      {!proofLoading && !proofError && proof ? (
        <div className="detail-stack">
          <div className="stats-grid stats-grid--compact">
            <MetricTile label={t(locale, "coverage")} value={proof.coverageStatus} />
            <MetricTile label={t(locale, "proofStatus")} value={proof.proofStatus} />
            <MetricTile label={t(locale, "chains")} value={String(proof.proofChain.length)} />
            <MetricTile label={t(locale, "issues")} value={String(proof.proofIssues.length)} />
          </div>

          <div className="table-wrap">
            <table className="data-table data-table--compact">
              <thead>
                <tr>
                  <th>{t(locale, "proofChain")}</th>
                  <th>{t(locale, "edges")}</th>
                  <th>{t(locale, "evidence")}</th>
                  <th>{t(locale, "findings")}</th>
                  <th>{t(locale, "gate")}</th>
                  <th>{t(locale, "replayColumn")}</th>
                </tr>
              </thead>
              <tbody>
                {proof.proofChain.map((chain, index) => (
                  <tr key={`${chain.testCaseId ?? "chain"}-${index}`}>
                    <td>
                      <strong>{chain.testCaseId ?? chain.testPointId ?? t(locale, "notCovered")}</strong>
                      <p>{chain.executionTaskId ?? t(locale, "noExecutionTask")}</p>
                    </td>
                    <td>{chain.proofEdges.length}</td>
                    <td>{chain.evidenceArtifactRefs.length}</td>
                    <td>{chain.normalizedFindingRefs.length}</td>
                    <td>{chain.gateDecisionRef ?? t(locale, "none")}</td>
                    <td>{chain.replayExportHash ?? t(locale, "liveProof")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="detail-grid">
            <SnapshotCard title={t(locale, "traceabilitySnapshot")} value={{
              traceabilitySnapshotRef: proof.proofChain[0]?.traceabilitySnapshotRef ?? null,
              traceabilitySnapshotHash: proof.proofChain[0]?.traceabilitySnapshotHash ?? null,
              coverageMatrixSnapshotRef: proof.proofChain[0]?.coverageMatrixSnapshotRef ?? null,
              coverageMatrixSnapshotHash: proof.proofChain[0]?.coverageMatrixSnapshotHash ?? null,
            }} />
            <SnapshotCard title={t(locale, "proofIssues")} value={proof.proofIssues} />
          </div>
        </div>
      ) : null}
      {!proofLoading && !proofError && !proof ? <div className="empty-state">{t(locale, "selectRequirement")}</div> : null}
    </section>
  );
}

function MetricTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="stat-tile">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function SnapshotCard({ title, value }: { title: string; value: unknown }) {
  return (
    <div>
      <h3>{title}</h3>
      <pre className="snapshot-json">{JSON.stringify(value, null, 2)}</pre>
    </div>
  );
}

function getRequirementItemId(row: CoverageMatrixRowItem) {
  return String(row.requirementItem.id ?? row.requirement);
}

function normalizeStringList(value: unknown, fallback: string[] = []) {
  if (!Array.isArray(value)) {
    return fallback;
  }
  return value.map((item) => String(item)).filter(Boolean);
}

function formatCoverage(value: number | null | undefined, emptyLabel: string) {
  if (value === null || value === undefined) {
    return emptyLabel;
  }
  return `${Math.round(value * 100)}%`;
}
