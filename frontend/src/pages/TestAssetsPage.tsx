/* SPDX-License-Identifier: Apache-2.0 */
import { Locale, t } from "../i18n";
import { CoverageMatrixItem, CoverageSummaryItem, PlanItem } from "../store/platform";

type TestAssetsPageProps = {
  locale: Locale;
  plans: PlanItem[];
  selectedPlanId: string | null;
  onSelectPlan: (planId: string) => void;
  coverageMatrix: CoverageMatrixItem | null;
  coverageSummary: CoverageSummaryItem | null;
  loading: boolean;
  error: string | null;
};

export function TestAssetsPage({
  locale,
  plans,
  selectedPlanId,
  onSelectPlan,
  coverageMatrix,
  coverageSummary,
  loading,
  error,
}: TestAssetsPageProps) {
  const selectedPlan = plans.find((plan) => plan.id === selectedPlanId) ?? plans[0] ?? null;
  const rows = coverageMatrix?.rows ?? [];
  const hasStableContext = Boolean(selectedPlan?.requirementVersionId);

  return (
    <div className="page-shell" data-route="/test-assets">
      <div className="page-toolbar">
        <div>
          <h1>{t(locale, "testAssets")}</h1>
        </div>
        <span className="status-pill">{t(locale, "readOnly")}</span>
      </div>

      <div className="work-grid work-grid--sidebar">
        <section className="panel">
          <div className="panel__header">
            <span className="eyebrow">{t(locale, "scope")}</span>
            <h2>{t(locale, "plan")}</h2>
          </div>
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
          {!hasStableContext ? <StateBanner title={t(locale, "unavailableContext")} copy={t(locale, "selectPlanWithRequirementVersion")} /> : null}
          {loading ? <StateBanner title={t(locale, "loading")} copy={t(locale, "loadingReadOnlyData")} /> : null}
          {error ? (
            <div className="error-banner">
              <strong>{t(locale, "errorState")}</strong>
              <p>{error}</p>
            </div>
          ) : null}
          {hasStableContext && !loading && !error ? (
            <div className="detail-stack">
              <div className="stats-grid stats-grid--compact">
                <MetricTile label={t(locale, "requirement")} value={String(rows.length)} />
                <MetricTile label={t(locale, "testPoints")} value={String(sumRows(rows, "testPoints"))} />
                <MetricTile label={t(locale, "testCases")} value={String(sumRows(rows, "testCases"))} />
                <MetricTile label={t(locale, "evidence")} value={String(sumRows(rows, "evidenceArtifacts"))} />
                <MetricTile label={t(locale, "findings")} value={String(sumRows(rows, "normalizedFindings"))} />
                <MetricTile label={t(locale, "coverage")} value={formatCoverage(coverageSummary?.requirementCoverage, t(locale, "none"))} />
              </div>

              <div className="table-wrap">
                <table className="data-table data-table--compact">
                  <thead>
                    <tr>
                      <th>{t(locale, "requirement")}</th>
                      <th>{t(locale, "testPoints")}</th>
                      <th>{t(locale, "testCases")}</th>
                      <th>{t(locale, "evidence")}</th>
                      <th>{t(locale, "findings")}</th>
                      <th>{t(locale, "status")}</th>
                      <th>{t(locale, "risk")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => (
                      <tr key={String(row.requirementItem.id ?? row.requirement)}>
                        <td>
                          <strong>{row.requirement}</strong>
                          <p>{String(row.requirementItem.id ?? row.requirementVersion)}</p>
                        </td>
                        <td>{row.testPoints.length}</td>
                        <td>{row.testCases.length}</td>
                        <td>{row.evidenceArtifacts.length}</td>
                        <td>{row.normalizedFindings.length}</td>
                        <td><span className={`status-pill status-pill--${row.coverageStatus}`}>{row.coverageStatus}</span></td>
                        <td><span className={`status-pill status-pill--${row.riskStatus}`}>{row.riskStatus}</span></td>
                      </tr>
                    ))}
                    {rows.length === 0 ? (
                      <tr>
                        <td colSpan={7}>{t(locale, "emptyReadOnlyResult")}</td>
                      </tr>
                    ) : null}
                  </tbody>
                </table>
              </div>
            </div>
          ) : null}
        </section>
      </div>
    </div>
  );
}

function StateBanner({ title, copy }: { title: string; copy: string }) {
  return (
    <div className="empty-state">
      <strong>{title}</strong>
      <p>{copy}</p>
    </div>
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

function sumRows(rows: CoverageMatrixItem["rows"], key: "testPoints" | "testCases" | "evidenceArtifacts" | "normalizedFindings") {
  return rows.reduce((total, row) => total + row[key].length, 0);
}

function formatCoverage(value: number | null | undefined, emptyLabel: string) {
  if (value === null || value === undefined) {
    return emptyLabel;
  }
  return `${Math.round(value * 100)}%`;
}
