/* SPDX-License-Identifier: Apache-2.0 */
import { SectionCard } from "../components/SectionCard";
import { Locale, t } from "../i18n";
import { AgentRunItem } from "../store/platform";

type AgentRunsPageProps = {
  locale: Locale;
  agentRuns: AgentRunItem[];
};

export function AgentRunsPage({ locale, agentRuns }: AgentRunsPageProps) {
  return (
    <div className="page-shell" data-route="/agent-runs">
      <SectionCard title={t(locale, "agentRuns")} eyebrow={t(locale, "decisionTrail")}>
        <table className="data-table">
          <thead>
            <tr>
              <th>{t(locale, "agent")}</th>
              <th>{t(locale, "status")}</th>
              <th>{t(locale, "execution")}</th>
              <th>{t(locale, "models")}</th>
              <th>{t(locale, "created")}</th>
            </tr>
          </thead>
          <tbody>
            {agentRuns.map((run) => (
              <tr key={run.id}>
                <td>{run.agentName}</td>
                <td>{run.status}</td>
                <td>{run.executionId ? run.executionId.slice(0, 8) : t(locale, "planLevel")}</td>
                <td>{run.modelId ? run.modelId.slice(0, 8) : t(locale, "stub")}</td>
                <td>{new Date(run.createdAt).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </SectionCard>
    </div>
  );
}
