/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useState } from "react";

import { SafeJsonViewer } from "../components/SafeJsonViewer";
import { SectionCard } from "../components/SectionCard";
import { Locale, t } from "../i18n";
import { displayStatus } from "../lib/presentation";
import type { ApprovalItem, GuardrailEventItem, ReplayItem, SkillInvocationItem } from "../store/platform";

type SkillInvocationsPageProps = {
  approvals: ApprovalItem[];
  guardrailEvents: GuardrailEventItem[];
  locale: Locale;
  replay: ReplayItem | null;
  skillInvocations: SkillInvocationItem[];
};

export function SkillInvocationsPage({
  approvals,
  guardrailEvents,
  locale,
  replay,
  skillInvocations,
}: SkillInvocationsPageProps) {
  const [selectedInvocationId, setSelectedInvocationId] = useState<string | null>(skillInvocations[0]?.id ?? null);
  const selectedInvocation =
    skillInvocations.find((invocation) => invocation.id === selectedInvocationId) ?? skillInvocations[0] ?? null;
  useEffect(() => {
    if (skillInvocations.length > 0 && !skillInvocations.some((invocation) => invocation.id === selectedInvocationId)) {
      setSelectedInvocationId(skillInvocations[0].id);
    }
  }, [selectedInvocationId, skillInvocations]);
  const linkedGuardrails = selectedInvocation
    ? guardrailEvents.filter((event) => event.skillInvocationId === selectedInvocation.id)
    : [];
  const replayInvocationCount = replay?.skillInvocations.length ?? 0;
  const linkedApprovals = selectedInvocation
    ? approvals.filter(
        (approval) =>
          approval.resourceId === selectedInvocation.id ||
          selectedInvocation.approvalRefs.some((ref) => String(ref.id ?? ref.approvalId ?? "") === approval.id),
      )
    : [];

  return (
    <div className="page-shell" data-route="/skill-invocations">
      <div className="page-toolbar">
        <div>
          <h1>{t(locale, "skillInvocations")}</h1>
        </div>
      </div>

      <div className="stats-grid stats-grid--compact">
        <div className="stat-tile">
          <span>{t(locale, "skillInvocationRecords")}</span>
          <strong>{skillInvocations.length}</strong>
          <p>{t(locale, "serviceOwnedCallRecords")}</p>
        </div>
        <div className="stat-tile">
          <span>{t(locale, "replaySnapshot")}</span>
          <strong>{replayInvocationCount}</strong>
          <p>{replay?.executionId ? replay.executionId.slice(0, 8) : t(locale, "none")}</p>
        </div>
        <div className="stat-tile">
          <span>{t(locale, "guardrails")}</span>
          <strong>{linkedGuardrails.length}</strong>
          <p>{t(locale, "selectedInvocation")}</p>
        </div>
      </div>

      <div className="page-columns page-columns--skill-observation">
        <SectionCard title={t(locale, "skillInvocationRecords")}>
          <div className="timeline-list">
            {skillInvocations.map((invocation) => (
              <button
                className={`timeline-item timeline-item--skill_invocation ${
                  selectedInvocation?.id === invocation.id ? "stack-row--selected" : ""
                }`}
                key={invocation.id}
                onClick={() => setSelectedInvocationId(invocation.id)}
                type="button"
              >
                <strong>{invocation.skillId}</strong>
                <span>{displayStatus(locale, invocation.status)}</span>
                <span className="technical-value">{invocation.extensionPointId ?? t(locale, "none")}</span>
              </button>
            ))}
            {skillInvocations.length === 0 ? <p className="empty-copy">{t(locale, "noSkillInvocations")}</p> : null}
          </div>
        </SectionCard>

        <SectionCard
          title={selectedInvocation ? selectedInvocation.skillId : t(locale, "selectedInvocation")}
          eyebrow={t(locale, "runtimeRefs")}
        >
          {selectedInvocation ? (
            <div className="detail-stack">
              <div className="detail-banner">
                <div>
                  <strong>{displayStatus(locale, selectedInvocation.status)}</strong>
                  <p className="technical-value">{selectedInvocation.extensionPointId ?? t(locale, "none")}</p>
                </div>
                <div className="metric-cluster">
                  <span className="status-pill">{selectedInvocation.version}</span>
                  {selectedInvocation.storageStatus ? (
                    <span>{t(locale, "storageStatus")}: {displayStatus(locale, selectedInvocation.storageStatus)}</span>
                  ) : null}
                </div>
              </div>

              <div className="detail-grid">
                <ReadonlyRef emptyLabel={t(locale, "none")} label={t(locale, "execution")} value={selectedInvocation.executionId} />
                <ReadonlyRef emptyLabel={t(locale, "none")} label={t(locale, "trace")} value={selectedInvocation.traceId} />
                <ReadonlyRef emptyLabel={t(locale, "none")} label={t(locale, "agentRun")} value={selectedInvocation.agentRunId ?? null} />
                <ReadonlyRef emptyLabel={t(locale, "none")} label={t(locale, "binding")} value={selectedInvocation.bindingId} />
              </div>

              <div className="detail-grid">
                <ReadonlyRef emptyLabel={t(locale, "none")} label={t(locale, "invocationId")} value={selectedInvocation.id} />
                <ReadonlyRef emptyLabel={t(locale, "none")} label={t(locale, "manifest")} value={selectedInvocation.manifestHash} />
                <ReadonlyRef emptyLabel={t(locale, "none")} label={t(locale, "sourceWorkflow")} value={selectedInvocation.sourceWorkflow} />
                <ReadonlyRef emptyLabel={t(locale, "none")} label={t(locale, "createdAt")} value={formatTimestamp(selectedInvocation.createdAt, locale)} />
              </div>

              <div className="detail-grid">
                <ReadonlyCount label={t(locale, "artifactRefs")} value={selectedInvocation.artifactRefs.length} />
                <ReadonlyCount label={t(locale, "toolRefs")} value={selectedInvocation.toolCallRefs.length} />
                <ReadonlyCount label={t(locale, "connectorRefs")} value={selectedInvocation.connectorCallRefs.length} />
                <ReadonlyCount label={t(locale, "approvalRefs")} value={selectedInvocation.approvalRefs.length} />
                <ReadonlyCount label={t(locale, "guardrailRefs")} value={linkedGuardrails.length} />
              </div>

              <div>
                <h3>{t(locale, "safeObservationSummary")}</h3>
                <p className="empty-copy">{t(locale, "safeObservationSummaryNotice")}</p>
                <div className="detail-grid">
                  <ObservationSnapshot locale={locale} title={t(locale, "inputSummary")} value={selectedInvocation.inputSummary ?? {}} />
                  <ObservationSnapshot locale={locale} title={t(locale, "outputSummary")} value={selectedInvocation.outputSummary ?? {}} />
                  <ObservationSnapshot locale={locale} title={t(locale, "policySummary")} value={selectedInvocation.policySummary ?? {}} />
                </div>
              </div>

              <div className="detail-grid">
                <ObservationSnapshot locale={locale} title={t(locale, "resolutionSnapshot")} value={selectedInvocation.resolutionSnapshot} />
                <ObservationSnapshot locale={locale} title={t(locale, "connectorBindingSnapshot")} value={selectedInvocation.connectorBindingSnapshot} />
              </div>

              <ObservationSnapshot
                locale={locale}
                title={t(locale, "linkedEvidenceAndCalls")}
                value={{
                  artifactRefs: selectedInvocation.artifactRefs,
                  toolCallRefs: selectedInvocation.toolCallRefs,
                  connectorCallRefs: selectedInvocation.connectorCallRefs,
                  approvalRefs: selectedInvocation.approvalRefs,
                }}
              />

              <div className="detail-grid">
                <LinkedRecords
                  emptyLabel={t(locale, "none")}
                  title={t(locale, "guardrailRefs")}
                  items={linkedGuardrails.map((event) => `${event.ruleId}: ${event.decision} · ${event.reason}`)}
                />
                <LinkedRecords
                  emptyLabel={t(locale, "none")}
                  title={t(locale, "approvalRefs")}
                  items={linkedApprovals.map((approval) => `${approval.summary}: ${displayStatus(locale, approval.status)}`)}
                />
              </div>

              {selectedInvocation.inputSnapshot || selectedInvocation.outputSnapshot || selectedInvocation.policySnapshot ? (
                <div>
                  <h3>{t(locale, "privilegedSnapshots")}</h3>
                  <p className="empty-copy">{t(locale, "privilegedSnapshotsNotice")}</p>
                  <div className="detail-grid">
                    {selectedInvocation.inputSnapshot ? <ObservationSnapshot locale={locale} title={t(locale, "input")} value={selectedInvocation.inputSnapshot} /> : null}
                    {selectedInvocation.outputSnapshot ? <ObservationSnapshot locale={locale} title={t(locale, "output")} value={selectedInvocation.outputSnapshot} /> : null}
                    {selectedInvocation.policySnapshot ? <ObservationSnapshot locale={locale} title={t(locale, "policy")} value={selectedInvocation.policySnapshot} /> : null}
                  </div>
                </div>
              ) : (
                <div className="empty-state">
                  <strong>{t(locale, "privilegedSnapshotsNotExposed")}</strong>
                  <p>{t(locale, "privilegedSnapshotsNotExposedNotice")}</p>
                </div>
              )}
            </div>
          ) : (
            <p className="empty-copy">{t(locale, "noSkillInvocations")}</p>
          )}
        </SectionCard>
      </div>
    </div>
  );
}

function ObservationSnapshot({ locale, title, value }: { locale: Locale; title: string; value: Record<string, unknown> }) {
  return (
    <div>
      <h3>{title}</h3>
      {Object.keys(value).length > 0 ? (
        <SafeJsonViewer locale={locale} value={value} limits={{ maxCharacters: 12000, maxNodes: 240 }} />
      ) : (
        <p className="empty-copy">{t(locale, "none")}</p>
      )}
    </div>
  );
}

function ReadonlyRef({ emptyLabel, label, value }: { emptyLabel: string; label: string; value: string | null }) {
  return (
    <div className="stack-row stack-row--dense">
      <div>
        <strong>{label}</strong>
        <p>{value ?? emptyLabel}</p>
      </div>
    </div>
  );
}

function ReadonlyCount({ label, value }: { label: string; value: number }) {
  return (
    <div className="stat-tile">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function LinkedRecords({ emptyLabel, title, items }: { emptyLabel: string; title: string; items: string[] }) {
  return (
    <div>
      <h3>{title}</h3>
      <div className="stack-list">
        {items.map((item) => (
          <div className="stack-row stack-row--dense" key={item}>
            <strong>{item}</strong>
          </div>
        ))}
        {items.length === 0 ? <p className="empty-copy">{emptyLabel}</p> : null}
      </div>
    </div>
  );
}

function formatTimestamp(value: string, locale: Locale) {
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.getTime()) ? value : timestamp.toLocaleString(locale);
}
