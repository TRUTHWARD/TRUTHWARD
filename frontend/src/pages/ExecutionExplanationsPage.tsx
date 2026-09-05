/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useMemo, useState, type KeyboardEvent } from "react";

import { SafeJsonViewer } from "../components/SafeJsonViewer";
import { formatT, t, type Locale } from "../i18n";
import { displayStatus } from "../lib/presentation";
import type {
  CurrentUser,
  DecisionTimelineEvent,
  DecisionTimelineReference,
  ExplanationMessage,
} from "../lib/api";
import { useExecutionExplanationTimeline } from "../hooks/useExecutionExplanationTimeline";
import type { ExecutionItem } from "../store/platform";


type ExplanationView = "plain" | "professional" | "raw";

export function ExecutionExplanationsPage({
  currentUser,
  executions,
  locale,
  onSelectExecution,
  selectedExecutionId,
}: {
  currentUser: CurrentUser | null;
  executions: ExecutionItem[];
  locale: Locale;
  onSelectExecution: (executionId: string | null) => void;
  selectedExecutionId: string | null;
}) {
  const canRead = Boolean(currentUser?.capabilities.includes("replay.read"));
  const { state, projection, error, loadingMore } = useExecutionExplanationTimeline(
    selectedExecutionId,
    canRead,
  );
  const [view, setView] = useState<ExplanationView>("plain");
  const professionalAllowed = Boolean(projection?.capabilityProjection.explanationProfessional);
  const rawAllowed = Boolean(projection?.capabilityProjection.explanationRaw);
  const viewAccess = {
    plain: canRead,
    professional: professionalAllowed,
    raw: rawAllowed,
  };

  useEffect(() => {
    if (
      (view === "professional" && !professionalAllowed)
      || (view === "raw" && !rawAllowed)
    ) {
      setView("plain");
    }
  }, [professionalAllowed, rawAllowed, view]);

  const tabOrder: ExplanationView[] = ["plain", "professional", "raw"];
  const onTabKeyDown = (event: KeyboardEvent<HTMLButtonElement>, current: ExplanationView) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const available = tabOrder.filter((item) => viewAccess[item]);
    if (available.length === 0) return;
    let next = available.indexOf(current);
    if (event.key === "Home") next = 0;
    else if (event.key === "End") next = available.length - 1;
    else if (event.key === "ArrowRight") next = (next + 1) % available.length;
    else next = (next - 1 + available.length) % available.length;
    setView(available[next]);
  };

  return (
    <section className="page-section execution-explanations" data-route="/execution-explanations">
      <div className="page-heading">
        <div>
          <p className="eyebrow">{t(locale, "timeline")}</p>
          <h1>{t(locale, "executionExplanations")}</h1>
          <p>{t(locale, "executionExplanationSubtitle")}</p>
        </div>
      </div>

      <div className="panel execution-explanations__toolbar">
        <label>
          <span>{t(locale, "executions")}</span>
          <select
            aria-label={t(locale, "executions")}
            value={selectedExecutionId ?? ""}
            onChange={(event) => onSelectExecution(event.target.value || null)}
          >
            <option value="">{t(locale, "executionExplanationSelect")}</option>
            {executions.map((execution) => (
              <option key={execution.id} value={execution.id}>
                {execution.id} · {displayStatus(locale, execution.status)}
              </option>
            ))}
          </select>
        </label>
        <p className="read-only-note">{t(locale, "executionExplanationReadOnly")}</p>
      </div>

      {state === "loading" ? <State role="status" copy={t(locale, "executionExplanationLoading")} /> : null}
      {state === "restricted" ? <State role="alert" copy={error ?? t(locale, "executionExplanationRestricted")} tone="restricted" /> : null}
      {state === "unavailable" ? <State role="status" copy={error ?? t(locale, "executionExplanationUnavailable")} tone="unavailable" /> : null}
      {state === "empty" ? <State role="status" copy={t(locale, "executionExplanationEmpty")} /> : null}
      {state === "error" ? <State role="alert" copy={error ?? t(locale, "executionExplanationLoadFailed")} tone="error" /> : null}

      {projection && state === "ready" ? (
        <>
          <div className="explanation-view-tabs" role="tablist" aria-label={t(locale, "executionExplanations")}>
            {tabOrder.map((item) => (
              <button
                aria-controls="execution-explanation-panel"
                aria-selected={view === item}
                className={view === item ? "explanation-view-tab explanation-view-tab--active" : "explanation-view-tab"}
                disabled={!viewAccess[item]}
                id={`execution-explanation-tab-${item}`}
                key={item}
                onClick={() => setView(item)}
                onKeyDown={(event) => onTabKeyDown(event, item)}
                role="tab"
                type="button"
              >
                {t(locale, viewLabel(item))}
              </button>
            ))}
          </div>
          {!viewAccess.professional ? <p className="capability-notice">{t(locale, "executionExplanationProfessionalRestricted")}</p> : null}
          {!viewAccess.raw ? <p className="capability-notice">{t(locale, "executionExplanationRawRestricted")}</p> : null}
          {loadingMore ? <p className="read-only-note" role="status">{t(locale, "executionExplanationLoadingMore")}</p> : null}
          {error ? <p className="capability-notice" role="alert">{error}</p> : null}
          <div
            aria-labelledby={`execution-explanation-tab-${view}`}
            id="execution-explanation-panel"
            role="tabpanel"
          >
            <TimelineGroups locale={locale} projection={projection} view={view} />
          </div>
        </>
      ) : null}
    </section>
  );
}

function TimelineGroups({
  locale,
  projection,
  view,
}: {
  locale: Locale;
  projection: NonNullable<ReturnType<typeof useExecutionExplanationTimeline>["projection"]>;
  view: ExplanationView;
}) {
  const firstPopulatedStage = useMemo(
    () => projection.stageGroups.find((group) => group.events.length > 0)?.lifecycleStage,
    [projection],
  );
  const [openStages, setOpenStages] = useState<Set<string>>(
    () => new Set(firstPopulatedStage ? [firstPopulatedStage] : []),
  );

  useEffect(() => {
    setOpenStages(new Set(firstPopulatedStage ? [firstPopulatedStage] : []));
  }, [firstPopulatedStage, projection.executionId]);

  return (
    <div className="explanation-stage-list">
      {projection.stageGroups.map((group) => (
        <details
          className="explanation-stage"
          key={group.lifecycleStage}
          onToggle={(event) => {
            const isOpen = event.currentTarget.open;
            setOpenStages((current) => {
              const next = new Set(current);
              if (isOpen) next.add(group.lifecycleStage);
              else next.delete(group.lifecycleStage);
              return next;
            });
          }}
          open={openStages.has(group.lifecycleStage)}
        >
          <summary>
            <strong>{group.lifecycleStage}</strong>
            <span>{formatT(locale, "executionExplanationStageEvents", { count: group.eventCount })}</span>
            <span className="status-pill status-pill--neutral">{displayStatus(locale, group.status)}</span>
          </summary>
          {openStages.has(group.lifecycleStage) ? (
            <>
              {group.unavailableReason ? (
                <p className="capability-notice">{group.unavailableReason.code}</p>
              ) : null}
              <div className="explanation-event-list">
                {group.events.map((event) => (
                  <TimelineEventCard event={event} key={event.eventId} locale={locale} view={view} />
                ))}
              </div>
            </>
          ) : null}
        </details>
      ))}
    </div>
  );
}

function TimelineEventCard({ event, locale, view }: { event: DecisionTimelineEvent; locale: Locale; view: ExplanationView }) {
  const [open, setOpen] = useState(false);
  return (
    <details
      className="explanation-event"
      data-event-id={event.eventId}
      onToggle={(toggleEvent) => setOpen(toggleEvent.currentTarget.open)}
    >
      <summary>
        <span>{event.eventType}</span>
        <span className="status-pill status-pill--neutral">{displayStatus(locale, event.status)}</span>
        <time dateTime={event.occurredAt}>{new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "medium" }).format(new Date(event.occurredAt))}</time>
      </summary>
      {open ? (
        <div className="explanation-event__body">
          <p className="technical-id">{event.eventId}</p>
          <ReferenceList locale={locale} refs={event.explainView.sourceRefs} />
          {view === "plain" ? <PlainView event={event} locale={locale} /> : null}
          {view === "professional" ? <ProfessionalView event={event} locale={locale} /> : null}
          {view === "raw" ? <RawView event={event} locale={locale} /> : null}
        </div>
      ) : null}
    </details>
  );
}

function PlainView({ event, locale }: { event: DecisionTimelineEvent; locale: Locale }) {
  const plain = event.explainView.plain;
  return (
    <div className="explanation-plain-grid">
      <MessageBlock label={t(locale, "executionExplanationWhat")} locale={locale} message={plain.whatHappened} />
      <MessageBlock label={t(locale, "executionExplanationWhy")} locale={locale} message={plain.why} />
      <MessageBlock label={t(locale, "executionExplanationImpact")} locale={locale} message={plain.impact} />
      <MessageBlock label={t(locale, "executionExplanationNextAction")} locale={locale} message={plain.nextAction} />
      {plain.cegPathMeaning ? <MessageBlock label={t(locale, "executionExplanationReasonCode")} locale={locale} message={plain.cegPathMeaning} /> : null}
      <div><strong>{t(locale, "executionExplanationEvidenceCount")}</strong><span>{plain.evidenceCount}</span></div>
    </div>
  );
}

function MessageBlock({ label, locale, message }: { label: string; locale: Locale; message: ExplanationMessage }) {
  return <div><strong>{label}</strong><span>{formatT(locale, message.messageKey, message.parameters)}</span></div>;
}

function ProfessionalView({ event, locale }: { event: DecisionTimelineEvent; locale: Locale }) {
  const professional = event.explainView.professional;
  if (!professional.available) return <p className="capability-notice">{t(locale, "executionExplanationProfessionalRestricted")}</p>;
  return (
    <dl className="explanation-professional-grid">
      <Field label={t(locale, "executionExplanationReasonCode")} value={professional.reasonCodes.join(", ")} />
      <Field label={t(locale, "executionExplanationRuleIds")} value={professional.ruleIds.join(", ")} />
      <Field label={t(locale, "executionExplanationPolicy")} value={professional.policy ? [professional.policy.policyId, professional.policy.versionId, professional.policy.versionHash].filter(Boolean).join(" / ") : ""} />
      <Field label={t(locale, "executionExplanationPromotionType")} value={professional.promotionType ?? ""} />
      <Field label={t(locale, "executionExplanationApproval")} value={professional.approvalState ?? (professional.humanApproved ? "approved" : "")} />
      <Field label={t(locale, "executionExplanationIntegrity")} value={professional.integrityStatus ?? ""} />
      <ReferenceField label={t(locale, "executionExplanationPolicyDecision")} locale={locale} refs={professional.policyDecisionRefs} />
      <ReferenceField label={t(locale, "executionExplanationFindingRefs")} locale={locale} refs={professional.findingRefs} />
      <ReferenceField label={t(locale, "executionExplanationMetricRefs")} locale={locale} refs={professional.metricRefs} />
      <ReferenceField label={t(locale, "executionExplanationEvidenceRefs")} locale={locale} refs={professional.evidenceRefs} />
    </dl>
  );
}

function RawView({ event, locale }: { event: DecisionTimelineEvent; locale: Locale }) {
  const raw = event.explainView.raw;
  if (!raw.available || !raw.source || !raw.projection) return <p className="capability-notice">{t(locale, "executionExplanationRawRestricted")}</p>;
  return (
    <div className="explanation-raw-view">
      <p className="read-only-note">{t(locale, "executionExplanationAuthorizedRawNotice")}</p>
      <dl className="explanation-professional-grid">
        <Field label={t(locale, "executionExplanationDataSource")} value={raw.source.sourceType} />
        <Field label={t(locale, "executionExplanationSourceTime")} value={raw.source.sourceTimestamp} />
        <Field label={t(locale, "executionExplanationProjectedTime")} value={raw.source.projectedAt} />
        <Field label={t(locale, "executionExplanationIntegrity")} value={raw.source.integrityStatus} />
        <Field label={t(locale, "executionExplanationRetention")} value={raw.source.retentionStatus} />
      </dl>
      <SafeJsonViewer locale={locale} value={raw.projection} />
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd>{value || "—"}</dd></div>;
}

function ReferenceField({ label, locale, refs }: { label: string; locale: Locale; refs: DecisionTimelineReference[] }) {
  return <div><dt>{label}</dt><dd><ReferenceList locale={locale} refs={refs} /></dd></div>;
}

function ReferenceList({ locale, refs }: { locale: Locale; refs: DecisionTimelineReference[] }) {
  if (refs.length === 0) return <span className="empty-copy">{t(locale, "executionExplanationNoRefs")}</span>;
  return (
    <ul className="explanation-reference-list">
      {refs.map((ref) => (
        <li key={`${ref.referenceType}:${ref.referenceId}:${ref.relationship}`}>
          {ref.available && ref.href ? <a href={ref.href}>{ref.referenceType}: {ref.referenceId}</a> : <span>{ref.referenceType}: {ref.referenceId} · {t(locale, "executionExplanationReferenceUnavailable")}</span>}
        </li>
      ))}
    </ul>
  );
}

function State({ copy, role, tone = "default" }: { copy: string; role: "status" | "alert"; tone?: string }) {
  return <div className={`empty-state empty-state--${tone}`} role={role}>{copy}</div>;
}

function viewLabel(view: ExplanationView): "executionExplanationPlain" | "executionExplanationProfessional" | "executionExplanationRaw" {
  if (view === "professional") return "executionExplanationProfessional";
  if (view === "raw") return "executionExplanationRaw";
  return "executionExplanationPlain";
}
