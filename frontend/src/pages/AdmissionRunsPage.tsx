/* SPDX-License-Identifier: Apache-2.0 */
import { useState } from "react";

import { SectionCard } from "../components/SectionCard";
import { useAdmissionGovernance } from "../hooks/useAdmissionGovernance";
import { type Locale, t } from "../i18n";
import {
  ApiRequestError,
  changeCIEnforcementPolicy,
  requestAdmissionReview,
  retryCIWriteback,
  retryAdmissionRun,
  type AdmissionArtifactRef,
  type CurrentUser,
} from "../lib/api";


type Props = {
  currentUser: CurrentUser | null;
  locale: Locale;
  projectId: string | null;
};

type ActionState = "idle" | "working" | "accepted" | "restricted" | "error";

export function AdmissionRunsPage({ currentUser, locale, projectId }: Props) {
  const canRead = currentUser?.capabilities.includes("admission.read") ?? false;
  const canReview = currentUser?.capabilities.includes("admission.review") ?? false;
  const canRetry = currentUser?.capabilities.includes("admission.retry") ?? false;
  const canManageEnforce = currentUser?.capabilities.includes("enforce.manage") ?? false;
  const canRetryCI = currentUser?.capabilities.includes("ci.retry") ?? false;
  const view = useAdmissionGovernance(projectId, canRead);
  const [actionState, setActionState] = useState<ActionState>("idle");
  const [branchProtectionConfirmed, setBranchProtectionConfirmed] = useState(false);

  async function requestReview() {
    if (!projectId || !view.selectedId || !canReview) return;
    setActionState("working");
    try {
      await requestAdmissionReview(projectId, view.selectedId, {
        intent: "acknowledge_evidence",
        idempotencyKey: `admission-review-${view.selectedId}`,
      });
      setActionState("accepted");
      view.refresh();
    } catch (error) {
      setActionState(error instanceof ApiRequestError && error.status === 403 ? "restricted" : "error");
    }
  }

  async function requestRetry() {
    if (!projectId || !view.selectedId || !canRetry) return;
    setActionState("working");
    try {
      await retryAdmissionRun(projectId, view.selectedId, "failed_only");
      setActionState("accepted");
      view.refresh();
    } catch (error) {
      setActionState(error instanceof ApiRequestError && error.status === 403 ? "restricted" : "error");
    }
  }

  async function requestEnforce() {
    if (!projectId || !view.detail || !canManageEnforce || !branchProtectionConfirmed) return;
    setActionState("working");
    try {
      await changeCIEnforcementPolicy(projectId, {
        repositoryRef: view.detail.repositoryRef,
        targetMode: "enforce",
        branchProtectionConfigured: true,
        reason: t(locale, "admissionEnforceRequestReason"),
        idempotencyKey: `admission-enforce-${view.detail.repositoryRef}-${Date.now()}`,
      });
      setActionState("accepted");
      view.refresh();
    } catch (error) {
      setActionState(error instanceof ApiRequestError && error.status === 403 ? "restricted" : "error");
    }
  }

  async function requestCIRetry() {
    if (!projectId || !view.selectedId || !canRetryCI) return;
    setActionState("working");
    try {
      await retryCIWriteback(projectId, view.selectedId, t(locale, "admissionCIRetryReason"));
      setActionState("accepted");
      view.refresh();
    } catch (error) {
      setActionState(error instanceof ApiRequestError && error.status === 403 ? "restricted" : "error");
    }
  }

  const detail = view.detail;
  const result = detail?.admissionResult;
  const evidence = result?.evidenceRefs ?? [];

  return <div className="page-shell" data-route="/admission-runs">
    <div className="page-toolbar">
      <div><h1>{t(locale, "admissionRuns")}</h1><p>{t(locale, "admissionBoundary")}</p></div>
      <div className="badge-row"><span className="status-pill">{t(locale, "admissionObserveShadowEnforce")}</span></div>
    </div>
    {view.state === "loading" ? <State text={t(locale, "loading")} /> : null}
    {view.state === "unavailable" ? <State text={t(locale, "admissionProjectUnavailable")} /> : null}
    {view.state === "restricted" ? <State text={t(locale, "admissionAccessRestricted")} /> : null}
    {view.state === "error" ? <State text={t(locale, "admissionLoadFailed")} /> : null}
    {view.state === "empty" ? <State text={t(locale, "admissionEmpty")} /> : null}
    {view.state === "ready" ? <div className="page-columns">
      <SectionCard title={t(locale, "admissionRunList")} eyebrow={t(locale, "admissionFrozenIdentity")}>
        <div className="list-stack" role="listbox">
          {view.items.map((run) => <button aria-selected={run.admissionRunId === view.selectedId} className="list-row" key={run.admissionRunId} onClick={() => view.select(run.admissionRunId)} role="option" type="button">
            <span><strong>{run.repositoryRef} #{run.pullRequestNumber}</strong><small>{run.sourceHeadSha.slice(0, 12)} {"·"} {run.workflowVersion}</small></span>
            <span className="badge-row"><span className="status-pill">{run.mode}</span><span className="status-pill">{run.status}</span></span>
          </button>)}
        </div>
      </SectionCard>
      <SectionCard title={t(locale, "admissionRunDetail")} eyebrow={detail?.rootTraceRef ?? t(locale, "loading")}>
        {detail && view.timeline ? <div className="detail-stack">
          <div className="badge-row"><span className="status-pill">{detail.mode}</span><span className="status-pill">{detail.status}</span><span className="status-pill">{result?.conclusion ?? t(locale, "unavailable")}</span></div>
          <p>{detail.repositoryRef} #{detail.pullRequestNumber}</p>
          <p>{t(locale, "admissionRevision")}: <code>{detail.baseSha}</code> -&gt; <code>{detail.sourceHeadSha}</code></p>
          <p className="technical-id">{detail.inputFingerprint}</p>

          <h3>{t(locale, "admissionStageTimeline")}</h3>
          <div className="detail-stack" aria-label={t(locale, "admissionStageTimeline")}>
            {view.timeline.stages.map((stage) => <article className={stage.status === "completed" ? "notice notice--info" : "notice notice--warning"} key={stage.lifecycleStage}>
              <div className="badge-row"><strong>{stage.sequence}. {stage.lifecycleStage}</strong><span className="status-pill">{stage.status}</span></div>
              {stage.reasonCode ? <small>{stage.reasonCode}</small> : null}
              <small>{t(locale, "admissionTraceRefs")}: {stage.traceRefs.length} {"·"} {t(locale, "admissionEvidenceRefs")}: {stage.evidenceRefs.length}</small>
            </article>)}
          </div>

          <h3>{t(locale, "admissionFrozenInputs")}</h3>
          <div className="badge-row">
            <Ref label={t(locale, "requirementMatchStatus")} value={detail.requirementMatchRef?.ref} />
            <Ref label={t(locale, "admissionImpact")} value={detail.impactResultRef?.ref} />
            <Ref label={t(locale, "admissionChangeSet")} value={detail.changeSetRef?.ref} />
            <Ref label={t(locale, "admissionReplayPlan")} value={detail.selectiveReplayPlanRef.ref} />
          </div>

          <h3>{t(locale, "admissionEvidence")}</h3>
          <p>{t(locale, "admissionStaticScan")}: {detail.staticScan?.status ?? t(locale, "unavailable")} {"·"} {t(locale, "admissionSmoke")}: {detail.smokeResult?.status ?? t(locale, "unavailable")}</p>
          <p>{t(locale, "admissionNormalizedFindings")}: {result?.normalizedFindingRefs.length ?? 0} {"·"} {t(locale, "admissionEvidenceRefs")}: {evidence.length}</p>
          <EvidenceList evidence={evidence} locale={locale} />

          <h3>{t(locale, "admissionShadowGate")}</h3>
          {result?.shadowGate ? <article className="notice notice--warning"><div className="badge-row"><strong>{result.shadowGate.decision ?? result.shadowGate.status}</strong><span className="status-pill">{t(locale, "admissionNonAuthoritative")}</span></div><p>{result.shadowGate.reasonCodes.join(", ") || result.shadowGate.reasonCode}</p><small>{t(locale, "admissionNoWriteback")}</small></article> : <State text={detail.mode === "observe" ? t(locale, "admissionObserveNoGate") : t(locale, "admissionShadowUnavailable")} />}

          {result?.enforceGate ? <><h3>{t(locale, "admissionEnforceGate")}</h3><article className="notice notice--warning"><div className="badge-row"><strong>{result.enforceGate.decision ?? result.enforceGate.status}</strong><span className="status-pill">{t(locale, "admissionAuthoritative")}</span></div><p>{result.enforceGate.reasonCodes.join(", ") || result.enforceGate.reasonCode}</p></article></> : null}

          <h3>{t(locale, "admissionCIWriteback")}</h3>
          <article className={detail.ciWriteback?.writeStatus === "completed" ? "notice notice--info" : "notice notice--warning"}>
            <div className="badge-row"><strong>{detail.ciWriteback?.status ?? t(locale, "unavailable")}</strong><span className="status-pill">{detail.ciWriteback?.writeStatus ?? detail.enforcementReadiness.status}</span><span className="status-pill">{detail.enforcementReadiness.mode}</span></div>
            <p>{detail.ciWriteback?.conclusion.summary ?? detail.enforcementReadiness.unavailableReason ?? t(locale, "admissionCINotWritten")}</p>
            <small>{t(locale, "admissionHeadCheck")}: {detail.ciWriteback?.staleRevision.status ?? t(locale, "unavailable")} {detail.ciWriteback?.staleRevision.reasonCode ?? ""}</small>
            {detail.ciWriteback?.legacyFieldNotice ? <p>{detail.ciWriteback.legacyFieldNotice.reasonCode}</p> : null}
            {detail.ciWriteback?.externalAction?.url ? <p><a href={detail.ciWriteback.externalAction.url} rel="noreferrer" target="_blank">{t(locale, "admissionExternalCheck")}</a></p> : null}
          </article>

          <h3>{t(locale, "admissionEnforceReadiness")}</h3>
          <article className={detail.enforcementReadiness.ready ? "notice notice--info" : "notice notice--warning"}><div className="badge-row"><strong>{detail.enforcementReadiness.ready ? t(locale, "admissionReady") : t(locale, "admissionNotReady")}</strong><span className="status-pill">{detail.enforcementReadiness.status}</span></div><p>{t(locale, "admissionBranchProtectionExternal")}</p></article>
          {canManageEnforce ? <div className="detail-stack">
            <label><input checked={branchProtectionConfirmed} onChange={(event) => setBranchProtectionConfirmed(event.target.checked)} type="checkbox" /> {t(locale, "admissionConfirmBranchProtection")}</label>
            <button className="secondary-button" disabled={actionState === "working" || !branchProtectionConfirmed} onClick={() => void requestEnforce()} type="button">{t(locale, "admissionRequestEnforce")}</button>
          </div> : null}
          {canRetryCI && ["failed", "unknown"].includes(detail.ciWriteback?.writeStatus ?? "") ? <button className="secondary-button" disabled={actionState === "working"} onClick={() => void requestCIRetry()} type="button">{t(locale, "admissionRetryCI")}</button> : null}

          <h3>{t(locale, "admissionHumanReview")}</h3>
          <article className="notice notice--info"><div className="badge-row"><strong>{view.review?.state ?? detail.review.state}</strong><span className="status-pill">{t(locale, "admissionAnnotationOnly")}</span></div><p>{t(locale, "admissionReviewBoundary")}</p></article>
          {canReview || canRetry ? <div className="button-row">
            {canReview ? <button className="secondary-button" disabled={actionState === "working"} onClick={() => void requestReview()} type="button">{t(locale, "admissionRequestReview")}</button> : null}
            {canRetry ? <button className="secondary-button" disabled={actionState === "working"} onClick={() => void requestRetry()} type="button">{t(locale, "admissionRetryFailed")}</button> : null}
          </div> : <State text={t(locale, "admissionBasicReadOnly")} />}
          {actionState === "accepted" ? <State text={t(locale, "admissionActionAccepted")} /> : null}
          {actionState === "restricted" ? <State text={t(locale, "admissionActionRestricted")} /> : null}
          {actionState === "error" ? <State text={t(locale, "admissionActionFailed")} /> : null}
        </div> : <State text={t(locale, "loading")} />}
      </SectionCard>
    </div> : null}
  </div>;
}

function Ref({ label, value }: { label: string; value?: string | null }) {
  return <span className="status-pill" title={value ?? undefined}>{label}: {value ? value.split("://")[1]?.slice(0, 8) ?? value.slice(0, 8) : "-"}</span>;
}

function EvidenceList({ evidence, locale }: { evidence: AdmissionArtifactRef[]; locale: Locale }) {
  if (!evidence.length) return <State text={t(locale, "admissionEvidenceEmpty")} />;
  return <div className="list-stack">{evidence.map((item) => <article className="list-row" key={item.ref}><span><strong>{item.type}</strong><small className="technical-id">{item.ref}</small></span><span className="status-pill">{item.redactionStatus ?? t(locale, "readOnly")}</span></article>)}</div>;
}

function State({ text }: { text: string }) {
  return <div className="notice notice--info" role="status">{text}</div>;
}
