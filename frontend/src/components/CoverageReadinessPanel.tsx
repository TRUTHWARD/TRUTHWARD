/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useState } from "react";

import { type Locale, t, userFacingError } from "../i18n";
import {
  fetchCoverageReadiness,
  materializeCommunityCoverage,
  type CoverageReadiness,
  type CoverageReadinessIssue,
  type CoverageReadinessStage,
} from "../lib/api";
import { SectionCard } from "./SectionCard";


type Props = {
  canRead: boolean;
  focusStage: CoverageReadinessStage["id"];
  locale: Locale;
  projectId: string | null;
  onMaterialized?: () => void | Promise<void>;
};

type LoadState = "idle" | "loading" | "ready" | "restricted" | "error";

const stageLabelKeys: Record<CoverageReadinessStage["id"], "coverageStageChangeSet" | "coverageStageImpact" | "coverageStageReplay" | "coverageStageProof"> = {
  change_set: "coverageStageChangeSet",
  impact: "coverageStageImpact",
  selective_replay: "coverageStageReplay",
  proof: "coverageStageProof",
};

const issueLabelKeys: Record<string, keyof typeof import("../i18n").dictionaries["en-US"]> = {
  REQUIREMENT_VERSION_MISSING: "coverageIssueRequirementMissing",
  REQUIREMENT_HISTORY_OR_SCM_CHANGE_MISSING: "coverageIssueRequirementHistory",
  CHANGE_SET_GENERATION_UNAVAILABLE: "coverageIssueChangeSetUnavailable",
  CHANGE_SET_MISSING: "coverageIssueChangeSetMissing",
  EXECUTION_GRAPH_MISSING: "coverageIssueGraphMissing",
  CAPABILITY_MAPPING_MISSING: "coverageIssueMappingMissing",
  IMPACT_GENERATION_UNAVAILABLE: "coverageIssueImpactUnavailable",
  IMPACT_RESULT_MISSING: "coverageIssueImpactMissing",
  BASE_EXECUTION_MISSING: "coverageIssueExecutionMissing",
  COVERAGE_SNAPSHOT_MISSING: "coverageIssueSnapshotMissing",
  REPLAY_GENERATION_UNAVAILABLE: "coverageIssueReplayUnavailable",
  TRACEABILITY_SNAPSHOT_MISSING: "coverageIssueTraceabilityMissing",
  PROOF_GENERATION_UNAVAILABLE: "coverageIssueProofUnavailable",
  CHANGE_SET_STALE: "coverageIssueChangeSetStale",
  IMPACT_RESULT_STALE: "coverageIssueImpactStale",
  SELECTIVE_REPLAY_PLAN_STALE: "coverageIssueReplayStale",
  COVERAGE_PROOF_STALE: "coverageIssueProofStale",
};

export function CoverageReadinessPanel({ canRead, focusStage, locale, onMaterialized, projectId }: Props) {
  const [state, setState] = useState<LoadState>("idle");
  const [readiness, setReadiness] = useState<CoverageReadiness | null>(null);
  const [errorText, setErrorText] = useState("");
  const [materializationState, setMaterializationState] = useState<"idle" | "loading" | "complete" | "partial" | "error">("idle");
  const [materializationError, setMaterializationError] = useState("");

  useEffect(() => {
    let active = true;
    setReadiness(null);
    setErrorText("");
    if (!projectId || !canRead) {
      setState(canRead ? "idle" : "restricted");
      return () => { active = false; };
    }
    setState("loading");
    void fetchCoverageReadiness(projectId).then((response) => {
      if (!active) return;
      setReadiness(response);
      setState("ready");
    }).catch((error) => {
      if (!active) return;
      const status = error instanceof Error && "status" in error ? Number((error as Error & { status: number }).status) : null;
      setErrorText(userFacingError(locale, error, "coverageReadinessLoadFailed"));
      setState(status === 403 ? "restricted" : "error");
    });
    return () => { active = false; };
  }, [canRead, locale, projectId]);

  if (state === "idle") return null;
  if (state === "loading") return <div className="notice notice--info" role="status">{t(locale, "coverageReadinessLoading")}</div>;
  if (state === "restricted") return <div className="notice notice--warning" role="status">{t(locale, "coverageReadinessRestricted")}</div>;
  if (state === "error") return <div className="notice notice--error" role="alert">{errorText}</div>;
  if (!readiness) return null;

  const materialize = async () => {
    if (!projectId || materializationState === "loading") return;
    setMaterializationError("");
    setMaterializationState("loading");
    try {
      const result = await materializeCommunityCoverage(projectId);
      setReadiness(result.readiness);
      setMaterializationState(result.complete ? "complete" : "partial");
      await onMaterialized?.();
    } catch (error) {
      setMaterializationError(userFacingError(locale, error, "coverageMaterializationFailed"));
      setMaterializationState("error");
    }
  };

  return (
    <SectionCard title={t(locale, "coverageReadinessTitle")} eyebrow={t(locale, "coverageReadinessServerDerived")}>
      <div className="detail-stack">
        <p>{t(locale, "coverageReadinessExplanation")}</p>
        {readiness.commandAvailability.analysisMaterialize ? (
          <div className="coverage-readiness-actions">
            <button
              className="button button--primary"
              disabled={materializationState === "loading"}
              onClick={() => void materialize()}
              type="button"
            >
              {materializationState === "loading"
                ? t(locale, "coverageMaterializationRunning")
                : t(locale, "coverageMaterializationAction")}
            </button>
            <small>{t(locale, "coverageMaterializationBoundary")}</small>
          </div>
        ) : null}
        {materializationState === "complete" ? <div className="notice notice--info" role="status">{t(locale, "coverageMaterializationComplete")}</div> : null}
        {materializationState === "partial" ? <div className="notice notice--warning" role="status">{t(locale, "coverageMaterializationPartial")}</div> : null}
        {materializationState === "error" ? <div className="notice notice--error" role="alert">{materializationError}</div> : null}
        <div className="coverage-readiness-flow">
          {readiness.stages.map((stage) => (
            <article
              className={`coverage-readiness-stage coverage-readiness-stage--${stage.status}${stage.id === focusStage ? " coverage-readiness-stage--focused" : ""}`}
              key={stage.id}
            >
              <div className="badge-row">
                <strong>{t(locale, stageLabelKeys[stage.id])}</strong>
                <span className={`status-pill status-pill--${stage.status}`}>
                  {stage.status === "ready"
                    ? t(locale, "coverageReadinessReady")
                    : stage.status === "stale"
                      ? t(locale, "coverageReadinessStale")
                      : t(locale, "coverageReadinessBlocked")}
                </span>
              </div>
              <p>{t(locale, "coverageReadinessRecordCount")}: {stage.recordCount}</p>
              {!stage.generationAvailable && stage.status !== "ready" ? <p className="muted-text">{t(locale, "coverageReadinessNoCommand")}</p> : null}
              {stage.issues.length ? (
                <ul className="coverage-readiness-issues">
                  {stage.issues.map((issue) => <Issue key={`${stage.id}-${issue.code}`} issue={issue} locale={locale} />)}
                </ul>
              ) : <p className="muted-text">{t(locale, "coverageReadinessPrerequisitesMet")}</p>}
              {stage.id === "change_set" && stage.status !== "ready" ? (
                <a className="button button--secondary" href={stage.nextRoute}>{t(locale, "coverageReadinessOpenRequirements")}</a>
              ) : null}
              {stage.id === "selective_replay" && readiness.counts.executions === 0 ? (
                <a className="button button--secondary" href="/executions">{t(locale, "coverageReadinessOpenExecutions")}</a>
              ) : null}
            </article>
          ))}
        </div>
        <div className="notice notice--info">
          <strong>{t(locale, "coverageReadinessCurrentData")}</strong>
          <p>{t(locale, "coverageReadinessCurrentDataSummary")
            .replace("{requirements}", String(readiness.counts.trackedRequirementVersions))
            .replace("{plans}", String(readiness.counts.testPlans))
            .replace("{executions}", String(readiness.counts.executions))
            .replace("{graphs}", String(readiness.counts.graphVersions))
            .replace("{snapshots}", String(readiness.counts.coverageSnapshots))}</p>
        </div>
      </div>
    </SectionCard>
  );
}

function Issue({ issue, locale }: { issue: CoverageReadinessIssue; locale: Locale }) {
  const key = issueLabelKeys[issue.code];
  const label = key ? t(locale, key) : issue.code;
  return <li className={issue.severity === "blocking" ? "error-copy" : "muted-text"}>{label}</li>;
}
