/* SPDX-License-Identifier: Apache-2.0 */
import { useState } from "react";

import { EvidenceReferenceList, type EvidenceReferenceLike } from "../components/EvidenceReferenceList";
import { SectionCard } from "../components/SectionCard";
import { useAdmissionRuns } from "../hooks/useAdmissionRuns";
import { usePrContexts } from "../hooks/usePrContexts";
import { type Locale, t } from "../i18n";
import { ApiRequestError, fetchRequirementLibrary, type CurrentUser, type RequirementMatchView } from "../lib/api";
import type { AdmissionRunProjection } from "../lib/api";
import { displayStatus, requirementMatchReasonPresentation } from "../lib/presentation";


type Props = {
  currentUser: CurrentUser | null;
  locale: Locale;
  projectId: string | null;
};

export function PrContextsPage({ currentUser, locale, projectId }: Props) {
  const canRead = currentUser?.capabilities.includes("pr.read") ?? false;
  const view = usePrContexts(projectId, canRead);
  const canReadRequirements = currentUser?.capabilities.includes("requirements.read") ?? false;
  const canReadAdmission = currentUser?.capabilities.includes("admission.read") ?? false;
  const admission = useAdmissionRuns(projectId, view.detail?.context.versionId ?? null, canReadAdmission);

  return <div className="page-shell" data-route="/pr-contexts">
    <div className="page-toolbar">
      <div><h1>{t(locale, "prContexts")}</h1><p>{t(locale, "prContextBoundary")}</p></div>
    </div>
    {view.state === "loading" ? <State text={t(locale, "loading")} /> : null}
    {view.state === "unavailable" ? <State text={t(locale, "prContextProjectUnavailable")} /> : null}
    {view.state === "restricted" ? <State text={t(locale, "prContextAccessRestricted")} /> : null}
    {view.state === "error" ? <State text={t(locale, "prContextLoadFailed")} tone="error" /> : null}
    {view.state === "empty" ? <State text={t(locale, "prContextEmpty")} /> : null}
    {view.state === "ready" ? <div className="page-columns">
      <SectionCard title={t(locale, "prContextList")} eyebrow={t(locale, "prContextProviderNeutral")}>
        <div className="list-stack" role="listbox">
          {view.items.map((item) => <button aria-selected={item.contextId === view.selectedId} className="list-row" key={item.contextId} onClick={() => view.select(item.contextId)} role="option" type="button"><span><strong>{item.provider} #{item.pullRequestNumber}</strong><small>{item.repositoryRef}</small></span><span className="badge-row"><span className="status-pill">{item.state}</span><span>v{item.latestVersion}</span></span></button>)}
        </div>
      </SectionCard>
      <SectionCard title={t(locale, "prContextDetail")} eyebrow={view.detail?.context.contextHash ?? t(locale, "loading")}>
        {view.detail ? <div className="detail-stack">
          <div className="badge-row"><span className="status-pill">{view.detail.context.state}</span><span className="status-pill">{view.detail.context.draft ? t(locale, "prContextDraft") : t(locale, "prContextReady")}</span>{view.detail.context.fork ? <span className="status-pill">{t(locale, "prContextFork")}</span> : null}</div>
          <p className="technical-id">{view.detail.context.versionId}</p>
          <p>{view.detail.context.repositoryRef} #{view.detail.context.pullRequestNumber}</p>
          <p>{t(locale, "prContextRevision")}: <code>{view.detail.context.revision.baseSha}</code> -&gt; <code>{view.detail.context.revision.headSha}</code></p>
          <p>{t(locale, "prContextChangedFiles")}: {view.detail.context.changedFiles.length}</p>
          <EvidenceReferenceList
            label={t(locale, "evidenceRefs")}
            locale={locale}
            refs={view.detail.context.changeSetRef ? [view.detail.context.changeSetRef] : []}
          />
          <h3>{t(locale, "requirementMatchStatus")}</h3>
          {view.detail.requirementMatch ? <div className="detail-stack">
            <div className="badge-row"><span className="status-pill">{view.detail.requirementMatch.status}</span>{view.detail.requirementMatch.reviewRequired ? <span className="status-pill">{t(locale, "requirementMatchReviewRequired")}</span> : null}</div>
            <details className="pr-match-audit"><summary>{t(locale, "prMatchReasonAuditDetails")}</summary><EvidenceReferenceList
              locale={locale}
              refs={[{ type: "requirement_match_snapshot", ref: `requirement-match-snapshot://${view.detail.requirementMatch.snapshotId}` }]}
            /></details>
            {view.detail.requirementMatch.explicitUnknownRefs.length ? <article className="notice notice--warning"><strong>{t(locale, "requirementMatchUnknownRefs")}</strong><p>{view.detail.requirementMatch.explicitUnknownRefs.join(", ")}</p></article> : null}
            {view.detail.requirementMatch.matches.map((match) => <article className={match.candidate.status === "confirmed" ? "notice notice--info" : "notice notice--warning"} key={match.matchId}>
              <strong>{match.candidate.requirementId} {"\u00b7"} {displayStatus(locale, match.candidate.status)}</strong>
              <p>{t(locale, "requirementVersion")}: {match.candidate.requirementVersion ?? t(locale, "unknown")} {"\u00b7"} {Math.round(match.candidate.confidence * 100)}%</p>
              {match.candidate.reviewRequired ? <p className="pr-match-review-note">{t(locale, "prMatchReviewExplanation")}</p> : null}
              <div className="detail-stack pr-match-reasons" aria-label={t(locale, "prMatchReasons")}>
                {match.candidate.reasons.map((reason) => {
                  const presentation = requirementMatchReasonPresentation(locale, reason);
                  const detailRows = prMatchReasonDetailRows(locale, reason.details);
                  return <article className="pr-match-reason" key={`${reason.code}:${reason.layer}`}>
                    <strong>{presentation.label}</strong>
                    <p>{prMatchReasonSummary(locale, reason, match.candidate)}</p>
                    <details className="pr-match-reason__facts"><summary>{t(locale, "prMatchReasonViewFacts")}</summary>
                      {detailRows.length ? <dl>{detailRows.map((row) => <div key={row.key}>
                        <dt>{row.label}</dt><dd>{row.values.length > 1 ? <ul className="pr-match-fact-list">{row.values.map((value, index) => <li key={`${value}:${index}`}>{value}</li>)}</ul> : row.values[0]}</dd>
                      </div>)}</dl> : <p>{t(locale, "prMatchReasonDetailsUnavailable")}</p>}
                      {reason.details?.factsTruncated ? <small>{t(locale, "prMatchReasonFactsTruncated")}</small> : null}
                    </details>
                    <details className="pr-match-audit"><summary>{t(locale, "prMatchReasonAuditDetails")}</summary><dl>
                      <div><dt>{t(locale, "prMatchReasonCode")}</dt><dd><code>{reason.code}</code></dd></div>
                      <div><dt>{t(locale, "prMatchReasonLayer")}</dt><dd><code>{reason.layer}</code></dd></div>
                      <div><dt>{t(locale, "prMatchReasonExplanationKey")}</dt><dd><code>{reason.explanationKey}</code></dd></div>
                    </dl>{reason.evidenceRefs?.length || reason.details?.historicalContextRef ? <EvidenceReferenceList
                      label={t(locale, "prMatchReasonEvidence")}
                      locale={locale}
                      refs={[
                        ...(reason.evidenceRefs ?? []),
                        ...(reason.details?.historicalContextRef ? [reason.details.historicalContextRef] : []),
                      ]}
                    /> : null}</details>
                  </article>;
                })}
              </div>
              <RequirementContentPreview
                canRead={canReadRequirements}
                key={match.matchId}
                locale={locale}
                projectId={projectId}
                requirementId={match.candidate.requirementId}
                versionId={match.candidate.requirementVersionId}
              />
            </article>)}
          </div> : <State text={t(locale, "requirementMatchUnavailable")} />}
          <h3>{t(locale, "admissionEvidence")}</h3>
          {admission.state === "loading" ? <State text={t(locale, "loading")} /> : null}
          {admission.state === "restricted" ? <State text={t(locale, "admissionEvidenceRestricted")} /> : null}
          {admission.state === "error" ? <State text={t(locale, "admissionEvidenceLoadFailed")} tone="error" /> : null}
          {admission.state === "empty" || admission.state === "unavailable" ? <State text={t(locale, "admissionEvidenceEmpty")} /> : null}
          {admission.state === "ready" ? <div className="detail-stack">
            {admission.items.map((run) => <article className={run.status === "completed" ? "notice notice--info" : "notice notice--warning"} key={run.admissionRunId}>
              <div className="badge-row"><strong>{t(locale, "admissionRun")}</strong><span className="status-pill">{run.mode}</span><span className="status-pill">{run.status}</span><span className="status-pill">{run.sandboxProfile.profileId}</span></div>
              <p>{t(locale, "admissionStaticScan")}: {run.staticScan?.status ?? t(locale, "unavailable")} {"·"} {t(locale, "admissionSmoke")}: {run.smokeResult?.status ?? t(locale, "unavailable")}</p>
              <small>{t(locale, "admissionNormalizedFindings")}: {(run.staticScan?.normalizedFindingRefs.length ?? 0) + (run.smokeResult?.normalizedFindingRefs.length ?? 0)} {"·"} {t(locale, "admissionArtifacts")}: {(run.staticScan?.artifactRefs.length ?? 0) + (run.smokeResult?.artifactRefs.length ?? 0)}</small>
              <EvidenceReferenceList locale={locale} maxVisible={5} refs={prAdmissionEvidence(run)} />
            </article>)}
          </div> : null}
          <div className="notice notice--info">{t(locale, "prContextDecisionBoundary")}</div>
        </div> : <State text={t(locale, "loading")} />}
      </SectionCard>
    </div> : null}
  </div>;
}

function State({ text, tone = "info" }: { text: string; tone?: "info" | "error" }) {
  return <div className={`notice notice--${tone}`} role={tone === "error" ? "alert" : "status"}>{text}</div>;
}

type MatchReason = RequirementMatchView["candidate"]["reasons"][number];
type MatchDetails = NonNullable<MatchReason["details"]>;

const MATCH_FACT_FIELDS = [
  "matchMethod", "explicitSources", "configuredPullRequestNumber", "matchedPullRequestNumber",
  "configuredLabels", "matchedLabels", "configuredPathPrefixes", "matchedPaths",
  "appliesToAll", "traceabilityPath", "capabilityRef", "overlappingLabels", "overlappingPaths",
] as const satisfies readonly (keyof MatchDetails)[];

function explicitSourceLabel(locale: Locale, source: string) {
  const names: Record<string, [string, string]> = {
    pr_title: ["PR title", "PR 标题"],
    pr_template: ["PR description", "PR 正文"],
    commit_message: ["commit message", "提交消息"],
  };
  const name = names[source];
  return name ? name[locale === "zh-CN" ? 1 : 0] : source;
}

function prMatchReasonSummary(locale: Locale, reason: MatchReason, candidate: RequirementMatchView["candidate"]) {
  const details = reason.details;
  const zh = locale === "zh-CN";
  const id = candidate.requirementId;
  const shortList = (values: string[]) => {
    const visible = values.slice(0, 2).join(zh ? "、" : ", ");
    const more = values.length - 2;
    return more > 0 ? `${visible}${zh ? `等 ${values.length} 项` : ` and ${more} more`}` : visible;
  };
  if (reason.code === "EXPLICIT_CONTROLLED_ID" || reason.code === "EXPLICIT_ID_NOT_FOUND") {
    const sources = details?.explicitSources?.length
      ? details.explicitSources
      : [...new Set((reason.evidenceRefs ?? []).map((item) => item.type).filter((type) => ["pr_title", "pr_template", "commit_message"].includes(type)))];
    const sourceText = sources.map((source) => explicitSourceLabel(locale, source));
    if (reason.code === "EXPLICIT_ID_NOT_FOUND") {
      return zh
        ? `${sourceText.length ? shortList(sourceText) : "PR 内容"}引用了 ${id}，但项目需求库中未找到该编号。`
        : `${sourceText.length ? shortList(sourceText) : "PR content"} references ${id}, but that ID was not found in this project's requirement library.`;
    }
    return zh
      ? `${sourceText.length ? shortList(sourceText) : "PR 内容"}明确引用了需求 ${id}。`
      : `${sourceText.length ? shortList(sourceText) : "PR content"} explicitly references requirement ${id}.`;
  }
  if (reason.code === "PROJECT_MAPPING_MATCH" || reason.code === "PROJECT_RULE_MATCH") {
    const matched: string[] = [];
    if (details?.matchedPullRequestNumber) matched.push(zh ? `PR 编号 ${details.matchedPullRequestNumber}` : `PR #${details.matchedPullRequestNumber}`);
    if (details?.matchedLabels?.length) matched.push(zh ? `标签 ${shortList(details.matchedLabels)}` : `label ${shortList(details.matchedLabels)}`);
    if (details?.matchedPaths?.length) matched.push(zh ? `变更文件 ${shortList(details.matchedPaths)}` : `changed file ${shortList(details.matchedPaths)}`);
    if (details?.appliesToAll && !matched.length) matched.push(zh ? "适用于所有 PR" : "applies to all PRs");
    if (matched.length) {
      const matchedText = shortList(matched);
      return zh
        ? `${matchedText}命中了${reason.code === "PROJECT_RULE_MATCH" ? "项目匹配规则" : "项目映射"}，关联需求 ${id}。`
        : `${matchedText[0].toUpperCase()}${matchedText.slice(1)} matched the ${reason.code === "PROJECT_RULE_MATCH" ? "project rule" : "project mapping"} for requirement ${id}.`;
    }
  }
  if (reason.code === "VERIFIED_CEG_TRACEABILITY" && details) {
    const path = details.matchedPaths?.length ? shortList(details.matchedPaths) : details.traceabilityPath;
    if (path) return zh
      ? `变更文件 ${path} 通过已验证的追溯关系关联到需求 ${id}。`
      : `Changed file ${path} is linked to requirement ${id} through verified traceability.`;
  }
  if (reason.code === "HISTORICAL_OVERLAP" && details) {
    const overlaps = [...(details.overlappingPaths ?? []), ...(details.overlappingLabels ?? [])];
    if (overlaps.length) return zh
      ? `当前 PR 与历史匹配记录在 ${shortList(overlaps)} 上重合，因此将需求 ${id} 列为待复核候选。`
      : `This PR overlaps a prior match on ${shortList(overlaps)}, so requirement ${id} remains a candidate for review.`;
  }
  if (reason.code === "AI_SUGGESTION") return zh
    ? `模型建议将需求 ${id} 作为候选（置信度 ${Math.round(candidate.confidence * 100)}%）；快照未保存可独立核验的命中条件，需人工复核。`
    : `The model suggested requirement ${id} (${Math.round(candidate.confidence * 100)}% confidence). This snapshot has no independently verifiable matching condition; review is required.`;
  return requirementMatchReasonPresentation(locale, reason).explanation;
}

function prMatchReasonDetailRows(locale: Locale, details: MatchDetails | null) {
  if (!details) return [];
  const labels: Record<(typeof MATCH_FACT_FIELDS)[number], [string, string]> = {
    matchMethod: ["Match method", "匹配方式"],
    explicitSources: ["ID found in", "编号出现于"],
    configuredPullRequestNumber: ["Configured PR number", "配置的 PR 编号"],
    matchedPullRequestNumber: ["Matched PR number", "命中的 PR 编号"],
    configuredLabels: ["Configured labels", "配置的标签"],
    matchedLabels: ["Matched labels", "实际命中的标签"],
    configuredPathPrefixes: ["Configured path prefixes", "配置的路径前缀"],
    matchedPaths: ["Matched changed files", "实际命中的变更文件"],
    appliesToAll: ["Applies to all PRs", "适用于所有 PR"],
    traceabilityPath: ["Traceability path", "追溯路径"],
    capabilityRef: ["Capability reference", "能力引用"],
    overlappingLabels: ["Overlapping labels", "重合标签"],
    overlappingPaths: ["Overlapping paths", "重合路径"],
  };
  const methods: Record<string, [string, string]> = {
    explicit_reference: ["Explicit requirement reference", "显式需求引用"],
    manual_mapping: ["Project mapping", "项目映射"],
    verified_traceability: ["Verified traceability", "已验证追溯关系"],
    project_rule: ["Project matching rule", "项目匹配规则"],
    historical_overlap: ["Historical overlap", "历史记录重合"],
    ai_suggestion: ["AI suggestion", "AI 建议"],
  };
  return MATCH_FACT_FIELDS.flatMap((key) => {
    const value = details[key];
    if (value === null || value === undefined || (Array.isArray(value) && !value.length)) return [];
    const values = key === "matchMethod" && methods[String(value)]
      ? [methods[String(value)][locale === "zh-CN" ? 1 : 0]]
      : key === "explicitSources" && Array.isArray(value)
        ? value.map((source) => explicitSourceLabel(locale, source))
        : Array.isArray(value)
          ? value
          : [typeof value === "boolean" ? (locale === "zh-CN" ? (value ? "是" : "否") : (value ? "Yes" : "No")) : String(value)];
    return [{ key, label: labels[key][locale === "zh-CN" ? 1 : 0], values }];
  });
}

function RequirementContentPreview({ canRead, locale, projectId, requirementId, versionId }: {
  canRead: boolean;
  locale: Locale;
  projectId: string | null;
  requirementId: string;
  versionId: string | null;
}) {
  const [preview, setPreview] = useState<{ status: "idle" | "loading" | "ready" | "unavailable" | "restricted" | "error"; text: string | null }>({ status: "idle", text: null });
  const load = async () => {
    if (!canRead || !projectId || !versionId || preview.status === "loading" || preview.status === "ready") return;
    setPreview({ status: "loading", text: null });
    try {
      const data = await fetchRequirementLibrary({ projectId, requirementVersionId: versionId, keyword: requirementId, pageSize: 100 });
      const item = data.items.find((entry) => entry.itemType === "requirement_item" && entry.requirementVersionId === versionId && entry.requirementItemId?.toLowerCase() === requirementId.toLowerCase());
      setPreview(item?.title ? { status: "ready", text: item.title } : { status: "unavailable", text: null });
    } catch (error) {
      setPreview({ status: error instanceof ApiRequestError && [401, 403].includes(error.status) ? "restricted" : "error", text: null });
    }
  };
  return <section className="pr-match-content">
    <strong>{t(locale, "prMatchRequirementText")}</strong>
    {canRead && projectId && versionId ? <>
      <div className="pr-match-content__actions">
        <button className="secondary-button" disabled={preview.status === "loading" || preview.status === "ready"} onClick={() => void load()} type="button">{t(locale, "prMatchRequirementContent")}</button>
        <a className="link-button" href={`/requirement-intake?projectId=${encodeURIComponent(projectId)}&requirementVersionId=${encodeURIComponent(versionId)}`}>{t(locale, "prMatchRequirementVersionLink")}</a>
      </div>
      {preview.status === "loading" ? <p>{t(locale, "prMatchRequirementLoading")}</p> : null}
      {preview.status === "ready" ? <p className="pr-match-content__text">{preview.text}</p> : null}
      {preview.status === "unavailable" ? <p>{t(locale, "prMatchRequirementUnavailable")}</p> : null}
      {preview.status === "restricted" ? <p>{t(locale, "prMatchRequirementRestricted")}</p> : null}
      {preview.status === "error" ? <p>{t(locale, "prMatchRequirementLoadFailed")}</p> : null}
    </> : <p>{canRead ? t(locale, "prMatchRequirementUnavailable") : t(locale, "prMatchRequirementRestricted")}</p>}
  </section>;
}

function prAdmissionEvidence(run: AdmissionRunProjection): EvidenceReferenceLike[] {
  const refs: EvidenceReferenceLike[] = [
    { type: "admission_run", ref: `admission-run://${run.admissionRunId}` },
    ...(run.staticScan?.artifactRefs ?? []),
    ...(run.staticScan?.normalizedFindingRefs ?? []),
    ...(run.smokeResult?.artifactRefs ?? []),
    ...(run.smokeResult?.normalizedFindingRefs ?? []),
  ];
  const seen = new Set<string>();
  return refs.filter((item) => {
    const ref = typeof item.ref === "string" ? item.ref : "";
    if (!ref || seen.has(ref)) return false;
    seen.add(ref);
    return true;
  });
}
