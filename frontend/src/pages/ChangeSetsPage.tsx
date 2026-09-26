/* SPDX-License-Identifier: Apache-2.0 */
import { SectionCard } from "../components/SectionCard";
import { CoverageReadinessPanel } from "../components/CoverageReadinessPanel";
import { EvidenceReferenceList } from "../components/EvidenceReferenceList";
import { useChangeSets } from "../hooks/useChangeSets";
import { type Locale, t } from "../i18n";
import type { CurrentUser, RequirementContentPreview } from "../lib/api";


type Props = {
  currentUser: CurrentUser | null;
  locale: Locale;
  projectId: string | null;
};

export function ChangeSetsPage({ currentUser, locale, projectId }: Props) {
  const canRead = currentUser?.capabilities.includes("change.read") ?? false;
  const canReadRequirements = currentUser?.capabilities.includes("requirements.read") ?? false;
  const view = useChangeSets(projectId, canRead, canReadRequirements);
  const visibleItems = view.detail && !view.items.some((item) => item.changeSetId === view.detail?.changeSetId)
    ? [view.detail, ...view.items]
    : view.items;
  const previewsByItemId = new Map(view.contentPreview?.items.map((item) => [item.itemId, item]) ?? []);

  return (
    <div className="page-shell" data-route="/change-sets">
      <div className="page-toolbar">
        <div>
          <h1>{t(locale, "changeSets")}</h1>
          <p>{t(locale, "changeSetBoundary")}</p>
        </div>
        {view.readOnly ? <span className="status-pill">{t(locale, "readOnly")}</span> : null}
      </div>

      {view.state === "loading" ? <State text={t(locale, "loading")} /> : null}
      {view.state === "unavailable" ? <State text={t(locale, "changeSetProjectUnavailable")} /> : null}
      {view.state === "restricted" ? <State text={t(locale, "changeSetAccessRestricted")} /> : null}
      {view.state === "error" ? <State text={t(locale, "changeSetLoadFailed")} tone="error" /> : null}
      {view.state === "empty" ? <>
        <State text={t(locale, "changeSetEmpty")} />
      </> : null}
      {view.state === "empty" || view.state === "ready" ? <CoverageReadinessPanel canRead={currentUser?.capabilities.includes("coverage.read") ?? false} focusStage="change_set" locale={locale} onMaterialized={view.reload} projectId={projectId} /> : null}

      {view.state === "ready" ? <div className="page-columns">
        <SectionCard title={t(locale, "changeSetList")} eyebrow={t(locale, "changeSetStableInputs")}>
          <div className="list-stack" role="listbox">
            {visibleItems.map((item) => <button aria-selected={item.changeSetId === view.selectedId} className="list-row" key={item.changeSetId} onClick={() => view.select(item.changeSetId)} role="option" type="button"><span><strong>{item.changeSetType}</strong><small>{item.sourceType} · {item.sourceRevision}</small></span><span className="badge-row"><span className={`status-pill status-pill--${item.status}`}>{item.status}</span><span>{item.itemCount} {t(locale, "changeSetItems")} · {item.issueCount} {t(locale, "changeSetIssues")}</span></span></button>)}
          </div>
        </SectionCard>

        <SectionCard title={t(locale, "changeSetDetail")} eyebrow={view.detail?.normalizerVersion ?? t(locale, "loading")}>
          {view.detail ? <div className="detail-stack">
            <div className="badge-row"><span className="status-pill">{view.detail.changeSetType}</span><span className={`status-pill status-pill--${view.detail.status}`}>{view.detail.status}</span>{view.detail.sensitive ? <span className="status-pill status-pill--partial">{t(locale, "changeSetSensitiveRedacted")}</span> : null}</div>
            <p className="technical-id">{view.detail.changeSetId}</p>
            <p>{t(locale, "changeSetSourceRevision")}: <code>{view.detail.sourceRevision}</code></p>
            <p>{t(locale, "changeSetFingerprint")}: <code>{view.detail.fingerprint}</code></p>
            <p>{t(locale, "changeSetTrace")}: <code>{view.detail.traceId}</code></p>
            <p>{t(locale, "changeSetItems")}: {view.detail.itemCount} · {t(locale, "changeSetIssues")}: {view.detail.issueCount}</p>
            {view.detail.items?.map((item) => <RequirementChangeArticle
              item={item}
              key={item.itemId}
              locale={locale}
              preview={previewsByItemId.get(item.itemId)}
              previewState={view.contentPreviewState}
            />)}
            {view.detail.files?.map((file) => <article className="notice notice--info" key={file.fileId}>
              <strong>{file.path} · {file.changeType}</strong>
              <p>{file.language ?? t(locale, "unknown")} · {t(locale, "changeSetHunks")}: {file.hunks.length}</p>
              {file.riskHints.length ? <p>{file.riskHints.join(", ")}</p> : null}
              <details><summary>{t(locale, "technicalDetails")}</summary>
                {file.oldPath ? <p>{t(locale, "changeSetOldPath")}: {file.oldPath}</p> : null}
                {file.hunks.map((hunk) => <div key={hunk.hunkId}>
                  <code>{hunk.header}</code>
                  <p>{t(locale, "changeSetLineRange")}: {t(locale, "changeSetBeforeText")} {hunk.oldLineStart} · {t(locale, "changeSetAfterText")} {hunk.newLineStart}</p>
                  {hunk.symbols.length ? <p>{t(locale, "changeSetSymbols")}: {hunk.symbols.map((symbol) => `${symbol.name} (${symbol.changeType})`).join(", ")}</p> : null}
                </div>)}
              </details>
            </article>)}
            {view.detail.issues.map((issue) => <article className="notice notice--warning" key={issue.issueId}><strong>{issue.category} · {issue.code}</strong><p>{issue.message}</p></article>)}
            <EvidenceReferenceList label={t(locale, "evidenceSourceReferences")} refs={view.detail.sourceRefs.map((ref) => requirementSourceLink(ref, projectId, view.contentPreview?.libraryVersionIds ?? []))} locale={locale} />
            <EvidenceReferenceList label={t(locale, "evidenceArtifactReferences")} refs={view.detail.artifactRefs} locale={locale} />
            <EvidenceReferenceList label={t(locale, "evidenceReplayReferences")} refs={view.detail.replayRefs} locale={locale} />
          </div> : <State text={t(locale, "loading")} />}
        </SectionCard>
      </div> : null}
    </div>
  );
}

function State({ text, tone = "info" }: { text: string; tone?: "info" | "error" }) {
  return <div className={`notice notice--${tone}`} role={tone === "error" ? "alert" : "status"}>{text}</div>;
}

type RequirementItem = NonNullable<import("../lib/api").ChangeSetDetail["items"]>[number];
type PreviewItem = RequirementContentPreview["items"][number];

function RequirementChangeArticle({ item, locale, preview, previewState }: {
  item: RequirementItem;
  locale: Locale;
  preview: PreviewItem | undefined;
  previewState: "loading" | "ready" | "restricted" | "error";
}) {
  const changedText = preview?.before.text !== preview?.after.text;
  return <article className="notice notice--info">
    <strong>{t(locale, "requirement")} {item.requirementId} · {changeTypeLabel(locale, item.changeType)}</strong>
    {preview?.identityBasis === "position" && item.changeType === "update" ? <small>{t(locale, "changeSetPositionalIdentity")}</small> : null}
    {previewState === "loading" ? <p>{t(locale, "loading")}</p> : null}
    {previewState === "restricted" ? <p>{t(locale, "changeSetContentRestricted")}</p> : null}
    {previewState === "error" ? <p>{t(locale, "changeSetContentUnavailable")}</p> : null}
    {previewState === "ready" && !preview ? <p>{t(locale, "changeSetContentUnavailable")}</p> : null}
    {preview ? <>
      {preview.before.status === "available" && (item.changeType !== "update" || changedText) ? <div><small>{t(locale, "changeSetBeforeText")}</small><p className="change-content-text">{preview.before.text}{preview.before.truncated ? "…" : ""}</p></div> : null}
      {preview.after.status === "available" && (item.changeType !== "update" || changedText) ? <div><small>{t(locale, "changeSetAfterText")}</small><p className="change-content-text">{preview.after.text}{preview.after.truncated ? "…" : ""}</p></div> : null}
      {item.changeType === "update" && preview.before.status === "available" && preview.after.status === "available" && !changedText ? <p>{t(locale, "changeSetTextUnchanged")}</p> : null}
      {preview.before.status === "unavailable" || preview.after.status === "unavailable" ? <p>{t(locale, "changeSetContentUnavailable")}</p> : null}
      {preview.before.status === "absent" && preview.after.status === "absent" ? <p>{t(locale, "changeSetContentUnavailable")}</p> : null}
    </> : null}
    <details><summary>{t(locale, "technicalDetails")}</summary><p>{t(locale, "changeSetChangedFields")}: {item.changedFields.join(", ") || t(locale, "none")}</p></details>
  </article>;
}

function changeTypeLabel(locale: Locale, value: string) {
  const labels: Record<string, Parameters<typeof t>[1]> = { add: "changeSetAdded", remove: "changeSetRemoved", update: "changeSetUpdated" };
  return labels[value] ? t(locale, labels[value]) : value;
}

function requirementSourceLink(ref: Record<string, unknown>, projectId: string | null, libraryVersionIds: string[]) {
  if (!projectId || ref.type !== "requirement_version" || typeof ref.ref !== "string") return ref;
  const match = ref.ref.match(/^requirement:\/\/versions\/([0-9a-f-]{36})$/i);
  return match && libraryVersionIds.includes(match[1]) ? { ...ref, href: `/requirement-intake?projectId=${encodeURIComponent(projectId)}&requirementVersionId=${encodeURIComponent(match[1])}` } : ref;
}
