/* SPDX-License-Identifier: Apache-2.0 */
import { SectionCard } from "../components/SectionCard";
import { useChangeSets } from "../hooks/useChangeSets";
import { type Locale, t } from "../i18n";
import type { CurrentUser } from "../lib/api";


type Props = {
  currentUser: CurrentUser | null;
  locale: Locale;
  projectId: string | null;
};

export function ChangeSetsPage({ currentUser, locale, projectId }: Props) {
  const canRead = currentUser?.capabilities.includes("change.read") ?? false;
  const view = useChangeSets(projectId, canRead);

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
      {view.state === "error" ? <State text={t(locale, "changeSetLoadFailed")} /> : null}
      {view.state === "empty" ? <State text={t(locale, "changeSetEmpty")} /> : null}

      {view.state === "ready" ? <div className="page-columns">
        <SectionCard title={t(locale, "changeSetList")} eyebrow={t(locale, "changeSetStableInputs")}>
          <div className="list-stack" role="listbox">
            {view.items.map((item) => <button aria-selected={item.changeSetId === view.selectedId} className="list-row" key={item.changeSetId} onClick={() => view.select(item.changeSetId)} role="option" type="button"><span><strong>{item.changeSetType}</strong><small>{item.sourceType} · {item.sourceRevision}</small></span><span className="badge-row"><span className="status-pill">{item.status}</span><span>{item.itemCount}/{item.issueCount}</span></span></button>)}
          </div>
        </SectionCard>

        <SectionCard title={t(locale, "changeSetDetail")} eyebrow={view.detail?.normalizerVersion ?? t(locale, "loading")}>
          {view.detail ? <div className="detail-stack">
            <div className="badge-row"><span className="status-pill">{view.detail.changeSetType}</span><span className="status-pill">{view.detail.status}</span>{view.detail.sensitive ? <span className="status-pill">{t(locale, "changeSetSensitiveRedacted")}</span> : null}</div>
            <p className="technical-id">{view.detail.changeSetId}</p>
            <p>{t(locale, "changeSetSourceRevision")}: <code>{view.detail.sourceRevision}</code></p>
            <p>{t(locale, "changeSetFingerprint")}: <code>{view.detail.fingerprint}</code></p>
            <p>{t(locale, "changeSetTrace")}: <code>{view.detail.traceId}</code></p>
            <p>{t(locale, "changeSetItems")}: {view.detail.itemCount} · {t(locale, "changeSetIssues")}: {view.detail.issueCount}</p>
            {view.detail.items?.map((item) => <article className="notice notice--info" key={item.itemId}><strong>{item.requirementId} · {item.changeType}</strong><p>{item.changedFields.join(", ") || t(locale, "none")}</p></article>)}
            {view.detail.files?.map((file) => <article className="notice notice--info" key={file.fileId}><strong>{file.path} · {file.changeType}</strong><p>{file.language ?? t(locale, "unknown")} · {t(locale, "changeSetHunks")}: {file.hunks.length}</p><p>{file.riskHints.join(", ") || t(locale, "none")}</p></article>)}
            {view.detail.issues.map((issue) => <article className="notice notice--warning" key={issue.issueId}><strong>{issue.category} · {issue.code}</strong><p>{issue.message}</p></article>)}
          </div> : <State text={t(locale, "loading")} />}
        </SectionCard>
      </div> : null}
    </div>
  );
}

function State({ text }: { text: string }) {
  return <div className="notice notice--info" role="status">{text}</div>;
}
