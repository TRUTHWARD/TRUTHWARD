/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useState } from "react";

import { SafeJsonViewer } from "../components/SafeJsonViewer";
import { t, type Locale } from "../i18n";
import {
  ApiRequestError,
  fetchEvidenceIndexEntry,
  fetchEvidenceIndexStatus,
  fetchEvidenceRawProjection,
  queryEvidence,
  type CurrentUser,
  type EvidenceCitation,
  type EvidenceIndexEntry,
  type EvidenceIndexStatus,
  type EvidenceQueryResult,
  type EvidenceRawProjection,
  type EvidenceSourceType,
} from "../lib/api";


type LoadState = "unavailable" | "restricted" | "idle" | "loading" | "ready" | "empty" | "error";

export function EvidenceSearchPage({
  currentUser,
  locale,
  projectId,
}: {
  currentUser: CurrentUser | null;
  locale: Locale;
  projectId: string | null;
}) {
  const canRead = Boolean(currentUser?.capabilities.includes("evidence.read"));
  const canQuery = Boolean(currentUser?.capabilities.includes("evidence.query"));
  const canReadRaw = Boolean(currentUser?.capabilities.includes("evidence.raw.read"));
  const [question, setQuestion] = useState("");
  const [queryMode, setQueryMode] = useState<"keyword" | "semantic" | "hybrid">("hybrid");
  const [sourceType, setSourceType] = useState<EvidenceSourceType | "">("");
  const [state, setState] = useState<LoadState>(projectId ? (canQuery ? "idle" : "restricted") : "unavailable");
  const [result, setResult] = useState<EvidenceQueryResult | null>(null);
  const [status, setStatus] = useState<EvidenceIndexStatus | null>(null);
  const [expanded, setExpanded] = useState<Record<string, EvidenceIndexEntry | EvidenceRawProjection>>({});
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setStatus(null);
    setResult(null);
    setExpanded({});
    setError(null);
    if (!projectId) {
      setState("unavailable");
      return () => {
        cancelled = true;
      };
    }
    if (!canRead || !canQuery) {
      setState("restricted");
      return () => {
        cancelled = true;
      };
    }
    setState("idle");
    void fetchEvidenceIndexStatus(projectId)
      .then((projection) => {
        if (!cancelled) setStatus(projection);
      })
      .catch((requestError: unknown) => {
        if (cancelled) return;
        if (requestError instanceof ApiRequestError && requestError.status === 403) {
          setState("restricted");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [canQuery, canRead, projectId]);

  const submit = async () => {
    if (!projectId || !canQuery || !question.trim()) return;
    setState("loading");
    setError(null);
    setResult(null);
    setExpanded({});
    try {
      const projection = await queryEvidence({
        projectId,
        question: question.trim(),
        queryMode,
        filters: { sourceTypes: sourceType ? [sourceType] : [] },
        limit: 20,
        includeAnswer: true,
      });
      setResult(projection);
      setState(projection.citations.length === 0 ? "empty" : "ready");
      void fetchEvidenceIndexStatus(projectId).then(setStatus).catch(() => undefined);
    } catch (requestError) {
      if (requestError instanceof ApiRequestError && requestError.status === 403) {
        setState("restricted");
        return;
      }
      if (
        requestError instanceof ApiRequestError
        && [404, 409, 410, 503].includes(requestError.status)
      ) {
        setState("unavailable");
        return;
      }
      setState("error");
      setError(requestError instanceof Error ? requestError.message : null);
    }
  };

  const expandCitation = async (citation: EvidenceCitation, raw: boolean) => {
    if (!projectId || !citation.available) return;
    const key = `${citation.entryId}:${raw ? "raw" : "index"}`;
    if (expanded[key]) {
      setExpanded((current) => {
        const next = { ...current };
        delete next[key];
        return next;
      });
      return;
    }
    try {
      const projection = raw
        ? await fetchEvidenceRawProjection(projectId, citation.entryId)
        : await fetchEvidenceIndexEntry(projectId, citation.entryId);
      setExpanded((current) => ({ ...current, [key]: projection }));
    } catch (requestError) {
      if (requestError instanceof ApiRequestError && requestError.status === 403) {
        setError(t(locale, "evidenceRawRestricted"));
      } else {
        setError(t(locale, "evidenceCitationUnavailable"));
      }
    }
  };

  return (
    <section className="page-section evidence-search" data-route="/evidence-search">
      <div className="page-heading">
        <div>
          <p className="eyebrow">{t(locale, "evidenceIndex")}</p>
          <h1>{t(locale, "evidenceSearch")}</h1>
          <p>{t(locale, "evidenceSearchSubtitle")}</p>
        </div>
      </div>

      {!projectId ? <State copy={t(locale, "evidenceProjectUnavailable")} tone="unavailable" /> : null}
      {projectId && state === "unavailable" ? <State copy={t(locale, "evidenceQueryUnavailable")} tone="unavailable" /> : null}
      {state === "restricted" ? <State copy={t(locale, "evidenceQueryRestricted")} tone="restricted" /> : null}

      {projectId && canRead && canQuery ? (
        <div className="panel evidence-search__query">
          <label>
            <span>{t(locale, "evidenceQuestion")}</span>
            <textarea
              aria-label={t(locale, "evidenceQuestion")}
              maxLength={2000}
              onChange={(event) => setQuestion(event.target.value)}
              placeholder={t(locale, "evidenceQuestionPlaceholder")}
              rows={3}
              value={question}
            />
          </label>
          <div className="evidence-search__filters">
            <label>
              <span>{t(locale, "evidenceQueryMode")}</span>
              <select value={queryMode} onChange={(event) => setQueryMode(event.target.value as typeof queryMode)}>
                <option value="hybrid">{t(locale, "evidenceModeHybrid")}</option>
                <option value="keyword">{t(locale, "evidenceModeKeyword")}</option>
                <option value="semantic">{t(locale, "evidenceModeSemantic")}</option>
              </select>
            </label>
            <label>
              <span>{t(locale, "evidenceSourceType")}</span>
              <select value={sourceType} onChange={(event) => setSourceType(event.target.value as EvidenceSourceType | "")}>
                <option value="">{t(locale, "all")}</option>
                {(["execution", "finding", "gate", "policy", "trace", "replay", "graph", "artifact"] as EvidenceSourceType[]).map((item) => (
                  <option key={item} value={item}>{item}</option>
                ))}
              </select>
            </label>
            <button disabled={!question.trim() || state === "loading"} onClick={() => void submit()} type="button">
              {state === "loading" ? t(locale, "evidenceQueryLoading") : t(locale, "evidenceQuerySubmit")}
            </button>
          </div>
          <p className="read-only-note">{t(locale, "evidenceUntrustedNotice")}</p>
        </div>
      ) : null}

      {status ? (
        <div className="evidence-search__status" role="status">
          <span>{t(locale, "evidenceActiveEntries")}: {status.activeEntryCount}</span>
          <span>{t(locale, "evidenceStaleEntries")}: {status.staleEntryCount}</span>
          <span>{t(locale, "evidenceRedactionVersion")}: {status.redactionVersion}</span>
        </div>
      ) : null}
      {state === "empty" ? <State copy={t(locale, "evidenceInsufficient")} /> : null}
      {state === "error" ? <State copy={error ?? t(locale, "evidenceQueryFailed")} tone="error" /> : null}
      {error && state !== "error" ? <div className="capability-notice" role="alert">{error}</div> : null}

      {result && state === "ready" ? (
        <div className="evidence-search__results">
          <article className="panel evidence-search__answer">
            <h2>{t(locale, "evidenceAnswer")}</h2>
            <p>{result.answer ?? t(locale, "evidenceAnswerUnavailable")}</p>
            <p className="technical-id">{result.queryHash} · {result.traceId}</p>
            {result.limitations.length > 0 ? (
              <ul>{result.limitations.map((item) => <li key={item}>{item}</li>)}</ul>
            ) : null}
            {result.unavailableReasons.length > 0 ? (
              <div className="capability-notice">
                <strong>{t(locale, "evidenceUnavailableReasons")}</strong>
                <ul>
                  {result.unavailableReasons.map((item, index) => (
                    <li key={`${String(item.code)}:${String(item.entryId)}:${index}`}>
                      {String(item.code)} · {String(item.sourceType)} · {String(item.entryId)}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </article>
          <div className="evidence-search__citations">
            <h2>{t(locale, "evidenceCitations")}</h2>
            {result.citations.map((citation) => {
              const safeKey = `${citation.entryId}:index`;
              const rawKey = `${citation.entryId}:raw`;
              return (
                <article className="panel evidence-citation" key={citation.citationId}>
                  <div className="evidence-citation__heading">
                    <div>
                      <span className="status-pill status-pill--neutral">{citation.sourceType}</span>
                      <h3>{citation.title}</h3>
                    </div>
                    <span>{citation.classification}</span>
                  </div>
                  <p>{citation.snippet}</p>
                  <p className="technical-id">{citation.contentHash}</p>
                  {!citation.available ? <p className="capability-notice">{citation.unavailableReasonCode}</p> : null}
                  <div className="action-row">
                    <button disabled={!citation.available} onClick={() => void expandCitation(citation, false)} type="button">
                      {expanded[safeKey] ? t(locale, "collapse") : t(locale, "evidenceExpandCitation")}
                    </button>
                    <button disabled={!canReadRaw || !citation.available} onClick={() => void expandCitation(citation, true)} type="button">
                      {expanded[rawKey] ? t(locale, "collapse") : t(locale, "evidenceOpenRaw")}
                    </button>
                  </div>
                  {!canReadRaw ? <p className="capability-notice">{t(locale, "evidenceRawRestricted")}</p> : null}
                  {expanded[safeKey] ? <SafeJsonViewer locale={locale} value={expanded[safeKey]} /> : null}
                  {expanded[rawKey] ? <SafeJsonViewer locale={locale} value={expanded[rawKey]} /> : null}
                </article>
              );
            })}
          </div>
        </div>
      ) : null}
    </section>
  );
}

function State({ copy, tone = "default" }: { copy: string; tone?: string }) {
  return <div className={`empty-state empty-state--${tone}`} role="status">{copy}</div>;
}
