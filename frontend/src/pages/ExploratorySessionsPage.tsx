/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { Locale, t } from "../i18n";
import {
  addExploratoryEvidenceRef,
  addExploratoryNote,
  createExploratoryBugCandidate,
  createExploratorySession,
  endExploratorySession,
  fetchExploratorySession,
  fetchExploratorySessions,
  type CurrentUser,
  type EnvironmentItem,
  type ExploratorySession,
  type ProjectItem,
} from "../lib/api";

type ExploratorySessionsPageProps = {
  currentUser: CurrentUser | null;
  environments: EnvironmentItem[];
  locale: Locale;
  projects: ProjectItem[];
};

type NoteType = "note" | "observation" | "risk" | "question";

const DEFAULT_SCOPE = "checkout happy path\npayment error handling";

export function ExploratorySessionsPage({ currentUser, environments, locale, projects }: ExploratorySessionsPageProps) {
  const canManage = currentUser?.capabilities.includes("exploratory_sessions.manage") ?? false;
  const canRead = currentUser?.capabilities.includes("exploratory_sessions.read") ?? false;
  const [sessions, setSessions] = useState<ExploratorySession[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [detail, setDetail] = useState<ExploratorySession | null>(null);
  const [loading, setLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [createForm, setCreateForm] = useState({
    projectId: projects[0]?.id ?? "",
    environmentId: "",
    charter: "",
    scope: DEFAULT_SCOPE,
    timeboxMinutes: 60,
    tester: currentUser?.name ?? "",
  });
  const [noteForm, setNoteForm] = useState({ noteType: "observation" as NoteType, content: "" });
  const [evidenceForm, setEvidenceForm] = useState({ evidenceType: "screenshot", ref: "", summary: "" });
  const [candidateForm, setCandidateForm] = useState({
    title: "",
    summary: "",
    severity: "medium",
    category: "functional_ui",
    confidence: 0.8,
    existingEvidenceRefId: "",
    newEvidenceRef: "",
  });
  const [debriefForm, setDebriefForm] = useState({ debrief: "", outcomeSummary: "", followUps: "" });

  const environmentsForProject = useMemo(
    () => environments.filter((environment) => environment.projectId === createForm.projectId),
    [createForm.projectId, environments],
  );

  useEffect(() => {
    if (!createForm.environmentId && environmentsForProject[0]) {
      setCreateForm((value) => ({ ...value, environmentId: environmentsForProject[0].id }));
    }
  }, [createForm.environmentId, environmentsForProject]);

  useEffect(() => {
    if (currentUser?.name && !createForm.tester) {
      setCreateForm((value) => ({ ...value, tester: currentUser.name }));
    }
  }, [createForm.tester, currentUser?.name]);

  useEffect(() => {
    if (!canRead) {
      return;
    }
    void loadSessions();
  }, [canRead]);

  useEffect(() => {
    if (!selectedSessionId || !canRead) {
      setDetail(null);
      return;
    }
    void loadDetail(selectedSessionId);
  }, [selectedSessionId, canRead]);

  const selectedSession = detail ?? sessions.find((session) => session.id === selectedSessionId) ?? null;
  const evidenceOptions = detail?.evidenceRefs ?? [];

  async function loadSessions() {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchExploratorySessions({ pageSize: 50 });
      setSessions(data.items);
      if (!selectedSessionId && data.items[0]) {
        setSelectedSessionId(data.items[0].id);
      }
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : t(locale, "exploratoryLoadFailed"));
    } finally {
      setLoading(false);
    }
  }

  async function loadDetail(sessionId: string) {
    setDetailLoading(true);
    setError(null);
    try {
      setDetail(await fetchExploratorySession(sessionId));
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : t(locale, "exploratoryLoadFailed"));
    } finally {
      setDetailLoading(false);
    }
  }

  async function runAction(action: () => Promise<void>, successKey: Parameters<typeof t>[1]) {
    setActionError(null);
    setStatusMessage(null);
    try {
      await action();
      setStatusMessage(t(locale, successKey));
      await loadSessions();
      if (selectedSessionId) {
        await loadDetail(selectedSessionId);
      }
    } catch (actionFailure) {
      setActionError(actionFailure instanceof Error ? actionFailure.message : t(locale, "exploratoryActionFailed"));
    }
  }

  const handleCreate = () =>
    runAction(async () => {
      const session = await createExploratorySession({
        projectId: createForm.projectId,
        environmentId: createForm.environmentId,
        charter: createForm.charter,
        scope: parseScope(createForm.scope),
        timeboxMinutes: createForm.timeboxMinutes,
        tester: createForm.tester,
        metadata: {},
      });
      setSelectedSessionId(session.id);
      setCreateForm((value) => ({ ...value, charter: "", scope: DEFAULT_SCOPE }));
    }, "exploratorySessionCreated");

  const handleAddNote = () =>
    selectedSessionId
      ? runAction(async () => {
          await addExploratoryNote(selectedSessionId, {
            noteType: noteForm.noteType,
            content: noteForm.content,
          });
          setNoteForm((value) => ({ ...value, content: "" }));
        }, "exploratoryNoteSaved")
      : undefined;

  const handleAddEvidence = () =>
    selectedSessionId
      ? runAction(async () => {
          await addExploratoryEvidenceRef(selectedSessionId, {
            evidenceType: evidenceForm.evidenceType as "screenshot",
            ref: evidenceForm.ref,
            summary: evidenceForm.summary || null,
          });
          setEvidenceForm((value) => ({ ...value, ref: "", summary: "" }));
        }, "exploratoryEvidenceSaved")
      : undefined;

  const handleCreateCandidate = () =>
    selectedSessionId
      ? runAction(async () => {
          const evidenceRefIds = candidateForm.existingEvidenceRefId ? [candidateForm.existingEvidenceRefId] : [];
          const evidenceRefs = candidateForm.newEvidenceRef
            ? [{ evidenceType: "other" as const, ref: candidateForm.newEvidenceRef, summary: candidateForm.title }]
            : [];
          await createExploratoryBugCandidate(selectedSessionId, {
            title: candidateForm.title,
            summary: candidateForm.summary,
            severity: candidateForm.severity as "medium",
            category: candidateForm.category,
            confidence: candidateForm.confidence,
            location: {},
            evidenceRefIds,
            evidenceRefs,
          });
          setCandidateForm((value) => ({ ...value, title: "", summary: "", newEvidenceRef: "" }));
        }, "exploratoryCandidateNormalized")
      : undefined;

  const handleEndSession = () =>
    selectedSessionId
      ? runAction(async () => {
          await endExploratorySession(selectedSessionId, {
            debrief: debriefForm.debrief,
            outcomeSummary: debriefForm.outcomeSummary || null,
            followUps: debriefForm.followUps.split("\n").filter(Boolean),
          });
        }, "exploratorySessionEnded")
      : undefined;

  return (
    <div className="page-shell" data-route="/exploratory-sessions">
      <div className="page-toolbar">
        <div>
          <h1>{t(locale, "exploratorySessions")}</h1>
        </div>
      </div>

      {!canRead ? <StateBanner title={t(locale, "accessRestricted")} copy={t(locale, "exploratoryReadRestricted")} /> : null}
      {error ? <ErrorBanner title={t(locale, "exploratoryLoadFailed")} message={error} /> : null}
      {actionError ? <ErrorBanner title={t(locale, "exploratoryActionFailed")} message={actionError} /> : null}
      {statusMessage ? <div className="empty-state"><strong>{statusMessage}</strong></div> : null}

      {canRead ? (
        <div className="page-columns">
          <section className="panel">
            <div className="panel__header">
              <span className="eyebrow">{t(locale, "sessions")}</span>
              <h2>{t(locale, "exploratorySessions")}</h2>
            </div>
            {loading ? <StateBanner title={t(locale, "loading")} copy={t(locale, "loadingReadOnlyData")} /> : null}
            <div className="stack-list">
              {sessions.map((session) => (
                <button
                  className={`stack-row stack-row--button ${session.id === selectedSessionId ? "stack-row--selected" : ""}`}
                  key={session.id}
                  onClick={() => setSelectedSessionId(session.id)}
                  type="button"
                >
                  <div>
                    <strong>{session.charter}</strong>
                    <p>{session.projectName ?? session.projectId}</p>
                  </div>
                  <span>{session.status}</span>
                </button>
              ))}
              {!loading && sessions.length === 0 ? <div className="empty-state">{t(locale, "noExploratorySessions")}</div> : null}
            </div>

            <section className="panel panel--flat">
              <div className="panel__header">
                <span className="eyebrow">{t(locale, "create")}</span>
                <h2>{t(locale, "newExploratorySession")}</h2>
              </div>
              {!canManage ? <StateBanner title={t(locale, "currentEditionReadOnly")} copy={t(locale, "exploratoryManageRestricted")} /> : null}
              <div className="form-grid">
                <label>
                  <span>{t(locale, "project")}</span>
                  <select disabled={!canManage} value={createForm.projectId} onChange={(event) => setCreateForm({ ...createForm, projectId: event.target.value, environmentId: "" })}>
                    {projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
                  </select>
                </label>
                <label>
                  <span>{t(locale, "environment")}</span>
                  <select disabled={!canManage} value={createForm.environmentId} onChange={(event) => setCreateForm({ ...createForm, environmentId: event.target.value })}>
                    {environmentsForProject.map((environment) => <option key={environment.id} value={environment.id}>{environment.name}</option>)}
                  </select>
                </label>
                <label>
                  <span>{t(locale, "tester")}</span>
                  <input disabled={!canManage} value={createForm.tester} onChange={(event) => setCreateForm({ ...createForm, tester: event.target.value })} />
                </label>
                <label>
                  <span>{t(locale, "timeboxMinutes")}</span>
                  <input disabled={!canManage} min={1} type="number" value={createForm.timeboxMinutes} onChange={(event) => setCreateForm({ ...createForm, timeboxMinutes: Number(event.target.value) })} />
                </label>
                <label className="form-grid__full">
                  <span>{t(locale, "charter")}</span>
                  <textarea disabled={!canManage} value={createForm.charter} onChange={(event) => setCreateForm({ ...createForm, charter: event.target.value })} />
                </label>
                <label className="form-grid__full">
                  <span>{t(locale, "scope")}</span>
                  <textarea disabled={!canManage} value={createForm.scope} onChange={(event) => setCreateForm({ ...createForm, scope: event.target.value })} />
                </label>
              </div>
              <button className="primary-button" disabled={!canManage || !createForm.projectId || !createForm.environmentId || !createForm.charter || !createForm.tester} onClick={() => void handleCreate()} type="button">
                {t(locale, "createExploratorySession")}
              </button>
            </section>
          </section>

          <section className="panel">
            {!selectedSession ? <StateBanner title={t(locale, "unavailableContext")} copy={t(locale, "selectExploratorySession")} /> : null}
            {detailLoading ? <StateBanner title={t(locale, "loading")} copy={t(locale, "loadingReadOnlyData")} /> : null}
            {selectedSession ? (
              <div className="detail-stack">
                <div className="panel__header">
                  <span className="eyebrow">{selectedSession.status}</span>
                  <h2>{selectedSession.charter}</h2>
                </div>
                <div className="stats-grid stats-grid--compact">
                  <MetricTile label={t(locale, "notes")} value={String(selectedSession.noteCount)} />
                  <MetricTile label={t(locale, "evidence")} value={String(selectedSession.evidenceCount)} />
                  <MetricTile label={t(locale, "bugCandidates")} value={String(selectedSession.candidateCount)} />
                  <MetricTile label={t(locale, "normalizedFindings")} value={String(selectedSession.normalizedFindingCount)} />
                </div>
                <div className="code-panel">
                  <strong>{t(locale, "traceability")}</strong>
                  <pre>{JSON.stringify({ executionId: selectedSession.backingExecutionId, traceId: selectedSession.traceId, replayRefs: selectedSession.replayRefs }, null, 2)}</pre>
                </div>

                <div className="work-grid">
                  <section className="panel panel--flat">
                    <div className="panel__header">
                      <span className="eyebrow">{t(locale, "notes")}</span>
                      <h3>{t(locale, "observationsRisksQuestions")}</h3>
                    </div>
                    <div className="form-grid">
                      <label>
                        <span>{t(locale, "type")}</span>
                        <select disabled={!canManage || selectedSession.status !== "active"} value={noteForm.noteType} onChange={(event) => setNoteForm({ ...noteForm, noteType: event.target.value as NoteType })}>
                          {(["note", "observation", "risk", "question"] as NoteType[]).map((item) => <option key={item} value={item}>{item}</option>)}
                        </select>
                      </label>
                      <label className="form-grid__full">
                        <span>{t(locale, "content")}</span>
                        <textarea disabled={!canManage || selectedSession.status !== "active"} value={noteForm.content} onChange={(event) => setNoteForm({ ...noteForm, content: event.target.value })} />
                      </label>
                    </div>
                    <button className="secondary-button" disabled={!canManage || selectedSession.status !== "active" || !noteForm.content} onClick={() => void handleAddNote()} type="button">{t(locale, "saveNote")}</button>
                    <RecordList rows={detail?.notes ?? []} emptyLabel={t(locale, "noNotes")} render={(note) => (
                      <div>
                        <strong>{String(note.noteType)}</strong>
                        <p>{String(note.content)}</p>
                      </div>
                    )} />
                  </section>

                  <section className="panel panel--flat">
                    <div className="panel__header">
                      <span className="eyebrow">{t(locale, "evidenceRefs")}</span>
                      <h3>{t(locale, "referenceEvidenceOnly")}</h3>
                    </div>
                    <div className="form-grid">
                      <label>
                        <span>{t(locale, "type")}</span>
                        <select disabled={!canManage || selectedSession.status !== "active"} value={evidenceForm.evidenceType} onChange={(event) => setEvidenceForm({ ...evidenceForm, evidenceType: event.target.value })}>
                          {["screenshot", "log", "link", "execution_artifact", "console", "network", "har", "other"].map((item) => <option key={item} value={item}>{item}</option>)}
                        </select>
                      </label>
                      <label>
                        <span>{t(locale, "reference")}</span>
                        <input disabled={!canManage || selectedSession.status !== "active"} value={evidenceForm.ref} onChange={(event) => setEvidenceForm({ ...evidenceForm, ref: event.target.value })} />
                      </label>
                      <label className="form-grid__full">
                        <span>{t(locale, "summary")}</span>
                        <input disabled={!canManage || selectedSession.status !== "active"} value={evidenceForm.summary} onChange={(event) => setEvidenceForm({ ...evidenceForm, summary: event.target.value })} />
                      </label>
                    </div>
                    <button className="secondary-button" disabled={!canManage || selectedSession.status !== "active" || !evidenceForm.ref} onClick={() => void handleAddEvidence()} type="button">{t(locale, "addEvidenceRef")}</button>
                    <RecordList rows={evidenceOptions} emptyLabel={t(locale, "noEvidenceRefs")} render={(evidence) => (
                      <div>
                        <strong>{String(evidence.evidenceType)}: {String(evidence.ref)}</strong>
                        <p>{String(evidence.redactionStatus)}</p>
                      </div>
                    )} />
                  </section>
                </div>

                <section className="panel panel--flat">
                  <div className="panel__header">
                    <span className="eyebrow">{t(locale, "bugCandidates")}</span>
                    <h3>{t(locale, "normalizationBoundary")}</h3>
                  </div>
                  <div className="form-grid">
                    <label>
                      <span>{t(locale, "title")}</span>
                      <input disabled={!canManage || selectedSession.status !== "active"} value={candidateForm.title} onChange={(event) => setCandidateForm({ ...candidateForm, title: event.target.value })} />
                    </label>
                    <label>
                      <span>{t(locale, "severity")}</span>
                      <select disabled={!canManage || selectedSession.status !== "active"} value={candidateForm.severity} onChange={(event) => setCandidateForm({ ...candidateForm, severity: event.target.value })}>
                        {["critical", "high", "medium", "low", "info"].map((item) => <option key={item} value={item}>{item}</option>)}
                      </select>
                    </label>
                    <label>
                      <span>{t(locale, "category")}</span>
                      <input disabled={!canManage || selectedSession.status !== "active"} value={candidateForm.category} onChange={(event) => setCandidateForm({ ...candidateForm, category: event.target.value })} />
                    </label>
                    <label>
                      <span>{t(locale, "confidence")}</span>
                      <input disabled={!canManage || selectedSession.status !== "active"} max={1} min={0} step={0.05} type="number" value={candidateForm.confidence} onChange={(event) => setCandidateForm({ ...candidateForm, confidence: Number(event.target.value) })} />
                    </label>
                    <label className="form-grid__full">
                      <span>{t(locale, "summary")}</span>
                      <textarea disabled={!canManage || selectedSession.status !== "active"} value={candidateForm.summary} onChange={(event) => setCandidateForm({ ...candidateForm, summary: event.target.value })} />
                    </label>
                    <label>
                      <span>{t(locale, "existingEvidence")}</span>
                      <select disabled={!canManage || selectedSession.status !== "active"} value={candidateForm.existingEvidenceRefId} onChange={(event) => setCandidateForm({ ...candidateForm, existingEvidenceRefId: event.target.value })}>
                        <option value="">{t(locale, "none")}</option>
                        {evidenceOptions.map((evidence) => <option key={evidence.id} value={evidence.id}>{evidence.ref}</option>)}
                      </select>
                    </label>
                    <label>
                      <span>{t(locale, "newEvidenceRef")}</span>
                      <input disabled={!canManage || selectedSession.status !== "active"} value={candidateForm.newEvidenceRef} onChange={(event) => setCandidateForm({ ...candidateForm, newEvidenceRef: event.target.value })} />
                    </label>
                  </div>
                  <button
                    className="primary-button"
                    disabled={!canManage || selectedSession.status !== "active" || !candidateForm.title || !candidateForm.summary || (!candidateForm.existingEvidenceRefId && !candidateForm.newEvidenceRef)}
                    onClick={() => void handleCreateCandidate()}
                    type="button"
                  >
                    {t(locale, "normalizeBugCandidate")}
                  </button>
                  <RecordList rows={detail?.bugCandidates ?? []} emptyLabel={t(locale, "noBugCandidates")} render={(candidate) => (
                    <div>
                      <strong>{String(candidate.title)}</strong>
                      <p>{String(candidate.status)} / {String(candidate.normalizedFindingId ?? t(locale, "none"))}</p>
                    </div>
                  )} />
                </section>

                <section className="panel panel--flat">
                  <div className="panel__header">
                    <span className="eyebrow">{t(locale, "debrief")}</span>
                    <h3>{t(locale, "exploratoryReport")}</h3>
                  </div>
                  <div className="form-grid">
                    <label className="form-grid__full">
                      <span>{t(locale, "debrief")}</span>
                      <textarea disabled={!canManage || selectedSession.status !== "active"} value={debriefForm.debrief} onChange={(event) => setDebriefForm({ ...debriefForm, debrief: event.target.value })} />
                    </label>
                    <label className="form-grid__full">
                      <span>{t(locale, "outcomeSummary")}</span>
                      <textarea disabled={!canManage || selectedSession.status !== "active"} value={debriefForm.outcomeSummary} onChange={(event) => setDebriefForm({ ...debriefForm, outcomeSummary: event.target.value })} />
                    </label>
                    <label className="form-grid__full">
                      <span>{t(locale, "followUps")}</span>
                      <textarea disabled={!canManage || selectedSession.status !== "active"} value={debriefForm.followUps} onChange={(event) => setDebriefForm({ ...debriefForm, followUps: event.target.value })} />
                    </label>
                  </div>
                  <button className="primary-button" disabled={!canManage || selectedSession.status !== "active" || !debriefForm.debrief} onClick={() => void handleEndSession()} type="button">{t(locale, "endSession")}</button>
                  {detail?.report ? <div className="code-panel"><pre>{JSON.stringify(detail.report, null, 2)}</pre></div> : null}
                </section>
              </div>
            ) : null}
          </section>
        </div>
      ) : null}
    </div>
  );
}

function parseScope(value: string): Array<Record<string, unknown>> {
  return value
    .split("\n")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => ({ item }));
}

function StateBanner({ title, copy }: { title: string; copy: string }) {
  return (
    <div className="empty-state">
      <strong>{title}</strong>
      <p>{copy}</p>
    </div>
  );
}

function ErrorBanner({ title, message }: { title: string; message: string }) {
  return (
    <div className="error-banner">
      <strong>{title}</strong>
      <p>{message}</p>
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

function RecordList<T>({ rows, emptyLabel, render }: { rows: T[]; emptyLabel: string; render: (row: T) => ReactNode }) {
  return (
    <div className="stack-list stack-list--compact">
      {rows.map((row, index) => (
        <div className="stack-row" key={index}>
          {render(row)}
        </div>
      ))}
      {rows.length === 0 ? <div className="empty-state">{emptyLabel}</div> : null}
    </div>
  );
}
