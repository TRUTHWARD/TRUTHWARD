/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { Locale, t, userFacingError } from "../i18n";
import {
  addExploratoryEvidenceRef,
  addExploratoryNote,
  createExploratoryBugCandidate,
  createExploratorySession,
  endExploratorySession,
  fetchExploratoryEvidenceContent,
  fetchExploratorySession,
  fetchExploratorySessions,
  fetchExploratoryTraceability,
  uploadExploratoryEvidenceImage,
  type CurrentUser,
  type EnvironmentItem,
  type ExploratoryEvidenceRef,
  type ExploratorySession,
  type ExploratoryTraceNode,
  type ExploratoryTraceability,
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
  const [traceability, setTraceability] = useState<ExploratoryTraceability | null>(null);
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
  const [noteForm, setNoteForm] = useState({ noteType: "observation" as NoteType, content: "", evidenceRefIds: [] as string[] });
  const [evidenceForm, setEvidenceForm] = useState({ evidenceType: "screenshot", ref: "", summary: "" });
  const [evidenceMode, setEvidenceMode] = useState<"upload" | "reference">("upload");
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadSummary, setUploadSummary] = useState("");
  const [confirmImageSafe, setConfirmImageSafe] = useState(false);
  const [preview, setPreview] = useState<{ evidenceId: string; url: string } | null>(null);
  const [candidateForm, setCandidateForm] = useState({
    title: "",
    summary: "",
    severity: "medium",
    category: "functional_ui",
    confidence: 0.8,
    evidenceRefIds: [] as string[],
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

  useEffect(() => () => {
    if (preview) URL.revokeObjectURL(preview.url);
  }, [preview]);

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
      setError(userFacingError(locale, loadError, "exploratoryLoadFailed"));
    } finally {
      setLoading(false);
    }
  }

  async function loadDetail(sessionId: string) {
    setDetailLoading(true);
    setError(null);
    try {
      const [session, trace] = await Promise.all([
        fetchExploratorySession(sessionId),
        fetchExploratoryTraceability(sessionId),
      ]);
      setDetail(session);
      setTraceability(trace);
    } catch (loadError) {
      setError(userFacingError(locale, loadError, "exploratoryLoadFailed"));
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
      setActionError(userFacingError(locale, actionFailure, "exploratoryActionFailed"));
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
            evidenceRefIds: noteForm.evidenceRefIds,
          });
          setNoteForm((value) => ({ ...value, content: "", evidenceRefIds: [] }));
        }, "exploratoryNoteSaved")
      : undefined;

  const handleUploadEvidence = () =>
    selectedSessionId && uploadFile
      ? runAction(async () => {
          await uploadExploratoryEvidenceImage(selectedSessionId, uploadFile, uploadSummary, confirmImageSafe);
          setUploadFile(null);
          setUploadSummary("");
          setConfirmImageSafe(false);
        }, "exploratoryImageUploaded")
      : undefined;

  const handlePreviewEvidence = async (evidence: ExploratoryEvidenceRef) => {
    if (!selectedSessionId || !evidence.contentAvailable) return;
    setActionError(null);
    try {
      const blob = await fetchExploratoryEvidenceContent(selectedSessionId, evidence.id);
      const url = URL.createObjectURL(blob);
      setPreview((current) => {
        if (current) URL.revokeObjectURL(current.url);
        return { evidenceId: evidence.id, url };
      });
    } catch (previewError) {
      setActionError(userFacingError(locale, previewError, "exploratoryActionFailed"));
    }
  };

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
          await createExploratoryBugCandidate(selectedSessionId, {
            title: candidateForm.title,
            summary: candidateForm.summary,
            severity: candidateForm.severity as "medium",
            category: candidateForm.category,
            confidence: candidateForm.confidence,
            location: {},
            evidenceRefIds: candidateForm.evidenceRefIds,
            evidenceRefs: [],
          });
          setCandidateForm((value) => ({ ...value, title: "", summary: "", evidenceRefIds: [] }));
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
    <div className="page-shell exploratory-sessions-page" data-route="/exploratory-sessions">
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
        <div className="page-columns page-columns--exploratory">
          <section className="panel exploratory-session-index">
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

            <section className="panel panel--flat exploratory-session-create">
              <div className="panel__header">
                <span className="eyebrow">{t(locale, "create")}</span>
                <h2>{t(locale, "newExploratorySession")}</h2>
              </div>
              {!canManage ? <StateBanner title={t(locale, "currentEditionReadOnly")} copy={t(locale, "exploratoryManageRestricted")} /> : null}
              <div className="form-grid exploratory-session-create__form">
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
                <TraceabilityCards locale={locale} traceability={traceability} />

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
                      <div className="form-grid__full">
                        <EvidenceChecklist
                          disabled={!canManage || selectedSession.status !== "active"}
                          evidence={evidenceOptions}
                          label={t(locale, "selectSupportingEvidence")}
                          locale={locale}
                          onChange={(ids) => setNoteForm({ ...noteForm, evidenceRefIds: ids })}
                          selectedIds={noteForm.evidenceRefIds}
                        />
                      </div>
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
                      <h3>{t(locale, "managedEvidence")}</h3>
                    </div>
                    <div className="evidence-mode-switch" role="tablist">
                      <button aria-selected={evidenceMode === "upload"} className={evidenceMode === "upload" ? "is-active" : ""} onClick={() => setEvidenceMode("upload")} role="tab" type="button">{t(locale, "uploadImage")}</button>
                      <button aria-selected={evidenceMode === "reference"} className={evidenceMode === "reference" ? "is-active" : ""} onClick={() => setEvidenceMode("reference")} role="tab" type="button">{t(locale, "referenceEvidence")}</button>
                    </div>
                    {evidenceMode === "upload" ? (
                      <div className="exploratory-upload-panel">
                        <p>{t(locale, "imageUploadPolicy")}</p>
                        <div className="form-grid">
                          <label className="form-grid__full">
                            <span>{t(locale, "selectImage")}</span>
                            <input
                              accept=".png,.jpg,.jpeg,.webp,image/png,image/jpeg,image/webp"
                              disabled={!canManage || selectedSession.status !== "active"}
                              onChange={(event) => setUploadFile(event.currentTarget.files?.[0] ?? null)}
                              type="file"
                            />
                          </label>
                          <label className="form-grid__full">
                            <span>{t(locale, "summary")}</span>
                            <input disabled={!canManage || selectedSession.status !== "active"} value={uploadSummary} onChange={(event) => setUploadSummary(event.target.value)} />
                          </label>
                          <label className="form-grid__full checkbox-field">
                            <input checked={confirmImageSafe} disabled={!canManage || selectedSession.status !== "active"} onChange={(event) => setConfirmImageSafe(event.target.checked)} type="checkbox" />
                            <span>{t(locale, "confirmImageSafe")}</span>
                          </label>
                        </div>
                        <button className="secondary-button" disabled={!canManage || selectedSession.status !== "active" || !uploadFile || !confirmImageSafe} onClick={() => void handleUploadEvidence()} type="button">{t(locale, "uploadEvidenceImage")}</button>
                      </div>
                    ) : (
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
                        <button className="secondary-button" disabled={!canManage || selectedSession.status !== "active" || !evidenceForm.ref} onClick={() => void handleAddEvidence()} type="button">{t(locale, "addEvidenceRef")}</button>
                      </div>
                    )}
                    <RecordList rows={evidenceOptions} emptyLabel={t(locale, "noEvidenceRefs")} render={(evidence) => (
                      <div className="evidence-record">
                        <strong>{evidence.summary || String(evidence.evidenceType)}</strong>
                        <p>{String(evidence.evidenceType)} · {String(evidence.redactionStatus)}</p>
                        {evidence.contentAvailable ? <button className="link-button" onClick={() => void handlePreviewEvidence(evidence)} type="button">{t(locale, "preview")}</button> : null}
                        <details><summary>{t(locale, "technicalDetails")}</summary><code>{String(evidence.ref)}</code></details>
                      </div>
                    )} />
                    {preview ? (
                      <div className="evidence-preview">
                        <div className="evidence-preview__toolbar">
                          <strong>{t(locale, "imagePreview")}</strong>
                          <button className="link-button" onClick={() => setPreview(null)} type="button">{t(locale, "closePreview")}</button>
                        </div>
                        <img alt={t(locale, "imagePreview")} src={preview.url} />
                      </div>
                    ) : null}
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
                    <div className="form-grid__full">
                      <EvidenceChecklist
                        disabled={!canManage || selectedSession.status !== "active"}
                        evidence={evidenceOptions}
                        label={t(locale, "selectSupportingEvidence")}
                        locale={locale}
                        onChange={(ids) => setCandidateForm({ ...candidateForm, evidenceRefIds: ids })}
                        selectedIds={candidateForm.evidenceRefIds}
                      />
                    </div>
                  </div>
                  <button
                    className="primary-button"
                    disabled={!canManage || selectedSession.status !== "active" || !candidateForm.title || !candidateForm.summary || candidateForm.evidenceRefIds.length === 0}
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

function EvidenceChecklist({
  disabled,
  evidence,
  label,
  locale,
  onChange,
  selectedIds,
}: {
  disabled: boolean;
  evidence: ExploratoryEvidenceRef[];
  label: string;
  locale: Locale;
  onChange: (ids: string[]) => void;
  selectedIds: string[];
}) {
  return (
    <fieldset className="evidence-checklist">
      <legend>{label}</legend>
      {evidence.map((item) => (
        <label key={item.id}>
          <input
            checked={selectedIds.includes(item.id)}
            disabled={disabled}
            onChange={(event) => onChange(event.target.checked ? [...selectedIds, item.id] : selectedIds.filter((id) => id !== item.id))}
            type="checkbox"
          />
          <span>{item.summary || item.ref}</span>
          <small>{item.evidenceType}</small>
        </label>
      ))}
      {evidence.length === 0 ? <p>{t(locale, "noSupportingEvidence")}</p> : null}
    </fieldset>
  );
}

function TraceabilityCards({ locale, traceability }: { locale: Locale; traceability: ExploratoryTraceability | null }) {
  if (!traceability) {
    return <StateBanner title={t(locale, "traceability")} copy={t(locale, "loadingReadOnlyData")} />;
  }
  const primary = traceability.nodes.filter((node) => node.group === "primary");
  const system = traceability.nodes.filter((node) => node.group === "system");
  const nodesById = new Map(traceability.nodes.map((node) => [node.id, node]));
  const primaryEdges = traceability.edges.filter(
    (edge) => nodesById.get(edge.source)?.group === "primary" && nodesById.get(edge.target)?.group === "primary",
  );
  return (
    <section className="traceability-panel" aria-label={t(locale, "traceability")}>
      <div className="traceability-panel__header">
        <div>
          <span className="eyebrow">{t(locale, "traceability")}</span>
          <h3>{t(locale, "humanReadableTrace")}</h3>
        </div>
        <span className={`traceability-status traceability-status--${traceability.status}`}>
          {traceability.status === "complete" ? t(locale, "traceLinksComplete") : t(locale, "traceLinksPartial")}
        </span>
      </div>
      <div className="traceability-summary">
        <span>{t(locale, "notes")}: {traceability.summary.notes ?? 0}</span>
        <span>{t(locale, "evidence")}: {traceability.summary.evidence ?? 0}</span>
        <span>{t(locale, "bugCandidates")}: {traceability.summary.bugCandidates ?? 0}</span>
        <span>{t(locale, "normalizedFindings")}: {traceability.summary.normalizedFindings ?? 0}</span>
      </div>
      <div className="traceability-node-grid">
        {primary.map((node) => <TraceNodeCard key={node.id} locale={locale} node={node} />)}
      </div>
      {primaryEdges.length > 0 ? (
        <div className="traceability-links">
          <strong>{t(locale, "traceRelationships")}</strong>
          {primaryEdges.map((edge, index) => (
            <div key={`${edge.source}:${edge.target}:${edge.relation}:${index}`}>
              <span>{traceNodeLabel(locale, nodesById.get(edge.source)?.kind ?? edge.source)}</span>
              <b>→ {traceRelationLabel(locale, edge.relation)} →</b>
              <span>{traceNodeLabel(locale, nodesById.get(edge.target)?.kind ?? edge.target)}</span>
            </div>
          ))}
        </div>
      ) : null}
      {traceability.missingLinks.length > 0 ? (
        <div className="traceability-warning">
          <strong>{t(locale, "missingTraceLinks")}</strong>
          <ul>{traceability.missingLinks.map((item) => <li key={`${item.code}:${item.sourceId}`}>{item.code}: {shortRef(item.sourceId)}</li>)}</ul>
        </div>
      ) : null}
      {system.length > 0 ? (
        <details className="traceability-system">
          <summary>{t(locale, "systemTraceReferences")} ({system.length})</summary>
          <div className="traceability-node-grid">{system.map((node) => <TraceNodeCard key={node.id} locale={locale} node={node} />)}</div>
        </details>
      ) : null}
      <details className="traceability-technical">
        <summary>{t(locale, "technicalDetails")}</summary>
        <pre>{JSON.stringify(traceability, null, 2)}</pre>
      </details>
    </section>
  );
}

function TraceNodeCard({ locale, node }: { locale: Locale; node: ExploratoryTraceNode }) {
  return (
    <article className={`traceability-node traceability-node--${node.group}`}>
      <div>
        <span>{traceNodeLabel(locale, node.kind)}</span>
        <small>{node.status}</small>
      </div>
      <strong>{node.description}</strong>
      <code title={node.referenceId}>{shortRef(node.referenceId)}</code>
    </article>
  );
}

function shortRef(value: string) {
  return value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
}

function traceNodeLabel(locale: Locale, kind: string) {
  const labels: Record<string, [string, string]> = {
    exploratory_session: ["Exploratory session", "探索会话"],
    execution: ["Backing execution", "承载执行"],
    note: ["Session note", "会话笔记"],
    image_evidence: ["Image evidence", "图片证据"],
    evidence_reference: ["Evidence reference", "证据引用"],
    bug_candidate: ["Bug candidate", "Bug 候选"],
    raw_finding: ["Raw finding", "原始问题"],
    normalized_finding: ["Normalized finding", "归一化问题"],
    session_report: ["Session report", "会话报告"],
    trace: ["Root trace", "根追踪"],
    audit: ["Audit record", "审计记录"],
    skill_invocation: ["Skill invocation", "Skill 调用"],
    execution_replay: ["Execution replay", "执行回放"],
  };
  const label = labels[kind];
  return label ? label[locale === "zh-CN" ? 1 : 0] : kind.replaceAll("_", " ");
}

function traceRelationLabel(locale: Locale, relation: string) {
  const labels: Record<string, [string, string]> = {
    backed_by: ["backed by", "由其承载"],
    records: ["records", "记录"],
    supports: ["supports", "支持"],
    produces: ["produces", "产生"],
    materializes: ["materializes", "形成"],
    normalizes_to: ["normalizes to", "归一化为"],
    summarizes: ["summarizes", "汇总为"],
  };
  const label = labels[relation];
  return label ? label[locale === "zh-CN" ? 1 : 0] : relation.replaceAll("_", " ");
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
