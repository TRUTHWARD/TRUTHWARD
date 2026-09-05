/* SPDX-License-Identifier: Apache-2.0 */
import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";

import { Locale, t } from "../i18n";
import {
  confirmRequirementIntakeBatch,
  confirmRequirementIntakePreview,
  createRequirementIntakeBatch,
  createRequirementIntakeDraft,
  createRequirementIntakePreview,
  fetchRequirementPipeline,
  fetchRequirementIntakeBatches,
  fetchRequirementLibrary,
  retryRequirementIntakeBatchSource,
  uploadRequirementIntakeBatchSources,
  uploadRequirementIntakeOcrSource,
  uploadRequirementIntakeSource,
  type ConnectorBindingItem,
  type CurrentUser,
  type EnvironmentItem,
  type ProjectItem,
  type RequirementIntakeBatch,
  type RequirementIntakeBatchSourcePayload,
  type RequirementIntakeDraft,
  type RequirementIntakePreview,
  type RequirementIntakeRequirementItem,
  type RequirementLibraryItem,
  type RequirementLibraryProjection,
  type RequirementPipelineState,
} from "../lib/api";

type RequirementIntakePageProps = {
  connectorBindings: ConnectorBindingItem[];
  currentUser: CurrentUser | null;
  environments: EnvironmentItem[];
  locale: Locale;
  onPipelineConfirmed: (pipeline: RequirementPipelineState) => Promise<void>;
  onViewPipeline: (pipelineId: string) => void;
  projects: ProjectItem[];
};

const DOMAIN_OPTIONS = ["functional", "performance", "security"];
const RISK_OPTIONS = ["low", "medium", "high"];
const REQUIREMENT_DOCUMENT_CONNECTOR_NAMES = new Set(["mock-requirement-docs", "lark-requirement-docs", "zentao-requirement-docs"]);
const SOURCE_FILTER_OPTIONS = ["paste", "upload", "ocr_upload", "external_link", "connector", "requirement_version"];
const STATUS_FILTER_OPTIONS = ["draft", "previewed", "review_required", "blocked", "generated", "confirmed", "active", "superseded", "discarded"];
type SourceMode = "paste" | "upload" | "ocr_upload" | "external_link" | "connector";
type WorkbenchView = "sources" | "drafts_previews" | "requirement_versions" | "requirement_items";

const WORKBENCH_VIEWS: Array<{ id: WorkbenchView; labelKey: Parameters<typeof t>[1] }> = [
  { id: "sources", labelKey: "sources" },
  { id: "drafts_previews", labelKey: "draftsPreviews" },
  { id: "requirement_versions", labelKey: "requirementVersions" },
  { id: "requirement_items", labelKey: "requirementItems" },
];

function toggleOption(values: string[], option: string) {
  if (values.includes(option)) {
    const next = values.filter((item) => item !== option);
    return next.length > 0 ? next : values;
  }
  return [...values, option];
}

function toggleString(values: string[], option: string) {
  return values.includes(option) ? values.filter((item) => item !== option) : [...values, option];
}

function splitLines(value: string) {
  return value
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function splitBatchBlocks(value: string) {
  return value
    .split(/\n\s*---\s*\n/g)
    .map((item) => item.trim())
    .filter(Boolean);
}

function compactJson(value: unknown) {
  if (value === null || value === undefined) {
    return "{}";
  }
  return JSON.stringify(value, null, 2);
}

export function RequirementIntakePage({ connectorBindings, currentUser, environments, locale, onPipelineConfirmed, onViewPipeline, projects }: RequirementIntakePageProps) {
  const canManageRequirements = currentUser?.capabilities.includes("requirements.manage") ?? false;
  const canReadRequirements = currentUser?.capabilities.includes("requirements.read") ?? false;
  const uploadInputRef = useRef<HTMLInputElement | null>(null);
  const ocrUploadInputRef = useRef<HTMLInputElement | null>(null);
  const batchUploadInputRef = useRef<HTMLInputElement | null>(null);
  const [sourceMode, setSourceMode] = useState<SourceMode>("paste");
  const [activeWorkbenchView, setActiveWorkbenchView] = useState<WorkbenchView>("sources");
  const [libraryProjection, setLibraryProjection] = useState<RequirementLibraryProjection | null>(null);
  const [libraryLoading, setLibraryLoading] = useState(false);
  const [libraryError, setLibraryError] = useState<string | null>(null);
  const [libraryRefreshToken, setLibraryRefreshToken] = useState(0);
  const [libraryFilters, setLibraryFilters] = useState({
    projectId: "",
    environmentId: "",
    sourceType: "",
    status: "",
    keyword: "",
  });
  const [form, setForm] = useState({
    name: "",
    sourceRef: "",
    sourceUri: "",
    connectorBindingId: "",
    externalDocumentId: "",
    rawContent: "",
    environment: "local",
    projectId: "",
    environmentId: "",
    domains: DOMAIN_OPTIONS,
    riskLevel: "medium",
  });
  const [draft, setDraft] = useState<RequirementIntakeDraft | null>(null);
  const [preview, setPreview] = useState<RequirementIntakePreview | null>(null);
  const [selectedRequirementItemIds, setSelectedRequirementItemIds] = useState<string[]>([]);
  const [confirmedPipeline, setConfirmedPipeline] = useState<RequirementPipelineState | null>(null);
  const [batchForm, setBatchForm] = useState({
    name: "",
    idempotencyKey: "",
    pasteDocuments: "",
    externalLinks: "",
    connectorDocumentRefs: "",
    connectorBindingId: "",
  });
  const [batchList, setBatchList] = useState<RequirementIntakeBatch[]>([]);
  const [activeBatch, setActiveBatch] = useState<RequirementIntakeBatch | null>(null);
  const [selectedBatchSourceIds, setSelectedBatchSourceIds] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const environmentsForProject = useMemo(
    () => environments.filter((environment) => !form.projectId || environment.projectId === form.projectId),
    [environments, form.projectId],
  );
  const environmentsForLibraryProject = useMemo(
    () => environments.filter((environment) => !libraryFilters.projectId || environment.projectId === libraryFilters.projectId),
    [environments, libraryFilters.projectId],
  );
  const requirementDocumentBindings = useMemo(
    () => connectorBindings.filter((binding) => (
      REQUIREMENT_DOCUMENT_CONNECTOR_NAMES.has(binding.connectorName)
      && binding.status === "active"
      && (!binding.projectId || !form.projectId || binding.projectId === form.projectId)
      && (!binding.environmentId || !form.environmentId || binding.environmentId === form.environmentId)
    )),
    [connectorBindings, form.environmentId, form.projectId],
  );
  const libraryItems = libraryProjection?.items ?? [];
  const workbenchItems = useMemo(
    () => libraryItemsForView(libraryItems, activeWorkbenchView),
    [activeWorkbenchView, libraryItems],
  );
  const selectedRequirementItemCount = selectedRequirementItemIds.length;
  const pendingBatchSources = activeBatch?.sources.filter((source) => source.status === "pending_confirm") ?? [];

  useEffect(() => {
    if (!preview) {
      setSelectedRequirementItemIds([]);
      return;
    }
    setSelectedRequirementItemIds(preview.requirementItems.filter((item) => item.selectedByDefault).map((item) => item.itemId));
  }, [preview?.previewId]);

  useEffect(() => {
    setSelectedBatchSourceIds(pendingBatchSources.map((source) => source.batchSourceId));
  }, [activeBatch?.batchId, activeBatch?.status]);

  useEffect(() => {
    let cancelled = false;
    if (!currentUser) {
      setLibraryProjection(null);
      setLibraryLoading(false);
      setLibraryError(null);
      return () => {
        cancelled = true;
      };
    }
    if (!canReadRequirements) {
      setLibraryProjection(null);
      setLibraryLoading(false);
      setLibraryError(null);
      return () => {
        cancelled = true;
      };
    }

    setLibraryLoading(true);
    setLibraryError(null);
    void fetchRequirementLibrary({
      projectId: libraryFilters.projectId || null,
      environmentId: libraryFilters.environmentId || null,
      sourceType: libraryFilters.sourceType || null,
      status: libraryFilters.status || null,
      keyword: libraryFilters.keyword || null,
      page: 1,
      pageSize: 100,
    })
      .then((projection) => {
        if (!cancelled) {
          setLibraryProjection(projection);
        }
      })
      .catch((loadError) => {
        if (!cancelled) {
          setLibraryProjection(null);
          setLibraryError(loadError instanceof Error ? loadError.message : t(locale, "requirementLibraryLoadFailed"));
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLibraryLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [
    canReadRequirements,
    currentUser,
    libraryFilters.environmentId,
    libraryFilters.keyword,
    libraryFilters.projectId,
    libraryFilters.sourceType,
    libraryFilters.status,
    libraryRefreshToken,
    locale,
  ]);

  useEffect(() => {
    let cancelled = false;
    if (!currentUser || !canManageRequirements) {
      setBatchList([]);
      return () => {
        cancelled = true;
      };
    }
    void fetchRequirementIntakeBatches(1, 20)
      .then((projection) => {
        if (!cancelled) {
          setBatchList(projection.items);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setBatchList([]);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [canManageRequirements, currentUser, libraryRefreshToken]);

  async function runAction(action: () => Promise<void>, successKey: Parameters<typeof t>[1]) {
    setSubmitting(true);
    setError(null);
    setMessage(null);
    try {
      await action();
      setLibraryRefreshToken((current) => current + 1);
      setMessage(t(locale, successKey));
    } catch (actionError) {
      setError(actionError instanceof Error ? actionError.message : t(locale, "requirementIntakeActionFailed"));
    } finally {
      setSubmitting(false);
    }
  }

  const submitDraft = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!canManageRequirements) {
      return;
    }
    void runAction(async () => {
      if (sourceMode === "upload") {
        const uploadFile = uploadInputRef.current?.files?.[0];
        if (!uploadFile) {
          throw new Error(t(locale, "uploadFileRequired"));
        }
        const result = await uploadRequirementIntakeSource({
          file: uploadFile,
          name: form.name,
          sourceRef: form.sourceRef || null,
          environment: form.environment,
          projectId: form.projectId || null,
          environmentId: form.environmentId || null,
          domains: form.domains,
          riskLevel: form.riskLevel,
          metadata: { source: "requirement-intake-ui" },
        });
        setDraft(result.draft);
        setPreview(result.preview);
        setSelectedRequirementItemIds(result.preview.requirementItems.map((item) => item.itemId));
        setConfirmedPipeline(null);
        return;
      }
      if (sourceMode === "ocr_upload") {
        const uploadFile = ocrUploadInputRef.current?.files?.[0];
        if (!uploadFile) {
          throw new Error(t(locale, "ocrFileRequired"));
        }
        const result = await uploadRequirementIntakeOcrSource({
          file: uploadFile,
          name: form.name,
          sourceRef: form.sourceRef || null,
          environment: form.environment,
          projectId: form.projectId || null,
          environmentId: form.environmentId || null,
          domains: form.domains,
          riskLevel: form.riskLevel,
          metadata: { source: "requirement-intake-ocr-ui" },
        });
        setDraft(result.draft);
        setPreview(result.preview);
        setSelectedRequirementItemIds(result.preview.requirementItems.map((item) => item.itemId));
        setConfirmedPipeline(null);
        return;
      }
      if (sourceMode === "external_link") {
        const savedDraft = await createRequirementIntakeDraft({
          sourceType: "external_link",
          name: form.name,
          sourceUri: form.sourceUri,
          sourceRef: form.sourceRef || null,
          environment: form.environment,
          projectId: form.projectId || null,
          environmentId: form.environmentId || null,
          domains: form.domains,
          riskLevel: form.riskLevel,
          metadata: { source: "requirement-intake-ui" },
        });
        setDraft(savedDraft);
        setPreview(null);
        setSelectedRequirementItemIds([]);
        setConfirmedPipeline(null);
        return;
      }
      if (sourceMode === "connector") {
        if (!form.connectorBindingId) {
          throw new Error(t(locale, "requirementDocumentBindingRequired"));
        }
        if (!form.externalDocumentId.trim()) {
          throw new Error(t(locale, "externalDocumentIdRequired"));
        }
        const savedDraft = await createRequirementIntakeDraft({
          sourceType: "connector",
          name: form.name,
          connectorBindingId: form.connectorBindingId,
          externalDocumentId: form.externalDocumentId,
          sourceRef: form.sourceRef || null,
          environment: form.environment,
          projectId: form.projectId || null,
          environmentId: form.environmentId || null,
          domains: form.domains,
          riskLevel: form.riskLevel,
          metadata: { source: "requirement-intake-ui" },
        });
        setDraft(savedDraft);
        setPreview(null);
        setSelectedRequirementItemIds([]);
        setConfirmedPipeline(null);
        return;
      }
      const savedDraft = await createRequirementIntakeDraft({
        sourceType: "paste",
        name: form.name,
        rawContent: form.rawContent,
        sourceRef: form.sourceRef || null,
        environment: form.environment,
        projectId: form.projectId || null,
        environmentId: form.environmentId || null,
        domains: form.domains,
        riskLevel: form.riskLevel,
        metadata: { source: "requirement-intake-ui" },
      });
      setDraft(savedDraft);
      setPreview(null);
      setSelectedRequirementItemIds([]);
      setConfirmedPipeline(null);
    }, sourceMode === "ocr_upload" ? "requirementOcrPreviewGenerated" : sourceMode === "upload" ? "requirementUploadPreviewGenerated" : sourceMode === "external_link" ? "requirementExternalLinkDraftSaved" : sourceMode === "connector" ? "requirementConnectorDraftSaved" : "requirementDraftSaved");
  };

  const generatePreview = () => {
    if (!draft || !canManageRequirements) {
      return;
    }
    void runAction(async () => {
      const generatedPreview = await createRequirementIntakePreview(draft.draftId);
      setPreview(generatedPreview);
      setSelectedRequirementItemIds(generatedPreview.requirementItems.map((item) => item.itemId));
      setConfirmedPipeline(null);
    }, "requirementPreviewGenerated");
  };

  const confirmPreview = () => {
    if (!preview || !canManageRequirements) {
      return;
    }
    void runAction(async () => {
      if (selectedRequirementItemIds.length === 0) {
        throw new Error(t(locale, "selectAtLeastOneRequirementItem"));
      }
      const result = await confirmRequirementIntakePreview(preview.previewId, {
        selectedRequirementItems: selectedRequirementItemIds,
        metadata: { source: "requirement-intake-ui" },
      });
      setDraft(result.draft);
      setPreview(result.preview);
      const confirmedSelection = result.preview.metadata.selectedRequirementItemIds;
      setSelectedRequirementItemIds(Array.isArray(confirmedSelection) ? confirmedSelection.map(String) : selectedRequirementItemIds);
      setConfirmedPipeline(result.pipeline);
      await onPipelineConfirmed(result.pipeline);
    }, "requirementPreviewConfirmed");
  };

  const refreshConfirmedPipeline = () => {
    if (!confirmedPipeline) {
      return;
    }
    setSubmitting(true);
    setError(null);
    setMessage(null);
    void fetchRequirementPipeline(confirmedPipeline.orchestrationId)
      .then(async (pipeline) => {
        setConfirmedPipeline(pipeline);
        await onPipelineConfirmed(pipeline);
        setMessage(t(locale, "requirementPipelineRefreshed"));
      })
      .catch((refreshError) => {
        setError(refreshError instanceof Error ? refreshError.message : t(locale, "requirementIntakeActionFailed"));
      })
      .finally(() => {
        setSubmitting(false);
      });
  };

  const submitBatch = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!canManageRequirements) {
      return;
    }
    void runAction(async () => {
      const sources: RequirementIntakeBatchSourcePayload[] = [];
      splitBatchBlocks(batchForm.pasteDocuments).forEach((document, index) => {
        sources.push({
          sourceType: "paste",
          sourceKey: `paste:${index + 1}`,
          name: `${batchForm.name || t(locale, "requirementBatch")} paste ${index + 1}`,
          rawContent: document,
          metadata: { source: "requirement-intake-batch-ui" },
        });
      });
      splitLines(batchForm.externalLinks).forEach((sourceUri, index) => {
        sources.push({
          sourceType: "external_link",
          sourceKey: `external_link:${index + 1}`,
          name: `${batchForm.name || t(locale, "requirementBatch")} link ${index + 1}`,
          sourceUri,
          metadata: { source: "requirement-intake-batch-ui" },
        });
      });
      splitLines(batchForm.connectorDocumentRefs).forEach((externalDocumentId, index) => {
        sources.push({
          sourceType: "connector",
          sourceKey: `connector:${index + 1}`,
          name: `${batchForm.name || t(locale, "requirementBatch")} connector ${index + 1}`,
          connectorBindingId: batchForm.connectorBindingId || null,
          externalDocumentId,
          metadata: { source: "requirement-intake-batch-ui" },
        });
      });
      if (sources.length === 0) {
        throw new Error(t(locale, "requirementBatchSourceRequired"));
      }
      if (sources.some((source) => source.sourceType === "connector" && !source.connectorBindingId)) {
        throw new Error(t(locale, "requirementDocumentBindingRequired"));
      }
      const batch = await createRequirementIntakeBatch({
        name: batchForm.name || t(locale, "requirementBatch"),
        idempotencyKey: batchForm.idempotencyKey || null,
        environment: form.environment,
        projectId: form.projectId || null,
        environmentId: form.environmentId || null,
        domains: form.domains,
        riskLevel: form.riskLevel,
        metadata: { source: "requirement-intake-batch-ui" },
        sources,
      });
      setActiveBatch(batch);
      setBatchList((current) => [batch, ...current.filter((item) => item.batchId !== batch.batchId)]);
    }, "requirementBatchCreated");
  };

  const submitBatchUploads = () => {
    if (!canManageRequirements) {
      return;
    }
    void runAction(async () => {
      const files = Array.from(batchUploadInputRef.current?.files ?? []);
      if (files.length === 0) {
        throw new Error(t(locale, "uploadFileRequired"));
      }
      const batch = await uploadRequirementIntakeBatchSources({
        files,
        name: batchForm.name || t(locale, "requirementBatch"),
        sourceRef: form.sourceRef || null,
        environment: form.environment,
        projectId: form.projectId || null,
        environmentId: form.environmentId || null,
        domains: form.domains,
        riskLevel: form.riskLevel,
        idempotencyKey: batchForm.idempotencyKey || null,
        metadata: { source: "requirement-intake-batch-upload-ui" },
      });
      setActiveBatch(batch);
      setBatchList((current) => [batch, ...current.filter((item) => item.batchId !== batch.batchId)]);
    }, "requirementBatchCreated");
  };

  const confirmBatchSources = () => {
    if (!activeBatch || !canManageRequirements) {
      return;
    }
    void runAction(async () => {
      if (selectedBatchSourceIds.length === 0) {
        throw new Error(t(locale, "requirementBatchConfirmSelectionRequired"));
      }
      const batch = await confirmRequirementIntakeBatch(activeBatch.batchId, {
        sourceIds: selectedBatchSourceIds,
        metadata: { source: "requirement-intake-batch-ui" },
      });
      setActiveBatch(batch);
      setBatchList((current) => [batch, ...current.filter((item) => item.batchId !== batch.batchId)]);
      const confirmedSource = batch.sources.find((source) => source.linkedPipelineId && source.status === "confirmed");
      const pipeline = confirmedSource?.metadata.pipeline;
      if (pipeline && typeof pipeline === "object" && "orchestrationId" in pipeline) {
        await onPipelineConfirmed(pipeline as RequirementPipelineState);
      }
    }, "requirementBatchConfirmed");
  };

  const retryBatchSource = (sourceId: string) => {
    if (!activeBatch || !canManageRequirements) {
      return;
    }
    void runAction(async () => {
      const batch = await retryRequirementIntakeBatchSource(activeBatch.batchId, sourceId, {
        metadata: { source: "requirement-intake-batch-ui" },
      });
      setActiveBatch(batch);
      setBatchList((current) => [batch, ...current.filter((item) => item.batchId !== batch.batchId)]);
    }, "requirementBatchSourceRetried");
  };

  return (
    <div className="page-shell" data-route="/requirement-intake">
      <div className="page-toolbar">
        <div>
          <span className="eyebrow">{t(locale, "requirementIntake")}</span>
          <h1>{t(locale, "requirementIntakeWorkbench")}</h1>
        </div>
      </div>

      {!canManageRequirements ? <div className="notice-banner">{t(locale, "requirementIntakeReadOnlyNotice")}</div> : null}
      {message ? <div className="success-banner">{message}</div> : null}
      {error ? <div className="error-banner"><strong>{t(locale, "errorState")}</strong><p>{error}</p></div> : null}

      <section className="panel requirement-intake-batch">
        <div className="panel__header">
          <h2>{t(locale, "requirementBatchIntake")}</h2>
        </div>
        <form className="control-form" onSubmit={submitBatch}>
          <div className="form-grid">
            <label className="form-field">
              {t(locale, "batchName")}
              <input
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setBatchForm((current) => ({ ...current, name: event.target.value }))}
                value={batchForm.name}
              />
            </label>
            <label className="form-field">
              {t(locale, "idempotencyKey")}
              <input
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setBatchForm((current) => ({ ...current, idempotencyKey: event.target.value }))}
                value={batchForm.idempotencyKey}
              />
            </label>
            <label className="form-field">
              {t(locale, "requirementDocumentConnectorBinding")}
              <select
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setBatchForm((current) => ({ ...current, connectorBindingId: event.target.value }))}
                value={batchForm.connectorBindingId}
              >
                <option value="">{t(locale, "none")}</option>
                {requirementDocumentBindings.map((binding) => (
                  <option key={binding.id} value={binding.id}>{binding.connectorName}</option>
                ))}
              </select>
            </label>
            <label className="form-field">
              {t(locale, "multiFileSources")}
              <input
                accept=".txt,.md,.json,.csv,text/plain,text/markdown,application/json,text/csv"
                disabled={!canManageRequirements || submitting}
                multiple
                ref={batchUploadInputRef}
                type="file"
              />
            </label>
          </div>
          <div className="form-grid">
            <label className="form-field">
              {t(locale, "pasteSources")}
              <textarea
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setBatchForm((current) => ({ ...current, pasteDocuments: event.target.value }))}
                rows={5}
                value={batchForm.pasteDocuments}
              />
            </label>
            <label className="form-field">
              {t(locale, "externalLinkSources")}
              <textarea
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setBatchForm((current) => ({ ...current, externalLinks: event.target.value }))}
                rows={5}
                value={batchForm.externalLinks}
              />
            </label>
            <label className="form-field">
              {t(locale, "connectorDocumentSources")}
              <textarea
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setBatchForm((current) => ({ ...current, connectorDocumentRefs: event.target.value }))}
                rows={5}
                value={batchForm.connectorDocumentRefs}
              />
            </label>
          </div>
          <div className="button-row">
            <button className="primary-button" disabled={!canManageRequirements || submitting} type="submit">{t(locale, "createBatch")}</button>
            <button className="secondary-button" disabled={!canManageRequirements || submitting} onClick={submitBatchUploads} type="button">{t(locale, "uploadBatchFiles")}</button>
            {activeBatch ? (
              <button className="secondary-button" disabled={!canManageRequirements || submitting || selectedBatchSourceIds.length === 0} onClick={confirmBatchSources} type="button">
                {t(locale, "confirmSelectedSources")}
              </button>
            ) : null}
          </div>
        </form>
        <div className="split-layout">
          <div className="list-panel">
            <h3>{t(locale, "recentBatches")}</h3>
            {batchList.length === 0 ? <p className="muted">{t(locale, "noRequirementBatches")}</p> : null}
            {batchList.map((batch) => (
              <button
                className={`list-row ${activeBatch?.batchId === batch.batchId ? "list-row--active" : ""}`}
                key={batch.batchId}
                onClick={() => setActiveBatch(batch)}
                type="button"
              >
                <span>{batch.name}</span>
                <span className="status-pill">{batch.status}</span>
              </button>
            ))}
          </div>
          <div className="detail-panel">
            {activeBatch ? (
              <>
                <div className="badge-row">
                  <span className="status-pill">{activeBatch.status}</span>
                  <span className="status-pill">{t(locale, "successfulSources")}: {String(activeBatch.summary.successfulSources ?? 0)}</span>
                  <span className="status-pill">{t(locale, "failedSources")}: {String(activeBatch.summary.failedSources ?? 0)}</span>
                  <span className="status-pill">{t(locale, "confirmedSources")}: {String(activeBatch.summary.confirmedSources ?? 0)}</span>
                </div>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>{t(locale, "selected")}</th>
                        <th>{t(locale, "source")}</th>
                        <th>{t(locale, "status")}</th>
                        <th>{t(locale, "evidence")}</th>
                        <th>{t(locale, "issues")}</th>
                        <th>{t(locale, "actions")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {activeBatch.sources.map((source) => (
                        <tr key={source.batchSourceId}>
                          <td>
                            <input
                              checked={selectedBatchSourceIds.includes(source.batchSourceId)}
                              disabled={source.status !== "pending_confirm"}
                              onChange={() => setSelectedBatchSourceIds((current) => toggleString(current, source.batchSourceId))}
                              type="checkbox"
                            />
                          </td>
                          <td>{source.ordinal}. {source.sourceType}</td>
                          <td><span className="status-pill">{source.status}</span></td>
                          <td>{source.evidenceRefs.length} / {source.artifactRefs.length}</td>
                          <td>{source.errorMessage ?? "-"}</td>
                          <td>
                            {source.status === "failed" ? (
                              <button className="secondary-button" disabled={!canManageRequirements || submitting || source.sourceType === "upload"} onClick={() => retryBatchSource(source.batchSourceId)} type="button">
                                {t(locale, "retry")}
                              </button>
                            ) : null}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            ) : (
              <p className="muted">{t(locale, "selectBatch")}</p>
            )}
          </div>
        </div>
      </section>

      <section className="panel requirement-library-workbench">
        <div className="panel__header">
          <h2>{t(locale, "requirementLibraryWorkbench")}</h2>
        </div>
        {!canReadRequirements ? <div className="notice-banner">{t(locale, "requirementLibraryReadRestricted")}</div> : null}
        {canReadRequirements ? (
          <>
            <div className="control-form control-form--inline">
              <label className="form-field">
                {t(locale, "search")}
                <input
                  onChange={(event) => setLibraryFilters((current) => ({ ...current, keyword: event.target.value }))}
                  placeholder={t(locale, "requirementLibrarySearchPlaceholder")}
                  value={libraryFilters.keyword}
                />
              </label>
              <label className="form-field">
                {t(locale, "project")}
                <select
                  onChange={(event) => setLibraryFilters((current) => ({ ...current, projectId: event.target.value, environmentId: "" }))}
                  value={libraryFilters.projectId}
                >
                  <option value="">{t(locale, "allProjects")}</option>
                  {projects.map((project) => (
                    <option key={project.id} value={project.id}>{project.name}</option>
                  ))}
                </select>
              </label>
              <label className="form-field">
                {t(locale, "environment")}
                <select
                  disabled={!libraryFilters.projectId}
                  onChange={(event) => setLibraryFilters((current) => ({ ...current, environmentId: event.target.value }))}
                  value={libraryFilters.environmentId}
                >
                  <option value="">{t(locale, "allEnvironments")}</option>
                  {environmentsForLibraryProject.map((environment) => (
                    <option key={environment.id} value={environment.id}>{environment.name}</option>
                  ))}
                </select>
              </label>
              <label className="form-field">
                {t(locale, "sourceType")}
                <select
                  onChange={(event) => setLibraryFilters((current) => ({ ...current, sourceType: event.target.value }))}
                  value={libraryFilters.sourceType}
                >
                  <option value="">{t(locale, "allSourceTypes")}</option>
                  {SOURCE_FILTER_OPTIONS.map((sourceType) => (
                    <option key={sourceType} value={sourceType}>{sourceTypeLabel(locale, sourceType)}</option>
                  ))}
                </select>
              </label>
              <label className="form-field">
                {t(locale, "status")}
                <select
                  onChange={(event) => setLibraryFilters((current) => ({ ...current, status: event.target.value }))}
                  value={libraryFilters.status}
                >
                  <option value="">{t(locale, "allStatuses")}</option>
                  {STATUS_FILTER_OPTIONS.map((status) => (
                    <option key={status} value={status}>{status}</option>
                  ))}
                </select>
              </label>
              <button className="secondary-button" onClick={() => setLibraryRefreshToken((current) => current + 1)} type="button">
                {t(locale, "refresh")}
              </button>
            </div>

            <div className="stats-grid stats-grid--compact">
              <Metric label={t(locale, "sources")} value={String(libraryProjection?.summary.returnedCount ?? 0)} />
              <Metric label={t(locale, "draftsPreviews")} value={String((libraryProjection?.summary.intakeDraftCount ?? 0) + (libraryProjection?.summary.intakePreviewCount ?? 0))} />
              <Metric label={t(locale, "requirementVersions")} value={String(libraryProjection?.summary.requirementVersionCount ?? 0)} />
              <Metric label={t(locale, "requirementItems")} value={String(libraryProjection?.summary.requirementItemCount ?? 0)} />
            </div>

            <div
              aria-label={t(locale, "requirementLibrary")}
              className="segmented-control"
              role="group"
            >
              {WORKBENCH_VIEWS.map((view) => (
                <button
                  className={activeWorkbenchView === view.id ? "segmented-control__item segmented-control__item--active" : "segmented-control__item"}
                  key={view.id}
                  onClick={() => setActiveWorkbenchView(view.id)}
                  type="button"
                >
                  {t(locale, view.labelKey)}
                </button>
              ))}
            </div>

            {libraryLoading ? <div className="empty-state">{t(locale, "requirementLibraryLoading")}</div> : null}
            {libraryError ? <div className="error-banner"><strong>{t(locale, "errorState")}</strong><p>{libraryError}</p></div> : null}
            {!libraryLoading && !libraryError ? (
              <WorkbenchTable items={workbenchItems} locale={locale} />
            ) : null}
          </>
        ) : null}
      </section>

      <div className="stats-grid">
        <Metric label={t(locale, "draft")} value={draft?.status ?? t(locale, "none")} />
        <Metric label={t(locale, "preview")} value={preview?.status ?? t(locale, "none")} />
        <Metric label={t(locale, "pipeline")} value={confirmedPipeline?.orchestrationId.slice(0, 8) ?? t(locale, "none")} />
        <Metric label={t(locale, "sourceType")} value={t(locale, sourceMode)} />
      </div>

      <div className="page-columns">
        <section className="panel">
          <div className="panel__header">
            <span className="eyebrow">{t(locale, "draft")}</span>
            <h2>{draftModeTitle(locale, sourceMode)}</h2>
          </div>
          <form className="control-form" onSubmit={submitDraft}>
            <label className="form-field">
              {t(locale, "sourceType")}
              <select
                disabled={!canManageRequirements || submitting}
                onChange={(event) => {
                  setSourceMode(event.target.value as SourceMode);
                  setDraft(null);
                  setPreview(null);
                  setSelectedRequirementItemIds([]);
                  setConfirmedPipeline(null);
                }}
                value={sourceMode}
              >
                <option value="paste">{t(locale, "paste")}</option>
                <option value="upload">{t(locale, "upload")}</option>
                <option value="ocr_upload">{t(locale, "ocr_upload")}</option>
                <option value="external_link">{t(locale, "external_link")}</option>
                <option value="connector">{t(locale, "connector")}</option>
              </select>
            </label>
            <label className="form-field">
              {t(locale, "requirementName")}
              <input
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
                required
                value={form.name}
              />
            </label>
            <label className="form-field">
              {t(locale, "sourceRef")}
              <input
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setForm((current) => ({ ...current, sourceRef: event.target.value }))}
                value={form.sourceRef}
              />
            </label>
            <label className="form-field">
              {t(locale, "project")}
              <select
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setForm((current) => ({ ...current, projectId: event.target.value, environmentId: "" }))}
                value={form.projectId}
              >
                <option value="">{t(locale, "none")}</option>
                {projects.map((project) => (
                  <option key={project.id} value={project.id}>{project.name}</option>
                ))}
              </select>
            </label>
            <label className="form-field">
              {t(locale, "environment")}
              <select
                disabled={!canManageRequirements || submitting || !form.projectId}
                onChange={(event) => {
                  const environment = environments.find((item) => item.id === event.target.value);
                  setForm((current) => ({
                    ...current,
                    environmentId: event.target.value,
                    environment: environment?.key || current.environment,
                  }));
                }}
                value={form.environmentId}
              >
                <option value="">{t(locale, "none")}</option>
                {environmentsForProject.map((environment) => (
                  <option key={environment.id} value={environment.id}>{environment.name}</option>
                ))}
              </select>
            </label>
            <label className="form-field">
              {t(locale, "environmentKey")}
              <input
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setForm((current) => ({ ...current, environment: event.target.value }))}
                required
                value={form.environment}
              />
            </label>
            <label className="form-field">
              {t(locale, "riskLevel")}
              <select
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setForm((current) => ({ ...current, riskLevel: event.target.value }))}
                value={form.riskLevel}
              >
                {RISK_OPTIONS.map((risk) => (
                  <option key={risk} value={risk}>{risk}</option>
                ))}
              </select>
            </label>
            <div className="checkbox-grid">
              {DOMAIN_OPTIONS.map((domain) => (
                <label className="check-row" key={domain}>
                  <input
                    checked={form.domains.includes(domain)}
                    disabled={!canManageRequirements || submitting}
                    onChange={() => setForm((current) => ({ ...current, domains: toggleOption(current.domains, domain) }))}
                    type="checkbox"
                  />
                  <span>{t(locale, domain as Parameters<typeof t>[1])}</span>
                </label>
              ))}
            </div>
            {sourceMode === "paste" ? (
              <label className="form-field">
                {t(locale, "pastedRequirement")}
                <textarea
                  disabled={!canManageRequirements || submitting}
                  onChange={(event) => setForm((current) => ({ ...current, rawContent: event.target.value }))}
                  required
                  rows={12}
                  value={form.rawContent}
                />
              </label>
            ) : null}
            {sourceMode === "upload" ? (
              <label className="form-field">
                {t(locale, "uploadRequirementFile")}
                <input
                  accept=".txt,.md,.json,.csv,.pdf,.docx,text/plain,text/markdown,application/json,text/csv,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                  disabled={!canManageRequirements || submitting}
                  ref={uploadInputRef}
                  required
                  type="file"
                />
              </label>
            ) : null}
            {sourceMode === "ocr_upload" ? (
              <label className="form-field">
                {t(locale, "ocrRequirementFile")}
                <input
                  accept=".pdf,.png,.jpg,.jpeg,.tif,.tiff,.bmp,.webp,application/pdf,image/png,image/jpeg,image/tiff,image/bmp,image/webp"
                  disabled={!canManageRequirements || submitting}
                  ref={ocrUploadInputRef}
                  required
                  type="file"
                />
                <small>{t(locale, "ocrUploadHint")}</small>
              </label>
            ) : null}
            {sourceMode === "external_link" ? (
              <label className="form-field">
                {t(locale, "externalLinkSourceUri")}
                <input
                  disabled={!canManageRequirements || submitting}
                  onChange={(event) => setForm((current) => ({ ...current, sourceUri: event.target.value }))}
                  required
                  type="url"
                  value={form.sourceUri}
                />
              </label>
            ) : null}
            {sourceMode === "connector" ? (
              <>
                <label className="form-field">
                  {t(locale, "requirementDocumentConnectorBinding")}
                  <select
                    disabled={!canManageRequirements || submitting}
                    onChange={(event) => setForm((current) => ({ ...current, connectorBindingId: event.target.value }))}
                    required
                    value={form.connectorBindingId}
                  >
                    <option value="">{t(locale, "none")}</option>
                    {requirementDocumentBindings.map((binding) => (
                      <option key={binding.id} value={binding.id}>{binding.connectorName} / {binding.id.slice(0, 8)}</option>
                    ))}
                  </select>
                </label>
                <label className="form-field">
                  {t(locale, "externalDocumentId")}
                  <input
                    disabled={!canManageRequirements || submitting}
                    onChange={(event) => setForm((current) => ({ ...current, externalDocumentId: event.target.value }))}
                    required
                    value={form.externalDocumentId}
                  />
                </label>
              </>
            ) : null}
            <div className="button-row">
              <button className="primary-button" disabled={!canManageRequirements || submitting} type="submit">
                {sourceMode === "ocr_upload" ? t(locale, "ocrAndPreview") : sourceMode === "upload" ? t(locale, "uploadAndPreview") : sourceMode === "external_link" ? t(locale, "fetchLinkDraft") : sourceMode === "connector" ? t(locale, "importConnectorDraft") : t(locale, "saveDraft")}
              </button>
              <button
                className="secondary-button"
                disabled={!canManageRequirements || submitting || !draft || draft.sourceType === "upload" || draft.sourceType === "ocr_upload"}
                onClick={generatePreview}
                type="button"
              >
                {t(locale, "generatePreview")}
              </button>
            </div>
          </form>
        </section>

        <section className="panel">
          <div className="panel__header">
            <span className="eyebrow">{t(locale, "preview")}</span>
            <h2>{t(locale, "requirementPreview")}</h2>
          </div>
          {!preview ? <div className="empty-state">{t(locale, "noRequirementPreview")}</div> : null}
          {preview ? (
            <div className="detail-stack">
              <ReadonlyRow label={t(locale, "sourceRef")} value={preview.sourceRef} />
              {preview.sourceUri ? <ReadonlyRow label={t(locale, "sourceUri")} value={preview.sourceUri} /> : null}
              <ReadonlyRow label={t(locale, "sourceType")} value={t(locale, preview.sourceType)} />
              {preview.mimeType ? <ReadonlyRow label={t(locale, "mimeType")} value={preview.mimeType} /> : null}
              {preview.byteSize !== null ? <ReadonlyRow label={t(locale, "byteSize")} value={String(preview.byteSize)} /> : null}
              <ReadonlyRow label={t(locale, "evidenceRefs")} value={String(preview.evidenceRefs.length)} />
              {preview.skillInvocationId ? <ReadonlyRow label={t(locale, "skillInvocation")} value={preview.skillInvocationId} /> : null}
              {preview.connectorCallRefs.length > 0 ? <ReadonlyRow label={t(locale, "connectorCalls")} value={String(preview.connectorCallRefs.length)} /> : null}
              <ReadonlyRow label={t(locale, "redactionStatus")} value={preview.redactionStatus} />
              {preview.ocr ? <ReadonlyRow label={t(locale, "ocrConfidence")} value={`${(preview.ocr.confidence * 100).toFixed(1)}%`} /> : null}
              {preview.ocr ? <ReadonlyRow label={t(locale, "ocrReviewStatus")} value={t(locale, preview.ocr.status as Parameters<typeof t>[1])} /> : null}
              {preview.ocr ? <ReadonlyRow label={t(locale, "ocrPagesAndLines")} value={`${preview.ocr.pageCount} / ${preview.ocr.lineCount}`} /> : null}
              {preview.ocr?.traceRefs.length ? <ReadonlyRow label={t(locale, "traceRefs")} value={preview.ocr.traceRefs.join(", ")} /> : null}
              {preview.ocr?.reviewRequired ? <div className="warning-banner">{t(locale, "ocrReviewRequiredNotice")}</div> : null}
              {preview.ocr?.blocked ? <div className="error-banner">{t(locale, "ocrBlockedNotice")}</div> : null}
              <ReadonlyRow label={t(locale, "requirementsList")} value={String(preview.requirements.length)} />
              <ReadonlyRow label={t(locale, "acceptanceCriteria")} value={String(preview.acceptanceCriteria.length)} />
              <ReadonlyRow label={t(locale, "selectedRequirementItems")} value={`${selectedRequirementItemCount} / ${preview.requirementItems.length}`} />
              <ReadonlyRow label={t(locale, "status")} value={preview.status} />
              {preview.warnings.length > 0 ? <ReadonlyRow label={t(locale, "warnings")} value={preview.warnings.map((warning) => warningLabel(locale, warning)).join(", ")} /> : null}
              <div className="stack-list">
                <PreviewRequirementSelection
                  disabled={!canManageRequirements || submitting || preview.status !== "generated"}
                  items={preview.requirementItems}
                  locale={locale}
                  onToggle={(itemId) => {
                    setSelectedRequirementItemIds((current) => (
                      current.includes(itemId) ? current.filter((value) => value !== itemId) : [...current, itemId]
                    ));
                  }}
                  selectedIds={selectedRequirementItemIds}
                />
                <PreviewList title={t(locale, "acceptanceCriteria")} items={preview.acceptanceCriteria} locale={locale} />
              </div>
              <button
                className="primary-button"
                disabled={!canManageRequirements || submitting || preview.status !== "generated" || selectedRequirementItemIds.length === 0}
                onClick={confirmPreview}
                type="button"
              >
                {t(locale, "confirmIntoPipeline")}
              </button>
              <pre className="snapshot-json">{compactJson(preview.pipelinePayload)}</pre>
            </div>
          ) : null}
        </section>
      </div>

      <section className="panel">
        <div className="panel__header">
          <span className="eyebrow">{t(locale, "pipelineState")}</span>
          <h2>{t(locale, "confirmedPipelineResult")}</h2>
        </div>
        {!confirmedPipeline ? (
          <div className="empty-state">
            <strong>{t(locale, "noConfirmedPipeline")}</strong>
            <p>{t(locale, "noConfirmedPipelineHint")}</p>
          </div>
        ) : null}
        {confirmedPipeline ? (
          <div className="detail-stack">
            <div className="stats-grid stats-grid--compact">
              <Metric label={t(locale, "status")} value={confirmedPipeline.status} />
              <Metric label={t(locale, "currentStep")} value={confirmedPipeline.currentStep ?? t(locale, "none")} />
              <Metric label={t(locale, "blocked")} value={confirmedPipeline.blocked ? t(locale, "yes") : t(locale, "no")} />
              <Metric label={t(locale, "pipeline")} value={confirmedPipeline.orchestrationId.slice(0, 8)} />
            </div>
            <div className="detail-grid">
              <ReadonlyRow label={t(locale, "pipeline")} value={confirmedPipeline.orchestrationId} />
              <ReadonlyRow label={t(locale, "requirementVersion")} value={confirmedPipeline.requirementVersionId ?? t(locale, "none")} />
              <ReadonlyRow label={t(locale, "plan")} value={confirmedPipeline.planId ?? t(locale, "none")} />
              <ReadonlyRow label={t(locale, "execution")} value={confirmedPipeline.executionId ?? t(locale, "none")} />
              {confirmedPipeline.errorMessage ? <ReadonlyRow label={t(locale, "errorState")} value={confirmedPipeline.errorMessage} /> : null}
            </div>
            <div className="button-row">
              <button className="secondary-button" disabled={submitting} onClick={refreshConfirmedPipeline} type="button">
                {t(locale, "refresh")}
              </button>
              <button className="primary-button" onClick={() => onViewPipeline(confirmedPipeline.orchestrationId)} type="button">
                {t(locale, "viewInWorkflow")}
              </button>
            </div>
            <details className="json-block">
              <summary>{t(locale, "result")}</summary>
              <pre>{compactJson(confirmedPipeline.result)}</pre>
            </details>
          </div>
        ) : null}
      </section>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="stat-tile">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ReadonlyRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="inline-status">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function PreviewList({ title, items, locale }: { title: string; items: string[]; locale: Locale }) {
  return (
    <div className="stack-row">
      <div>
        <strong>{title}</strong>
        {items.length > 0 ? (
          <ul>
            {items.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        ) : (
          <p>{t(locale, "none")}</p>
        )}
      </div>
    </div>
  );
}

function PreviewRequirementSelection({
  disabled,
  items,
  locale,
  onToggle,
  selectedIds,
}: {
  disabled: boolean;
  items: RequirementIntakeRequirementItem[];
  locale: Locale;
  onToggle: (itemId: string) => void;
  selectedIds: string[];
}) {
  return (
    <div className="stack-row">
      <div>
        <strong>{t(locale, "selectableRequirementItems")}</strong>
        {items.length === 0 ? (
          <p>{t(locale, "none")}</p>
        ) : (
          <div className="detail-stack">
            {items.map((item) => (
              <label className="check-row check-row--stacked" key={item.itemId}>
                <input
                  checked={selectedIds.includes(item.itemId)}
                  disabled={disabled}
                  onChange={() => onToggle(item.itemId)}
                  type="checkbox"
                />
                <span>
                  <span className="status-pill">{item.itemId}</span>
                  <strong>{item.requirement}</strong>
                  {item.acceptanceCriteria.length > 0 ? (
                    <small>{`${t(locale, "acceptanceCriteria")}: ${item.acceptanceCriteria.join("; ")}`}</small>
                  ) : null}
                  <small>{`${t(locale, "evidenceRefs")}: ${item.evidenceRefs.length} / ${t(locale, "artifactRefs")}: ${item.artifactRefs.length}`}</small>
                </span>
              </label>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function WorkbenchTable({ items, locale }: { items: RequirementLibraryItem[]; locale: Locale }) {
  if (items.length === 0) {
    return <div className="empty-state">{t(locale, "noRequirementLibraryItems")}</div>;
  }
  return (
    <div className="table-wrap">
      <table className="data-table data-table--compact">
        <thead>
          <tr>
            <th>{t(locale, "type")}</th>
            <th>{t(locale, "title")}</th>
            <th>{t(locale, "status")}</th>
            <th>{t(locale, "source")}</th>
            <th>{t(locale, "linkedRequirementVersionId")}</th>
            <th>{t(locale, "evidenceRefs")}</th>
            <th>{t(locale, "created")}</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.itemId}>
              <td>
                <span className="status-pill">{libraryItemTypeLabel(locale, item.itemType)}</span>
              </td>
              <td>
                <strong>{item.title}</strong>
                {item.summary ? <p>{item.summary}</p> : null}
              </td>
              <td>
                <span className={`status-pill status-pill--${item.status}`}>{item.status}</span>
              </td>
              <td>
                <span>{sourceTypeLabel(locale, item.sourceType)}</span>
                {item.sourceRef ? <p>{item.sourceRef}</p> : null}
                {item.sourceUri ? <p>{item.sourceUri}</p> : null}
              </td>
              <td>{item.linkedRequirementVersionId ?? t(locale, "none")}</td>
              <td>{evidenceRefsSummary(item.evidenceRefs, locale)}</td>
              <td>{new Date(item.createdAt).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function libraryItemsForView(items: RequirementLibraryItem[], view: WorkbenchView) {
  if (view === "drafts_previews") {
    return items.filter((item) => item.itemType === "requirement_intake_draft" || item.itemType === "requirement_intake_preview");
  }
  if (view === "requirement_versions") {
    return items.filter((item) => item.itemType === "requirement_version");
  }
  if (view === "requirement_items") {
    return items.filter((item) => item.itemType === "requirement_item");
  }
  return items;
}

function sourceTypeLabel(locale: Locale, sourceType: string) {
  if (sourceType === "paste") {
    return t(locale, "paste");
  }
  if (sourceType === "upload") {
    return t(locale, "upload");
  }
  if (sourceType === "external_link") {
    return t(locale, "external_link");
  }
  if (sourceType === "connector") {
    return t(locale, "connector");
  }
  if (sourceType === "requirement_version") {
    return t(locale, "requirementVersionSource");
  }
  return sourceType;
}

function libraryItemTypeLabel(locale: Locale, itemType: RequirementLibraryItem["itemType"]) {
  if (itemType === "requirement_version") {
    return t(locale, "requirementVersion");
  }
  if (itemType === "requirement_intake_draft") {
    return t(locale, "draft");
  }
  if (itemType === "requirement_intake_preview") {
    return t(locale, "preview");
  }
  return t(locale, "requirementItem");
}

function evidenceRefsSummary(evidenceRefs: Array<Record<string, unknown>>, locale: Locale) {
  if (evidenceRefs.length === 0) {
    return t(locale, "none");
  }
  const firstRef = evidenceRefs[0];
  const refType = String(firstRef.type ?? firstRef.evidenceType ?? t(locale, "evidence"));
  const refId = String(firstRef.id ?? firstRef.ref ?? firstRef.storageRef ?? "");
  const firstLabel = refId ? `${refType}:${refId.slice(0, 12)}` : refType;
  return evidenceRefs.length === 1 ? firstLabel : `${firstLabel} +${evidenceRefs.length - 1}`;
}

function draftModeTitle(locale: Locale, sourceMode: SourceMode) {
  if (sourceMode === "ocr_upload") {
    return t(locale, "ocrRequirementDraft");
  }
  if (sourceMode === "upload") {
    return t(locale, "uploadRequirementDraft");
  }
  if (sourceMode === "external_link") {
    return t(locale, "externalLinkRequirementDraft");
  }
  if (sourceMode === "connector") {
    return t(locale, "connectorRequirementDraft");
  }
  return t(locale, "pasteRequirementDraft");
}

function warningLabel(locale: Locale, warning: string) {
  if (warning === "ocr_text_extracted") {
    return t(locale, "warningOcrTextExtracted");
  }
  if (warning === "ocr_review_required") {
    return t(locale, "warningOcrReviewRequired");
  }
  if (warning === "ocr_low_confidence_blocked") {
    return t(locale, "warningOcrLowConfidenceBlocked");
  }
  if (warning === "missing_requirements") {
    return t(locale, "warningMissingRequirements");
  }
  if (warning === "missing_acceptance_criteria") {
    return t(locale, "warningMissingAcceptanceCriteria");
  }
  if (warning === "sensitive_content_redacted") {
    return t(locale, "warningSensitiveContentRedacted");
  }
  return warning;
}
