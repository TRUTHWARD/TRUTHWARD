/* SPDX-License-Identifier: Apache-2.0 */
import { type FormEvent, useEffect, useMemo, useState } from "react";

import { SectionCard } from "../components/SectionCard";
import { Locale, t } from "../i18n";
import type { CurrentUser, WorkItem, WorkItemCreatePayload, WorkItemPriority, WorkItemStatus } from "../lib/api";
import { displayFindingTitle, displayStatus } from "../lib/presentation";
import type { ExecutionItem, PlanItem } from "../store/platform";

type FindingItem = {
  id: string;
  executionId: string;
  taskId: string | null;
  domain: string;
  severity: string;
  source: string;
  title: string;
  summary: string;
};

type ProjectItem = {
  id: string;
  key: string;
  name: string;
};

type WorkItemsPageProps = {
  canManageWorkItems: boolean;
  currentUser: CurrentUser | null;
  executions: ExecutionItem[];
  findings: FindingItem[];
  locale: Locale;
  onAssign: (workItemId: string, assigneeId: string | null) => Promise<void>;
  onClaim: (workItemId: string) => Promise<void>;
  onCreate: (payload: WorkItemCreatePayload) => Promise<void>;
  onSelectExecution: (executionId: string) => void;
  onTransition: (workItemId: string, status: WorkItemStatus, comment?: string | null) => Promise<void>;
  plans: PlanItem[];
  projects: ProjectItem[];
  selectedProjectId: string;
  workItems: WorkItem[];
};

const priorities: WorkItemPriority[] = ["low", "medium", "high", "urgent"];

export function WorkItemsPage({
  canManageWorkItems,
  executions,
  findings,
  locale,
  onAssign,
  onClaim,
  onCreate,
  onSelectExecution,
  onTransition,
  plans,
  projects,
  selectedProjectId,
  workItems,
}: WorkItemsPageProps) {
  const canManage = canManageWorkItems;
  const projectOptions = selectedProjectId === "all-projects" ? projects : projects.filter((project) => project.id === selectedProjectId);
  const initialProjectId = projectOptions[0]?.id ?? "";
  const [selectedWorkItemId, setSelectedWorkItemId] = useState<string | null>(workItems[0]?.id ?? null);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState<WorkItemPriority>("medium");
  const [projectId, setProjectId] = useState(initialProjectId);
  const [executionId, setExecutionId] = useState("");
  const [findingId, setFindingId] = useState("");
  const [requirementItemId, setRequirementItemId] = useState("");
  const [evidenceArtifactId, setEvidenceArtifactId] = useState("");
  const [assigneeId, setAssigneeId] = useState("");
  const [actionAssigneeId, setActionAssigneeId] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const planProjectIds = useMemo(
    () => new Map(plans.filter((plan) => Boolean(plan.projectId)).map((plan) => [plan.id, String(plan.projectId)])),
    [plans],
  );
  const projectExecutions = useMemo(
    () => executions.filter((execution) => !projectId || planProjectIds.get(execution.planId) === projectId),
    [executions, planProjectIds, projectId],
  );
  const executionFindings = useMemo(
    () => findings.filter((finding) => !executionId || finding.executionId === executionId),
    [executionId, findings],
  );
  const selectedWorkItem = workItems.find((item) => item.id === selectedWorkItemId) ?? workItems[0] ?? null;

  useEffect(() => {
    if (projectId && projectOptions.some((project) => project.id === projectId)) {
      return;
    }
    if (initialProjectId) {
      setProjectId(initialProjectId);
    }
  }, [initialProjectId, projectId, projectOptions]);

  useEffect(() => {
    if (selectedWorkItemId && workItems.some((item) => item.id === selectedWorkItemId)) {
      return;
    }
    setSelectedWorkItemId(workItems[0]?.id ?? null);
  }, [selectedWorkItemId, workItems]);

  useEffect(() => {
    setActionAssigneeId(selectedWorkItem?.assigneeId ?? "");
  }, [selectedWorkItem]);

  const runAction = async (action: () => Promise<void>, messageKey: Parameters<typeof t>[1]) => {
    setActionError(null);
    setActionMessage(null);
    try {
      await action();
      setActionMessage(t(locale, messageKey));
    } catch (error) {
      setActionError(error instanceof Error ? error.message : t(locale, "workItemActionFailed"));
    }
  };

  const submitCreate = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!projectId || !title.trim()) {
      return;
    }
    await runAction(async () => {
      await onCreate({
        projectId,
        title: title.trim(),
        description: description.trim() || null,
        priority,
        assigneeId: assigneeId.trim() || null,
        requirementItemId: requirementItemId.trim() || null,
        executionId: executionId || null,
        findingId: findingId || null,
        evidenceArtifactId: evidenceArtifactId.trim() || null,
        evidenceRefs: evidenceArtifactId.trim()
          ? [{ evidenceType: "execution_artifact", ref: evidenceArtifactId.trim() }]
          : [],
        metadata: { source: "tasks_page" },
      });
      setTitle("");
      setDescription("");
      setRequirementItemId("");
      setEvidenceArtifactId("");
      setAssigneeId("");
    }, "workItemCreated");
  };

  const handleExecutionChange = (value: string) => {
    setExecutionId(value);
    setFindingId("");
    if (value) {
      onSelectExecution(value);
    }
  };

  return (
    <div className="page-shell" data-route="/tasks">
      <div className="page-columns">
        <SectionCard title={t(locale, "workItems")} eyebrow={t(locale, "humanTasks")}>
          <div className="stack-list">
            {workItems.map((item) => (
              <button
                className={`stack-row stack-row--button ${item.id === selectedWorkItem?.id ? "stack-row--selected" : ""}`}
                key={item.id}
                onClick={() => setSelectedWorkItemId(item.id)}
                type="button"
              >
                <div>
                  <strong>{item.title}</strong>
                  <p>{displayStatus(locale, item.priority)} {t(locale, "valueSeparator")} {item.assigneeName ?? item.assigneeId ?? t(locale, "unassigned")}</p>
                </div>
                <span>{displayStatus(locale, item.status)}</span>
              </button>
            ))}
            {workItems.length === 0 ? <p className="empty-copy">{t(locale, "noWorkItems")}</p> : null}
          </div>
        </SectionCard>

        <SectionCard title={t(locale, "workItemDetail")}>
          <div className="detail-stack">
            {!canManage ? (
              <div className="warning-banner">
                <strong>{t(locale, "readOnly")}</strong>
                <p>{t(locale, "workItemsManageRestricted")}</p>
              </div>
            ) : null}
            {actionError ? <p className="error-copy">{actionError}</p> : null}
            {actionMessage ? <p className="success-copy">{actionMessage}</p> : null}

            {selectedWorkItem ? (
              <div className="detail-banner">
                <div>
                  <strong>{selectedWorkItem.title}</strong>
                  <p>{displayStatus(locale, selectedWorkItem.status)} {t(locale, "valueSeparator")} {displayStatus(locale, selectedWorkItem.priority)}</p>
                </div>
                <div className="chip-row">
                  <span className="tag">{t(locale, "project")} {selectedWorkItem.projectId.slice(0, 8)}</span>
                  {selectedWorkItem.executionId ? <span className="tag">{t(locale, "execution")} {selectedWorkItem.executionId.slice(0, 8)}</span> : null}
                  {selectedWorkItem.findingId ? <span className="tag">{t(locale, "finding")} {selectedWorkItem.findingId.slice(0, 8)}</span> : null}
                </div>
              </div>
            ) : null}

            {selectedWorkItem ? (
              <div className="detail-grid">
                <div>
                  <h3>{t(locale, "linkedResources")}</h3>
                  <dl className="definition-list">
                    <dt>{t(locale, "requirementItem")}</dt>
                    <dd>{selectedWorkItem.requirementItemId ?? t(locale, "none")}</dd>
                    <dt>{t(locale, "evidenceArtifact")}</dt>
                    <dd>{selectedWorkItem.evidenceArtifactId ?? t(locale, "none")}</dd>
                    <dt>{t(locale, "traceability")}</dt>
                    <dd>{selectedWorkItem.traceId ? selectedWorkItem.traceId.slice(0, 8) : t(locale, "none")}</dd>
                  </dl>
                </div>
                <div>
                  <h3>{t(locale, "actions")}</h3>
                  <div className="form-stack">
                    <label>
                      {t(locale, "assigneeId")}
                      <input disabled={!canManage} onChange={(event) => setActionAssigneeId(event.target.value)} value={actionAssigneeId} />
                    </label>
                    <div className="button-row">
                      <button
                        className="secondary-button"
                        disabled={!canManage}
                        onClick={() => void runAction(() => onAssign(selectedWorkItem.id, actionAssigneeId.trim() || null), "workItemUpdated")}
                        type="button"
                      >
                        {t(locale, "assign")}
                      </button>
                      <button
                        className="secondary-button"
                        disabled={!canManage}
                        onClick={() => void runAction(() => onClaim(selectedWorkItem.id), "workItemUpdated")}
                        type="button"
                      >
                        {t(locale, "claim")}
                      </button>
                      <button
                        className="secondary-button"
                        disabled={!canManage}
                        onClick={() => void runAction(() => onTransition(selectedWorkItem.id, "completed"), "workItemUpdated")}
                        type="button"
                      >
                        {t(locale, "complete")}
                      </button>
                      <button
                        className="secondary-button"
                        disabled={!canManage}
                        onClick={() => void runAction(() => onTransition(selectedWorkItem.id, "cancelled"), "workItemUpdated")}
                        type="button"
                      >
                        {t(locale, "cancelWorkItem")}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ) : null}

            <form className="form-stack" onSubmit={(event) => void submitCreate(event)}>
              <h3>{t(locale, "newWorkItem")}</h3>
              <label>
                {t(locale, "project")}
                <select disabled={!canManage} onChange={(event) => setProjectId(event.target.value)} value={projectId}>
                  {projectOptions.map((project) => (
                    <option key={project.id} value={project.id}>{project.key} {t(locale, "valueSeparator")} {project.name}</option>
                  ))}
                </select>
              </label>
              <label>
                {t(locale, "workItemTitle")}
                <input disabled={!canManage} onChange={(event) => setTitle(event.target.value)} required value={title} />
              </label>
              <label>
                {t(locale, "workItemDescription")}
                <textarea disabled={!canManage} onChange={(event) => setDescription(event.target.value)} value={description} />
              </label>
              <div className="form-grid">
                <label>
                  {t(locale, "priority")}
                  <select disabled={!canManage} onChange={(event) => setPriority(event.target.value as WorkItemPriority)} value={priority}>
                    {priorities.map((item) => <option key={item} value={item}>{displayStatus(locale, item)}</option>)}
                  </select>
                </label>
                <label>
                  {t(locale, "assigneeId")}
                  <input disabled={!canManage} onChange={(event) => setAssigneeId(event.target.value)} value={assigneeId} />
                </label>
              </div>
              <div className="form-grid">
                <label>
                  {t(locale, "execution")}
                  <select disabled={!canManage} onChange={(event) => handleExecutionChange(event.target.value)} value={executionId}>
                    <option value="">{t(locale, "none")}</option>
                    {projectExecutions.map((execution) => (
                      <option key={execution.id} value={execution.id}>{execution.id.slice(0, 8)} {t(locale, "valueSeparator")} {displayStatus(locale, execution.status)}</option>
                    ))}
                  </select>
                </label>
                <label>
                  {t(locale, "finding")}
                  <select disabled={!canManage || !executionId} onChange={(event) => setFindingId(event.target.value)} value={findingId}>
                    <option value="">{t(locale, "none")}</option>
                    {executionFindings.map((finding) => (
                      <option key={finding.id} value={finding.id}>{displayFindingTitle(locale, finding.title)}</option>
                    ))}
                  </select>
                </label>
              </div>
              <div className="form-grid">
                <label>
                  {t(locale, "requirementItem")}
                  <input disabled={!canManage} onChange={(event) => setRequirementItemId(event.target.value)} value={requirementItemId} />
                </label>
                <label>
                  {t(locale, "evidenceArtifact")}
                  <input disabled={!canManage} onChange={(event) => setEvidenceArtifactId(event.target.value)} value={evidenceArtifactId} />
                </label>
              </div>
              <button className="primary-button" disabled={!canManage || !projectId || !title.trim()} type="submit">
                {t(locale, "create")}
              </button>
            </form>
          </div>
        </SectionCard>
      </div>
    </div>
  );
}
