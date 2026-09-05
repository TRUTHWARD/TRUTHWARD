/* SPDX-License-Identifier: Apache-2.0 */
import { FormEvent, useEffect, useMemo, useState } from "react";

import type {
  CurrentUser,
  EnvironmentItem,
  ExecutionPayload,
  PlanPayload,
  PlanUpdatePayload,
  ProjectItem,
  RequirementClarification,
  RequirementLibraryItem,
  RequirementLibraryPipelinePayload,
  RequirementLibraryProjection,
  RequirementPipelinePayload,
  RequirementPipelineState,
  WorkflowRunProjection,
} from "../lib/api";
import { fetchRequirementLibrary } from "../lib/api";
import { BrowserPlanFields } from "../components/BrowserPlanFields";
import { browserPlanError, buildBrowserPlan, readBrowserPlan } from "../lib/browserPlan";
import { Locale, t } from "../i18n";
import {
  displayDomainLabel,
  displayFindingTitle,
  displayReasonCode,
  displayStageLabel,
  displayStatus,
  displayStrategyLabel,
} from "../lib/presentation";
import type { ApprovalItem, ExecutionItem, JobItem, PlanItem, ReplayItem } from "../store/platform";

type WorkflowPageProps = {
  approvals: ApprovalItem[];
  clarifications: RequirementClarification[];
  currentUser: CurrentUser | null;
  environments: EnvironmentItem[];
  error: string | null;
  executionFindings: Array<{ id: string; domain: string; severity: string; title: string; summary: string; confidence: number | null }>;
  executionProgress: { progress: number; currentTask: string | null; completedTasks: number; totalTasks: number } | null;
  executionTasks: Array<{
    id: string;
    domain: string;
    taskType: string;
    runner: string;
    status: string;
    stage: string | null;
    retryCount: number;
    errorMessage: string | null;
    resultPayload: Record<string, unknown>;
  }>;
  executions: ExecutionItem[];
  jobs: JobItem[];
  loading: boolean;
  locale: Locale;
  onAnswerClarification: (runId: string, clarificationId: string, answer: string) => Promise<void>;
  onApproveApproval: (approvalId: string, comment: string) => Promise<void>;
  onCancelApproval: (approvalId: string, comment: string) => Promise<void>;
  onCancelExecution: (executionId: string) => Promise<void>;
  onCreateExecution: (payload: ExecutionPayload) => Promise<void>;
  onCreatePlan: (payload: PlanPayload) => Promise<void>;
  onCreateRequirementLibraryPipeline: (payload: RequirementLibraryPipelinePayload) => Promise<void>;
  onCreateRequirementPipeline: (payload: RequirementPipelinePayload) => Promise<void>;
  onDeletePlan: (planId: string) => Promise<void>;
  onGateExecution: (executionId: string) => Promise<void>;
  onGeneratePlan: (planId: string) => Promise<void>;
  onHealExecution: (executionId: string) => Promise<void>;
  onRejectApproval: (approvalId: string, comment: string) => Promise<void>;
  onRetryExecution: (executionId: string) => Promise<void>;
  onNavigateRoute: (route: string) => void;
  onSelectExecution: (executionId: string) => void;
  onSelectPipeline: (runId: string) => Promise<void>;
  onSelectPlan: (planId: string) => void;
  onUpdatePlan: (planId: string, payload: PlanUpdatePayload) => Promise<void>;
  pipelineReplay: Record<string, unknown> | null;
  pipelines: RequirementPipelineState[];
  plans: PlanItem[];
  projects: ProjectItem[];
  replay: ReplayItem | null;
  selectedExecutionId: string | null;
  selectedPipelineId: string | null;
  selectedPlanId: string | null;
  workflowRunProjection: WorkflowRunProjection | null;
  workflowRuns: WorkflowRunProjection[];
};

const DOMAIN_OPTIONS = ["functional", "performance", "security"];
const RISK_OPTIONS = ["low", "medium", "high"];
const SOURCE_FILTER_OPTIONS = ["paste", "upload", "external_link", "connector", "requirement_version"];
const STATUS_FILTER_OPTIONS = ["draft", "previewed", "generated", "confirmed", "active", "superseded", "discarded"];
type RequirementInputMode = "manual" | "library";
type SelectedRequirementItemRef = { requirementVersionId: string; requirementItemId: string };

function hasCapability(user: CurrentUser | null, capability: string) {
  return user?.capabilities.includes(capability) ?? false;
}

function hasRole(user: CurrentUser | null, role: string) {
  return user?.roles.includes(role) ?? false;
}

function splitLines(value: string) {
  return value
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function toggleOption(values: string[], option: string) {
  if (values.includes(option)) {
    const next = values.filter((item) => item !== option);
    return next.length > 0 ? next : values;
  }
  return [...values, option];
}

function compactJson(value: unknown) {
  if (value === null || value === undefined) {
    return "{}";
  }
  return JSON.stringify(value, null, 2);
}

export function WorkflowPage({
  approvals,
  clarifications,
  currentUser,
  environments,
  error,
  executionFindings,
  executionProgress,
  executionTasks,
  executions,
  jobs,
  loading,
  locale,
  onAnswerClarification,
  onApproveApproval,
  onCancelApproval,
  onCancelExecution,
  onCreateExecution,
  onCreatePlan,
  onCreateRequirementLibraryPipeline,
  onCreateRequirementPipeline,
  onDeletePlan,
  onGateExecution,
  onGeneratePlan,
  onHealExecution,
  onRejectApproval,
  onRetryExecution,
  onNavigateRoute,
  onSelectExecution,
  onSelectPipeline,
  onSelectPlan,
  onUpdatePlan,
  pipelineReplay,
  pipelines,
  plans,
  projects,
  replay,
  selectedExecutionId,
  selectedPipelineId,
  selectedPlanId,
  workflowRunProjection,
  workflowRuns,
}: WorkflowPageProps) {
  const canReadRequirements = hasCapability(currentUser, "requirements.read");
  const canManageRequirements = hasCapability(currentUser, "requirements.manage");
  const canManagePlans = hasCapability(currentUser, "test_plans.manage");
  const canManageExecutions = hasCapability(currentUser, "executions.manage");
  const canManageExploratory = hasCapability(currentUser, "exploratory_sessions.manage");
  const canManageApprovals = hasRole(currentUser, "admin");
  const isCommunityEdition = currentUser?.edition === "community";
  const createRequirementLibraryPipeline = onCreateRequirementLibraryPipeline;
  const selectedPipeline = pipelines.find((pipeline) => pipeline.orchestrationId === selectedPipelineId) ?? pipelines[0] ?? null;
  const selectedPlan = plans.find((plan) => plan.id === selectedPlanId) ?? plans[0] ?? null;
  const selectedExecution = executions.find((execution) => execution.id === selectedExecutionId) ?? executions[0] ?? null;
  const selectedWorkflowProjection =
    workflowRunProjection
    ?? workflowRuns.find((run) => run.runId === selectedPipeline?.orchestrationId)
    ?? workflowRuns.find((run) => String(run.linkedResources.execution?.executionId ?? "") === selectedExecution?.id)
    ?? workflowRuns.find((run) => String(run.linkedResources.plan?.planId ?? "") === selectedPlan?.id)
    ?? workflowRuns[0]
    ?? null;
  const pendingApprovals = approvals.filter((approval) => approval.status === "pending");
  const selectedReason = String(selectedPipeline?.result?.reason ?? "");
  const approvalRequired = selectedReason === "high_risk_approval_required" || pendingApprovals.length > 0;
  const blocked = Boolean(selectedPipeline?.blocked);
  const selectedPipelineLabel = selectedPipeline ? selectedPipeline.orchestrationId.slice(0, 8) : t(locale, "none");
  const exploratorySessionCount = selectedWorkflowProjection?.linkedResources.exploratorySessions.length ?? 0;
  const regressionCaseCount = Number(selectedWorkflowProjection?.linkedResources.regressionPlan?.["recommendedCaseCount"] ?? 0);
  const governanceStatus: WorkflowRunProjection["governanceStatus"] = selectedWorkflowProjection?.governanceStatus ?? {};

  const [requirementInputMode, setRequirementInputMode] = useState<RequirementInputMode>("manual");
  const [libraryProjection, setLibraryProjection] = useState<RequirementLibraryProjection | null>(null);
  const [libraryLoading, setLibraryLoading] = useState(false);
  const [libraryError, setLibraryError] = useState<string | null>(null);
  const [libraryRefreshToken, setLibraryRefreshToken] = useState(0);
  const [libraryFilters, setLibraryFilters] = useState({
    projectId: "",
    environmentId: "",
    requirementVersionId: "",
    sourceType: "",
    status: "",
    keyword: "",
  });
  const [selectedLibraryRequirementVersionId, setSelectedLibraryRequirementVersionId] = useState("");
  const [selectedLibraryRequirementItemRefs, setSelectedLibraryRequirementItemRefs] = useState<SelectedRequirementItemRef[]>([]);
  const [requirementForm, setRequirementForm] = useState({
    name: "",
    sourceRef: "",
    document: "",
    requirements: "",
    acceptanceCriteria: "",
    environment: "local",
    projectId: "",
    environmentId: "",
    domains: DOMAIN_OPTIONS,
    riskLevel: "medium",
  });
  const [planForm, setPlanForm] = useState({
    name: "",
    sourceRef: "",
    environment: "local",
    projectId: "",
    environmentId: "",
    domains: DOMAIN_OPTIONS,
    riskLevel: "medium",
    status: "draft",
  });
  const [browserForm, setBrowserForm] = useState(() => readBrowserPlan({}));
  const [browserEdited, setBrowserEdited] = useState(false);
  const [executionForm, setExecutionForm] = useState({
    planId: selectedPlan?.id ?? "",
    environment: selectedPlan?.environment ?? "local",
    runFunctional: true,
    runPerformance: true,
    runSecurity: true,
    enableTriage: !isCommunityEdition,
    enableHealing: false,
    parallelism: 1,
  });
  const [clarificationAnswers, setClarificationAnswers] = useState<Record<string, string>>({});
  const [approvalComments, setApprovalComments] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const environmentsForLibraryProject = useMemo(
    () => environments.filter((environment) => !libraryFilters.projectId || environment.projectId === libraryFilters.projectId),
    [environments, libraryFilters.projectId],
  );
  const libraryItems = libraryProjection?.items ?? [];
  const libraryRequirementVersions = useMemo(
    () => libraryItems.filter((item) => item.itemType === "requirement_version" && item.requirementVersionId),
    [libraryItems],
  );
  const libraryRequirementItems = useMemo(
    () => libraryItems.filter((item) => item.itemType === "requirement_item" && item.requirementVersionId && item.requirementItemId),
    [libraryItems],
  );
  const selectedLibraryVersion = libraryRequirementVersions.find(
    (item) => item.requirementVersionId === selectedLibraryRequirementVersionId,
  );

  useEffect(() => {
    let cancelled = false;
    if (!currentUser || !canReadRequirements) {
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
      requirementVersionId: libraryFilters.requirementVersionId || null,
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
    libraryFilters.requirementVersionId,
    libraryFilters.sourceType,
    libraryFilters.status,
    libraryRefreshToken,
    locale,
  ]);

  useEffect(() => {
    if (
      selectedLibraryRequirementVersionId
      && !libraryItems.some((item) => item.requirementVersionId === selectedLibraryRequirementVersionId)
    ) {
      setSelectedLibraryRequirementVersionId("");
      setSelectedLibraryRequirementItemRefs([]);
    }
  }, [libraryItems, selectedLibraryRequirementVersionId]);

  useEffect(() => {
    if (!selectedPlan) {
      setBrowserForm(readBrowserPlan({}));
      setBrowserEdited(false);
      return;
    }
    setPlanForm({
      name: selectedPlan.name,
      sourceRef: selectedPlan.sourceRef ?? "",
      environment: selectedPlan.environment,
      projectId: selectedPlan.projectId ?? "",
      environmentId: selectedPlan.environmentId ?? "",
      domains: selectedPlan.domains.length > 0 ? selectedPlan.domains : DOMAIN_OPTIONS,
      riskLevel: selectedPlan.riskLevel,
      status: selectedPlan.status,
    });
    setBrowserForm(readBrowserPlan(selectedPlan.domainConfig ?? {}));
    setBrowserEdited(false);
    setExecutionForm((current) => ({
      ...current,
      planId: selectedPlan.id,
      environment: selectedPlan.environment,
      runFunctional: selectedPlan.domains.includes("functional"),
      runPerformance: selectedPlan.domains.includes("performance"),
      runSecurity: selectedPlan.domains.includes("security"),
    }));
  }, [selectedPlan?.id]);

  const environmentOptionsForProject = (projectId: string) =>
    environments.filter((environment) => !projectId || environment.projectId === projectId);

  const runAction = async (action: () => Promise<void>, successKey: Parameters<typeof t>[1]) => {
    setSubmitting(true);
    setMessage(null);
    try {
      await action();
      setMessage(t(locale, successKey));
    } catch (actionError) {
      setMessage(actionError instanceof Error ? actionError.message : t(locale, "workflowActionFailed"));
    } finally {
      setSubmitting(false);
    }
  };

  const submitRequirement = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!canManageRequirements) {
      return;
    }
    void runAction(
      () =>
        onCreateRequirementPipeline({
          name: requirementForm.name,
          sourceRef: requirementForm.sourceRef,
          document: requirementForm.document,
          requirements: splitLines(requirementForm.requirements),
          acceptanceCriteria: splitLines(requirementForm.acceptanceCriteria),
          environment: requirementForm.environment,
          projectId: requirementForm.projectId || null,
          environmentId: requirementForm.environmentId || null,
          domains: requirementForm.domains,
          riskLevel: requirementForm.riskLevel,
          metadata: { source: "workflow-ui" },
        }),
      "requirementPipelineSubmitted",
    );
  };

  const selectLibraryVersion = (item: RequirementLibraryItem) => {
    const versionId = item.requirementVersionId ?? item.linkedRequirementVersionId ?? "";
    if (!versionId) {
      return;
    }
    setSelectedLibraryRequirementVersionId(versionId);
  };

  const toggleLibraryRequirementItem = (item: RequirementLibraryItem) => {
    const versionId = item.requirementVersionId ?? "";
    const itemId = item.requirementItemId ?? "";
    if (!versionId || !itemId) {
      return;
    }
    if (!selectedLibraryRequirementVersionId) {
      setSelectedLibraryRequirementVersionId(versionId);
    }
    setSelectedLibraryRequirementItemRefs((currentRefs) => {
      const exists = currentRefs.some(
        (current) => current.requirementVersionId === versionId && current.requirementItemId === itemId,
      );
      if (exists) {
        return currentRefs.filter(
          (current) => current.requirementVersionId !== versionId || current.requirementItemId !== itemId,
        );
      }
      return [...currentRefs, { requirementVersionId: versionId, requirementItemId: itemId }];
    });
  };

  const submitLibrarySelection = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!canManageRequirements || (!selectedLibraryRequirementVersionId && selectedLibraryRequirementItemRefs.length === 0)) {
      return;
    }
    const requirementVersionIds = selectedLibraryRequirementItemRefs.length > 0
      ? Array.from(new Set(selectedLibraryRequirementItemRefs.map((item) => item.requirementVersionId)))
      : [selectedLibraryRequirementVersionId];
    const requirementItemRefs = requirementVersionIds.map((requirementVersionId) => ({
      requirementVersionId,
      requirementItemIds: selectedLibraryRequirementItemRefs
        .filter((item) => item.requirementVersionId === requirementVersionId)
        .map((item) => item.requirementItemId),
    }));
    const selectionMode = requirementVersionIds.length > 1
      ? "requirement_scope"
      : selectedLibraryRequirementItemRefs.length > 0 ? "requirement_items" : "requirement_version";
    void runAction(
      () =>
        createRequirementLibraryPipeline({
          selectionMode,
          requirementVersionId: requirementVersionIds[0],
          requirementVersionIds,
          requirementItemIds: requirementItemRefs[0]?.requirementItemIds ?? [],
          requirementItemRefs,
          metadata: { source: "workflow-requirement-library-ui" },
        }),
      "requirementLibraryPipelineSubmitted",
    );
  };

  const validateBrowserForm = () => {
    const error = browserEdited ? browserPlanError(browserForm) : null;
    if (error) {
      setMessage(t(locale, error));
      return false;
    }
    if (browserForm.mode !== "none" && (!planForm.projectId || !planForm.environmentId || !planForm.domains.includes("functional"))) {
      setMessage(t(locale, "browserScopeRequired"));
      return false;
    }
    return true;
  };
  const planDomainConfig = () => browserEdited
    ? buildBrowserPlan(selectedPlan?.domainConfig ?? {}, browserForm, planForm.riskLevel)
    : selectedPlan?.domainConfig ?? {};

  const submitPlanCreate = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!canManagePlans || submitting || !validateBrowserForm()) {
      return;
    }
    const payload: PlanPayload = {
      name: planForm.name,
      sourceType: "manual",
      sourceRef: planForm.sourceRef || null,
      environment: planForm.environment,
      projectId: planForm.projectId || null,
      environmentId: planForm.environmentId || null,
      domains: planForm.domains,
      domainConfig: planDomainConfig(),
      riskLevel: planForm.riskLevel,
      input: { source: "workflow-ui" },
    };
    void runAction(() => onCreatePlan(payload), "planSaved");
  };

  const updateSelectedPlan = () => {
    if (!canManagePlans || submitting || !selectedPlan || !validateBrowserForm()) {
      return;
    }
    void runAction(
      () =>
        onUpdatePlan(selectedPlan.id, {
          name: planForm.name,
          environment: planForm.environment,
          projectId: planForm.projectId || null,
          environmentId: planForm.environmentId || null,
          domains: planForm.domains,
          domainConfig: planDomainConfig(),
          riskLevel: planForm.riskLevel,
          input: selectedPlan.input,
          status: planForm.status,
        }),
      "planSaved",
    );
  };

  const submitExecution = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!canManageExecutions || submitting || !executionForm.planId) {
      return;
    }
    void runAction(
      () =>
        onCreateExecution({
          planId: executionForm.planId,
          environment: executionForm.environment,
          triggeredBy: "workflow-ui",
          options: {
            runFunctional: executionForm.runFunctional,
            runPerformance: executionForm.runPerformance,
            runSecurity: executionForm.runSecurity,
            enableTriage: !isCommunityEdition && executionForm.enableTriage,
            enableHealing: !isCommunityEdition && executionForm.enableHealing,
            parallelism: executionForm.parallelism,
          },
        }),
      "executionStarted",
    );
  };

  const answerClarification = (clarification: RequirementClarification) => {
    if (!canManageRequirements || !selectedPipeline) {
      return;
    }
    const answer = clarificationAnswers[clarification.clarificationId]?.trim();
    if (!answer) {
      return;
    }
    void runAction(
      () => onAnswerClarification(selectedPipeline.orchestrationId, clarification.clarificationId, answer),
      "clarificationAnswered",
    );
  };

  const selectedExecutionJobs = selectedExecution
    ? jobs.filter((job) => job.resultRef === selectedExecution.id || String(job.payload.executionId ?? "") === selectedExecution.id)
    : [];

  return (
    <div className="page-shell" data-route="/workflow">
      <div className="page-toolbar">
        <div>
          <span className="eyebrow">{t(locale, "coreWorkflow")}</span>
          <h1>{t(locale, "workflowEntry")}</h1>
        </div>
      </div>

      {!canManageRequirements && !canManagePlans && !canManageExecutions ? (
        <div className="notice-banner">{t(locale, "workflowReadOnlyNotice")}</div>
      ) : null}
      {loading ? <div className="notice-banner">{t(locale, "workflowLoading")}</div> : null}
      {error ? <div className="notice-banner">{t(locale, "workflowErrorState")}: {error}</div> : null}
      {message ? <div className="notice-banner">{message}</div> : null}
      {blocked ? <div className="notice-banner">{t(locale, "workflowBlockedState")}</div> : null}
      {approvalRequired ? <div className="notice-banner">{t(locale, "workflowApprovalRequired")}</div> : null}

      <div className="stats-grid">
        <Metric label={t(locale, "pipeline")} value={selectedPipelineLabel} />
        <Metric label={t(locale, "plans")} value={String(plans.length)} />
        <Metric label={t(locale, "executions")} value={String(executions.length)} />
        <Metric label={t(locale, "pendingApprovals")} value={String(pendingApprovals.length)} />
      </div>

      <section className="panel">
        <div className="panel__header">
          <span className="eyebrow">{t(locale, "workflowProjectionContext")}</span>
          <h2>{t(locale, "mainGovernanceFlow")}</h2>
        </div>
        {!selectedWorkflowProjection ? (
          <div className="empty-state">{t(locale, "workflowProjectionUnavailable")}</div>
        ) : (
          <div className="detail-stack">
            <div className="workflow-stage-track" aria-label={t(locale, "workflowStages")}>
              {selectedWorkflowProjection.stageSummaries.map((stage) => (
                <div className={`workflow-stage workflow-stage--${stage.status}`} key={stage.stageKey}>
                  <span>{displayStageLabel(locale, stage.stageKey, stage.label)}</span>
                  <strong>{displayStatus(locale, stage.status)}</strong>
                  {stage.statusReason ? <small title={stage.statusReason}>{displayReasonCode(locale, stage.statusReason)}</small> : null}
                </div>
              ))}
            </div>

            <div className="workflow-summary-columns">
              <div className="workflow-summary-column">
                <section>
                  <h3>{t(locale, "testDomains")}</h3>
                  <div className="inline-status-list">
                    {selectedWorkflowProjection.testDomains.map((domain) => (
                      <div className="inline-status" key={domain.domain}>
                        <span>{domainLabel(locale, domain.domain)}</span>
                        <strong>{displayStatus(locale, domain.status)}</strong>
                      </div>
                    ))}
                  </div>
                </section>
                <section>
                  <h3>{t(locale, "governanceStatus")}</h3>
                  <div className="stats-grid stats-grid--compact">
                    <Metric label={t(locale, "activeSkillBindings")} value={String(countRefs(governanceStatus.activeSkillBindings))} />
                    <Metric label={t(locale, "skillInvocationRefs")} value={String(countRefs(governanceStatus.skillInvocationRefs))} />
                    <Metric label={t(locale, "approvalRefs")} value={String(countRefs(governanceStatus.approvalRefs))} />
                    <Metric label={t(locale, "guardrailRefs")} value={String(countRefs(governanceStatus.guardrailEventRefs))} />
                    <Metric label={t(locale, "auditRefs")} value={String(countRefs(governanceStatus.auditRefs))} />
                    <Metric label={t(locale, "replayRefs")} value={String(countRefs(governanceStatus.replayRefs))} />
                    <Metric label={t(locale, "exploratorySessions")} value={String(exploratorySessionCount)} />
                    <Metric label={t(locale, "regressionRecommendedCases")} value={String(regressionCaseCount)} />
                  </div>
                </section>
              </div>

              <div className="workflow-summary-column">
                <section>
                  <h3>{t(locale, "executionStrategies")}</h3>
                  <div className="stack-list">
                    {selectedWorkflowProjection.executionStrategies.map((strategy) => (
                      <div className="stack-row stack-row--dense" key={strategy.strategy}>
                        <div>
                          <strong>{displayStrategyLabel(locale, strategy.strategy)}</strong>
                          <p className="technical-value">{strategy.requiredCapability ?? t(locale, "none")}</p>
                        </div>
                        <span className={`status-pill status-pill--${strategy.status}`}>{displayStatus(locale, strategy.status)}</span>
                      </div>
                    ))}
                  </div>
                  <div className="button-row">
                    <button className="secondary-button" onClick={() => onNavigateRoute("/exploratory-sessions")} type="button">
                      {t(locale, "openExploratoryWorkbench")}
                    </button>
                    <button className="secondary-button" disabled={!canManageExploratory} onClick={() => onNavigateRoute("/exploratory-sessions")} type="button">
                      {t(locale, "createOrLinkExploratory")}
                    </button>
                    <button className="secondary-button" onClick={() => onNavigateRoute("/executions")} type="button">
                      {t(locale, "openRegressionExecution")}
                    </button>
                  </div>
                </section>
                <section>
                  <h3>{t(locale, "currentUserCapabilityState")}</h3>
                  <div className="inline-status-list">
                    {Object.entries(governanceStatus.currentUserCapabilityState ?? {}).slice(0, 8).map(([capability, state]) => (
                      <div className="inline-status" key={capability}>
                        <span className="technical-value">{capability}</span>
                        <strong>{displayStatus(locale, state)}</strong>
                      </div>
                    ))}
                  </div>
                  <div className="button-row">
                    <button className="secondary-button" onClick={() => onNavigateRoute("/workflow-runs")} type="button">{t(locale, "openWorkflowRunBoard")}</button>
                    <button className="secondary-button" onClick={() => onNavigateRoute("/capability-bindings")} type="button">{t(locale, "capabilityBindings")}</button>
                    <button className="secondary-button" onClick={() => onNavigateRoute("/skill-invocations")} type="button">{t(locale, "skillInvocations")}</button>
                    <button className="secondary-button" onClick={() => onNavigateRoute("/audit-logs")} type="button">{t(locale, "auditLogs")}</button>
                    <button className="secondary-button" onClick={() => onNavigateRoute("/replay-repository")} type="button">{t(locale, "replayRepository")}</button>
                    <button className="secondary-button" onClick={() => onNavigateRoute("/gate-decisions")} type="button">{t(locale, "gateDecisions")}</button>
                  </div>
                </section>
              </div>
            </div>
          </div>
        )}
      </section>

      <div className="page-columns">
        <section className="panel">
          <div className="panel__header">
            <span className="eyebrow">{t(locale, "requirementIntake")}</span>
            <h2>{t(locale, "submitRequirement")}</h2>
          </div>
          <div
            aria-label={t(locale, "requirementIntake")}
            className="segmented-control"
            role="group"
          >
            <button
              className={requirementInputMode === "manual" ? "segmented-control__item segmented-control__item--active" : "segmented-control__item"}
              onClick={() => setRequirementInputMode("manual")}
              type="button"
            >
              {t(locale, "manualRequirementMode")}
            </button>
            <button
              className={requirementInputMode === "library" ? "segmented-control__item segmented-control__item--active" : "segmented-control__item"}
              onClick={() => setRequirementInputMode("library")}
              type="button"
            >
              {t(locale, "requirementLibraryMode")}
            </button>
          </div>
          {requirementInputMode === "manual" ? (
          <form className="control-form" onSubmit={submitRequirement}>
            <label className="form-field">
              {t(locale, "requirementName")}
              <input
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setRequirementForm((current) => ({ ...current, name: event.target.value }))}
                required
                value={requirementForm.name}
              />
            </label>
            <label className="form-field">
              {t(locale, "sourceRef")}
              <input
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setRequirementForm((current) => ({ ...current, sourceRef: event.target.value }))}
                required
                value={requirementForm.sourceRef}
              />
            </label>
            <label className="form-field">
              {t(locale, "project")}
              <select
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setRequirementForm((current) => ({ ...current, projectId: event.target.value, environmentId: "" }))}
                value={requirementForm.projectId}
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
                disabled={!canManageRequirements || submitting || !requirementForm.projectId}
                onChange={(event) => {
                  const environment = environments.find((item) => item.id === event.target.value);
                  setRequirementForm((current) => ({
                    ...current,
                    environmentId: event.target.value,
                    environment: environment?.key || current.environment,
                  }));
                }}
                value={requirementForm.environmentId}
              >
                <option value="">{t(locale, "none")}</option>
                {environmentOptionsForProject(requirementForm.projectId).map((environment) => (
                  <option key={environment.id} value={environment.id}>{environment.name}</option>
                ))}
              </select>
            </label>
            <label className="form-field">
              {t(locale, "environmentKey")}
              <input
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setRequirementForm((current) => ({ ...current, environment: event.target.value }))}
                required
                value={requirementForm.environment}
              />
            </label>
            <label className="form-field">
              {t(locale, "riskLevel")}
              <select
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setRequirementForm((current) => ({ ...current, riskLevel: event.target.value }))}
                value={requirementForm.riskLevel}
              >
                {RISK_OPTIONS.map((risk) => (
                  <option key={risk} value={risk}>{displayStatus(locale, risk)}</option>
                ))}
              </select>
            </label>
            <DomainChooser
              disabled={!canManageRequirements || submitting}
              locale={locale}
              onToggle={(domain) => setRequirementForm((current) => ({ ...current, domains: toggleOption(current.domains, domain) }))}
              selected={requirementForm.domains}
            />
            <label className="form-field">
              {t(locale, "requirementDocument")}
              <textarea
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setRequirementForm((current) => ({ ...current, document: event.target.value }))}
                required
                rows={5}
                value={requirementForm.document}
              />
            </label>
            <label className="form-field">
              {t(locale, "requirementsList")}
              <textarea
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setRequirementForm((current) => ({ ...current, requirements: event.target.value }))}
                rows={4}
                value={requirementForm.requirements}
              />
            </label>
            <label className="form-field">
              {t(locale, "acceptanceCriteria")}
              <textarea
                disabled={!canManageRequirements || submitting}
                onChange={(event) => setRequirementForm((current) => ({ ...current, acceptanceCriteria: event.target.value }))}
                rows={4}
                value={requirementForm.acceptanceCriteria}
              />
            </label>
            <button className="primary-button" disabled={!canManageRequirements || submitting} type="submit">
              {t(locale, "submitRequirement")}
            </button>
          </form>
          ) : (
          <form className="control-form" onSubmit={submitLibrarySelection}>
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
                    {t(locale, "requirementVersion")}
                    <input
                      onChange={(event) => setLibraryFilters((current) => ({ ...current, requirementVersionId: event.target.value }))}
                      placeholder={t(locale, "requirementVersionFilterPlaceholder")}
                      value={libraryFilters.requirementVersionId}
                    />
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
                        <option key={status} value={status}>{displayStatus(locale, status)}</option>
                      ))}
                    </select>
                  </label>
                  <button className="secondary-button" onClick={() => setLibraryRefreshToken((current) => current + 1)} type="button">
                    {t(locale, "refresh")}
                  </button>
                </div>

                <div className="stats-grid stats-grid--compact">
                  <Metric label={t(locale, "requirementVersions")} value={String(libraryProjection?.summary.requirementVersionCount ?? 0)} />
                  <Metric label={t(locale, "requirementItems")} value={String(libraryProjection?.summary.requirementItemCount ?? 0)} />
                  <Metric label={t(locale, "selectedRequirementItems")} value={String(selectedLibraryRequirementItemRefs.length)} />
                  <Metric label={t(locale, "pipeline")} value={selectedLibraryVersion?.linkedPipelineId?.slice(0, 8) ?? t(locale, "none")} />
                </div>

                {libraryLoading ? <div className="empty-state">{t(locale, "requirementLibraryLoading")}</div> : null}
                {libraryError ? <div className="error-banner"><strong>{t(locale, "errorState")}</strong><p>{libraryError}</p></div> : null}
                {!libraryLoading && !libraryError ? (
                  <>
                    <RequirementLibraryVersionList
                      items={libraryRequirementVersions}
                      locale={locale}
                      onSelect={selectLibraryVersion}
                      selectedRequirementVersionId={selectedLibraryRequirementVersionId}
                    />
                    <RequirementLibraryItemSelection
                      disabled={!canManageRequirements || submitting}
                      items={libraryRequirementItems}
                      locale={locale}
                      onToggle={toggleLibraryRequirementItem}
                      selectedRequirementItemRefs={selectedLibraryRequirementItemRefs}
                    />
                  </>
                ) : null}
                <ReadonlyRow
                  label={t(locale, "selectedRequirementVersion")}
                  value={selectedLibraryRequirementVersionId || t(locale, "none")}
                />
                <button
                  className="primary-button"
                  disabled={!canManageRequirements || submitting || !selectedLibraryRequirementVersionId}
                  type="submit"
                >
                  {t(locale, "createPipelineFromRequirementLibrary")}
                </button>
              </>
            ) : null}
          </form>
          )}
        </section>

        <section className="panel">
          <div className="panel__header">
            <span className="eyebrow">{t(locale, "pipelineState")}</span>
            <h2>{t(locale, "requirementPipelines")}</h2>
          </div>
          <div className="stack-list">
            {pipelines.map((pipeline) => (
              <button
                className={`stack-row stack-row--button ${pipeline.orchestrationId === selectedPipeline?.orchestrationId ? "stack-row--selected" : ""}`}
                key={pipeline.orchestrationId}
                onClick={() => void onSelectPipeline(pipeline.orchestrationId)}
                type="button"
              >
                <span>{pipeline.orchestrationId.slice(0, 8)}</span>
                <strong>{displayStatus(locale, pipeline.status)}</strong>
                <span>{pipeline.currentStep ?? t(locale, "none")}</span>
              </button>
            ))}
            {pipelines.length === 0 ? <div className="empty-state">{t(locale, "noRequirementPipelines")}</div> : null}
          </div>

          <div className="detail-stack">
            <ReadonlyRow
              label={t(locale, "status")}
              value={selectedPipeline ? displayStatus(locale, selectedPipeline.status) : t(locale, "none")}
            />
            <ReadonlyRow label={t(locale, "currentStep")} value={selectedPipeline?.currentStep ?? t(locale, "none")} />
            <ReadonlyRow label={t(locale, "plan")} value={selectedPipeline?.planId ?? t(locale, "none")} />
            <ReadonlyRow label={t(locale, "execution")} value={selectedPipeline?.executionId ?? t(locale, "none")} />
          </div>

          <div className="panel__header">
            <span className="eyebrow">{t(locale, "clarifications")}</span>
            <h2>{t(locale, "answerClarifications")}</h2>
          </div>
          <div className="stack-list">
            {clarifications.map((clarification) => (
              <div className="stack-row" key={clarification.clarificationId}>
                <div>
                  <strong>{displayStatus(locale, clarification.priority)} {clarification.questionKey}</strong>
                  <p>{clarification.question}</p>
                  <p>{displayStatus(locale, clarification.status)}</p>
                </div>
                {clarification.status !== "closed" ? (
                  <div className="control-form">
                    <label className="form-field">
                      {t(locale, "answer")}
                      <textarea
                        disabled={!canManageRequirements || submitting}
                        onChange={(event) =>
                          setClarificationAnswers((current) => ({ ...current, [clarification.clarificationId]: event.target.value }))
                        }
                        rows={3}
                        value={clarificationAnswers[clarification.clarificationId] ?? ""}
                      />
                    </label>
                    <button
                      className="secondary-button"
                      disabled={!canManageRequirements || submitting || !(clarificationAnswers[clarification.clarificationId] ?? "").trim()}
                      onClick={() => answerClarification(clarification)}
                      type="button"
                    >
                      {t(locale, "submitAnswer")}
                    </button>
                  </div>
                ) : (
                  <p>{clarification.answer ?? t(locale, "none")}</p>
                )}
              </div>
            ))}
            {selectedPipeline && clarifications.length === 0 ? <div className="empty-state">{t(locale, "noClarifications")}</div> : null}
          </div>
          <pre className="snapshot-json">{compactJson(pipelineReplay)}</pre>
        </section>
      </div>

      <div className="page-columns page-columns--workflow">
        <section className="panel">
          <div className="panel__header">
            <span className="eyebrow">{t(locale, "planning")}</span>
            <h2>{t(locale, "testPlanManagement")}</h2>
          </div>
          <form className="control-form" onSubmit={submitPlanCreate}>
            <label className="form-field">
              {t(locale, "planName")}
              <input
                disabled={!canManagePlans || submitting}
                onChange={(event) => setPlanForm((current) => ({ ...current, name: event.target.value }))}
                required
                value={planForm.name}
              />
            </label>
            <label className="form-field">
              {t(locale, "sourceRef")}
              <input
                disabled={!canManagePlans || submitting}
                onChange={(event) => setPlanForm((current) => ({ ...current, sourceRef: event.target.value }))}
                value={planForm.sourceRef}
              />
            </label>
            <label className="form-field">
              {t(locale, "project")}
              <select
                disabled={!canManagePlans || submitting}
                onChange={(event) => setPlanForm((current) => ({ ...current, projectId: event.target.value, environmentId: "" }))}
                value={planForm.projectId}
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
                disabled={!canManagePlans || submitting || !planForm.projectId}
                onChange={(event) => {
                  const environment = environments.find((item) => item.id === event.target.value);
                  setPlanForm((current) => ({
                    ...current,
                    environmentId: event.target.value,
                    environment: environment?.key || current.environment,
                  }));
                }}
                value={planForm.environmentId}
              >
                <option value="">{t(locale, "none")}</option>
                {environmentOptionsForProject(planForm.projectId).map((environment) => (
                  <option key={environment.id} value={environment.id}>{environment.name}</option>
                ))}
              </select>
            </label>
            <label className="form-field">
              {t(locale, "environmentKey")}
              <input
                disabled={!canManagePlans || submitting}
                onChange={(event) => setPlanForm((current) => ({ ...current, environment: event.target.value }))}
                required
                value={planForm.environment}
              />
            </label>
            <label className="form-field">
              {t(locale, "riskLevel")}
              <select
                disabled={!canManagePlans || submitting}
                onChange={(event) => setPlanForm((current) => ({ ...current, riskLevel: event.target.value }))}
                value={planForm.riskLevel}
              >
                {RISK_OPTIONS.map((risk) => (
                  <option key={risk} value={risk}>{displayStatus(locale, risk)}</option>
                ))}
              </select>
            </label>
            <label className="form-field">
              {t(locale, "status")}
              <select
                disabled={!canManagePlans || submitting}
                onChange={(event) => setPlanForm((current) => ({ ...current, status: event.target.value }))}
                value={planForm.status}
              >
                {["draft", "generated", "approved", "archived"].map((status) => (
                  <option key={status} value={status}>{displayStatus(locale, status)}</option>
                ))}
              </select>
            </label>
            <BrowserPlanFields
              locale={locale}
              value={browserForm}
              disabled={!canManagePlans || submitting}
              onChange={(value) => {
                setBrowserForm(value);
                setBrowserEdited(true);
                if (value.mode !== "none" && value.mode !== "preserve" && browserForm.mode === "none") {
                  setPlanForm(current => ({ ...current, domains: ["functional"] }));
                }
              }}
            />
            <DomainChooser
              disabled={!canManagePlans || submitting}
              locale={locale}
              onToggle={(domain) => setPlanForm((current) => ({ ...current, domains: toggleOption(current.domains, domain) }))}
              selected={planForm.domains}
            />
            <div className="button-row">
              <button className="primary-button" disabled={!canManagePlans || submitting} type="submit">
                {t(locale, "createPlan")}
              </button>
              <button className="secondary-button" disabled={!canManagePlans || submitting || !selectedPlan} onClick={updateSelectedPlan} type="button">
                {t(locale, "updatePlan")}
              </button>
              <button
                className="secondary-button"
                disabled={!canManagePlans || submitting || !selectedPlan}
                onClick={() => selectedPlan && void runAction(() => onDeletePlan(selectedPlan.id), "planDeleted")}
                type="button"
              >
                {t(locale, "deletePlan")}
              </button>
              {!isCommunityEdition ? (
                <button
                  className="secondary-button"
                  disabled={!canManagePlans || submitting || !selectedPlan}
                  onClick={() => selectedPlan && void runAction(() => onGeneratePlan(selectedPlan.id), "planGenerationStarted")}
                  type="button"
                >
                  {t(locale, "generatePlan")}
                </button>
              ) : null}
            </div>
          </form>

          <div className="stack-list">
            {plans.map((plan) => (
              <button
                className={`stack-row stack-row--button ${plan.id === selectedPlan?.id ? "stack-row--selected" : ""}`}
                key={plan.id}
                onClick={() => onSelectPlan(plan.id)}
                type="button"
              >
                <span>{plan.name}</span>
                <strong>{displayStatus(locale, plan.status)}</strong>
                <span>{plan.environment}</span>
              </button>
            ))}
            {plans.length === 0 ? <div className="empty-state">{t(locale, "noPlans")}</div> : null}
          </div>
        </section>

        <section className="panel">
          <div className="panel__header">
            <span className="eyebrow">{t(locale, "execution")}</span>
            <h2>{t(locale, "executionControl")}</h2>
          </div>
          <form className="control-form" onSubmit={submitExecution}>
            <label className="form-field">
              {t(locale, "plan")}
              <select
                disabled={!canManageExecutions || submitting || plans.length === 0}
                onChange={(event) => {
                  const plan = plans.find(item => item.id === event.target.value);
                  setExecutionForm(current => ({
                    ...current,
                    planId: event.target.value,
                    environment: plan?.environment ?? current.environment,
                    runFunctional: plan?.domains.includes("functional") ?? false,
                    runPerformance: plan?.domains.includes("performance") ?? false,
                    runSecurity: plan?.domains.includes("security") ?? false,
                  }));
                }}
                required
                value={executionForm.planId}
              >
                <option value="">{t(locale, "none")}</option>
                {plans.map((plan) => (
                  <option key={plan.id} value={plan.id}>{plan.name}</option>
                ))}
              </select>
            </label>
            <label className="form-field">
              {t(locale, "environmentKey")}
              <input
                disabled={!canManageExecutions || submitting}
                onChange={(event) => setExecutionForm((current) => ({ ...current, environment: event.target.value }))}
                required
                value={executionForm.environment}
              />
            </label>
            <div className="checkbox-grid">
              {[
                ["runFunctional", "functional"],
                ["runPerformance", "performance"],
                ["runSecurity", "security"],
                ...(!isCommunityEdition
                  ? [["enableTriage", "triage"], ["enableHealing", "healing"]]
                  : []),
              ].map(([field, label]) => (
                <label className="check-row" key={field}>
                  <input
                    checked={Boolean(executionForm[field as keyof typeof executionForm])}
                    disabled={!canManageExecutions || submitting}
                    onChange={(event) => setExecutionForm((current) => ({ ...current, [field]: event.target.checked }))}
                    type="checkbox"
                  />
                  <span>{t(locale, label as Parameters<typeof t>[1])}</span>
                </label>
              ))}
            </div>
            <label className="form-field">
              {t(locale, "parallelism")}
              <input
                disabled={!canManageExecutions || submitting}
                min={1}
                max={20}
                onChange={(event) => setExecutionForm((current) => ({ ...current, parallelism: Number(event.target.value) || 1 }))}
                type="number"
                value={executionForm.parallelism}
              />
            </label>
            <button className="primary-button" disabled={!canManageExecutions || submitting || !executionForm.planId} type="submit">
              {t(locale, "startExecution")}
            </button>
          </form>

          <div className="stack-list">
            {executions.map((execution) => (
              <button
                className={`stack-row stack-row--button ${execution.id === selectedExecution?.id ? "stack-row--selected" : ""}`}
                key={execution.id}
                onClick={() => onSelectExecution(execution.id)}
                type="button"
              >
                <span>{execution.id.slice(0, 8)}</span>
                <strong>{displayStatus(locale, execution.status)}</strong>
                <span>{displayStageLabel(locale, execution.stage)}</span>
              </button>
            ))}
            {executions.length === 0 ? <div className="empty-state">{t(locale, "noExecutionCreated")}</div> : null}
          </div>

          <div className="button-row">
            <button
              className="secondary-button"
              disabled={!canManageExecutions || submitting || !selectedExecution}
              onClick={() => selectedExecution && void runAction(() => onCancelExecution(selectedExecution.id), "executionCancelled")}
              type="button"
            >
              {t(locale, "cancelExecution")}
            </button>
            {!isCommunityEdition ? (
              <>
                <button
                  className="secondary-button"
                  disabled={!canManageExecutions || submitting || !selectedExecution}
                  onClick={() => selectedExecution && void runAction(() => onRetryExecution(selectedExecution.id), "executionRetryStarted")}
                  type="button"
                >
                  {t(locale, "retryExecution")}
                </button>
                <button
                  className="secondary-button"
                  disabled={!canManageExecutions || submitting || !selectedExecution}
                  onClick={() => selectedExecution && void runAction(() => onHealExecution(selectedExecution.id), "healingSuggestStarted")}
                  type="button"
                >
                  {t(locale, "healingSuggestOnly")}
                </button>
                <button
                  className="secondary-button"
                  disabled={!canManageExecutions || submitting || !selectedExecution}
                  onClick={() => selectedExecution && void runAction(() => onGateExecution(selectedExecution.id), "gateRequested")}
                  type="button"
                >
                  {t(locale, "runGate")}
                </button>
              </>
            ) : null}
          </div>

          <div className="stats-grid stats-grid--compact">
            <Metric label={t(locale, "progress")} value={executionProgress ? `${executionProgress.progress}%` : t(locale, "none")} />
            <Metric label={t(locale, "tasks")} value={String(executionTasks.length)} />
            <Metric label={t(locale, "findings")} value={String(executionFindings.length)} />
            <Metric label={t(locale, "replayTimeline")} value={String(replay?.timeline?.length ?? 0)} />
          </div>
          <div className="detail-stack">
            {executionTasks.slice(0, 4).map((task) => (
              <div key={task.id}>
                <ReadonlyRow
                  label={`${displayDomainLabel(locale, task.domain)} ${task.taskType}`}
                  value={`${displayStatus(locale, task.status)} ${task.stage ? displayStageLabel(locale, task.stage) : ""}`}
                />
                {task.domain === "functional" ? <p>{t(locale,
                  task.resultPayload.executionMode === "actual" ? "browserActualExecution"
                    : task.resultPayload.executionMode === "simulated" ? "browserSimulatedExecution" : "browserExecutionNotRecorded",
                )}</p> : null}
                {task.errorMessage ? <p role="alert">{task.errorMessage}</p> : null}
              </div>
            ))}
            {selectedExecution ? <button className="secondary-button" type="button" onClick={() => onNavigateRoute("/executions")}>
              {t(locale, "browserInspectArtifacts")}
            </button> : null}
            {executionFindings.slice(0, 4).map((finding) => (
              <ReadonlyRow
                key={finding.id}
                label={`${displayStatus(locale, finding.severity)} ${displayDomainLabel(locale, finding.domain)}`}
                value={displayFindingTitle(locale, finding.title)}
              />
            ))}
            {selectedExecutionJobs.slice(0, 4).map((job) => (
              <ReadonlyRow key={job.id} label={job.jobType} value={`${displayStatus(locale, job.status)} ${job.progress}%`} />
            ))}
          </div>
        </section>
      </div>

      <section className="panel">
        <div className="panel__header">
          <span className="eyebrow">{t(locale, "approvalCenter")}</span>
          <h2>{t(locale, "pendingApprovals")}</h2>
        </div>
        {!canManageApprovals ? <div className="empty-state">{t(locale, "approvalReadOnlyNotice")}</div> : null}
        <div className="table-wrap">
          <table className="data-table data-table--compact">
            <thead>
              <tr>
                <th>{t(locale, "summary")}</th>
                <th>{t(locale, "type")}</th>
                <th>{t(locale, "resource")}</th>
                <th>{t(locale, "status")}</th>
                <th>{t(locale, "decisionComment")}</th>
                <th>{t(locale, "actions")}</th>
              </tr>
            </thead>
            <tbody>
              {approvals.map((approval) => (
                <tr key={approval.id}>
                  <td>{approval.summary}</td>
                  <td>{approval.type}</td>
                  <td>{approval.resourceType}</td>
                  <td>{displayStatus(locale, approval.status)}</td>
                  <td>
                    <input
                      className="text-input"
                      disabled={!canManageApprovals || approval.status !== "pending" || submitting}
                      onChange={(event) => setApprovalComments((current) => ({ ...current, [approval.id]: event.target.value }))}
                      value={approvalComments[approval.id] ?? ""}
                    />
                  </td>
                  <td>
                    <div className="button-row">
                      <button
                        className="link-button"
                        disabled={!canManageApprovals || approval.status !== "pending" || submitting}
                        onClick={() => void runAction(() => onApproveApproval(approval.id, approvalComments[approval.id] ?? ""), "approvalApproved")}
                        type="button"
                      >
                        {t(locale, "approve")}
                      </button>
                      <button
                        className="link-button link-button--danger"
                        disabled={!canManageApprovals || approval.status !== "pending" || submitting}
                        onClick={() => void runAction(() => onRejectApproval(approval.id, approvalComments[approval.id] ?? ""), "approvalRejected")}
                        type="button"
                      >
                        {t(locale, "reject")}
                      </button>
                      <button
                        className="link-button"
                        disabled={!canManageApprovals || approval.status !== "pending" || submitting}
                        onClick={() => void runAction(() => onCancelApproval(approval.id, approvalComments[approval.id] ?? ""), "approvalCancelled")}
                        type="button"
                      >
                        {t(locale, "cancel")}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {approvals.length === 0 ? (
                <tr>
                  <td colSpan={6}>{t(locale, "noPendingApprovals")}</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function countRefs(value: unknown) {
  return Array.isArray(value) ? value.length : 0;
}

function domainLabel(locale: Locale, domain: string) {
  if (domain === "functional" || domain === "performance" || domain === "security") {
    return t(locale, domain);
  }
  return domain;
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

function RequirementLibraryVersionList({
  items,
  locale,
  onSelect,
  selectedRequirementVersionId,
}: {
  items: RequirementLibraryItem[];
  locale: Locale;
  onSelect: (item: RequirementLibraryItem) => void;
  selectedRequirementVersionId: string;
}) {
  if (items.length === 0) {
    return <div className="empty-state">{t(locale, "noRequirementLibraryItems")}</div>;
  }
  return (
    <div className="stack-list">
      {items.map((item) => {
        const versionId = item.requirementVersionId ?? item.linkedRequirementVersionId ?? "";
        return (
          <button
            className={`stack-row stack-row--button ${versionId === selectedRequirementVersionId ? "stack-row--selected" : ""}`}
            key={item.itemId}
            onClick={() => onSelect(item)}
            type="button"
          >
            <span className="status-pill">{sourceTypeLabel(locale, item.sourceType)}</span>
            <strong>{item.title}</strong>
            <span>{versionId || t(locale, "none")}</span>
          </button>
        );
      })}
    </div>
  );
}

function RequirementLibraryItemSelection({
  disabled,
  items,
  locale,
  onToggle,
  selectedRequirementItemRefs,
}: {
  disabled: boolean;
  items: RequirementLibraryItem[];
  locale: Locale;
  onToggle: (item: RequirementLibraryItem) => void;
  selectedRequirementItemRefs: SelectedRequirementItemRef[];
}) {
  if (items.length === 0) {
    return <div className="empty-state">{t(locale, "noRequirementLibraryItems")}</div>;
  }
  return (
    <div className="table-wrap">
      <table className="data-table data-table--compact">
        <thead>
          <tr>
            <th>{t(locale, "select")}</th>
            <th>{t(locale, "requirementItem")}</th>
            <th>{t(locale, "requirementVersion")}</th>
            <th>{t(locale, "source")}</th>
            <th>{t(locale, "status")}</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => {
            const itemId = item.requirementItemId ?? "";
            const versionId = item.requirementVersionId ?? "";
            const checked = selectedRequirementItemRefs.some(
              (selected) => selected.requirementVersionId === versionId && selected.requirementItemId === itemId,
            );
            return (
              <tr key={item.itemId}>
                <td>
                  <input
                    checked={checked}
                    disabled={disabled}
                    onChange={() => onToggle(item)}
                    type="checkbox"
                  />
                </td>
                <td>
                  <strong>{item.title}</strong>
                  {item.summary ? <p>{item.summary}</p> : null}
                </td>
                <td>{versionId || t(locale, "none")}</td>
                <td>
                  <span>{sourceTypeLabel(locale, item.sourceType)}</span>
                  {item.sourceRef ? <p>{item.sourceRef}</p> : null}
                </td>
                <td>
                  <span className={`status-pill status-pill--${item.status}`}>{displayStatus(locale, item.status)}</span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
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

function DomainChooser({
  disabled,
  locale,
  onToggle,
  selected,
}: {
  disabled: boolean;
  locale: Locale;
  onToggle: (domain: string) => void;
  selected: string[];
}) {
  return (
    <div className="checkbox-grid">
      {DOMAIN_OPTIONS.map((domain) => (
        <label className="check-row" key={domain}>
          <input checked={selected.includes(domain)} disabled={disabled} onChange={() => onToggle(domain)} type="checkbox" />
          <span>{t(locale, domain as Parameters<typeof t>[1])}</span>
        </label>
      ))}
    </div>
  );
}
