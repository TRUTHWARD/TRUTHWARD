/* SPDX-License-Identifier: Apache-2.0 */
import { useEffect, useMemo, useState } from "react";

import {
  ApiRequestError,
  answerRequirementClarification,
  assignWorkItem,
  approveApproval,
  cancelApproval,
  cancelExecution,
  clearCommunityAuthToken,
  claimWorkItem,
  createExecution,
  createPlan,
  createRequirementLibraryPipeline,
  createRequirementPipeline,
  createWorkItem,
  fetchAgentRuns,
  fetchAuditLogProjection,
  fetchApprovals,
  fetchCapabilityBindings,
  fetchCiGate,
  fetchCorrectionGovernanceProjection,
  fetchCoverageMatrix,
  fetchCoverageProof,
  fetchCoverageSummary,
  fetchCurrentUser,
  fetchEnvironments,
  fetchExecutionFindings,
  fetchExecutionHealing,
  fetchExecutionProgress,
  fetchExecutionReplay,
  fetchExecutionReplayExport,
  fetchExecutionTask,
  fetchExecutionTaskArtifacts,
  fetchExecutionTaskLogs,
  fetchExecutionTaskMetrics,
  fetchExecutionTasks,
  fetchExecutions,
  fetchProjectMembers,
  fetchProjects,
  fetchRequirementClarifications,
  fetchRequirementPipeline,
  fetchRequirementPipelineReplay,
  fetchWorkItems,
  fetchWorkflowRun,
  fetchWorkflowRuns,
  fetchGuardrailEvents,
  fetchGuardrailPolicies,
  fetchHealth,
  fetchJobs,
  fetchObservabilityMetrics,
  fetchPlans,
  fetchQualityDashboard,
  fetchReplayExports,
  fetchRuntimeReadiness,
  fetchSkillInvocations,
  fetchSkills,
  fetchStructuredLogs,
  fetchTraces,
  fetchWorkflowCapabilityGraph,
  deletePlan,
  gateExecution,
  healExecution,
  logoutCommunity,
  rejectApproval,
  refreshFindingExternalIssueStatus,
  retryExecution,
  syncFindingExternalIssue,
  triggerPlanGenerate,
  transitionWorkItem,
  updatePlan,
  type CapabilityBindingMutationPayload,
  type CapabilityBindingMutationResult,
  type ConnectorBindingMutationPayload,
  type ConnectorBindingItem,
  type ConnectorBindingUpdatePayload,
  type CorrectionGovernanceProjection,
  type CurrentUser,
  type EnvironmentMutationPayload,
  type EnvironmentItem,
  type ExecutionTaskArtifact,
  type ExecutionTaskLog,
  type ExecutionTaskMetric,
  type ExecutionTaskRecord,
  type ExternalIssueLink,
  type ProjectMemberMutationPayload,
  type ProjectMutationPayload,
  type ProjectItem,
  type ExecutionPayload,
  type AuditLogProjection,
  ObservabilityMetric,
  type PlanPayload,
  type PlanUpdatePayload,
  QualityDashboard,
  type RequirementClarification,
  type RequirementLibraryPipelinePayload,
  type RequirementPipelinePayload,
  type RequirementPipelineState,
  type RuntimeReadiness,
  type StructuredLogProjection,
  StructuredLogItem,
  type WorkflowRunAction,
  type WorkflowRunProjection,
  type IssueSyncPayload,
  type WorkItem,
  type WorkItemCreatePayload,
  type WorkItemStatus,
} from "./lib/api";
import { Locale, t } from "./i18n";
import {
  IS_OSS_PROFILE,
  isSectionIncludedInProductProfile,
  isSectionVisibleInProductProfile,
} from "./productProfile";
import { ProjectSwitcher, type ProjectOption } from "./components/ProjectSwitcher";
import {
  AccessControlPage,
  AdvancedVisualizationPage,
  ConnectorSettingsPage,
  CorrectionGovernancePage,
  EnterpriseModulesPage,
  EnvironmentSettingsPage,
  GraphCorrectionsPage,
  ImprovementProposalsPage,
  InteractiveGovernancePage,
  KnowledgeGovernancePage,
  LessonsCenterPage,
  ModelsPage,
  ProjectSettingsPage,
  ReplayRepositoryPage,
  SkillGovernancePanel,
  enterpriseApi,
} from "@truthward/enterprise-pages";
import { AgentRunsPage } from "./pages/AgentRunsPage";
import { AuditLogsPage, type AuditLogsAccessState } from "./pages/AuditLogsPage";
import { CandidatePathsPage } from "./pages/CandidatePathsPage";
import { CegVisualizationPage } from "./pages/CegVisualizationPage";
import { ChangeSetsPage } from "./pages/ChangeSetsPage";
import { AdmissionRunsPage } from "./pages/AdmissionRunsPage";
import { PrContextsPage } from "./pages/PrContextsPage";
import { ImpactAnalysisPage } from "./pages/ImpactAnalysisPage";
import { CoverageMatrixPage } from "./pages/CoverageMatrixPage";
import { ExecutionsPage } from "./pages/ExecutionsPage";
import { ExecutionExplanationsPage } from "./pages/ExecutionExplanationsPage";
import { EvidenceSearchPage } from "./pages/EvidenceSearchPage";
import { ExploratorySessionsPage } from "./pages/ExploratorySessionsPage";
import { FindingsPage } from "./pages/FindingsPage";
import { GateDashboardPage } from "./pages/GateDashboardPage";
import { GateDecisionsPage } from "./pages/GateDecisionsPage";
import { GatePoliciesPage } from "@truthward/gate-policies-page";
import { JobsPage } from "./pages/JobsPage";
import { ObservabilityPage } from "./pages/ObservabilityPage";
import { OverviewPage } from "./pages/OverviewPage";
import { RequirementIntakePage } from "./pages/RequirementIntakePage";
import { ReplayCenterPage } from "./pages/ReplayCenterPage";
import { SelectiveReplayPlansPage } from "./pages/SelectiveReplayPlansPage";
import { SkillInvocationsPage } from "./pages/SkillInvocationsPage";
import { SkillRuntimePage } from "./pages/SkillRuntimePage";
import { TestAssetsPage } from "./pages/TestAssetsPage";
import { WorkflowPage } from "./pages/WorkflowPage";
import { WorkflowRunsPage } from "./pages/WorkflowRunsPage";
import { WorkItemsPage } from "./pages/WorkItemsPage";
import { type ExecutionItem, type PlanItem, usePlatformStore } from "./store/platform";

type AppSection =
  | "workspace"
  | "requirement-intake"
  | "workflow-runs"
  | "workflow"
  | "exploratory-sessions"
  | "test-assets"
  | "tasks"
  | "findings"
  | "gate-decisions"
  | "audit-logs"
  | "candidate-paths"
  | "ceg"
  | "change-sets"
  | "pr-contexts"
  | "admission-runs"
  | "impact-analysis"
  | "selective-replay-plans"
  | "graph-corrections"
  | "enterprise-modules"
  | "access-control"
  | "knowledge-governance"
  | "lessons-center"
  | "improvement-proposals"
  | "coverage-matrix"
  | "replay-center"
  | "execution-explanations"
  | "evidence-search"
  | "replay-repository"
  | "interactive-governance"
  | "advanced-visualization"
  | "observability"
  | "execution-dashboard"
  | "gate-dashboard"
  | "gate-policies"
  | "correction-governance"
  | "skill-invocations"
  | "capability-bindings"
  | "project-settings"
  | "environment-settings"
  | "connector-settings"
  | "model-config"
  | "agent-runs"
  | "queue-jobs";

type AppSectionMeta = {
  id: AppSection;
  labelKey: Parameters<typeof t>[1];
  path: string;
  aliases?: string[];
  hiddenFromNavigation?: boolean;
};

type NavigationGroup = {
  id: string;
  labelKey: Parameters<typeof t>[1];
  sectionIds: AppSection[];
};

const sections: AppSectionMeta[] = [
  { id: "workspace", labelKey: "workspace", path: "/" },
  { id: "requirement-intake", labelKey: "requirementIntakeWorkbench", path: "/requirement-intake" },
  { id: "workflow-runs", labelKey: "workflowRuns", path: "/workflow-runs" },
  { id: "workflow", labelKey: "workflowEntry", path: "/workflow" },
  { id: "exploratory-sessions", labelKey: "exploratorySessions", path: "/exploratory-sessions", hiddenFromNavigation: true },
  { id: "test-assets", labelKey: "testAssets", path: "/test-assets" },
  { id: "tasks", labelKey: "workItems", path: "/tasks" },
  { id: "findings", labelKey: "findings", path: "/findings" },
  { id: "gate-decisions", labelKey: "gateDecisions", path: "/gate-decisions" },
  { id: "audit-logs", labelKey: "auditLogs", path: "/audit-logs" },
  { id: "candidate-paths", labelKey: "candidatePaths", path: "/candidate-paths" },
  { id: "ceg", labelKey: "cegVisualization", path: "/ceg" },
  { id: "change-sets", labelKey: "changeSets", path: "/change-sets" },
  { id: "pr-contexts", labelKey: "prContexts", path: "/pr-contexts" },
  { id: "admission-runs", labelKey: "admissionRuns", path: "/admission-runs" },
  { id: "impact-analysis", labelKey: "impactAnalysis", path: "/impact-analysis" },
  { id: "selective-replay-plans", labelKey: "selectiveReplayPlans", path: "/selective-replay-plans" },
  { id: "graph-corrections", labelKey: "graphCorrections", path: "/graph-corrections" },
  { id: "enterprise-modules", labelKey: "enterpriseModules", path: "/enterprise-modules" },
  { id: "access-control", labelKey: "accessControl", path: "/access-control" },
  { id: "knowledge-governance", labelKey: "knowledgeGovernance", path: "/knowledge-governance" },
  { id: "lessons-center", labelKey: "lessonsCenter", path: "/lessons" },
  { id: "improvement-proposals", labelKey: "improvementProposals", path: "/improvement-proposals" },
  { id: "coverage-matrix", labelKey: "coverageMatrix", path: "/coverage-matrix" },
  { id: "replay-center", labelKey: "replayCenter", path: "/replay-center" },
  { id: "execution-explanations", labelKey: "executionExplanations", path: "/execution-explanations" },
  { id: "evidence-search", labelKey: "evidenceSearch", path: "/evidence-search" },
  { id: "replay-repository", labelKey: "replayRepository", path: "/replay-repository" },
  { id: "interactive-governance", labelKey: "interactiveGovernance", path: "/interactive-governance" },
  { id: "advanced-visualization", labelKey: "advancedVisualization", path: "/advanced-visualization" },
  { id: "observability", labelKey: "observability", path: "/observability" },
  { id: "execution-dashboard", labelKey: "executions", path: "/executions", aliases: ["/execution-dashboard"] },
  { id: "gate-dashboard", labelKey: "qualitySignals", path: "/gate-dashboard" },
  { id: "gate-policies", labelKey: "gatePolicies", path: "/gate-policies" },
  { id: "correction-governance", labelKey: "governedCorrections", path: "/correction-governance" },
  { id: "skill-invocations", labelKey: "skillInvocations", path: "/skill-invocations" },
  { id: "capability-bindings", labelKey: "capabilityBindings", path: "/capability-bindings", aliases: ["/skill-runtime"] },
  { id: "project-settings", labelKey: "projectSettings", path: "/project-settings" },
  { id: "environment-settings", labelKey: "environmentSettings", path: "/environment-settings" },
  { id: "connector-settings", labelKey: "connectorSettings", path: "/connector-settings" },
  { id: "model-config", labelKey: "modelConfig", path: "/model-config" },
  { id: "agent-runs", labelKey: "agentRuns", path: "/agent-runs" },
  { id: "queue-jobs", labelKey: "jobs", path: "/queue-jobs" },
];

const navigationGroups: NavigationGroup[] = [
  { id: "workspace", labelKey: "navWorkspace", sectionIds: ["workspace", "requirement-intake", "workflow-runs", "workflow"] },
  { id: "test-assets", labelKey: "navTestAssets", sectionIds: ["test-assets"] },
  { id: "execution-findings", labelKey: "navExecutionFindings", sectionIds: ["execution-dashboard", "tasks", "findings", "gate-decisions", "gate-dashboard", "queue-jobs"] },
  { id: "coverage-proof", labelKey: "navCoverageProof", sectionIds: ["coverage-matrix", "change-sets", "pr-contexts", "admission-runs", "impact-analysis", "selective-replay-plans", "ceg"] },
  {
    id: "replay-audit",
    labelKey: "navReplayAudit",
    sectionIds: [
      "replay-center",
      "execution-explanations",
      "candidate-paths",
      "evidence-search",
      "replay-repository",
      "interactive-governance",
      "advanced-visualization",
      "skill-invocations",
      "audit-logs",
      "observability",
      "agent-runs",
    ],
  },
  { id: "correction-governance", labelKey: "navCorrectionGovernance", sectionIds: ["correction-governance", "graph-corrections", "knowledge-governance", "lessons-center", "improvement-proposals", "enterprise-modules"] },
  {
    id: "system-settings",
    labelKey: "navSystemSettings",
    sectionIds: ["project-settings", "environment-settings", "access-control", "connector-settings", "model-config", "gate-policies", "capability-bindings"],
  },
];

const plannedSections: Array<{ labelKey: Parameters<typeof t>[1] }> = [
];

function sectionFromPath(pathname: string): AppSection {
  const section = sections.find((item) => item.path === pathname || item.aliases?.includes(pathname));
  return section && isSectionIncludedInProductProfile(section.id) ? section.id : "workspace";
}

function deepLinkFromLocation() {
  const query = new URLSearchParams(window.location.search);
  return { graphId: query.get("graphId"), versionId: query.get("versionId"), pathId: query.get("pathId") };
}

function pathForSection(sectionId: AppSection) {
  return sections.find((section) => section.id === sectionId)?.path ?? "/";
}

function navigationGroupForSection(sectionId: AppSection) {
  return navigationGroups.find((group) => group.sectionIds.includes(sectionId))?.id ?? "workspace";
}

const ALL_PROJECTS_ID = "all-projects";

function hasUserCapability(user: CurrentUser | null, capability: string) {
  return user?.capabilities.includes(capability) ?? false;
}

function hasUserRole(user: CurrentUser | null, role: string) {
  return user?.roles.includes(role) ?? false;
}

function buildProjectOptions(
  projects: ProjectItem[],
  environments: EnvironmentItem[],
  plans: PlanItem[],
  executions: ExecutionItem[],
  locale: Locale,
): { projectOptions: ProjectOption[]; planProjectIds: Map<string, string> } {
  const planProjectIds = new Map<string, string>(
    plans.filter((plan) => Boolean(plan.projectId)).map((plan) => [plan.id, String(plan.projectId)]),
  );
  const executionCountByProject = new Map<string, number>();
  for (const execution of executions) {
    const projectId = planProjectIds.get(execution.planId);
    if (projectId) {
      executionCountByProject.set(projectId, (executionCountByProject.get(projectId) ?? 0) + 1);
    }
  }

  const specificProjects = projects
    .map((project) => {
      const projectEnvironments = environments.filter((environment) => environment.projectId === project.id);
      return {
        id: project.id,
        key: project.key,
        name: project.name,
        planCount: project.planCount,
        executionCount: project.executionCount || executionCountByProject.get(project.id) || 0,
        environments: projectEnvironments.map((environment) => environment.name),
        environmentCount: project.environmentCount || projectEnvironments.length,
        memberCount: project.memberCount,
        status: project.status,
      };
    })
    .sort((left, right) => left.name.localeCompare(right.name));
  return {
    planProjectIds,
    projectOptions: IS_OSS_PROFILE ? specificProjects : [
      {
        id: ALL_PROJECTS_ID,
        key: "all",
        name: t(locale, "allProjects"),
        planCount: plans.length,
        executionCount: executions.length,
        environments: environments.map((environment) => environment.name),
        environmentCount: environments.length,
        memberCount: projects.reduce((count, project) => count + project.memberCount, 0),
        status: t(locale, "active"),
      },
      ...specificProjects,
    ],
  };
}

async function loadStructuredLogsForUser(
  user: CurrentUser,
  locale: Locale,
  filters: { executionId?: string | null; traceId?: string | null; level?: string; component?: string } = {},
): Promise<{ accessState: AuditLogsAccessState; projection: StructuredLogProjection | null; items: StructuredLogItem[]; error: string | null }> {
  if (!user.capabilities.includes("audit.logs.read")) {
    return { accessState: "access-restricted", projection: null, items: [], error: null };
  }
  try {
    const data = await fetchStructuredLogs(filters);
    return { accessState: "ready", projection: data, items: data.items, error: null };
  } catch (error) {
    if (error instanceof ApiRequestError && error.status === 403) {
      return { accessState: "access-restricted", projection: null, items: [], error: error.message };
    }
    return { accessState: "error", projection: null, items: [], error: error instanceof Error ? error.message : t(locale, "auditLogsLoadFailed") };
  }
}

async function loadAuditLogProjectionForUser(
  user: CurrentUser,
  locale: Locale,
  filters: { executionId?: string | null; traceId?: string | null; level?: string; component?: string } = {},
): Promise<{ accessState: AuditLogsAccessState; projection: AuditLogProjection | null; items: StructuredLogItem[]; error: string | null }> {
  if (!user.capabilities.includes("audit.logs.read")) {
    return { accessState: "access-restricted", projection: null, items: [], error: null };
  }
  try {
    const data = await fetchAuditLogProjection(filters);
    return { accessState: "ready", projection: data, items: data.items, error: null };
  } catch (error) {
    if (error instanceof ApiRequestError && error.status === 403) {
      return { accessState: "access-restricted", projection: null, items: [], error: error.message };
    }
    return { accessState: "error", projection: null, items: [], error: error instanceof Error ? error.message : t(locale, "auditLogsLoadFailed") };
  }
}

async function loadSkillsForUser(user: CurrentUser) {
  return hasUserCapability(user, "skills.catalog.read") ? fetchSkills() : { items: [], total: 0 };
}

async function loadSkillInvocationsForUser(user: CurrentUser, filters: { executionId?: string; skillId?: string; pageSize?: number } = {}) {
  return hasUserCapability(user, "skill_invocations.read")
    ? fetchSkillInvocations({
        ...filters,
        includeSnapshots: hasUserCapability(user, "capability_bindings.admin"),
      })
    : { items: [], total: 0 };
}

async function loadWorkflowCapabilityGraphForUser(user: CurrentUser) {
  return hasUserCapability(user, "capability_bindings.read") ? fetchWorkflowCapabilityGraph() : { nodes: [], scope: {} };
}

async function loadCapabilityBindingsForUser(user: CurrentUser, filters: { extensionPointId?: string; status?: string; pageSize?: number } = {}) {
  return hasUserCapability(user, "capability_bindings.read") ? fetchCapabilityBindings(filters) : { items: [], total: 0 };
}

async function loadWorkItemsForUser(user: CurrentUser, filters: { projectId?: string; pageSize?: number } = {}) {
  return hasUserCapability(user, "work_items.read") ? fetchWorkItems(filters) : { items: [], total: 0, page: 1, pageSize: 0 };
}

async function loadConnectorBindingsForUser(user: CurrentUser, filters: { projectId?: string; environmentId?: string; pageSize?: number } = {}) {
  return hasUserCapability(user, "capability_bindings.admin") || hasUserCapability(user, "connector_bindings.manage")
    ? enterpriseApi.fetchConnectorBindings(filters)
    : { items: [], total: 0 };
}

async function loadGuardrailPoliciesForUser(user: CurrentUser) {
  return !IS_OSS_PROFILE && hasUserRole(user, "admin") ? fetchGuardrailPolicies() : { items: [], total: 0 };
}

async function loadApprovalsForUser(user: CurrentUser, filters: { status?: string; type?: string; resourceType?: string; pageSize?: number } = {}) {
  return !IS_OSS_PROFILE && hasUserRole(user, "admin") ? fetchApprovals(filters) : { items: [], total: 0 };
}

async function loadExecutionReplayForUser(
  user: CurrentUser,
  executionId: string,
  options: { compact?: boolean } = {},
) {
  return hasUserCapability(user, "replay.read") ? fetchExecutionReplay(executionId, options) : null;
}

async function loadExecutionReplayExportForUser(user: CurrentUser, executionId: string) {
  return hasUserCapability(user, "replay.export.read") ? fetchExecutionReplayExport(executionId).catch(() => null) : null;
}

async function loadReplayExportsForUser(user: CurrentUser, executionId?: string | null, pageSize?: number) {
  return hasUserCapability(user, "replay.export.read")
    ? fetchReplayExports({ executionId: executionId ?? undefined, pageSize })
    : { items: [], total: 0 };
}

async function loadCorrectionGovernanceProjectionForUser(user: CurrentUser, filters: { executionId?: string | null; pageSize?: number } = {}) {
  return !IS_OSS_PROFILE && hasUserCapability(user, "correction.read")
    ? fetchCorrectionGovernanceProjection(filters)
    : {
        schemaVersion: "phase8.correction-governance-projection.v1" as const,
        generatedAt: "",
        filters,
        capability: {},
        operationPolicy: {},
        operationAvailability: {},
        items: [],
        total: 0,
        page: 1,
        pageSize: 0,
        readOnly: true,
        evidenceOnly: true,
        writesDecision: false,
      };
}

function App() {
  const {
    locale,
    currentUser,
    health,
    models,
    projects,
    environments,
    projectMembers,
    connectorBindings,
    plans,
    executions,
    agentRuns,
    skills,
    skillInvocations,
    capabilityBindings,
    workflowCapabilityGraph,
    traces,
    jobs,
    latestReplay,
    latestReplayExport,
    replayExports,
    guardrailPolicies,
    guardrailEvents,
    approvals,
    coverageSummary,
    coverageMatrix,
    coverageProof,
    guardrailSummary,
    setLocale,
    setCurrentUser,
    setHealth,
    setModels,
    setProjects,
    setEnvironments,
    setProjectMembers,
    setConnectorBindings,
    setPlans,
    setExecutions,
    setAgentRuns,
    setSkills,
    setSkillInvocations,
    setCapabilityBindings,
    setWorkflowCapabilityGraph,
    setTraces,
    setJobs,
    setLatestReplay,
    setLatestReplayExport,
    setReplayExports,
    setGuardrailPolicies,
    setGuardrailEvents,
    setApprovals,
    setCoverageSummary,
    setCoverageMatrix,
    setCoverageProof,
  } = usePlatformStore();

  const [activeSection, setActiveSection] = useState<AppSection>(() => sectionFromPath(window.location.pathname));
  const [cegDeepLink, setCegDeepLink] = useState(deepLinkFromLocation);
  const [expandedNavigationGroups, setExpandedNavigationGroups] = useState<Set<string>>(
    () => new Set([navigationGroupForSection(sectionFromPath(window.location.pathname))]),
  );
  const [selectedProjectId, setSelectedProjectId] = useState(ALL_PROJECTS_ID);
  const [workflowRuns, setWorkflowRuns] = useState<WorkflowRunProjection[]>([]);
  const [selectedWorkflowRunId, setSelectedWorkflowRunId] = useState<string | null>(null);
  const [selectedWorkflowRun, setSelectedWorkflowRun] = useState<WorkflowRunProjection | null>(null);
  const [workflowRunsLoading, setWorkflowRunsLoading] = useState(false);
  const [workflowRunsError, setWorkflowRunsError] = useState<string | null>(null);
  const [requirementPipelines, setRequirementPipelines] = useState<RequirementPipelineState[]>([]);
  const [selectedPipelineId, setSelectedPipelineId] = useState<string | null>(null);
  const [requirementClarifications, setRequirementClarifications] = useState<RequirementClarification[]>([]);
  const [requirementPipelineReplay, setRequirementPipelineReplay] = useState<Record<string, unknown> | null>(null);
  const [selectedPlanId, setSelectedPlanId] = useState<string | null>(null);
  const [selectedExecutionId, setSelectedExecutionId] = useState<string | null>(null);
  const [selectedRequirementItemId, setSelectedRequirementItemId] = useState<string | null>(null);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [workflowLoading, setWorkflowLoading] = useState(false);
  const [workflowError, setWorkflowError] = useState<string | null>(null);
  const [proofLoading, setProofLoading] = useState(false);
  const [proofError, setProofError] = useState<string | null>(null);
  const [coverageLoading, setCoverageLoading] = useState(false);
  const [coverageError, setCoverageError] = useState<string | null>(null);
  const [executionDetailLoading, setExecutionDetailLoading] = useState(false);
  const [executionDetailError, setExecutionDetailError] = useState<string | null>(null);
  const [executionProgress, setExecutionProgress] = useState<{
    progress: number;
    currentTask: string | null;
    completedTasks: number;
    totalTasks: number;
  } | null>(null);
  const [executionTasks, setExecutionTasks] = useState<
    ExecutionTaskRecord[]
  >([]);
  const [selectedExecutionTaskId, setSelectedExecutionTaskId] = useState<string | null>(null);
  const [selectedExecutionTask, setSelectedExecutionTask] = useState<ExecutionTaskRecord | null>(null);
  const [executionTaskArtifacts, setExecutionTaskArtifacts] = useState<ExecutionTaskArtifact[]>([]);
  const [executionTaskLogs, setExecutionTaskLogs] = useState<ExecutionTaskLog[]>([]);
  const [executionTaskMetrics, setExecutionTaskMetrics] = useState<ExecutionTaskMetric[]>([]);
  const [executionTaskDetailLoading, setExecutionTaskDetailLoading] = useState(false);
  const [executionTaskDetailError, setExecutionTaskDetailError] = useState<string | null>(null);
  const [executionFindings, setExecutionFindings] = useState<
    Array<{
      id: string;
      executionId: string;
      taskId: string | null;
      domain: string;
      severity: string;
      source: string;
      title: string;
      summary: string;
      confidence: number | null;
      externalIssueLink: ExternalIssueLink | null;
    }>
  >([]);
  const [workItems, setWorkItems] = useState<WorkItem[]>([]);
  const [syncingIssueFindingId, setSyncingIssueFindingId] = useState<string | null>(null);
  const [executionHealing, setExecutionHealing] = useState<
    Array<{ taskId: string | null; type: string; summary: string; patch: string | null }>
  >([]);
  const [gateSnapshot, setGateSnapshot] = useState<{
    overall: string;
    functional: string;
    performance: string;
    security: string;
    reasons?: string[];
  } | null>(null);
  const [observabilityMetrics, setObservabilityMetrics] = useState<ObservabilityMetric[]>([]);
  const [structuredLogProjection, setStructuredLogProjection] = useState<StructuredLogProjection | null>(null);
  const [structuredLogs, setStructuredLogs] = useState<StructuredLogItem[]>([]);
  const [auditLogProjection, setAuditLogProjection] = useState<AuditLogProjection | null>(null);
  const [auditLogItems, setAuditLogItems] = useState<StructuredLogItem[]>([]);
  const [auditLogsAccessState, setAuditLogsAccessState] = useState<AuditLogsAccessState>("loading");
  const [auditLogsError, setAuditLogsError] = useState<string | null>(null);
  const [structuredLogsAccessState, setStructuredLogsAccessState] = useState<AuditLogsAccessState>("loading");
  const [structuredLogsError, setStructuredLogsError] = useState<string | null>(null);
  const [qualityDashboard, setQualityDashboard] = useState<QualityDashboard | null>(null);
  const [runtimeReadiness, setRuntimeReadiness] = useState<RuntimeReadiness | null>(null);
  const [correctionGovernanceProjection, setCorrectionGovernanceProjection] = useState<CorrectionGovernanceProjection | null>(null);

  const executionDetailMode = activeSection === "execution-explanations"
    ? "timeline"
    : activeSection === "replay-center"
      ? "replay"
      : "full";
  const requiresFullShell = executionDetailMode === "full";

  useEffect(() => {
    document.documentElement.lang = locale;
    document.title = t(locale, "appTitle");
  }, [locale]);

  const hasCapability = (capability: string) => currentUser?.capabilities.includes(capability) ?? false;
  const visibleNavigationGroups = useMemo(
    () => navigationGroups
      .map((group) => ({
        ...group,
        sectionIds: group.sectionIds.filter((sectionId) =>
          isSectionVisibleInProductProfile(sectionId, currentUser?.capabilities ?? []),
        ),
      }))
      .filter((group) => group.sectionIds.length > 0),
    [currentUser?.capabilities],
  );
  const canManageModels = hasCapability("model.governance.manage") || hasCapability("model.config.manage");
  const issueTrackerBindings: ConnectorBindingItem[] = connectorBindings.filter(
    (binding) => ["jira", "zentao", "mock-issue-tracker"].includes(binding.connectorName) && binding.status === "active",
  );
  const canOperateCorrections =
    hasCapability("correction.apply") ||
    hasCapability("correction.validate") ||
    hasCapability("correction.rollback") ||
    hasCapability("correction.promote");
  const canManageWorkItems = hasCapability("work_items.manage");
  const { projectOptions } = useMemo(
    () => buildProjectOptions(projects, environments, plans, executions, locale),
    [environments, executions, locale, plans, projects],
  );
  const selectedProject = projectOptions.find((project) => project.id === selectedProjectId) ?? projectOptions[0] ?? null;
  const visiblePlans = useMemo(
    () =>
      selectedProjectId === ALL_PROJECTS_ID
        ? plans
        : plans.filter((plan) => plan.projectId === selectedProjectId),
    [plans, selectedProjectId],
  );
  const visiblePlanIds = useMemo(() => new Set(visiblePlans.map((plan) => plan.id)), [visiblePlans]);
  const visibleExecutions = useMemo(
    () =>
      selectedProjectId === ALL_PROJECTS_ID
        ? executions
        : executions.filter((execution) => visiblePlanIds.has(execution.planId)),
    [executions, selectedProjectId, visiblePlanIds],
  );
  const visibleWorkItems = useMemo(
    () =>
      selectedProjectId === ALL_PROJECTS_ID
        ? workItems
        : workItems.filter((item) => item.projectId === selectedProjectId),
    [selectedProjectId, workItems],
  );

  const navigateToSection = (sectionId: AppSection) => {
    const destination = isSectionVisibleInProductProfile(sectionId, currentUser?.capabilities ?? [])
      ? sectionId
      : "workspace";
    setActiveSection(destination);
    setExpandedNavigationGroups((current) => new Set(current).add(navigationGroupForSection(destination)));
    const path = pathForSection(destination);
    if (destination !== "ceg") setCegDeepLink({ graphId: null, versionId: null, pathId: null });
    if (window.location.pathname !== path) {
      window.history.pushState(null, "", path);
    }
  };

  const toggleNavigationGroup = (groupId: string) => {
    setExpandedNavigationGroups((current) => {
      const next = new Set(current);
      if (next.has(groupId)) {
        next.delete(groupId);
      } else {
        next.add(groupId);
      }
      return next;
    });
  };

  const refreshModels = async () => {
    const modelsData = await enterpriseApi.fetchModels();
    setModels(modelsData.items);
  };

  const refreshSkills = async () => {
    if (!currentUser || !hasUserCapability(currentUser, "skills.catalog.read")) {
      setSkills([]);
      return;
    }
    const skillsData = await loadSkillsForUser(currentUser);
    setSkills(skillsData.items);
  };

  const refreshProjectEnvironmentData = async () => {
    const [projectsData, environmentsData] = await Promise.all([fetchProjects(), fetchEnvironments()]);
    setProjects(projectsData.items);
    setEnvironments(environmentsData.items);
  };

  const refreshWorkItems = async () => {
    if (!currentUser || !hasUserCapability(currentUser, "work_items.read")) {
      setWorkItems([]);
      return;
    }
    const workItemsData = await loadWorkItemsForUser(currentUser, { pageSize: 100 });
    setWorkItems(workItemsData.items);
  };

  const refreshProjectMembers = async (projectId: string) => {
    const membersData = await fetchProjectMembers(projectId);
    setProjectMembers(membersData.items);
  };

  const refreshConnectorBindings = async () => {
    if (!currentUser || (
      !hasUserCapability(currentUser, "capability_bindings.admin")
      && !hasUserCapability(currentUser, "connector_bindings.manage")
    )) {
      setConnectorBindings([]);
      return;
    }
    const connectorBindingData = await loadConnectorBindingsForUser(currentUser);
    setConnectorBindings(connectorBindingData.items);
  };

  const refreshCapabilityBindings = async () => {
    if (!currentUser || !hasUserCapability(currentUser, "capability_bindings.read")) {
      setWorkflowCapabilityGraph([]);
      setCapabilityBindings([]);
      return;
    }
    const [graphData, bindingData] = await Promise.all([
      loadWorkflowCapabilityGraphForUser(currentUser),
      loadCapabilityBindingsForUser(currentUser),
    ]);
    setWorkflowCapabilityGraph(graphData.nodes);
    setCapabilityBindings(bindingData.items);
  };

  const refreshCorrectionGovernance = async () => {
    if (!currentUser || !hasUserCapability(currentUser, "correction.read")) {
      setCorrectionGovernanceProjection(null);
      return;
    }
    const [projectionData, approvalsData, replayData] = await Promise.all([
      loadCorrectionGovernanceProjectionForUser(currentUser, { executionId: selectedExecutionId, pageSize: 50 }),
      loadApprovalsForUser(currentUser, { status: "pending", pageSize: 20 }),
      selectedExecutionId && hasUserCapability(currentUser, "replay.read")
        ? loadExecutionReplayForUser(currentUser, selectedExecutionId)
        : Promise.resolve(latestReplay),
    ]);
    setCorrectionGovernanceProjection(projectionData);
    setApprovals(approvalsData.items);
    if (replayData) {
      setLatestReplay(replayData);
    }
  };

  const applyWorkflowRunList = (items: WorkflowRunProjection[]) => {
    setWorkflowRuns(items);
    setSelectedWorkflowRunId((current) => {
      if (current && items.some((item) => item.runId === current)) {
        return current;
      }
      return items[0]?.runId ?? null;
    });
    setSelectedWorkflowRun((current) => {
      if (current) {
        return items.find((item) => item.runId === current.runId) ?? current;
      }
      return items[0] ?? null;
    });
  };

  const upsertRequirementPipeline = (pipeline: RequirementPipelineState) => {
    setRequirementPipelines((current) => [
      pipeline,
      ...current.filter((item) => item.orchestrationId !== pipeline.orchestrationId),
    ]);
  };

  const refreshWorkflowCollections = async () => {
    const [plansData, executionsData, jobsData, approvalsData, workflowRunsData] = await Promise.all([
      fetchPlans(),
      fetchExecutions(),
      IS_OSS_PROFILE ? { items: [], total: 0 } : fetchJobs({ pageSize: 24 }),
      currentUser ? loadApprovalsForUser(currentUser, { status: "pending", pageSize: 20 }) : { items: [], total: 0 },
      fetchWorkflowRuns({ pageSize: 25 }),
    ]);
    setPlans(plansData.items);
    setExecutions(executionsData.items);
    setJobs(jobsData.items);
    setApprovals(approvalsData.items);
    applyWorkflowRunList(workflowRunsData.items);
  };

  const loadWorkflowRunProjection = async (runId: string) => {
    setSelectedWorkflowRunId(runId);
    setWorkflowRunsLoading(true);
    setWorkflowRunsError(null);
    try {
      const projection = await fetchWorkflowRun(runId);
      setSelectedWorkflowRun(projection);
      setWorkflowRuns((current) => [
        projection,
        ...current.filter((item) => item.runId !== projection.runId),
      ]);
      const planId = String(projection.linkedResources.plan?.planId ?? "");
      const executionId = String(projection.linkedResources.execution?.executionId ?? "");
      if (planId) {
        setSelectedPlanId(planId);
      }
      if (executionId) {
        setSelectedExecutionId(executionId);
      }
    } catch (projectionError) {
      setWorkflowRunsError(projectionError instanceof Error ? projectionError.message : t(locale, "workflowRunsLoadFailed"));
    } finally {
      setWorkflowRunsLoading(false);
    }
  };

  const loadRequirementPipelineDetails = async (runId: string) => {
    setSelectedPipelineId(runId);
    setWorkflowLoading(true);
    setWorkflowError(null);
    try {
      const pipeline = await fetchRequirementPipeline(runId);
      upsertRequirementPipeline(pipeline);
      setSelectedPipelineId(pipeline.orchestrationId);
      if (pipeline.planId) {
        setSelectedPlanId(pipeline.planId);
      }
      if (pipeline.executionId) {
        setSelectedExecutionId(pipeline.executionId);
      }
      const clarificationsData = pipeline.requirementVersionId
        ? await fetchRequirementClarifications(runId).catch(() => ({ items: [] }))
        : { items: [] };
      const replayData = await fetchRequirementPipelineReplay(runId).catch(() => null);
      setRequirementClarifications(clarificationsData.items);
      setRequirementPipelineReplay(replayData);
      await fetchWorkflowRun(runId)
        .then((projection) => {
          setSelectedWorkflowRunId(projection.runId);
          setSelectedWorkflowRun(projection);
          setWorkflowRuns((current) => [
            projection,
            ...current.filter((item) => item.runId !== projection.runId),
          ]);
        })
        .catch(() => undefined);
    } catch (pipelineError) {
      setWorkflowError(pipelineError instanceof Error ? pipelineError.message : t(locale, "workflowActionFailed"));
    } finally {
      setWorkflowLoading(false);
    }
  };

  const reloadIssueTrackerFindingProjections = async () => {
    if (!selectedExecutionId) {
      return;
    }
    const findingsData = await fetchExecutionFindings(selectedExecutionId);
    setExecutionFindings(findingsData.items);
    if (currentUser) {
      const replayData = await loadExecutionReplayForUser(currentUser, selectedExecutionId);
      setLatestReplay(replayData);
    }
  };

  const handleSyncFindingExternalIssue = async (findingId: string) => {
    if (!hasCapability("issue_tracker.sync")) {
      throw new Error(t(locale, "issueTrackerSyncCapabilityRequired"));
    }
    const binding = issueTrackerBindings[0];
    if (!binding) {
      throw new Error(t(locale, "issueTrackerBindingRequired"));
    }
    const payload: IssueSyncPayload = {
      connectorBindingId: binding.id,
      issueType: "Bug",
      labels: ["agentic-qa"],
      extraFields: {
        source: "normalized_finding",
      },
    };
    setSyncingIssueFindingId(findingId);
    try {
      await syncFindingExternalIssue(findingId, payload);
      await reloadIssueTrackerFindingProjections();
    } finally {
      setSyncingIssueFindingId(null);
    }
  };

  const handleRefreshFindingExternalIssue = async (findingId: string) => {
    const finding = executionFindings.find((item) => item.id === findingId);
    const connectorBindingId = finding?.externalIssueLink?.connectorBindingId ?? issueTrackerBindings[0]?.id;
    if (!hasCapability("issue_tracker.sync")) {
      throw new Error(t(locale, "issueTrackerSyncCapabilityRequired"));
    }
    if (!connectorBindingId) {
      throw new Error(t(locale, "issueTrackerBindingRequired"));
    }
    setSyncingIssueFindingId(findingId);
    try {
      await refreshFindingExternalIssueStatus(findingId, { connectorBindingId });
      await reloadIssueTrackerFindingProjections();
    } finally {
      setSyncingIssueFindingId(null);
    }
  };

  const handleWorkflowRunAction = async (action: WorkflowRunAction, run: WorkflowRunProjection) => {
    setSelectedWorkflowRunId(run.runId);
    setSelectedWorkflowRun(run);
    const planId = String(run.linkedResources.plan?.planId ?? "");
    const executionId = String(run.linkedResources.execution?.executionId ?? "");
    if (planId) {
      setSelectedPlanId(planId);
    }
    if (executionId) {
      setSelectedExecutionId(executionId);
    }
    if (action.targetRoute === "/workflow") {
      await loadRequirementPipelineDetails(run.runId);
    }
    navigateToSection(sectionFromPath(action.targetRoute));
  };

  const handleCreateRequirementPipeline = async (payload: RequirementPipelinePayload) => {
    try {
      const pipeline = await createRequirementPipeline(payload);
      upsertRequirementPipeline(pipeline);
      setSelectedPipelineId(pipeline.orchestrationId);
      if (pipeline.planId) {
        setSelectedPlanId(pipeline.planId);
      }
      if (pipeline.executionId) {
        setSelectedExecutionId(pipeline.executionId);
      }
      await refreshWorkflowCollections();
      await loadRequirementPipelineDetails(pipeline.orchestrationId);
    } catch (actionError) {
      setWorkflowError(actionError instanceof Error ? actionError.message : t(locale, "workflowActionFailed"));
      throw actionError;
    }
  };

  const handleCreateRequirementLibraryPipeline = async (payload: RequirementLibraryPipelinePayload) => {
    try {
      const pipeline = await createRequirementLibraryPipeline(payload);
      upsertRequirementPipeline(pipeline);
      setSelectedPipelineId(pipeline.orchestrationId);
      if (pipeline.planId) {
        setSelectedPlanId(pipeline.planId);
      }
      if (pipeline.executionId) {
        setSelectedExecutionId(pipeline.executionId);
      }
      await refreshWorkflowCollections();
      await loadRequirementPipelineDetails(pipeline.orchestrationId);
    } catch (actionError) {
      setWorkflowError(actionError instanceof Error ? actionError.message : t(locale, "workflowActionFailed"));
      throw actionError;
    }
  };

  const handleRequirementIntakePipelineConfirmed = async (pipeline: RequirementPipelineState) => {
    upsertRequirementPipeline(pipeline);
    setSelectedPipelineId(pipeline.orchestrationId);
    if (pipeline.planId) {
      setSelectedPlanId(pipeline.planId);
    }
    if (pipeline.executionId) {
      setSelectedExecutionId(pipeline.executionId);
    }
    await refreshWorkflowCollections();
    await loadRequirementPipelineDetails(pipeline.orchestrationId);
  };

  const handleRequirementIntakeViewPipeline = (pipelineId: string) => {
    navigateToSection("workflow");
    void loadRequirementPipelineDetails(pipelineId);
  };

  const handleAnswerRequirementClarification = async (runId: string, clarificationId: string, answer: string) => {
    try {
      const pipeline = await answerRequirementClarification(runId, clarificationId, answer);
      upsertRequirementPipeline(pipeline);
      await refreshWorkflowCollections();
      await loadRequirementPipelineDetails(pipeline.orchestrationId);
    } catch (actionError) {
      setWorkflowError(actionError instanceof Error ? actionError.message : t(locale, "workflowActionFailed"));
      throw actionError;
    }
  };

  const handleCreatePlan = async (payload: PlanPayload) => {
    const plan = await createPlan(payload);
    await refreshWorkflowCollections();
    if (payload.projectId) setSelectedProjectId(payload.projectId);
    setSelectedPlanId(plan.id);
  };

  const handleUpdatePlan = async (planId: string, payload: PlanUpdatePayload) => {
    const plan = await updatePlan(planId, payload);
    await refreshWorkflowCollections();
    if (payload.projectId) setSelectedProjectId(payload.projectId);
    setSelectedPlanId(plan.id);
  };

  const handleDeletePlan = async (planId: string) => {
    await deletePlan(planId);
    await refreshWorkflowCollections();
    setSelectedPlanId(null);
  };

  const handleGeneratePlan = async (planId: string) => {
    await triggerPlanGenerate(planId);
    await refreshWorkflowCollections();
    setSelectedPlanId(planId);
  };

  const handleCreateExecution = async (payload: ExecutionPayload) => {
    const execution = await createExecution(payload);
    await refreshWorkflowCollections();
    setSelectedExecutionId(execution.id);
  };

  const handleCancelExecution = async (executionId: string) => {
    await cancelExecution(executionId);
    await refreshWorkflowCollections();
    setSelectedExecutionId(executionId);
  };

  const handleRetryExecution = async (executionId: string) => {
    await retryExecution(executionId);
    await refreshWorkflowCollections();
    setSelectedExecutionId(executionId);
  };

  const handleHealExecution = async (executionId: string) => {
    await healExecution(executionId, "suggest_only");
    await refreshWorkflowCollections();
    setSelectedExecutionId(executionId);
  };

  const handleGateExecution = async (executionId: string) => {
    await gateExecution(executionId);
    await refreshWorkflowCollections();
    setSelectedExecutionId(executionId);
  };

  const handleCreateWorkItem = async (payload: WorkItemCreatePayload) => {
    await createWorkItem(payload);
    await refreshWorkItems();
  };

  const handleAssignWorkItem = async (workItemId: string, assigneeId: string | null) => {
    await assignWorkItem(workItemId, assigneeId);
    await refreshWorkItems();
  };

  const handleClaimWorkItem = async (workItemId: string) => {
    await claimWorkItem(workItemId);
    await refreshWorkItems();
  };

  const handleTransitionWorkItem = async (workItemId: string, status: WorkItemStatus, comment?: string | null) => {
    await transitionWorkItem(workItemId, { status, comment: comment ?? null });
    await refreshWorkItems();
  };

  const refreshAfterApprovalDecision = async () => {
    await refreshWorkflowCollections();
    if (selectedPipelineId) {
      await loadRequirementPipelineDetails(selectedPipelineId);
    }
  };

  const handleApproveApproval = async (approvalId: string, comment: string) => {
    await approveApproval(approvalId, comment || null);
    await refreshAfterApprovalDecision();
  };

  const handleRejectApproval = async (approvalId: string, comment: string) => {
    await rejectApproval(approvalId, comment || null);
    await refreshAfterApprovalDecision();
  };

  const handleCancelApproval = async (approvalId: string, comment: string) => {
    await cancelApproval(approvalId, comment || null);
    await refreshAfterApprovalDecision();
  };

  const handleCreateCapabilityBinding = async (payload: CapabilityBindingMutationPayload): Promise<CapabilityBindingMutationResult> => {
    const result = await enterpriseApi.createCapabilityBinding(payload);
    await Promise.all([refreshCapabilityBindings(), refreshWorkflowCollections()]);
    return result;
  };

  const handleUpdateCapabilityBinding = async (
    bindingId: string,
    payload: Partial<CapabilityBindingMutationPayload>,
  ): Promise<CapabilityBindingMutationResult> => {
    const result = await enterpriseApi.updateCapabilityBinding(bindingId, payload);
    await Promise.all([refreshCapabilityBindings(), refreshWorkflowCollections()]);
    return result;
  };

  const handleCreateProject = async (payload: ProjectMutationPayload) => {
    await enterpriseApi.createProject(payload);
    await refreshProjectEnvironmentData();
  };

  const handleUpdateProject = async (projectId: string, payload: Partial<ProjectMutationPayload>) => {
    await enterpriseApi.updateProject(projectId, payload);
    await refreshProjectEnvironmentData();
  };

  const handleArchiveProject = async (projectId: string) => {
    await enterpriseApi.deleteProject(projectId);
    await refreshProjectEnvironmentData();
  };

  const handleCreateEnvironment = async (projectId: string, payload: EnvironmentMutationPayload) => {
    await enterpriseApi.createProjectEnvironment(projectId, payload);
    await refreshProjectEnvironmentData();
  };

  const handleUpdateEnvironment = async (environmentId: string, payload: Partial<EnvironmentMutationPayload>) => {
    await enterpriseApi.updateEnvironment(environmentId, payload);
    await refreshProjectEnvironmentData();
  };

  const handleArchiveEnvironment = async (environmentId: string) => {
    await enterpriseApi.deleteEnvironment(environmentId);
    await refreshProjectEnvironmentData();
  };

  const handleCreateProjectMember = async (projectId: string, payload: ProjectMemberMutationPayload) => {
    await enterpriseApi.createProjectMember(projectId, payload);
    await Promise.all([refreshProjectMembers(projectId), refreshProjectEnvironmentData()]);
  };

  const handleUpdateProjectMember = async (memberId: string, payload: Partial<Omit<ProjectMemberMutationPayload, "userId">>) => {
    await enterpriseApi.updateProjectMember(memberId, payload);
    const projectId = projectMembers.find((member) => member.id === memberId)?.projectId;
    if (projectId) {
      await Promise.all([refreshProjectMembers(projectId), refreshProjectEnvironmentData()]);
    }
  };

  const handleCreateConnectorBinding = async (payload: ConnectorBindingMutationPayload) => {
    await enterpriseApi.createConnectorBinding(payload);
    await refreshConnectorBindings();
  };

  const handleUpdateConnectorBinding = async (bindingId: string, payload: ConnectorBindingUpdatePayload) => {
    await enterpriseApi.updateConnectorBinding(bindingId, payload);
    await refreshConnectorBindings();
  };

  const handleArchiveConnectorBinding = async (bindingId: string) => {
    await enterpriseApi.deleteConnectorBinding(bindingId);
    await refreshConnectorBindings();
  };

  useEffect(() => {
    if (IS_OSS_PROFILE) {
      const requestedSection = sections.find(
        (item) => item.path === window.location.pathname || item.aliases?.includes(window.location.pathname),
      );
      if (!requestedSection || !isSectionIncludedInProductProfile(requestedSection.id)) {
        window.history.replaceState(null, "", pathForSection("workspace"));
      }
    }
    const onPopState = () => {
      const section = sectionFromPath(window.location.pathname);
      setActiveSection(section);
      if (section === "ceg") setCegDeepLink(deepLinkFromLocation());
      setExpandedNavigationGroups((current) => new Set(current).add(navigationGroupForSection(section)));
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  useEffect(() => {
    if (selectedProjectId === ALL_PROJECTS_ID) return;
    let cancelled = false;
    void fetchCurrentUser()
      .then((user) => {
        if (!cancelled) setCurrentUser(user);
      })
      .catch(() => {
        // Project-scoped requests remain backend-authoritative. A failed refresh
        // never grants cached capabilities or enables a guarded control.
      });
    return () => {
      cancelled = true;
    };
  }, [selectedProjectId, setCurrentUser]);

  useEffect(() => {
    let cancelled = false;

    const loadShell = async () => {
      try {
        const currentUserData = await fetchCurrentUser();
        if (cancelled) return;
        setCurrentUser(currentUserData);

        // Route-critical data is applied before the broad workspace shell.
        // Replay and explanation pages can select an execution immediately
        // instead of waiting for every administration projection to finish.
        const executionsData = await fetchExecutions();
        if (cancelled) return;
        setExecutions(executionsData.items);
        if (!requiresFullShell) {
          setLoadError(null);
          return;
        }

        const structuredLogResultPromise = loadStructuredLogsForUser(currentUserData, locale);
        const auditLogResultPromise = loadAuditLogProjectionForUser(currentUserData, locale);
        const [
          healthData,
          runtimeReadinessData,
          modelsData,
          projectsData,
          environmentsData,
          plansData,
          workflowRunsData,
          agentRunsData,
          skillsData,
          skillInvocationsData,
          workflowCapabilityGraphData,
          capabilityBindingsData,
          workItemsData,
          connectorBindingsData,
          tracesData,
          jobsData,
          guardrailPoliciesData,
          guardrailEventsData,
          approvalsData,
          observabilityMetricsData,
          qualityDashboardData,
          correctionGovernanceProjectionData,
          structuredLogResult,
          auditLogResult,
        ] = await Promise.all([
          fetchHealth(),
          fetchRuntimeReadiness(),
          enterpriseApi.fetchModels(),
          fetchProjects(),
          fetchEnvironments(),
          fetchPlans(),
          fetchWorkflowRuns({ pageSize: 25 }),
          IS_OSS_PROFILE ? { items: [], total: 0 } : fetchAgentRuns(),
          loadSkillsForUser(currentUserData),
          loadSkillInvocationsForUser(currentUserData),
          loadWorkflowCapabilityGraphForUser(currentUserData),
          loadCapabilityBindingsForUser(currentUserData),
          loadWorkItemsForUser(currentUserData, { pageSize: 100 }),
          loadConnectorBindingsForUser(currentUserData),
          fetchTraces(),
          IS_OSS_PROFILE ? { items: [], total: 0 } : fetchJobs({ pageSize: 24 }),
          loadGuardrailPoliciesForUser(currentUserData),
          IS_OSS_PROFILE ? { items: [], total: 0, summary: { allow: 0, warn: 0, block: 0 } } : fetchGuardrailEvents(),
          loadApprovalsForUser(currentUserData, { status: "pending", pageSize: 20 }),
          fetchObservabilityMetrics(),
          fetchQualityDashboard(),
          loadCorrectionGovernanceProjectionForUser(currentUserData, { pageSize: 50 }),
          structuredLogResultPromise,
          auditLogResultPromise,
        ]);

        if (cancelled) {
          return;
        }

        setHealth(healthData.services);
        setRuntimeReadiness(runtimeReadinessData);
        setModels(modelsData.items);
        setProjects(projectsData.items);
        setEnvironments(environmentsData.items);
        setPlans(plansData.items);
        applyWorkflowRunList(workflowRunsData.items);
        setAgentRuns(agentRunsData.items);
        setSkills(skillsData.items);
        setSkillInvocations(skillInvocationsData.items);
        setWorkflowCapabilityGraph(workflowCapabilityGraphData.nodes);
        setCapabilityBindings(capabilityBindingsData.items);
        setWorkItems(workItemsData.items);
        setConnectorBindings(connectorBindingsData.items);
        setTraces(tracesData.items);
        setJobs(jobsData.items);
        setGuardrailPolicies(guardrailPoliciesData.items);
        setGuardrailEvents(guardrailEventsData.items, guardrailEventsData.summary);
        setApprovals(approvalsData.items);
        setObservabilityMetrics(observabilityMetricsData.metrics);
        setQualityDashboard(qualityDashboardData);
        setCorrectionGovernanceProjection(correctionGovernanceProjectionData);
        setStructuredLogProjection(structuredLogResult.projection);
        setStructuredLogs(structuredLogResult.items);
        setStructuredLogsAccessState(structuredLogResult.accessState);
        setStructuredLogsError(structuredLogResult.error);
        setAuditLogProjection(auditLogResult.projection);
        setAuditLogItems(auditLogResult.items);
        setAuditLogsAccessState(auditLogResult.accessState);
        setAuditLogsError(auditLogResult.error);
        setLoadError(null);
      } catch (error) {
        if (!cancelled) {
          setLoadError(error instanceof Error ? error.message : t(locale, "workspaceLoadFailed"));
        }
      }
    };

    void loadShell();

    return () => {
      cancelled = true;
    };
  }, [
    setAgentRuns,
    setApprovals,
    setCapabilityBindings,
    setConnectorBindings,
    setCurrentUser,
    setEnvironments,
    setExecutions,
    setGuardrailEvents,
    setGuardrailPolicies,
    setHealth,
    setJobs,
    setModels,
    setPlans,
    setProjects,
    setSkillInvocations,
    setSkills,
    setTraces,
    setWorkflowCapabilityGraph,
    locale,
    requiresFullShell,
  ]);

  useEffect(() => {
    if (!projectOptions.some((project) => project.id === selectedProjectId)) {
      setSelectedProjectId(ALL_PROJECTS_ID);
    }
  }, [projectOptions, selectedProjectId]);

  useEffect(() => {
    if (visiblePlans.length > 0 && !visiblePlans.some((plan) => plan.id === selectedPlanId)) {
      setSelectedPlanId(visiblePlans[0].id);
    } else if (visiblePlans.length === 0 && selectedPlanId !== null) {
      setSelectedPlanId(null);
    }
  }, [selectedPlanId, visiblePlans]);

  useEffect(() => {
    if (visibleExecutions.length > 0 && !visibleExecutions.some((execution) => execution.id === selectedExecutionId)) {
      setSelectedExecutionId(visibleExecutions[0].id);
    } else if (visibleExecutions.length === 0 && selectedExecutionId !== null) {
      setSelectedExecutionId(null);
    }
  }, [selectedExecutionId, visibleExecutions]);

  useEffect(() => {
    if (jobs.length > 0 && !jobs.some((job) => job.id === selectedJobId)) {
      setSelectedJobId(jobs[0].id);
    }
  }, [jobs, selectedJobId]);

  useEffect(() => {
    setExecutionTasks([]);
    setSelectedExecutionTaskId(null);
    setSelectedExecutionTask(null);
    setExecutionTaskArtifacts([]);
    setExecutionTaskLogs([]);
    setExecutionTaskMetrics([]);
    setExecutionTaskDetailError(null);
  }, [selectedExecutionId]);

  useEffect(() => {
    if (executionTasks.length > 0 && !executionTasks.some((task) => task.id === selectedExecutionTaskId)) {
      setSelectedExecutionTaskId(executionTasks[0].id);
    } else if (executionTasks.length === 0 && selectedExecutionTaskId !== null) {
      setSelectedExecutionTaskId(null);
    }
  }, [executionTasks, selectedExecutionTaskId]);

  useEffect(() => {
    let cancelled = false;

    const loadExecutionTaskDetail = async () => {
      if (!selectedExecutionTaskId) {
        setSelectedExecutionTask(null);
        setExecutionTaskArtifacts([]);
        setExecutionTaskLogs([]);
        setExecutionTaskMetrics([]);
        setExecutionTaskDetailLoading(false);
        setExecutionTaskDetailError(null);
        return;
      }
      setExecutionTaskDetailLoading(true);
      setExecutionTaskDetailError(null);
      try {
        const [taskData, artifactsData, logsData, metricsData] = await Promise.all([
          fetchExecutionTask(selectedExecutionTaskId),
          fetchExecutionTaskArtifacts(selectedExecutionTaskId),
          fetchExecutionTaskLogs(selectedExecutionTaskId),
          fetchExecutionTaskMetrics(selectedExecutionTaskId),
        ]);
        if (cancelled) {
          return;
        }
        setSelectedExecutionTask(taskData);
        setExecutionTaskArtifacts(artifactsData.items);
        setExecutionTaskLogs(logsData.items);
        setExecutionTaskMetrics(metricsData.items);
      } catch (error) {
        if (!cancelled) {
          setSelectedExecutionTask(executionTasks.find((task) => task.id === selectedExecutionTaskId) ?? null);
          setExecutionTaskArtifacts([]);
          setExecutionTaskLogs([]);
          setExecutionTaskMetrics([]);
          setExecutionTaskDetailError(error instanceof Error ? error.message : t(locale, "executionTaskDetailLoadFailed"));
        }
      } finally {
        if (!cancelled) {
          setExecutionTaskDetailLoading(false);
        }
      }
    };

    void loadExecutionTaskDetail();

    return () => {
      cancelled = true;
    };
  }, [executionTasks, locale, selectedExecutionTaskId]);

  useEffect(() => {
    let cancelled = false;
    const selectedPlan = visiblePlans.find((plan) => plan.id === selectedPlanId) ?? null;
    setSelectedRequirementItemId(null);
    setCoverageProof(null);
    setProofError(null);

    if (!currentUser || !selectedPlan?.requirementVersionId || !hasUserCapability(currentUser, "coverage.read")) {
      setCoverageSummary(null);
      setCoverageMatrix(null);
      setCoverageLoading(false);
      setCoverageError(null);
      return;
    }
    const requirementVersionId = selectedPlan.requirementVersionId;
    const selectedRequirementItemIds = selectedPlan.requirementScope?.selectedRequirementItemIds ?? [];
    const scopeId = selectedPlan.requirementScope?.scopeId ?? null;

    const loadCoverage = async () => {
      setCoverageLoading(true);
      setCoverageError(null);
      try {
        const [summaryData, matrixData] = await Promise.all([
          fetchCoverageSummary(requirementVersionId, { scopeId, selectedRequirementItemIds }),
          fetchCoverageMatrix(requirementVersionId, { pageSize: 50, scopeId, selectedRequirementItemIds }),
        ]);
        if (!cancelled) {
          setCoverageSummary(summaryData);
          setCoverageMatrix(matrixData);
          const firstRow = matrixData.rows[0];
          setSelectedRequirementItemId(firstRow ? String(firstRow.requirementItem.id ?? firstRow.requirement) : null);
        }
      } catch (error) {
        if (!cancelled) {
          setCoverageSummary(null);
          setCoverageMatrix(null);
          setCoverageError(error instanceof Error ? error.message : t(locale, "coverageMatrixLoadFailed"));
          setLoadError(error instanceof Error ? error.message : t(locale, "coverageMatrixLoadFailed"));
        }
      } finally {
        if (!cancelled) {
          setCoverageLoading(false);
        }
      }
    };

    void loadCoverage();

    return () => {
      cancelled = true;
    };
  }, [currentUser, locale, selectedPlanId, setCoverageMatrix, setCoverageProof, setCoverageSummary, visiblePlans]);

  useEffect(() => {
    let cancelled = false;
    const selectedPlan = visiblePlans.find((plan) => plan.id === selectedPlanId) ?? null;

    if (!currentUser || !selectedPlan?.requirementVersionId || !selectedRequirementItemId || !hasUserCapability(currentUser, "coverage.proof.read")) {
      setCoverageProof(null);
      setProofLoading(false);
      return;
    }
    const requirementVersionId = selectedPlan.requirementVersionId;
    const requirementItemId = selectedRequirementItemId;
    const selectedRequirementItemIds = selectedPlan.requirementScope?.selectedRequirementItemIds ?? [];
    const scopeId = selectedPlan.requirementScope?.scopeId ?? null;

    const loadProof = async () => {
      setProofLoading(true);
      setProofError(null);
      try {
        const proofData = await fetchCoverageProof(requirementVersionId, requirementItemId, { scopeId, selectedRequirementItemIds });
        if (!cancelled) {
          setCoverageProof(proofData);
        }
      } catch (error) {
        if (!cancelled) {
          setCoverageProof(null);
          setProofError(error instanceof Error ? error.message : t(locale, "coverageProofLoadFailed"));
        }
      } finally {
        if (!cancelled) {
          setProofLoading(false);
        }
      }
    };

    void loadProof();

    return () => {
      cancelled = true;
    };
  }, [currentUser, locale, selectedPlanId, selectedRequirementItemId, setCoverageProof, visiblePlans]);

  useEffect(() => {
    let cancelled = false;

    const loadExecutionDetail = async () => {
      if (!selectedExecutionId) {
        setExecutionDetailLoading(false);
        setExecutionDetailError(null);
        setExecutionProgress(null);
        setExecutionTasks([]);
        setSelectedExecutionTaskId(null);
        setSelectedExecutionTask(null);
        setExecutionTaskArtifacts([]);
        setExecutionTaskLogs([]);
        setExecutionTaskMetrics([]);
        setExecutionFindings([]);
        setExecutionHealing([]);
        setLatestReplay(null);
        setLatestReplayExport(null);
        setReplayExports([]);
        setGateSnapshot(null);
        setSkillInvocations([]);
        setAuditLogsAccessState(currentUser ? (currentUser.capabilities.includes("audit.logs.read") ? "ready" : "access-restricted") : "loading");
        setAuditLogProjection(null);
        setAuditLogsError(null);
        return;
      }
      if (!currentUser) {
        setExecutionDetailLoading(true);
        setAuditLogsAccessState("loading");
        return;
      }

      if (executionDetailMode === "timeline") {
        setExecutionDetailLoading(false);
        setExecutionDetailError(null);
        return;
      }

      setExecutionDetailLoading(true);
      setExecutionDetailError(null);
      setLatestReplay(null);
      setLatestReplayExport(null);
      setReplayExports([]);
      try {
        if (executionDetailMode === "replay") {
          const [replayData, replayExportsData] = await Promise.all([
            loadExecutionReplayForUser(currentUser, selectedExecutionId, { compact: true }),
            loadReplayExportsForUser(currentUser, selectedExecutionId, 6),
          ]);
          if (cancelled) return;
          const latestPersistedExport = replayExportsData.items[0] ?? null;
          setLatestReplay(replayData);
          setReplayExports(replayExportsData.items);
          setLatestReplayExport(
            latestPersistedExport
              ? { ...latestPersistedExport, replay: {}, auditLogs: [] }
              : null,
          );
          setLoadError(null);
          return;
        }

        const structuredLogResultPromise = loadStructuredLogsForUser(currentUser, locale, { executionId: selectedExecutionId });
        const auditLogResultPromise = loadAuditLogProjectionForUser(currentUser, locale, { executionId: selectedExecutionId });
        const [
          progressData,
          tasksData,
          findingsData,
          healingData,
          replayData,
          replayExportData,
          replayExportsData,
          gateData,
          skillInvocationsData,
          metricsData,
          dashboardData,
          correctionGovernanceProjectionData,
          structuredLogResult,
          auditLogResult,
        ] = await Promise.all([
          fetchExecutionProgress(selectedExecutionId),
          fetchExecutionTasks(selectedExecutionId),
          fetchExecutionFindings(selectedExecutionId),
          IS_OSS_PROFILE
            ? { executionId: selectedExecutionId, suggestions: [] }
            : fetchExecutionHealing(selectedExecutionId),
          loadExecutionReplayForUser(currentUser, selectedExecutionId),
          loadExecutionReplayExportForUser(currentUser, selectedExecutionId),
          loadReplayExportsForUser(currentUser, selectedExecutionId),
          IS_OSS_PROFILE ? null : fetchCiGate(selectedExecutionId),
          loadSkillInvocationsForUser(currentUser, { executionId: selectedExecutionId, pageSize: 24 }),
          fetchObservabilityMetrics(selectedExecutionId),
          fetchQualityDashboard(selectedExecutionId),
          loadCorrectionGovernanceProjectionForUser(currentUser, { executionId: selectedExecutionId, pageSize: 50 }),
          structuredLogResultPromise,
          auditLogResultPromise,
        ]);
        if (cancelled) {
          return;
        }
        setExecutionProgress(progressData);
        setExecutionTasks(tasksData.items);
        setExecutionFindings(findingsData.items);
        setExecutionHealing(healingData.suggestions);
        setLatestReplay(replayData);
        setLatestReplayExport(replayExportData);
        setReplayExports(replayExportsData.items);
        setGateSnapshot(gateData);
        setSkillInvocations(skillInvocationsData.items);
        setObservabilityMetrics(metricsData.metrics);
        setQualityDashboard(dashboardData);
        setCorrectionGovernanceProjection(correctionGovernanceProjectionData);
        setStructuredLogProjection(structuredLogResult.projection);
        setStructuredLogs(structuredLogResult.items);
        setStructuredLogsAccessState(structuredLogResult.accessState);
        setStructuredLogsError(structuredLogResult.error);
        setAuditLogProjection(auditLogResult.projection);
        setAuditLogItems(auditLogResult.items);
        setAuditLogsAccessState(auditLogResult.accessState);
        setAuditLogsError(auditLogResult.error);
        setLoadError(null);
      } catch (error) {
        if (!cancelled) {
          setExecutionDetailError(error instanceof Error ? error.message : t(locale, "executionDetailLoadFailed"));
          setLoadError(error instanceof Error ? error.message : t(locale, "executionDetailLoadFailed"));
        }
      } finally {
        if (!cancelled) {
          setExecutionDetailLoading(false);
        }
      }
    };

    void loadExecutionDetail();

    return () => {
      cancelled = true;
    };
  }, [currentUser, executionDetailMode, locale, selectedExecutionId, setLatestReplay, setLatestReplayExport, setReplayExports, setSkillInvocations]);

  const selectedExecutionJobs = selectedExecutionId
    ? jobs.filter((job) => job.resultRef === selectedExecutionId || String(job.payload.executionId ?? "") === selectedExecutionId)
    : [];

  const renderSection = () => {
    switch (activeSection) {
      case "workspace":
        return (
          <OverviewPage
            executions={visibleExecutions}
            guardrailSummary={guardrailSummary}
            health={health}
            jobs={jobs}
            locale={locale}
            models={models}
          />
        );
      case "requirement-intake":
        return (
          <RequirementIntakePage
            connectorBindings={connectorBindings}
            currentUser={currentUser}
            environments={environments}
            locale={locale}
            onPipelineConfirmed={handleRequirementIntakePipelineConfirmed}
            onViewPipeline={handleRequirementIntakeViewPipeline}
            projects={projects}
          />
        );
      case "workflow-runs":
        return (
          <WorkflowRunsPage
            detail={selectedWorkflowRun}
            error={workflowRunsError}
            loading={workflowRunsLoading}
            locale={locale}
            onNavigateAction={handleWorkflowRunAction}
            onSelectRun={loadWorkflowRunProjection}
            runs={workflowRuns}
            selectedRunId={selectedWorkflowRunId}
          />
        );
      case "workflow":
        return (
          <WorkflowPage
            approvals={approvals}
            clarifications={requirementClarifications}
            currentUser={currentUser}
            environments={environments}
            error={workflowError}
            executionFindings={executionFindings}
            executionProgress={executionProgress}
            executionTasks={executionTasks}
            executions={visibleExecutions}
            jobs={jobs}
            loading={workflowLoading}
            locale={locale}
            onAnswerClarification={handleAnswerRequirementClarification}
            onApproveApproval={handleApproveApproval}
            onCancelApproval={handleCancelApproval}
            onCancelExecution={handleCancelExecution}
            onCreateExecution={handleCreateExecution}
            onCreatePlan={handleCreatePlan}
            onCreateRequirementLibraryPipeline={handleCreateRequirementLibraryPipeline}
            onCreateRequirementPipeline={handleCreateRequirementPipeline}
            onDeletePlan={handleDeletePlan}
            onGateExecution={handleGateExecution}
            onGeneratePlan={handleGeneratePlan}
            onHealExecution={handleHealExecution}
            onNavigateRoute={(route) => navigateToSection(sectionFromPath(route))}
            onRejectApproval={handleRejectApproval}
            onRetryExecution={handleRetryExecution}
            onSelectExecution={setSelectedExecutionId}
            onSelectPipeline={loadRequirementPipelineDetails}
            onSelectPlan={setSelectedPlanId}
            onUpdatePlan={handleUpdatePlan}
            pipelineReplay={requirementPipelineReplay}
            pipelines={requirementPipelines}
            plans={visiblePlans}
            projects={projects}
            replay={latestReplay}
            selectedExecutionId={selectedExecutionId}
            selectedPipelineId={selectedPipelineId}
            selectedPlanId={selectedPlanId}
            workflowRunProjection={selectedWorkflowRun}
            workflowRuns={workflowRuns}
          />
        );
      case "test-assets":
        return (
          <TestAssetsPage
            coverageMatrix={coverageMatrix}
            coverageSummary={coverageSummary}
            error={coverageError}
            loading={coverageLoading}
            locale={locale}
            onSelectPlan={setSelectedPlanId}
            plans={visiblePlans}
            selectedPlanId={selectedPlanId}
          />
        );
      case "exploratory-sessions":
        return (
          <ExploratorySessionsPage
            currentUser={currentUser}
            environments={environments}
            locale={locale}
            projects={projects}
          />
        );
      case "tasks":
        return (
          <WorkItemsPage
            canManageWorkItems={canManageWorkItems}
            currentUser={currentUser}
            executions={visibleExecutions}
            findings={executionFindings}
            locale={locale}
            onAssign={handleAssignWorkItem}
            onClaim={handleClaimWorkItem}
            onCreate={handleCreateWorkItem}
            onSelectExecution={setSelectedExecutionId}
            onTransition={handleTransitionWorkItem}
            plans={visiblePlans}
            projects={projects}
            selectedProjectId={selectedProjectId}
            workItems={visibleWorkItems}
          />
        );
      case "findings":
        return (
          <FindingsPage
            canSyncIssueTracker={hasCapability("issue_tracker.sync")}
            error={executionDetailError}
            executions={visibleExecutions}
            findings={executionFindings}
            issueTrackerBindingCount={issueTrackerBindings.length}
            loading={executionDetailLoading}
            locale={locale}
            onRefreshExternalIssue={handleRefreshFindingExternalIssue}
            onSelectExecution={setSelectedExecutionId}
            onSyncExternalIssue={handleSyncFindingExternalIssue}
            selectedExecutionId={selectedExecutionId}
            syncingFindingId={syncingIssueFindingId}
          />
        );
      case "gate-decisions":
        return (
          <GateDecisionsPage
            error={executionDetailError}
            executions={visibleExecutions}
            gate={gateSnapshot}
            loading={executionDetailLoading}
            locale={locale}
            onSelectExecution={setSelectedExecutionId}
            replay={latestReplay}
            selectedExecutionId={selectedExecutionId}
          />
        );
      case "audit-logs":
        return (
          <AuditLogsPage
            accessState={auditLogsAccessState}
            canManageAuditRetention={hasCapability("audit.retention.manage")}
            canReadAuditLogs={hasCapability("audit.logs.read")}
            error={auditLogsError}
            executions={visibleExecutions}
            locale={locale}
            logs={auditLogItems}
            onSelectExecution={setSelectedExecutionId}
            projection={auditLogProjection}
            selectedExecutionId={selectedExecutionId}
          />
        );
      case "enterprise-modules":
        return (
          <EnterpriseModulesPage
            capabilities={currentUser?.capabilities ?? []}
            edition={currentUser?.edition ?? null}
            locale={locale}
            onNavigate={navigateToSection}
            projectId={selectedProjectId === ALL_PROJECTS_ID ? null : selectedProjectId}
            roles={currentUser?.roles ?? []}
            runtimeReadiness={runtimeReadiness}
          />
        );
      case "access-control":
        return <AccessControlPage currentUser={currentUser} locale={locale} />;
      case "knowledge-governance":
        return <KnowledgeGovernancePage currentUser={currentUser} locale={locale} />;
      case "lessons-center":
        return <LessonsCenterPage currentUser={currentUser} locale={locale} projectId={selectedProjectId === ALL_PROJECTS_ID ? null : selectedProjectId} />;
      case "improvement-proposals":
        return <ImprovementProposalsPage currentUser={currentUser} locale={locale} projectId={selectedProjectId === ALL_PROJECTS_ID ? null : selectedProjectId} />;
      case "coverage-matrix":
        return (
          <CoverageMatrixPage
            coverageMatrix={coverageMatrix}
            coverageProof={coverageProof}
            coverageSummary={coverageSummary}
            locale={locale}
            onSelectPlan={setSelectedPlanId}
            onSelectRequirementItem={setSelectedRequirementItemId}
            plans={visiblePlans}
            proofError={proofError}
            proofLoading={proofLoading}
            selectedPlanId={selectedPlanId}
            selectedRequirementItemId={selectedRequirementItemId}
          />
        );
      case "ceg":
        return (
          <CegVisualizationPage
            currentUser={currentUser}
            deepLink={cegDeepLink}
            locale={locale}
            onNavigateCorrections={() => navigateToSection("graph-corrections")}
            projectId={selectedProjectId === ALL_PROJECTS_ID ? null : selectedProjectId}
          />
        );
      case "change-sets":
        return (
          <ChangeSetsPage
            currentUser={currentUser}
            locale={locale}
            projectId={selectedProjectId === ALL_PROJECTS_ID ? null : selectedProjectId}
          />
        );
      case "pr-contexts":
        return (
          <PrContextsPage
            currentUser={currentUser}
            locale={locale}
            projectId={selectedProjectId === ALL_PROJECTS_ID ? null : selectedProjectId}
          />
        );
      case "admission-runs":
        return (
          <AdmissionRunsPage
            currentUser={currentUser}
            locale={locale}
            projectId={selectedProjectId === ALL_PROJECTS_ID ? null : selectedProjectId}
          />
        );
      case "impact-analysis":
        return (
          <ImpactAnalysisPage
            currentUser={currentUser}
            locale={locale}
            projectId={selectedProjectId === ALL_PROJECTS_ID ? null : selectedProjectId}
          />
        );
      case "selective-replay-plans":
        return (
          <SelectiveReplayPlansPage
            currentUser={currentUser}
            locale={locale}
            projectId={selectedProjectId === ALL_PROJECTS_ID ? null : selectedProjectId}
          />
        );
      case "replay-center":
        return (
          <ReplayCenterPage
            canCompare={hasCapability("replay.compare")}
            executions={visibleExecutions}
            issueTrackerSyncAvailable={hasCapability("issue_tracker.sync")}
            loading={executionDetailLoading}
            locale={locale}
            onSelectExecution={setSelectedExecutionId}
            replay={latestReplay}
            replayExport={latestReplayExport}
            replayExports={replayExports}
            selectedExecutionId={selectedExecutionId}
          />
        );
      case "execution-explanations":
        return (
          <ExecutionExplanationsPage
            currentUser={currentUser}
            executions={visibleExecutions}
            locale={locale}
            onSelectExecution={setSelectedExecutionId}
            selectedExecutionId={selectedExecutionId}
          />
        );
      case "candidate-paths":
        return (
          <CandidatePathsPage
            currentUser={currentUser}
            locale={locale}
            projectId={selectedProjectId === ALL_PROJECTS_ID ? null : selectedProjectId}
          />
        );
      case "graph-corrections":
        return (
          <GraphCorrectionsPage
            currentUser={currentUser}
            locale={locale}
            projectId={selectedProjectId === ALL_PROJECTS_ID ? null : selectedProjectId}
          />
        );
      case "evidence-search":
        return (
          <EvidenceSearchPage
            currentUser={currentUser}
            locale={locale}
            projectId={selectedProjectId === ALL_PROJECTS_ID ? null : selectedProjectId}
          />
        );
      case "replay-repository":
        return (
          <ReplayRepositoryPage
            currentUser={currentUser}
            executions={visibleExecutions}
            locale={locale}
          />
        );
      case "interactive-governance":
        return <InteractiveGovernancePage currentUser={currentUser} locale={locale} />;
      case "advanced-visualization":
        return <AdvancedVisualizationPage currentUser={currentUser} locale={locale} />;
      case "observability":
        return (
          <ObservabilityPage
            guardrailEvents={guardrailEvents}
            guardrailSummary={guardrailSummary}
            locale={locale}
            logsAccessState={structuredLogsAccessState}
            logsError={structuredLogsError}
            metrics={observabilityMetrics}
            policies={guardrailPolicies}
            qualityDashboard={qualityDashboard}
            replay={latestReplay}
            structuredLogProjection={structuredLogProjection}
            structuredLogs={structuredLogs}
            traces={traces}
            canReadStructuredLogs={hasCapability("audit.logs.read")}
          />
        );
      case "execution-dashboard":
        return (
          <ExecutionsPage
            canGenerateRegressionPresentation={hasCapability("executions.manage")}
            canSyncIssueTracker={hasCapability("issue_tracker.sync")}
            executions={visibleExecutions}
            findings={executionFindings}
            healingSuggestions={executionHealing}
            issueTrackerBindingCount={issueTrackerBindings.length}
            locale={locale}
            onRefreshExternalIssue={handleRefreshFindingExternalIssue}
            onSelectExecution={setSelectedExecutionId}
            onSelectTask={setSelectedExecutionTaskId}
            onSyncExternalIssue={handleSyncFindingExternalIssue}
            progress={executionProgress}
            relatedJobs={selectedExecutionJobs}
            replay={latestReplay}
            selectedExecutionId={selectedExecutionId}
            selectedTask={selectedExecutionTask}
            selectedTaskArtifacts={executionTaskArtifacts}
            selectedTaskDetailError={executionTaskDetailError}
            selectedTaskDetailLoading={executionTaskDetailLoading}
            selectedTaskId={selectedExecutionTaskId}
            selectedTaskLogs={executionTaskLogs}
            selectedTaskMetrics={executionTaskMetrics}
            syncingFindingId={syncingIssueFindingId}
            tasks={executionTasks}
          />
        );
      case "gate-dashboard":
        return (
          <GateDashboardPage
            approvals={approvals}
            executions={visibleExecutions}
            findings={executionFindings}
            gate={gateSnapshot}
            guardrailEvents={guardrailEvents}
            guardrailSummary={guardrailSummary}
            locale={locale}
            metrics={observabilityMetrics}
            onSelectExecution={setSelectedExecutionId}
            policies={guardrailPolicies}
            qualityDashboard={qualityDashboard}
            replay={latestReplay}
            selectedExecutionId={selectedExecutionId}
            skillInvocations={skillInvocations}
            skills={skills}
            structuredLogs={structuredLogs}
          />
        );
      case "gate-policies":
        return (
          <GatePoliciesPage
            currentUser={currentUser}
            locale={locale}
            projectId={selectedProjectId === ALL_PROJECTS_ID ? null : selectedProjectId}
          />
        );
      case "correction-governance":
        return (
          <CorrectionGovernancePage
            canOperate={canOperateCorrections}
            edition={currentUser?.edition ?? null}
            locale={locale}
            onOperationComplete={refreshCorrectionGovernance}
            projection={correctionGovernanceProjection}
            selectedExecutionId={selectedExecutionId}
          />
        );
      case "skill-invocations":
        return (
          <SkillInvocationsPage
            approvals={approvals}
            guardrailEvents={guardrailEvents}
            locale={locale}
            replay={latestReplay}
            skillInvocations={skillInvocations}
          />
        );
      case "capability-bindings":
        return (
          <SkillRuntimePage
            approvals={approvals}
            capabilityBindings={capabilityBindings}
            currentUser={currentUser}
            guardrailEvents={guardrailEvents}
            governancePanel={(
              <SkillGovernancePanel
                capabilityBindings={capabilityBindings}
                currentUser={currentUser}
                environments={environments}
                locale={locale}
                onRefresh={async () => { await Promise.all([refreshSkills(), refreshCapabilityBindings(), refreshWorkflowCollections()]); }}
                projects={projects}
                skillInvocations={skillInvocations}
                skills={skills}
              />
            )}
            locale={locale}
            onCreateBinding={handleCreateCapabilityBinding}
            onRefreshSkills={async () => { await Promise.all([refreshSkills(), refreshCapabilityBindings(), refreshWorkflowCollections()]); }}
            onUpdateBinding={handleUpdateCapabilityBinding}
            environments={environments}
            projects={projects}
            replay={latestReplay}
            selectedProjectId={selectedProjectId}
            skillInvocations={skillInvocations}
            skills={skills}
            workflowCapabilityGraph={workflowCapabilityGraph}
          />
        );
      case "project-settings":
        return (
          <ProjectSettingsPage
            currentUser={currentUser}
            locale={locale}
            members={projectMembers}
            onArchiveProject={handleArchiveProject}
            onCreateMember={handleCreateProjectMember}
            onCreateProject={handleCreateProject}
            onLoadMembers={refreshProjectMembers}
            onSelectProject={setSelectedProjectId}
            onUpdateMember={handleUpdateProjectMember}
            onUpdateProject={handleUpdateProject}
            projects={projects}
            selectedProjectId={selectedProjectId}
          />
        );
      case "environment-settings":
        return (
          <EnvironmentSettingsPage
            currentUser={currentUser}
            environments={environments}
            locale={locale}
            onArchiveEnvironment={handleArchiveEnvironment}
            onCreateEnvironment={handleCreateEnvironment}
            onSelectProject={setSelectedProjectId}
            onUpdateEnvironment={handleUpdateEnvironment}
            projects={projects}
            selectedProjectId={selectedProjectId}
          />
        );
      case "connector-settings":
        return (
          <ConnectorSettingsPage
            connectorBindings={connectorBindings}
            currentUser={currentUser}
            environments={environments}
            locale={locale}
            onArchiveConnectorBinding={handleArchiveConnectorBinding}
            onCreateConnectorBinding={handleCreateConnectorBinding}
            onRefreshConnectorBindings={refreshConnectorBindings}
            onUpdateConnectorBinding={handleUpdateConnectorBinding}
            projects={projects}
            selectedProjectId={selectedProjectId}
          />
        );
      case "model-config":
        return (
          <ModelsPage
            canManageModels={canManageModels}
            environments={environments}
            locale={locale}
            models={models}
            onRefreshModels={refreshModels}
            projects={projects}
            selectedProjectId={selectedProjectId}
          />
        );
      case "agent-runs":
        return <AgentRunsPage agentRuns={agentRuns} locale={locale} />;
      case "queue-jobs":
        return (
          <JobsPage
            jobs={jobs}
            locale={locale}
            onSelectJob={setSelectedJobId}
            runtimeReadiness={runtimeReadiness}
            selectedJobId={selectedJobId}
          />
        );
      default:
        return null;
    }
  };

  return (
    <div className="app-frame">
      <a className="skip-link" href="#main-content">
        {t(locale, "skipToContent")}
      </a>
      <aside className="sidebar">
        <div className="brand-block">
          <span className="brand-block__mark">{t(locale, "brandMark")}</span>
          <div>
            <strong>{t(locale, "brandName")}</strong>
            {t(locale, "productDescriptor") ? <p>{t(locale, "productDescriptor")}</p> : null}
          </div>
        </div>

        <nav className="side-nav" aria-label={t(locale, "primaryNavigation")}>
          {visibleNavigationGroups.map((group) => (
            <div className="side-nav__group" key={group.labelKey}>
              <button
                aria-expanded={expandedNavigationGroups.has(group.id)}
                className="side-nav__group-button"
                onClick={() => toggleNavigationGroup(group.id)}
                type="button"
              >
                <span>{t(locale, group.labelKey)}</span>
                <span aria-hidden="true">{expandedNavigationGroups.has(group.id) ? "-" : "+"}</span>
              </button>
              <div className="side-nav__items" hidden={!expandedNavigationGroups.has(group.id)}>
                {group.sectionIds
                  .map((sectionId) => sections.find((section) => section.id === sectionId))
                  .filter((section): section is AppSectionMeta => Boolean(section))
                  .filter((section) => !section.hiddenFromNavigation)
                  .map((section) => (
                    <button
                      className={`side-nav__item ${section.id === activeSection ? "side-nav__item--active" : ""}`}
                      key={section.id}
                      onClick={() => navigateToSection(section.id)}
                      type="button"
                    >
                      {t(locale, section.labelKey)}
                    </button>
                  ))}
              </div>
            </div>
          ))}
        </nav>

        {plannedSections.length > 0 ? (
          <div className="planned-nav">
            <span>{t(locale, "planned")}</span>
            {plannedSections.map((section) => (
              <button className="side-nav__item side-nav__item--disabled" disabled key={section.labelKey} type="button">
                <span>{t(locale, section.labelKey)}</span>
                <small>{t(locale, "enterpriseOnly")}</small>
              </button>
            ))}
          </div>
        ) : null}
      </aside>

      <div className="main-frame">
        <header className="topbar">
          <div>
            <h1>{t(locale, "appTitle")}</h1>
          </div>
          <div className="topbar__actions">
            <ProjectSwitcher
              locale={locale}
              onSelectProject={setSelectedProjectId}
              projects={projectOptions}
              selectedProjectId={selectedProject?.id ?? selectedProjectId}
            />
            <LocaleSwitch locale={locale} onChange={setLocale} />
            {IS_OSS_PROFILE ? <CommunityLogoutButton locale={locale} /> : null}
          </div>
        </header>

        {loadError ? <div className="error-banner"><strong>{t(locale, "loadError")}</strong><p>{loadError}</p></div> : null}

        <main className="workspace" id="main-content" tabIndex={-1}>
          {currentUser?.edition === "basic" ? <div className="notice notice--info" role="status">{t(locale, "currentEditionReadOnly")}</div> : null}
          {renderSection()}
        </main>
      </div>
    </div>
  );
}

function LocaleSwitch({ locale, onChange }: { locale: Locale; onChange: (locale: Locale) => void }) {
  return (
    <div className="segmented-control" aria-label={t(locale, "localeLabel")}>
      {(["zh-CN", "en-US"] as Locale[]).map((item) => (
        <button
          className={item === locale ? "segmented-control__item segmented-control__item--active" : "segmented-control__item"}
          key={item}
          onClick={() => onChange(item)}
          type="button"
        >
          {item}
        </button>
      ))}
    </div>
  );
}

function CommunityLogoutButton({ locale }: { locale: Locale }) {
  const logout = async () => {
    try {
      await logoutCommunity();
    } finally {
      clearCommunityAuthToken();
      window.location.assign("/");
    }
  };
  return <button className="link-button" onClick={() => void logout()} type="button">{locale === "zh-CN" ? "退出登录" : "Sign out"}</button>;
}

export default App;
