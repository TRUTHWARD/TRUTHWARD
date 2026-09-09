/* SPDX-License-Identifier: Apache-2.0 */
import { create } from "zustand";

import type {
  ConnectorBindingItem,
  CoverageProofBundle,
  CurrentUser,
  EnvironmentItem,
  ExecutionRuntimeProjection,
  ProjectItem,
  ProjectMemberItem,
  ReplayExport,
  ReplayExportRecord,
  ExternalIssueLink,
} from "../lib/api";
import type { Locale } from "../i18n";

const LOCALE_STORAGE_KEY = "agentic-qa.locale";
const DEFAULT_LOCALE: Locale = "en-US";
const SUPPORTED_LOCALES = new Set<Locale>(["en-US", "zh-CN"]);

function isSupportedLocale(value: string | null): value is Locale {
  return value !== null && SUPPORTED_LOCALES.has(value as Locale);
}

function readStoredLocale(): Locale {
  if (typeof window === "undefined") {
    return DEFAULT_LOCALE;
  }
  try {
    const storedLocale = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    return isSupportedLocale(storedLocale) ? storedLocale : DEFAULT_LOCALE;
  } catch {
    return DEFAULT_LOCALE;
  }
}

function writeStoredLocale(value: Locale) {
  if (typeof window === "undefined") {
    return;
  }
  try {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, value);
  } catch {
    // Ignore storage failures so language switching still works in memory.
  }
}

export type HealthItem = {
  name: string;
  status: string;
};

export type ModelItem = {
  id: string;
  name: string;
  projectId: string | null;
  environmentId: string | null;
  provider: string;
  model: string;
  baseUrl: string | null;
  apiKeyConfigured: boolean;
  roles: string[];
  priority: number;
  enabled: boolean;
  healthStatus: string;
  capabilities: Record<string, unknown>;
  config: Record<string, unknown>;
  lastHealthCheck: {
    id: string;
    status: string;
    latencyMs: number | null;
    details: Record<string, unknown>;
    checkedAt: string;
  } | null;
  lastCapabilityScan: {
    id: string;
    scanner: string;
    capabilities: Record<string, unknown>;
    details: Record<string, unknown>;
    scannedAt: string;
  } | null;
  createdAt: string;
  updatedAt: string;
};

export type PlanItem = {
  id: string;
  name: string;
  status: string;
  environment: string;
  projectId: string | null;
  environmentId: string | null;
  domains: string[];
  domainConfig: Record<string, Record<string, unknown>>;
  riskLevel: string;
  sourceType: string;
  sourceRef: string | null;
  requirementVersionId: string | null;
  requirementScope: RequirementScopeItem | null;
  input: Record<string, unknown>;
  generatedPlan: Record<string, unknown>;
};

export type RequirementScopeItem = {
  schemaVersion: string;
  requirementVersionId: string;
  requirementVersionIds?: string[];
  requirementItemRefs?: Array<{ requirementVersionId: string; requirementItemIds: string[] }>;
  scopeItemRefs?: Array<{ scopeItemId: string; requirementVersionId: string; requirementItemId: string }>;
  scopeId: string;
  selectedRequirementItemIds: string[];
  filters: Record<string, unknown>;
  metadata: Record<string, unknown>;
};

export type ExecutionItem = {
  id: string;
  planId: string;
  status: string;
  stage: string;
  environment: string;
  summary: Record<string, string>;
  startedAt: string | null;
  endedAt: string | null;
  runtime: ExecutionRuntimeProjection | null;
};

export type AgentRunItem = {
  id: string;
  executionId: string | null;
  taskId: string | null;
  agentName: string;
  status: string;
  modelId: string | null;
  createdAt: string;
};

export type MemoryItem = {
  id: string;
  type: string;
  scope: string;
  namespace: string;
  content: string;
  metadata: Record<string, unknown>;
};

export type TraceItem = {
  id: string;
  executionId: string | null;
  rootSpanName: string | null;
  metadata?: Record<string, unknown>;
  spanCount: number;
  modelInvocationCount: number;
  agentRunCount: number;
  skillInvocationCount: number;
  auditLogCount?: number;
  guardrailEventCount: number;
  createdAt: string;
};

export type ReplayEvent = {
  kind: string;
  label: string;
  status: string;
  timestamp: string;
  details?: Record<string, unknown>;
};

export type ReplayFinding = {
  id: string;
  severity: string;
  title: string;
  summary?: string;
  category?: string;
  externalIssueLink?: ExternalIssueLink | null;
};

export type SkillItem = {
  id: string;
  skillId: string;
  displayName: string;
  status: string;
  version: string;
  manifestHash: string;
  capabilities: Record<string, unknown>;
  allowedTools: string[];
  allowedConnectors: string[];
  riskProfile: Record<string, unknown>;
  dataAccessPolicy: Record<string, unknown>;
  replayPolicy: Record<string, unknown>;
  extensionPoints: string[];
  compatibility: Record<string, unknown>;
  runtime: Record<string, unknown>;
  governanceStatus?: string;
};

export type SkillInvocationItem = {
  id: string;
  skillId: string;
  version: string;
  manifestHash: string;
  status: string;
  storageStatus?: string;
  idempotencyKey: string | null;
  traceId: string | null;
  executionId: string | null;
  agentRunId?: string | null;
  extensionPointId: string | null;
  bindingId: string | null;
  sourceWorkflow: string | null;
  resolutionSnapshot: Record<string, unknown>;
  inputSummary?: Record<string, unknown>;
  outputSummary?: Record<string, unknown>;
  policySummary?: Record<string, unknown>;
  inputSnapshot?: Record<string, unknown>;
  outputSnapshot?: Record<string, unknown>;
  policySnapshot?: Record<string, unknown>;
  connectorBindingSnapshot: Record<string, unknown>;
  approvalRefs: Array<Record<string, unknown>>;
  artifactRefs: Array<Record<string, unknown>>;
  toolCallRefs: Array<Record<string, unknown>>;
  connectorCallRefs: Array<Record<string, unknown>>;
  createdAt: string;
  updatedAt?: string;
};

export type CapabilityBindingItem = {
  stateHash?: string;
  communityLifecycle?: { canEnable: boolean; canDisable: boolean; unavailableReason: string | null };
  id: string;
  extensionPointId: string;
  skillId: string;
  skillVersionId: string;
  version: string;
  manifestHash: string;
  scopeType: string;
  scopeId: string | null;
  projectId: string | null;
  environment: string | null;
  stage: string | null;
  domain: string | null;
  status: string;
  priority: number;
  bindingConfig: Record<string, unknown>;
  activationReadiness?: {
    candidate: boolean;
    skillVersionGovernanceStatus: string;
    contractValidation: string;
    datasetEvaluation: string;
    shadowComparison: string;
    evidenceReady: boolean;
    canRequestActivation: boolean;
    directExecutionAllowed: false;
  };
  pendingChange: Record<string, unknown>;
  approvalRefs: Array<Record<string, unknown>>;
  guardrailEventRefs: Array<Record<string, unknown>>;
  auditRefs: Array<Record<string, unknown>>;
  approvalRequired: boolean;
  approvalEnvelope: Record<string, unknown> | null;
  createdAt: string;
  updatedAt: string;
};

export type WorkflowCapabilityNode = {
  lifecycleStage: string;
  extensionPointId: string;
  label: string;
  bindable: boolean;
  currentBindingSummary: Record<string, unknown> | null;
  requiredCapability: string | null;
  requiredEdition: string | null;
  unavailableReason: string | null;
};

export type ReplayVisualGroundingAttempt = {
  id: string;
  actionId: string;
  actionType: string;
  status: string;
  verificationStatus: string | null;
  confidence: number | null;
  chosenLocator: Record<string, unknown>;
  coordinateClickAllowed: boolean;
  riskLevel: string;
  guardrailDecision: string | null;
  redactionStatus: string;
  artifactRefs: Array<Record<string, unknown>>;
  verificationResult: Record<string, unknown>;
};

export type ReplayVerificationResult = {
  id: string;
  verificationType: string;
  status: string;
  confidence: number | null;
  normalizedFindingId: string | null;
};

export type CorrectionGovernanceItem = {
  correctionProposalId: string;
  proposalType: string;
  status: string;
  overallStatus: string;
  riskLevel: string;
  approvalRefs: Array<Record<string, unknown>>;
  evidenceRefs: Array<Record<string, unknown>>;
  traceRefs: string[];
  replayRefs?: Array<Record<string, unknown>>;
  applications: Array<Record<string, unknown>>;
  validations: Array<Record<string, unknown>>;
  rollbackRecords: Array<Record<string, unknown>>;
  approvals: Array<Record<string, unknown>>;
  promotionRefs: Array<Record<string, unknown>>;
  promotedAt: string | null;
  timeline: Array<{ kind: string; status: string; timestamp: string; details: Record<string, unknown> }>;
  metadata: Record<string, unknown>;
};

export type ReplayItem = {
  executionId: string;
  traceCount: number;
  timeline: ReplayEvent[];
  findings: ReplayFinding[];
  rawFindings: Array<Record<string, unknown>>;
  metrics: Array<Record<string, unknown>>;
  correctionRecords: Array<Record<string, unknown>>;
  correctionGovernance: CorrectionGovernanceItem[];
  skillInvocations: SkillInvocationItem[];
  visualGroundingAttempts: ReplayVisualGroundingAttempt[];
  verificationResults: ReplayVerificationResult[];
  guardrailEvents: Array<{ id: string; ruleId: string; decision: string; reason: string; createdAt: string }>;
  gate: { overall: string; reasons: string[]; functional?: string; performance?: string; security?: string } | null;
  orchestrator?: { checkpointCount: number; status: string } | null;
};

export type GuardrailPolicyItem = {
  ruleId: string;
  name: string;
  description: string;
  owner: string;
  enabled: boolean;
  defaultEnabled: boolean;
  decisionOverrides: Record<string, string>;
  defaultDecisionOverrides: Record<string, string>;
  effectiveDecisions: Record<string, string>;
  metadata: Record<string, unknown>;
  updatedAt: string | null;
};

export type GuardrailEventItem = {
  id: string;
  traceId: string | null;
  executionId: string | null;
  skillInvocationId: string | null;
  connectorBindingId: string | null;
  toolCallId: string | null;
  actorId: string | null;
  requestId: string | null;
  resourceType: string;
  resourceId: string;
  ruleId: string;
  decision: string;
  reason: string;
  evidence: string[];
  metadata: Record<string, unknown>;
  createdAt: string;
};

export type ApprovalItem = {
  id: string;
  type: string;
  resourceType: string;
  resourceId: string;
  summary: string;
  payload: Record<string, unknown>;
  status: string;
  requestedBy: string | null;
  decidedBy: string | null;
  decisionComment: string | null;
  decidedAt: string | null;
  createdAt: string;
  updatedAt: string;
};

export type JobItem = {
  id: string;
  jobType: string;
  status: string;
  progress: number;
  payload: Record<string, unknown>;
  result: Record<string, unknown>;
  resultRef: string | null;
  errorMessage: string | null;
  startedAt: string | null;
  endedAt: string | null;
  createdAt: string;
  updatedAt: string;
};

export type MissingLinkItem = {
  code: string;
  fromType: string;
  fromId: string;
  expectedTargetType: string;
  severity: string;
  blocksCoverage: boolean;
};

export type CoverageSummaryItem = {
  schemaVersion: string;
  requirementVersionId: string;
  scope: RequirementScopeItem & { activeInScopeRequirementItems: number };
  status: string;
  reason: string | null;
  requirementCoverage: number | null;
  testPointCoverage: number | null;
  testCaseCoverage: number | null;
  evidenceCoverage: number | null;
  findingTraceCoverage: number | null;
  gateImpactCoverage: number | null;
  missingLinks: MissingLinkItem[];
  calculatedAt: string;
};

export type CoverageMatrixRowItem = {
  requirement: string;
  requirementVersion: string;
  requirementItem: Record<string, unknown>;
  testPoints: Array<Record<string, unknown>>;
  testCases: Array<Record<string, unknown>>;
  executionTasks: Array<Record<string, unknown>>;
  evidenceArtifacts: Array<Record<string, unknown>>;
  rawFindings: Array<Record<string, unknown>>;
  normalizedFindings: Array<Record<string, unknown>>;
  gateImpact: Array<Record<string, unknown>>;
  coverageStatus: string;
  riskStatus: string;
  missingLinks: MissingLinkItem[];
};

export type CoverageMatrixItem = {
  schemaVersion: string;
  requirementVersionId: string;
  summary: CoverageSummaryItem;
  rows: CoverageMatrixRowItem[];
  missingLinks: MissingLinkItem[];
  status: string;
  scope: CoverageSummaryItem["scope"];
  calculatedAt: string;
  pagination: { page: number; pageSize: number; total: number };
  filters: Record<string, unknown>;
};

type PlatformState = {
  locale: Locale;
  currentUser: CurrentUser | null;
  health: HealthItem[];
  models: ModelItem[];
  projects: ProjectItem[];
  environments: EnvironmentItem[];
  projectMembers: ProjectMemberItem[];
  connectorBindings: ConnectorBindingItem[];
  plans: PlanItem[];
  executions: ExecutionItem[];
  agentRuns: AgentRunItem[];
  skills: SkillItem[];
  skillInvocations: SkillInvocationItem[];
  capabilityBindings: CapabilityBindingItem[];
  workflowCapabilityGraph: WorkflowCapabilityNode[];
  memories: MemoryItem[];
  traces: TraceItem[];
  jobs: JobItem[];
  latestReplay: ReplayItem | null;
  latestReplayExport: ReplayExport | null;
  replayExports: ReplayExportRecord[];
  guardrailPolicies: GuardrailPolicyItem[];
  guardrailEvents: GuardrailEventItem[];
  approvals: ApprovalItem[];
  coverageSummary: CoverageSummaryItem | null;
  coverageMatrix: CoverageMatrixItem | null;
  coverageProof: CoverageProofBundle | null;
  guardrailSummary: { allow: number; warn: number; block: number };
  search: string;
  setLocale: (value: Locale) => void;
  setCurrentUser: (value: CurrentUser | null) => void;
  setHealth: (items: HealthItem[]) => void;
  setModels: (items: ModelItem[]) => void;
  setProjects: (items: ProjectItem[]) => void;
  setEnvironments: (items: EnvironmentItem[]) => void;
  setProjectMembers: (items: ProjectMemberItem[]) => void;
  setConnectorBindings: (items: ConnectorBindingItem[]) => void;
  setPlans: (items: PlanItem[]) => void;
  setExecutions: (items: ExecutionItem[]) => void;
  setAgentRuns: (items: AgentRunItem[]) => void;
  setSkills: (items: SkillItem[]) => void;
  setSkillInvocations: (items: SkillInvocationItem[]) => void;
  setCapabilityBindings: (items: CapabilityBindingItem[]) => void;
  setWorkflowCapabilityGraph: (items: WorkflowCapabilityNode[]) => void;
  setMemories: (items: MemoryItem[]) => void;
  setTraces: (items: TraceItem[]) => void;
  setJobs: (items: JobItem[]) => void;
  setLatestReplay: (value: ReplayItem | null) => void;
  setLatestReplayExport: (value: ReplayExport | null) => void;
  setReplayExports: (items: ReplayExportRecord[]) => void;
  setGuardrailPolicies: (items: GuardrailPolicyItem[]) => void;
  setGuardrailEvents: (items: GuardrailEventItem[], summary: { allow: number; warn: number; block: number }) => void;
  setApprovals: (items: ApprovalItem[]) => void;
  setCoverageSummary: (value: CoverageSummaryItem | null) => void;
  setCoverageMatrix: (value: CoverageMatrixItem | null) => void;
  setCoverageProof: (value: CoverageProofBundle | null) => void;
  setSearch: (value: string) => void;
};

export const usePlatformStore = create<PlatformState>((set) => ({
  locale: readStoredLocale(),
  currentUser: null,
  health: [],
  models: [],
  projects: [],
  environments: [],
  projectMembers: [],
  connectorBindings: [],
  plans: [],
  executions: [],
  agentRuns: [],
  skills: [],
  skillInvocations: [],
  capabilityBindings: [],
  workflowCapabilityGraph: [],
  memories: [],
  traces: [],
  jobs: [],
  latestReplay: null,
  latestReplayExport: null,
  replayExports: [],
  guardrailPolicies: [],
  guardrailEvents: [],
  approvals: [],
  coverageSummary: null,
  coverageMatrix: null,
  coverageProof: null,
  guardrailSummary: { allow: 0, warn: 0, block: 0 },
  search: "checkout",
  setLocale: (value) => {
    writeStoredLocale(value);
    set({ locale: value });
  },
  setCurrentUser: (value) => set({ currentUser: value }),
  setHealth: (items) => set({ health: items }),
  setModels: (items) => set({ models: items }),
  setProjects: (items) => set({ projects: items }),
  setEnvironments: (items) => set({ environments: items }),
  setProjectMembers: (items) => set({ projectMembers: items }),
  setConnectorBindings: (items) => set({ connectorBindings: items }),
  setPlans: (items) => set({ plans: items }),
  setExecutions: (items) => set({ executions: items }),
  setAgentRuns: (items) => set({ agentRuns: items }),
  setSkills: (items) => set({ skills: items }),
  setSkillInvocations: (items) => set({ skillInvocations: items }),
  setCapabilityBindings: (items) => set({ capabilityBindings: items }),
  setWorkflowCapabilityGraph: (items) => set({ workflowCapabilityGraph: items }),
  setMemories: (items) => set({ memories: items }),
  setTraces: (items) => set({ traces: items }),
  setJobs: (items) => set({ jobs: items }),
  setLatestReplay: (value) => set({ latestReplay: value }),
  setLatestReplayExport: (value) => set({ latestReplayExport: value }),
  setReplayExports: (items) => set({ replayExports: items }),
  setGuardrailPolicies: (items) => set({ guardrailPolicies: items }),
  setGuardrailEvents: (items, summary) => set({ guardrailEvents: items, guardrailSummary: summary }),
  setApprovals: (items) => set({ approvals: items }),
  setCoverageSummary: (value) => set({ coverageSummary: value }),
  setCoverageMatrix: (value) => set({ coverageMatrix: value }),
  setCoverageProof: (value) => set({ coverageProof: value }),
  setSearch: (value) => set({ search: value }),
}));
