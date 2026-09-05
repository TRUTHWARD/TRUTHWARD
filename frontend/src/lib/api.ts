/* SPDX-License-Identifier: Apache-2.0 */
import { IS_OSS_PROFILE } from "../productProfile";

const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? "/api/v1").trim().replace(/\/+$/, "");
const COMMUNITY_TOKEN_STORAGE_KEY = "truthward.community.token";

export function getStoredAuthToken() {
  if (!IS_OSS_PROFILE) return import.meta.env.VITE_DEMO_TOKEN || "admin-token";
  if (typeof window === "undefined") return "";
  return window.localStorage.getItem(COMMUNITY_TOKEN_STORAGE_KEY) ?? "";
}

export function storeCommunityAuthToken(token: string) {
  if (typeof window !== "undefined") window.localStorage.setItem(COMMUNITY_TOKEN_STORAGE_KEY, token);
}

export function clearCommunityAuthToken() {
  if (typeof window !== "undefined") window.localStorage.removeItem(COMMUNITY_TOKEN_STORAGE_KEY);
}

export type RequestOptions = {
  method?: "GET" | "PATCH" | "POST" | "PUT" | "DELETE";
  body?: unknown;
  timeoutMs?: number;
  signal?: AbortSignal;
  authenticated?: boolean;
};

export type QueryScalar = string | number;
export type QueryValue = QueryScalar | readonly QueryScalar[] | undefined | null;

export class ApiRequestError extends Error {
  status: number;
  path: string;
  detail: unknown;
  code: string | null;
  capability: string | null;
  kind: "authentication" | "authorization" | "conflict" | "payload_too_large" | "validation" | "rate_limited" | "unavailable" | "unknown";
  retryable: boolean;
  retryAfterSeconds: number | null;
  requestId: string | null;

  constructor(status: number, path: string, detail: unknown = null, metadata: { code?: string | null; retryAfterSeconds?: number | null; requestId?: string | null } = {}) {
    super(`Request failed: ${status}`);
    this.name = "ApiRequestError";
    this.status = status;
    this.path = path;
    this.detail = detail;
    this.code = metadata.code ?? (isErrorDetail(detail) && typeof detail.code === "string" ? detail.code : null);
    this.capability = isErrorDetail(detail) && typeof detail.capability === "string" ? detail.capability : null;
    this.kind = apiErrorKind(status);
    this.retryable = status === 429 || status === 0 || status >= 500;
    this.retryAfterSeconds = metadata.retryAfterSeconds ?? null;
    this.requestId = metadata.requestId ?? null;
    this.message = `Request failed: ${status} for ${path}`;
  }
}

function apiErrorKind(status: number): ApiRequestError["kind"] {
  if (status === 401) return "authentication";
  if (status === 403) return "authorization";
  if (status === 409) return "conflict";
  if (status === 413) return "payload_too_large";
  if (status === 422) return "validation";
  if (status === 429) return "rate_limited";
  if (status === 0 || status >= 500) return "unavailable";
  return "unknown";
}

function isErrorDetail(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function withQuery(path: string, query: Record<string, QueryValue>) {
  const params = new URLSearchParams();
  Object.entries(query).forEach(([key, value]) => {
    if (Array.isArray(value)) {
      value.forEach((item) => params.append(key, String(item)));
      return;
    }
    if (value !== undefined && value !== null && value !== "") {
      params.set(key, String(value));
    }
  });
  const queryString = params.toString();
  return queryString ? `${path}?${queryString}` : path;
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const isFormData = typeof FormData !== "undefined" && options.body instanceof FormData;
  const requestBody: BodyInit | undefined =
    options.body === undefined ? undefined : isFormData ? (options.body as FormData) : JSON.stringify(options.body);
  const controller = new AbortController();
  const timeoutMs = options.timeoutMs ?? 30_000;
  const timeout = window.setTimeout(() => controller.abort("request-timeout"), timeoutMs);
  const abortFromCaller = () => controller.abort(options.signal?.reason);
  options.signal?.addEventListener("abort", abortFromCaller, { once: true });
  let response: Response;
  const token = getStoredAuthToken();
  const authenticated = options.authenticated !== false;
  const authorizationHeaders: Record<string, string> = authenticated && token ? { Authorization: `Bearer ${token}` } : {};
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method: options.method ?? "GET",
      headers: isFormData
        ? authorizationHeaders
        : {
            ...authorizationHeaders,
            "Content-Type": "application/json",
          },
      body: requestBody,
      signal: controller.signal,
    });
  } catch (error) {
    if (controller.signal.aborted || error instanceof TypeError) {
      throw new ApiRequestError(0, path, null, { code: controller.signal.reason === "request-timeout" ? "CLIENT_REQUEST_TIMEOUT" : "CLIENT_REQUEST_UNAVAILABLE" });
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
    options.signal?.removeEventListener("abort", abortFromCaller);
  }
  if (!response.ok) {
    let detail: unknown = null;
    let code: string | null = null;
    let requestId: string | null = null;
    try {
      const errorBody = (await response.json()) as { detail?: unknown; details?: unknown; errorCode?: unknown; requestId?: unknown; message?: unknown };
      detail = errorBody.detail ?? errorBody.details ?? errorBody.message ?? null;
      code = typeof errorBody.errorCode === "string" ? errorBody.errorCode : null;
      requestId = typeof errorBody.requestId === "string" ? errorBody.requestId : null;
      if (!code && isErrorDetail(detail)) {
        code = typeof detail.errorCode === "string" ? detail.errorCode : typeof detail.code === "string" ? detail.code : null;
      }
    } catch {
      // Some infrastructure failures do not provide a JSON error envelope.
    }
    const retryAfter = Number(response.headers.get("Retry-After"));
    throw new ApiRequestError(response.status, path, detail, {
      code,
      requestId,
      retryAfterSeconds: Number.isFinite(retryAfter) ? retryAfter : null,
    });
  }
  const body = await response.json();
  return body.data as T;
}

export type CurrentUser = {
  id: string;
  name: string;
  email: string;
  roles: string[];
  status: string;
  edition: "basic" | "community" | "pro" | "enterprise";
  capabilities: string[];
  deploymentProfile?: "full" | "oss";
  authorizationRevision?: string;
  editionProjection?: EditionProjection;
};

export type EffectiveCapability = {
  capability: string;
  granted: boolean;
  source: "edition" | "role" | "entitlement" | "reserved" | "inactive" | "not_granted";
  riskLevel: "low" | "medium" | "high";
  decisionRef: string;
};

export type EditionProjection = {
  schemaVersion: "phase8.edition-projection.v1";
  edition: "basic" | "community" | "pro" | "enterprise";
  authorizationRevision: string;
  effectiveCapabilities: EffectiveCapability[];
  backendAuthoritative: true;
  editionStringAuthorizes: false;
};

export type GovernanceModuleReadiness = {
  moduleId: string;
  route: string;
  readCapability: string;
  governanceCapabilities: string[];
  workflowImplemented: boolean;
  visible: boolean;
  governanceAvailable: boolean;
  readOnly: boolean;
  unavailableReason: string | null;
};

export type GovernanceReadiness = {
  schemaVersion: "phase8.governance-readiness.v1";
  scopeContext: {
    schemaVersion: "phase8.scope-context.v1";
    tenantId: string;
    workspaceId: string;
    projectId: string;
    environmentId: string | null;
    membershipRole: string | null;
    accessSource: "project_membership" | "platform_admin" | "service_role";
    decisionRef: string;
    serverDerived: true;
  };
  editionProjection: EditionProjection;
  modules: GovernanceModuleReadiness[];
  graphAutonomy: {
    policy: boolean;
    eligibility: boolean;
    replay: boolean;
    shadow: boolean;
    killSwitch: boolean;
    approval: boolean;
    complete: boolean;
    configurable: boolean;
    requiredCapability: "graph.autonomy.configure";
    unavailableReasons: string[];
  };
  basicReadOnly: boolean;
  directSkillExecution: false;
  frontendAuthorizationBoundary: "ux_only";
  backendAuthorizationBoundary: "service_api";
};

export type GovernanceAggregation = {
  schemaVersion: "phase8.governance-aggregation.v1";
  scopeContext: GovernanceReadiness["scopeContext"];
  projectCount: number;
  omittedUnauthorizedProjectCount: number;
  lessonTaxonomyCounts: Record<string, number>;
  lessonStatusCounts: Record<string, number>;
  improvementStatusCounts: Record<string, number>;
  admissionModeCounts: Record<string, number>;
  minimumVisibility: "aggregate_only";
  rawEvidenceIncluded: false;
  projectIdentifiersIncluded: false;
};

export async function fetchCurrentUser() {
  return request<CurrentUser>("/auth/me");
}

export type CommunityBootstrapStatus = {
  deploymentProfile: "full" | "oss";
  bootstrapRequired: boolean;
  authenticationMode: "demo" | "community_local";
};

export type CommunityTokenResponse = {
  token: string;
  tokenType: "bearer";
  expiresAt: string;
  user: CurrentUser;
};

export async function fetchCommunityBootstrapStatus() {
  return request<CommunityBootstrapStatus>("/auth/bootstrap-status", { authenticated: false });
}

export async function bootstrapCommunity(payload: { username: string; email: string; displayName: string; password: string }) {
  return request<CommunityTokenResponse>("/auth/bootstrap", { method: "POST", body: payload, authenticated: false });
}

export async function loginCommunity(payload: { identity: string; password: string; tokenName?: string }) {
  return request<CommunityTokenResponse>("/auth/login", { method: "POST", body: payload, authenticated: false });
}

export async function logoutCommunity() {
  return request<{ revoked: true }>("/auth/logout", { method: "POST" });
}

export async function revokeAllCommunityTokens() {
  return request<{ revoked: true; scope: "all" }>("/auth/tokens/revoke-all", { method: "POST" });
}

export type CommunityUserItem = {
  id: string;
  username: string;
  email: string;
  displayName: string;
  roles: string[];
  edition: "community";
  status: string;
  createdAt: string;
};

export async function fetchCommunityUsers() {
  return request<{ items: CommunityUserItem[] }>("/community/users");
}

export async function createCommunityUser(payload: { username: string; email: string; displayName: string; password: string }) {
  return request<CommunityUserItem>("/community/users", { method: "POST", body: payload });
}

export async function createCommunityProject(payload: ProjectMutationPayload) {
  return request<ProjectItem>("/projects", { method: "POST", body: payload });
}

export async function updateCommunityProject(projectId: string, payload: Partial<ProjectMutationPayload>) {
  return request<ProjectItem>(`/projects/${encodeURIComponent(projectId)}`, { method: "PUT", body: payload });
}

export async function archiveCommunityProject(projectId: string) {
  return request<ProjectItem>(`/projects/${encodeURIComponent(projectId)}`, { method: "DELETE" });
}

export async function createCommunityEnvironment(projectId: string, payload: EnvironmentMutationPayload) {
  return request<EnvironmentItem>(`/projects/${encodeURIComponent(projectId)}/environments`, { method: "POST", body: payload });
}

export async function updateCommunityEnvironment(environmentId: string, payload: Partial<EnvironmentMutationPayload>) {
  return request<EnvironmentItem>(`/environments/${encodeURIComponent(environmentId)}`, { method: "PUT", body: payload });
}

export async function archiveCommunityEnvironment(environmentId: string) {
  return request<EnvironmentItem>(`/environments/${encodeURIComponent(environmentId)}`, { method: "DELETE" });
}

export async function createCommunityProjectMember(projectId: string, payload: ProjectMemberMutationPayload) {
  return request<ProjectMemberItem>(`/projects/${encodeURIComponent(projectId)}/members`, { method: "POST", body: payload });
}

export async function updateCommunityProjectMember(
  memberId: string,
  payload: Partial<Omit<ProjectMemberMutationPayload, "userId">>,
) {
  return request<ProjectMemberItem>(`/project-members/${encodeURIComponent(memberId)}`, { method: "PUT", body: payload });
}

export async function fetchGovernanceReadiness(projectId: string) {
  return request<GovernanceReadiness>(
    `/projects/${encodeURIComponent(projectId)}/governance/readiness`,
  );
}

export async function fetchGovernanceAggregation(projectId: string) {
  return request<GovernanceAggregation>(
    `/projects/${encodeURIComponent(projectId)}/governance/aggregation`,
  );
}

export type CandidateEvidenceSummary = {
  independentRunCount: number;
  successCount: number;
  failureCount: number;
  distinctRevisionCount: number;
  distinctEnvironmentCount: number;
  verificationCoverage: number;
  retryCount: number;
  fallbackTypes: string[];
  coordinateClickCount: number;
  conflictRefs: Array<Record<string, unknown>>;
  flakySignals: string[];
  lastObservedAt: string;
};

export type CandidateBuildSummary = {
  buildId: string;
  buildRef: string;
  graphId: string;
  executionId: string;
  candidateVersionId: string;
  status: "completed";
  outcome: "success" | "failure" | "partial" | "unknown";
  transformerVersion: string;
  evidenceSummary: CandidateEvidenceSummary;
  ambiguityCount: number;
  modelSuggestionStatus: "not_requested" | "unavailable" | "suggested" | "rejected";
  canonical: false;
  active: false;
  promotionPerformed: false;
  readOnly: true;
  observedAt: string;
  createdAt: string;
};

export type CandidateBuildList = {
  items: CandidateBuildSummary[];
  total: number;
  page: number;
  pageSize: number;
};

export async function fetchCandidateBuilds(projectId: string, query: { graphId?: string; pageSize?: number } = {}) {
  return request<CandidateBuildList>(withQuery(
    `/internal/projects/${encodeURIComponent(projectId)}/execution-graph-candidates/builds`,
    { graphId: query.graphId, pageSize: query.pageSize ?? 50 },
  ));
}

export type GraphLearningMode = "learn_only" | "human_supervised" | "controlled_autonomy";
export type GraphCorrectionEntityType = "node" | "edge" | "path";
export type GraphCorrectionOperationType = "add" | "update" | "remove" | "reorder";

export type GraphCorrectionTarget = {
  id: string;
  stableKey: string;
  lockVersion: number;
  summary: string;
  value: Record<string, unknown>;
};

export type GraphCorrectionCandidate = {
  buildId: string;
  buildRef: string;
  graphId: string;
  baseVersionId: string;
  baseVersionHash: string;
  baseVersionLockVersion: number;
  candidateVersionId: string;
  candidateVersionHash: string;
  candidateVersionLockVersion: number;
  riskLevel: "low" | "medium" | "high";
  targets: Record<GraphCorrectionEntityType, GraphCorrectionTarget[]>;
  allowedOperations: GraphCorrectionOperationType[];
  authoritative: true;
};

export type GraphCorrectionOperation = {
  operationId: string;
  entityType: GraphCorrectionEntityType;
  operation: GraphCorrectionOperationType;
  targetId?: string;
  stableKey: string;
  expectedLockVersion?: number;
  value: Record<string, unknown>;
};

export type GraphPromotionEligibility = {
  assessmentId: string;
  learningMode: GraphLearningMode;
  eligible: boolean;
  automaticPromotionAllowed: boolean;
  humanReviewRequired: boolean;
  checks: Array<{
    code: string;
    state: "passed" | "failed" | "unknown" | "unavailable";
    passed: boolean;
    actual: unknown;
    required: unknown;
    evidenceRefs: Array<Record<string, unknown>>;
  }>;
  reasonCodes: string[];
  proposalLockVersion?: number;
};

export type GraphCorrectionProposal = {
  proposalId: string;
  graphId: string;
  baseVersionId: string;
  baseVersionHash: string;
  candidateVersionId: string;
  candidateVersionHash: string;
  patch: { operations: GraphCorrectionOperation[] };
  patchHash: string;
  riskLevel: "low" | "medium" | "high";
  rationaleCode: string;
  status: "draft" | "validated" | "invalid" | "pending_review" | "promoted" | "rejected";
  validationReport: null | {
    summary: { valid: boolean; errorCount: number; warningCount: number };
    issues: Array<{ code: string; severity: string; operationId?: string | null }>;
    reasonCodes: string[];
    reportHash: string;
  };
  eligibilityAssessment: GraphPromotionEligibility | null;
  evidenceRefs: Array<Record<string, unknown>>;
  approvalRefs: Array<Record<string, unknown>>;
  lockVersion: number;
  readOnly: boolean;
};

export type GraphCorrectionWorkspace = {
  schemaVersion: "phase8.graph-correction-workspace.v1";
  items: GraphCorrectionProposal[];
  candidateIntake: GraphCorrectionCandidate[];
  learningModeProjection: {
    graphLearningMode: GraphLearningMode;
    defaultMode: "human_supervised";
    binding: null | GraphLearningBindingProjection;
    policy: null | { policyVersionId: string; contentHash: string; policyDocument: Record<string, unknown> };
    fallbackReason: string;
    modeSemantics: Record<GraphLearningMode, string>;
  };
  readOnly: boolean;
  authorizationBoundary: "backend_service_api";
  frontendBoundary: "ux_only";
};

export type GraphLearningPolicyProjection = {
  policyId: string;
  policyVersionId: string;
  version: number;
  status: "draft" | "active";
  policyDocument: Record<string, unknown>;
  contentHash: string;
  lockVersion: number;
};

export type GraphLearningBindingProjection = {
  bindingId: string;
  projectId: string;
  environmentId: string | null;
  scopeType: "project" | "environment";
  scopeId: string;
  policyVersionId: string;
  policyVersionHash: string;
  graphLearningMode: GraphLearningMode;
  status: string;
  autonomyPaused: boolean;
  pauseReasonCode: string | null;
  lockVersion: number;
};

export type GraphAutonomyMutationResult = {
  status: "approval_pending" | "configured";
  productionApplied: boolean;
  approvalRequired: boolean;
  approval?: { id: string; status: string };
  binding: GraphLearningBindingProjection;
};

export type GraphStalenessStatus = "fresh" | "suspect" | "stale" | "invalid" | "unknown";
export type GraphStalenessAssessment = {
  schemaVersion?: "phase8.graph-staleness-assessment.v1";
  assessmentId: string | null;
  graphId: string;
  graphVersionId: string;
  status: GraphStalenessStatus;
  applicabilityRange: Record<string, unknown>;
  signals: Array<{
    signalId?: string;
    source?: string;
    type?: string;
    ref?: string;
    severity?: string;
    confidence?: number;
    oldFingerprint?: string | null;
    newFingerprint?: string | null;
    evidence?: Array<Record<string, unknown>>;
    evidenceCount?: number;
    changeRefRedacted?: boolean;
  }>;
  reasonCodes: string[];
  impact: {
    autoPromotionSuspended: boolean;
    alertRequired: boolean;
    reviewRequired: boolean;
    controlledRollbackAvailable?: boolean;
    historicalVersionRetained: boolean;
  };
  automaticPromotionEligible: boolean;
  assessmentHash: string | null;
  assessedAt: string | null;
  changeRefsRedacted?: boolean;
};
export type GraphStalenessReview = {
  reviewId: string;
  action: "confirm" | "override" | "deprecate";
  requestedStatus: GraphStalenessStatus | null;
  reasonCode: string;
  expiresAt: string | null;
  status: "pending" | "applied" | "rejected" | "expired";
  approvalId: string;
  lockVersion: number;
  automaticPromotionRestored: false;
};
export type GraphStalenessVersion = {
  graphId: string;
  graphVersionId: string;
  versionNumber: number;
  versionRef: string;
  contentHash: string;
  lifecycleStatus: string;
  scope: { type: "project" | "environment"; id: string; environmentId: string | null };
  assessment: GraphStalenessAssessment;
  effectiveUseStatus: GraphStalenessStatus;
  override: GraphStalenessReview | null;
  confirmation: GraphStalenessReview | null;
  deprecation: GraphStalenessReview | null;
  automaticPromotionEligible: boolean;
  historicalVersionRetained: true;
  replaySelection: "exact_version_only";
  changeRefsRedacted: boolean;
};
export type GraphStalenessWorkspace = {
  schemaVersion: "phase8.graph-staleness-workspace.v1";
  items: GraphStalenessVersion[];
  selectionRule: {
    scopePrecedence: string[];
    candidateOrder: string[];
    invalidExcluded: true;
    unknownIsFresh: false;
    staleRequiresExplicitPolicy: true;
    replayUsesExactFrozenVersion: true;
  };
  readOnly: boolean;
};

export async function fetchGraphStaleness(projectId: string) {
  return request<GraphStalenessWorkspace>(`/projects/${encodeURIComponent(projectId)}/canonical-graphs/staleness`);
}

export async function fetchGraphCorrections(projectId: string, graphId?: string) {
  return request<GraphCorrectionWorkspace>(withQuery(
    `/projects/${encodeURIComponent(projectId)}/graph-corrections`,
    { graphId },
  ));
}

export type AccessControlProjection = {
  schemaVersion: string;
  generatedAt: string;
  capability: {
    required: string;
    guard: string;
    riskLevel: string;
    approvalRequired: boolean;
    guardrailRequired: boolean;
    auditRequired: boolean;
  };
  users: Array<{
    id: string;
    name: string;
    username: string | null;
    email: string;
    displayName: string | null;
    roles: string[];
    edition: "basic" | "pro" | "enterprise";
    status: string;
    effectiveCapabilities: string[];
    createdAt: string;
    updatedAt: string;
  }>;
  capabilities: Array<{
    capabilityKey: string;
    category: string;
    description: string;
    riskLevel: string;
    isActive: boolean;
    reserved: boolean;
  }>;
  editionCapabilities: Array<{
    edition: string;
    capabilityKey: string;
    enabled: boolean;
    createdAt: string;
  }>;
  roleCapabilities: Array<{
    roleName: string;
    capabilityKey: string;
    effect: "allow" | "deny";
    createdAt: string;
    updatedAt: string;
  }>;
  userEntitlements: Array<{
    id: string;
    userId: string;
    capabilityKey: string;
    effect: "allow" | "deny";
    reason: string | null;
    expiresAt: string | null;
    createdAt: string;
  }>;
  workflows: Array<Record<string, unknown>>;
  approvalRefs: Array<Record<string, unknown>>;
  guardrailEventRefs: Array<Record<string, unknown>>;
  auditRefs: Array<Record<string, unknown>>;
  readOnly: boolean;
};

export type AccessControlUserAccessChangePayload = {
  edition?: "basic" | "pro" | "enterprise";
  roles?: string[];
  status?: "active" | "inactive" | "disabled";
  reason: string;
  idempotencyKey: string;
  metadata?: Record<string, unknown>;
};

export type AccessControlRoleCapabilityPayload = {
  roleName: string;
  capabilityKey: string;
  effect: "allow" | "deny";
  reason: string;
  idempotencyKey: string;
  metadata?: Record<string, unknown>;
};

export type AccessControlUserEntitlementPayload = {
  userId: string;
  capabilityKey: string;
  effect: "allow" | "deny";
  expiresAt?: string | null;
  reason: string;
  idempotencyKey: string;
  metadata?: Record<string, unknown>;
};

export type KnowledgePromotionRecord = {
  knowledgePromotionId: string;
  source: string;
  sourceCorrectionId: string;
  correctionValidationId: string;
  knowledgeEntry: Record<string, unknown>;
  evidenceRefs: Array<Record<string, unknown>>;
  replayRefs: Array<Record<string, unknown>>;
  approvalRefs: Array<Record<string, unknown>>;
  auditRefs: Array<Record<string, unknown>>;
  rollbackRef: Record<string, unknown>;
  supersedeRef: Record<string, unknown>;
  status: string;
  promotedAt: string | null;
  promotedBy: string | null;
  metadata: Record<string, unknown>;
};

export type KnowledgeSupersedePayload = {
  idempotencyKey: string;
  requestId: string;
  supersedeReason: string;
  supersedeRef: Record<string, unknown>;
  replacementKnowledgePromotionId?: string | null;
  evidenceRefs: Array<Record<string, unknown>>;
  traceRefs: string[];
  metadata?: Record<string, unknown>;
};

export async function fetchKnowledgePromotion(promotionId: string) {
  return request<KnowledgePromotionRecord>(`/corrections/knowledge-promotions/${encodeURIComponent(promotionId)}`);
}

export type CorrectionOperationAvailability = {
  action: string;
  capability: string;
  available: boolean;
  reason: string;
  approvalRequired: boolean;
  guardrailRequired: boolean;
  auditRequired: boolean;
  backendAuthoritative: boolean;
};

export type CorrectionGovernanceItem = {
  correctionProposalId: string;
  proposalType: string;
  proposedChange: Record<string, unknown>;
  status: string;
  overallStatus: string;
  riskLevel: string;
  requirementVersionId: string | null;
  executionId: string | null;
  findingId: string | null;
  attributionId: string | null;
  approvalRefs: Array<Record<string, unknown>>;
  evidenceRefs: Array<Record<string, unknown>>;
  traceRefs: string[];
  replayRefs: Array<Record<string, unknown>>;
  applications: Array<Record<string, unknown>>;
  validations: Array<Record<string, unknown>>;
  rollbackRecords: Array<Record<string, unknown>>;
  approvals: Array<Record<string, unknown>>;
  knowledgePromotions: Array<Record<string, unknown>>;
  promotionRefs: Array<Record<string, unknown>>;
  promotedAt: string | null;
  auditRefs: Array<Record<string, unknown>>;
  guardrailEventRefs: Array<Record<string, unknown>>;
  operationAvailability: Record<string, CorrectionOperationAvailability>;
  timeline: Array<{ kind: string; status: string; timestamp: string; details: Record<string, unknown> }>;
  metadata: Record<string, unknown>;
};

export type CorrectionGovernanceProjection = {
  schemaVersion: "phase8.correction-governance-projection.v1";
  generatedAt: string;
  filters: Record<string, unknown>;
  capability: Record<string, unknown>;
  operationPolicy: Record<string, Record<string, unknown>>;
  operationAvailability: Record<string, CorrectionOperationAvailability>;
  items: CorrectionGovernanceItem[];
  total: number;
  page: number;
  pageSize: number;
  readOnly: boolean;
  evidenceOnly: boolean;
  writesDecision: boolean;
};

export type CreateCorrectionProposalPayload = {
  proposalType:
    | "locator_update"
    | "assertion_update"
    | "test_case_update"
    | "test_step_update"
    | "requirement_mapping_update"
    | "execution_config_update"
    | "generate_patch_suggestion";
  proposedChange: Record<string, unknown>;
  requirementVersionId?: string | null;
  executionId?: string | null;
  findingId?: string | null;
  attributionId?: string | null;
  riskLevel: "low" | "medium" | "high";
  evidenceRefs: Array<Record<string, unknown>>;
  traceRefs?: string[];
  idempotencyKey?: string | null;
  metadata?: Record<string, unknown>;
};

export async function fetchCorrectionGovernanceProjection(filters: { executionId?: string | null; requirementVersionId?: string | null; status?: string | null; pageSize?: number } = {}) {
  return request<CorrectionGovernanceProjection>(
    withQuery("/corrections/projection", {
      executionId: filters.executionId,
      requirementVersionId: filters.requirementVersionId,
      status: filters.status,
      page_size: filters.pageSize ?? 50,
    }),
  );
}

export async function fetchHealth() {
  const data = await request<{ status: string; services: Record<string, string> | Array<{ name: string; status: string }> }>("/health");
  return {
    ...data,
    services: Array.isArray(data.services)
      ? data.services
      : Object.entries(data.services).map(([name, status]) => ({ name, status })),
  };
}

export type RuntimeReadinessStatus =
  | "local_passed"
  | "deployment_specific_not_validated"
  | "missing_dependency"
  | "not_configured"
  | "unavailable";

export type RuntimeReadinessItem = {
  id: string;
  label: string;
  status: RuntimeReadinessStatus;
  summary: string;
  details: Record<string, unknown>;
  evidenceRefs: string[];
  validationCommand: string | null;
  secretSafe: boolean;
};

export type RuntimeReadinessCategory = {
  id: string;
  title: string;
  status: RuntimeReadinessStatus;
  items: RuntimeReadinessItem[];
};

export type RuntimeReadiness = {
  schemaVersion: string;
  generatedAt: string;
  status: string;
  ready: boolean;
  dependencies: Record<string, string>;
  categories: RuntimeReadinessCategory[];
  summary: {
    localPassed: number;
    deploymentSpecificNotValidated: number;
    missingDependency: number;
    notConfigured: number;
    unavailable: number;
  };
  secretSafe: boolean;
  writeActions: boolean;
};

export async function fetchRuntimeReadiness() {
  return request<RuntimeReadiness>("/readiness");
}

export type ProjectItem = {
  id: string;
  key: string;
  name: string;
  description: string | null;
  status: string;
  metadata: Record<string, unknown>;
  planCount: number;
  executionCount: number;
  environmentCount: number;
  memberCount: number;
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
};

export type ProjectMutationPayload = {
  key: string;
  name: string;
  description?: string | null;
  status?: string;
  metadata?: Record<string, unknown>;
};

export type EnvironmentItem = {
  id: string;
  projectId: string;
  key: string;
  name: string;
  description: string | null;
  baseUrl: string | null;
  status: string;
  variables: Record<string, unknown>;
  metadata: Record<string, unknown>;
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
};

export type EnvironmentMutationPayload = {
  key: string;
  name: string;
  description?: string | null;
  baseUrl?: string | null;
  status?: string;
  variables?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
};

export type ProjectMemberItem = {
  id: string;
  projectId: string;
  userId: string | null;
  userName: string | null;
  userEmail: string | null;
  role: string;
  status: string;
  metadata: Record<string, unknown>;
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
};

export type ProjectMemberMutationPayload = {
  userId: string;
  role: string;
  status?: string;
  metadata?: Record<string, unknown>;
};

export type ConnectorBindingItem = {
  id: string;
  connectorName: string;
  secretConfigured: boolean;
  credentialConfigured: boolean;
  scope: Record<string, unknown>;
  projectId: string | null;
  environmentId: string | null;
  configurationHash: string;
  redactionPolicyVersion: string;
  status: string;
  createdAt: string;
  updatedAt: string;
};

export type ConnectorBindingMutationPayload = {
  connectorName: string;
  secretRef: string;
  credentialRef?: string | null;
  scope?: Record<string, unknown>;
  status?: string;
};

export type ConnectorBindingUpdatePayload = {
  secretRef?: string;
  credentialRef?: string | null;
  scope?: Record<string, unknown>;
  status?: string;
};

export async function fetchCommunityConnectorBindings(
  filters: { connectorName?: string; projectId?: string; environmentId?: string; status?: string } = {},
) {
  return request<{ items: ConnectorBindingItem[]; total: number }>(withQuery("/connector-bindings", {
    connectorName: filters.connectorName,
    projectId: filters.projectId,
    environmentId: filters.environmentId,
    status: filters.status,
    page_size: 100,
  }));
}

export async function createCommunityConnectorBinding(payload: ConnectorBindingMutationPayload) {
  return request<ConnectorBindingItem>("/connector-bindings", { method: "POST", body: payload });
}

export async function updateCommunityConnectorBinding(bindingId: string, payload: ConnectorBindingUpdatePayload) {
  return request<ConnectorBindingItem>(`/connector-bindings/${encodeURIComponent(bindingId)}`, { method: "PATCH", body: payload });
}

export async function archiveCommunityConnectorBinding(bindingId: string) {
  return request<ConnectorBindingItem>(`/connector-bindings/${encodeURIComponent(bindingId)}`, { method: "DELETE" });
}

export type ExternalIssueLink = {
  id: string;
  findingId: string;
  executionId: string;
  connectorBindingId: string | null;
  connectorName: string;
  externalIssueId: string | null;
  externalIssueKey: string | null;
  externalIssueUrl: string | null;
  externalStatus: string | null;
  syncStatus: string;
  idempotencyKey: string;
  lastSyncedAt: string | null;
  lastStatusSyncedAt: string | null;
  evidenceRefs: Array<Record<string, unknown>>;
  replayRefs: Array<Record<string, unknown>>;
  traceRefs: string[];
  auditRefs: Array<Record<string, unknown>>;
  connectorCallRefs: Array<Record<string, unknown>>;
  createdAt: string;
  updatedAt: string;
};

export type WorkItemStatus = "open" | "assigned" | "in_progress" | "completed" | "cancelled";
export type WorkItemPriority = "low" | "medium" | "high" | "urgent";

export type WorkItem = {
  id: string;
  projectId: string;
  requirementVersionId: string | null;
  requirementItemId: string | null;
  executionId: string | null;
  findingId: string | null;
  evidenceArtifactId: string | null;
  title: string;
  description: string | null;
  status: WorkItemStatus;
  priority: WorkItemPriority;
  assigneeId: string | null;
  assigneeName: string | null;
  claimedBy: string | null;
  claimedByName: string | null;
  completedAt: string | null;
  cancelledAt: string | null;
  evidenceRefs: Array<Record<string, unknown>>;
  traceId: string | null;
  metadata: Record<string, unknown>;
  createdBy: string | null;
  updatedBy: string | null;
  createdAt: string;
  updatedAt: string;
  linkedResources: {
    projectId: string;
    requirementVersionId: string | null;
    requirementItemId: string | null;
    executionId: string | null;
    findingId: string | null;
    evidenceArtifactId: string | null;
    evidenceRefCount: number;
  };
};

export type WorkItemCreatePayload = {
  projectId: string;
  title: string;
  description?: string | null;
  priority?: WorkItemPriority;
  assigneeId?: string | null;
  requirementVersionId?: string | null;
  requirementItemId?: string | null;
  executionId?: string | null;
  findingId?: string | null;
  evidenceArtifactId?: string | null;
  evidenceRefs?: Array<Record<string, unknown>>;
  metadata?: Record<string, unknown>;
};

export type WorkItemTransitionPayload = {
  status: WorkItemStatus;
  comment?: string | null;
};

export type IssueSyncPayload = {
  connectorBindingId: string;
  projectKey?: string | null;
  issueType?: string;
  forceUpdate?: boolean;
  labels?: string[];
  extraFields?: Record<string, unknown>;
};

export type ExploratoryEvidenceRefInput = {
  evidenceType: "screenshot" | "log" | "link" | "execution_artifact" | "console" | "network" | "har" | "other";
  ref: string;
  summary?: string | null;
  redactionStatus?: "not_required" | "redacted" | "pending" | null;
  metadata?: Record<string, unknown>;
};

export type ExploratorySessionPayload = {
  projectId: string;
  environmentId: string;
  charter: string;
  scope: Array<Record<string, unknown>>;
  timeboxMinutes: number;
  tester: string;
  metadata?: Record<string, unknown>;
};

export type ExploratoryNotePayload = {
  noteType: "note" | "observation" | "risk" | "question";
  content: string;
  evidenceRefs?: ExploratoryEvidenceRefInput[];
  metadata?: Record<string, unknown>;
};

export type ExploratoryBugCandidatePayload = {
  title: string;
  summary: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  confidence: number;
  location?: Record<string, unknown>;
  evidenceRefIds?: string[];
  evidenceRefs?: ExploratoryEvidenceRefInput[];
  metadata?: Record<string, unknown>;
};

export type ExploratoryEndPayload = {
  debrief: string;
  outcomeSummary?: string | null;
  risks?: string[];
  questions?: string[];
  followUps?: string[];
  metadata?: Record<string, unknown>;
};

export type ExploratoryEvidenceRef = {
  id: string;
  sessionId: string;
  noteId: string | null;
  candidateId: string | null;
  artifactId: string | null;
  evidenceType: string;
  ref: string;
  summary: string | null;
  redactionStatus: string;
  traceId: string | null;
  metadata: Record<string, unknown>;
  createdBy: string | null;
  createdAt: string;
};

export type ExploratoryNote = {
  id: string;
  sessionId: string;
  noteType: string;
  content: string;
  evidenceRefs: ExploratoryEvidenceRef[];
  traceId: string | null;
  replayRefs: Array<Record<string, unknown>>;
  metadata: Record<string, unknown>;
  createdBy: string | null;
  createdAt: string;
};

export type ExploratoryBugCandidate = {
  id: string;
  sessionId: string;
  rawFindingId: string | null;
  normalizedFindingId: string | null;
  title: string;
  summary: string;
  severity: string;
  category: string;
  confidence: number;
  location: Record<string, unknown>;
  evidenceRefs: ExploratoryEvidenceRef[];
  traceId: string | null;
  replayRefs: Array<Record<string, unknown>>;
  status: string;
  metadata: Record<string, unknown>;
  finding: Record<string, unknown> | null;
  createdAt: string;
  updatedAt: string;
};

export type ExploratorySession = {
  id: string;
  projectId: string;
  projectName: string | null;
  environmentId: string;
  environmentName: string | null;
  backingPlanId: string;
  backingExecutionId: string;
  charter: string;
  scope: Array<Record<string, unknown>>;
  timeboxMinutes: number;
  testerId: string | null;
  tester: string;
  status: string;
  startedAt: string;
  endedAt: string | null;
  debrief: Record<string, unknown>;
  traceId: string | null;
  replayRefs: Array<Record<string, unknown>>;
  metadata: Record<string, unknown>;
  noteCount: number;
  evidenceCount: number;
  candidateCount: number;
  normalizedFindingCount: number;
  notes?: ExploratoryNote[];
  evidenceRefs?: ExploratoryEvidenceRef[];
  bugCandidates?: ExploratoryBugCandidate[];
  report?: ExploratoryReport | null;
  createdAt: string;
  updatedAt: string;
};

export type ExploratoryReport = {
  schemaVersion: string;
  sessionId: string;
  projectId: string;
  environmentId: string;
  backingExecutionId: string;
  charter: string;
  scope: Array<Record<string, unknown>>;
  timeboxMinutes: number;
  tester: string;
  status: string;
  debrief: Record<string, unknown>;
  counts: Record<string, number>;
  notes: ExploratoryNote[];
  evidenceRefs: ExploratoryEvidenceRef[];
  bugCandidates: ExploratoryBugCandidate[];
  findingRefs: Array<Record<string, unknown>>;
  traceRefs: string[];
  replayRefs: Array<Record<string, unknown>>;
  evidenceMode: string;
  uploadsSupported: boolean;
  generatedAt: string;
};

export async function fetchExploratorySessions(filters: { projectId?: string; environmentId?: string; status?: string; pageSize?: number } = {}) {
  return request<{ items: ExploratorySession[]; total: number; page: number; pageSize: number }>(
    withQuery("/exploratory-sessions", {
      projectId: filters.projectId,
      environmentId: filters.environmentId,
      status: filters.status,
      page_size: filters.pageSize ?? 20,
    }),
  );
}

export async function fetchExploratorySession(sessionId: string) {
  return request<ExploratorySession>(`/exploratory-sessions/${encodeURIComponent(sessionId)}`);
}

export async function createExploratorySession(payload: ExploratorySessionPayload) {
  return request<ExploratorySession>("/exploratory-sessions", { method: "POST", body: payload });
}

export async function addExploratoryNote(sessionId: string, payload: ExploratoryNotePayload) {
  return request<ExploratoryNote>(`/exploratory-sessions/${encodeURIComponent(sessionId)}/notes`, { method: "POST", body: payload });
}

export async function addExploratoryEvidenceRef(sessionId: string, payload: ExploratoryEvidenceRefInput) {
  return request<ExploratoryEvidenceRef>(`/exploratory-sessions/${encodeURIComponent(sessionId)}/evidence-refs`, { method: "POST", body: payload });
}

export async function createExploratoryBugCandidate(sessionId: string, payload: ExploratoryBugCandidatePayload) {
  return request<ExploratoryBugCandidate>(`/exploratory-sessions/${encodeURIComponent(sessionId)}/bug-candidates`, { method: "POST", body: payload });
}

export async function endExploratorySession(sessionId: string, payload: ExploratoryEndPayload) {
  return request<ExploratorySession>(`/exploratory-sessions/${encodeURIComponent(sessionId)}/end`, { method: "POST", body: payload });
}

export async function fetchExploratoryReport(sessionId: string) {
  return request<ExploratoryReport>(`/exploratory-sessions/${encodeURIComponent(sessionId)}/report`);
}

export async function fetchProjects(filters: { pageSize?: number; status?: string } = {}) {
  return request<{ items: ProjectItem[]; total: number }>(
    withQuery("/projects", { page_size: filters.pageSize ?? 100, status: filters.status }),
  );
}

export async function fetchWorkItems(filters: { projectId?: string; status?: WorkItemStatus; assigneeId?: string; pageSize?: number } = {}) {
  return request<{ items: WorkItem[]; total: number; page: number; pageSize: number }>(
    withQuery("/work-items", {
      projectId: filters.projectId,
      status: filters.status,
      assigneeId: filters.assigneeId,
      page_size: filters.pageSize ?? 100,
    }),
  );
}

export async function createWorkItem(payload: WorkItemCreatePayload) {
  return request<WorkItem>("/work-items", { method: "POST", body: payload });
}

export async function assignWorkItem(workItemId: string, assigneeId: string | null) {
  return request<WorkItem>(`/work-items/${encodeURIComponent(workItemId)}/assign`, {
    method: "POST",
    body: { assigneeId },
  });
}

export async function claimWorkItem(workItemId: string) {
  return request<WorkItem>(`/work-items/${encodeURIComponent(workItemId)}/claim`, { method: "POST" });
}

export async function transitionWorkItem(workItemId: string, payload: WorkItemTransitionPayload) {
  return request<WorkItem>(`/work-items/${encodeURIComponent(workItemId)}/transition`, { method: "POST", body: payload });
}

export async function fetchEnvironments(filters: { projectId?: string; pageSize?: number; status?: string } = {}) {
  return request<{ items: EnvironmentItem[]; total: number }>(
    withQuery("/environments", {
      projectId: filters.projectId,
      page_size: filters.pageSize ?? 100,
      status: filters.status,
    }),
  );
}

export async function fetchProjectMembers(projectId: string, filters: { pageSize?: number } = {}) {
  return request<{ items: ProjectMemberItem[]; total: number }>(
    withQuery(`/projects/${encodeURIComponent(projectId)}/members`, { page_size: filters.pageSize ?? 100 }),
  );
}

export type ModelItemProjection = {
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

export type ModelProvider = "openai" | "anthropic" | "ollama" | "vllm" | "openai_compatible" | "custom";
export type ModelRole = "PRIMARY" | "CHALLENGER" | "JUDGE" | "LOCAL_FALLBACK";

export type ModelMutationPayload = {
  name: string;
  projectId?: string | null;
  environmentId?: string | null;
  provider: ModelProvider;
  model: string;
  baseUrl: string | null;
  apiKeyRef: string | null;
  roles: ModelRole[];
  priority: number;
  enabled: boolean;
  capabilities: {
    tools: boolean;
    vision: boolean;
    json: boolean;
    longContext: boolean;
    streaming: boolean;
    local: boolean;
  };
  config: {
    timeoutMs: number;
    maxRetries: number;
    temperature: number;
  };
};

export async function fetchCommunityModels(filters: { projectId?: string; environmentId?: string } = {}) {
  return request<{ items: ModelItemProjection[]; total: number }>(withQuery("/models", {
    projectId: filters.projectId,
    environmentId: filters.environmentId,
    page_size: 100,
  }));
}

export async function createCommunityModel(payload: ModelMutationPayload) {
  return request<{ id: string }>("/models", { method: "POST", body: payload });
}

export async function updateCommunityModel(modelId: string, payload: Partial<ModelMutationPayload>) {
  return request<ModelItemProjection>(`/models/${encodeURIComponent(modelId)}`, { method: "PUT", body: payload });
}

export async function deleteCommunityModel(modelId: string) {
  return request<{ id: string }>(`/models/${encodeURIComponent(modelId)}`, { method: "DELETE" });
}

export async function runCommunityModelHealthCheck(modelId: string) {
  return request<{ modelId: string; status: string; latencyMs: number; details: Record<string, unknown> }>(
    `/models/${encodeURIComponent(modelId)}/health-check`,
    { method: "POST" },
  );
}

export async function runCommunityModelCapabilityScan(modelId: string) {
  return request<{ modelId: string; scanId: string; capabilities: Record<string, unknown> }>(
    `/models/${encodeURIComponent(modelId)}/capability-scan`,
    { method: "POST" },
  );
}

export type ModelGovernanceActionResponse = {
  approvalRequired: boolean;
  approvalMode: string;
  approvalId: string;
  status: string;
  workflow: string;
  action: "create" | "update" | "delete";
  modelId: string | null;
  guardrailEventRefs: Array<Record<string, unknown>>;
  auditRefs: Array<Record<string, unknown>>;
};

export type RoutingPolicyPayload = {
  name: string;
  taskType: string;
  riskLevel: "low" | "medium" | "high";
  requiresTools: boolean;
  requiresVision: boolean;
  requiresJson: boolean;
  dataSensitivity: string;
  preferLocal: boolean;
  challengerRequired: boolean;
  fallbackRequired: boolean;
  humanApprovalRequired: boolean;
  enabled: boolean;
  metadata: Record<string, unknown>;
};

export type RoutingPolicyItem = RoutingPolicyPayload & {
  id: string;
  createdAt: string;
  updatedAt: string;
};

export type RoutingPolicyGovernanceActionResponse = {
  approvalRequired: boolean;
  approvalMode: string;
  approvalId: string;
  status: string;
  workflow: string;
  action: "create" | "update" | "delete";
  policyId: string | null;
  guardrailEventRefs: Array<Record<string, unknown>>;
  auditRefs: Array<Record<string, unknown>>;
};

export type PlanPayload = {
  name: string;
  sourceType: string;
  sourceRef?: string | null;
  environment: string;
  projectId?: string | null;
  environmentId?: string | null;
  domains: string[];
  domainConfig?: Record<string, Record<string, unknown>>;
  riskLevel: string;
  requirementVersionId?: string | null;
  requirementScope?: RequirementScope | null;
  input?: Record<string, unknown>;
};

export type PlanUpdatePayload = Partial<Omit<PlanPayload, "sourceType" | "sourceRef">> & {
  status?: string;
};

export type PlanRecord = {
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
  requirementScope: RequirementScope | null;
  input: Record<string, unknown>;
  generatedPlan: Record<string, unknown>;
};

export type RequirementScope = {
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

export type RequirementPipelinePayload = {
  name: string;
  sourceRef: string;
  document: string;
  requirements: string[];
  acceptanceCriteria: string[];
  environment: string;
  projectId?: string | null;
  environmentId?: string | null;
  domains: string[];
  riskLevel: string;
  metadata?: Record<string, unknown>;
};

export type RequirementLibraryPipelinePayload = {
  selectionMode: "requirement_version" | "requirement_items" | "requirement_scope";
  requirementVersionId?: string | null;
  requirementVersionIds?: string[];
  requirementItemIds?: string[];
  requirementItemRefs?: Array<{ requirementVersionId: string; requirementItemIds: string[] }>;
  requirementScope?: RequirementScope | null;
  metadata?: Record<string, unknown>;
};

export type RequirementPipelineState = {
  orchestrationId: string;
  requirementVersionId: string | null;
  requirementScope: RequirementScope | null;
  planId: string | null;
  executionId: string | null;
  status: string;
  currentStep: string | null;
  blocked: boolean;
  result: Record<string, unknown>;
  errorMessage: string | null;
};

export type RequirementIntakeSourceType = "paste" | "upload" | "ocr_upload" | "external_link" | "connector";

export type RequirementIntakeDraftPayload = {
  sourceType: "paste" | "external_link" | "connector";
  name: string;
  rawContent?: string;
  sourceUri?: string | null;
  connectorBindingId?: string | null;
  externalDocumentId?: string | null;
  sourceRef?: string | null;
  environment: string;
  projectId?: string | null;
  environmentId?: string | null;
  domains: string[];
  riskLevel: string;
  metadata?: Record<string, unknown>;
};

export type RequirementIntakeUploadPayload = {
  file: File;
  name: string;
  sourceRef?: string | null;
  environment: string;
  projectId?: string | null;
  environmentId?: string | null;
  domains: string[];
  riskLevel: string;
  metadata?: Record<string, unknown>;
};

export type RequirementIntakeOcrProjection = {
  status: "ready" | "review_required" | "blocked";
  confidence: number;
  reviewRequired: boolean;
  blocked: boolean;
  reviewReasons: string[];
  adapter: string;
  pageCount: number;
  lineCount: number;
  readyConfidenceThreshold: number;
  blockConfidenceThreshold: number;
  traceRefs: string[];
  pages: Array<Record<string, unknown>>;
};

export type RequirementIntakeDraft = {
  draftId: string;
  sourceType: RequirementIntakeSourceType;
  sourceRef: string;
  sourceUri: string | null;
  name: string;
  rawContent: string;
  normalizedDocument: string;
  storageRef: string | null;
  contentHash: string | null;
  mimeType: string | null;
  byteSize: number | null;
  artifactRefs: Array<Record<string, unknown>>;
  evidenceRefs: Array<Record<string, unknown>>;
  redactionStatus: string;
  environment: string;
  projectId: string | null;
  environmentId: string | null;
  domains: string[];
  riskLevel: string;
  status: string;
  traceId: string | null;
  skillInvocationId: string | null;
  connectorBindingSnapshot: Record<string, unknown>;
  connectorCallRefs: Array<Record<string, unknown>>;
  ocr: RequirementIntakeOcrProjection | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
};

export type RequirementIntakeRequirementItem = {
  itemId: string;
  ordinal: number;
  requirement: string;
  acceptanceCriteria: string[];
  sourceRef: string;
  sourceUri: string | null;
  evidenceRefs: Array<Record<string, unknown>>;
  artifactRefs: Array<Record<string, unknown>>;
  selectedByDefault: boolean;
  metadata: Record<string, unknown>;
};

export type RequirementIntakePreview = {
  previewId: string;
  draftId: string;
  sourceType: RequirementIntakeSourceType;
  sourceRef: string;
  sourceUri: string | null;
  document: string;
  storageRef: string | null;
  contentHash: string | null;
  mimeType: string | null;
  byteSize: number | null;
  artifactRefs: Array<Record<string, unknown>>;
  evidenceRefs: Array<Record<string, unknown>>;
  redactionStatus: string;
  requirements: string[];
  acceptanceCriteria: string[];
  requirementItems: RequirementIntakeRequirementItem[];
  pipelinePayload: RequirementPipelinePayload;
  warnings: string[];
  status: string;
  linkedRequirementVersionId: string | null;
  linkedPipelineId: string | null;
  confirmedAt: string | null;
  traceId: string | null;
  skillInvocationId: string | null;
  connectorBindingSnapshot: Record<string, unknown>;
  connectorCallRefs: Array<Record<string, unknown>>;
  ocr: RequirementIntakeOcrProjection | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
};

export type RequirementIntakeConfirmResult = {
  draft: RequirementIntakeDraft;
  preview: RequirementIntakePreview;
  pipeline: RequirementPipelineState;
};

export type RequirementIntakeConfirmPayload = {
  selectedRequirementItems?: string[];
  metadata?: Record<string, unknown>;
};

export type RequirementIntakeUploadResult = {
  draft: RequirementIntakeDraft;
  preview: RequirementIntakePreview;
};

export type RequirementIntakeBatchSourcePayload = {
  sourceType: "paste" | "external_link" | "connector";
  sourceKey?: string | null;
  name?: string | null;
  rawContent?: string | null;
  sourceUri?: string | null;
  connectorBindingId?: string | null;
  externalDocumentId?: string | null;
  sourceRef?: string | null;
  metadata?: Record<string, unknown>;
};

export type RequirementIntakeBatchPayload = {
  name: string;
  idempotencyKey?: string | null;
  environment: string;
  projectId?: string | null;
  environmentId?: string | null;
  domains: string[];
  riskLevel: string;
  metadata?: Record<string, unknown>;
  sources: RequirementIntakeBatchSourcePayload[];
};

export type RequirementIntakeBatchUploadPayload = {
  files: File[];
  name: string;
  sourceRef?: string | null;
  environment: string;
  projectId?: string | null;
  environmentId?: string | null;
  domains: string[];
  riskLevel: string;
  metadata?: Record<string, unknown>;
  idempotencyKey?: string | null;
};

export type RequirementIntakeBatchConfirmPayload = {
  sourceIds?: string[];
  selectedRequirementItemsBySource?: Record<string, string[]>;
  metadata?: Record<string, unknown>;
};

export type RequirementIntakeBatchSourceRetryPayload = {
  source?: RequirementIntakeBatchSourcePayload;
  metadata?: Record<string, unknown>;
};

export type RequirementIntakeBatchSource = {
  batchSourceId: string;
  batchId: string;
  ordinal: number;
  sourceType: RequirementIntakeSourceType;
  sourceKey: string;
  status: string;
  draftId: string | null;
  previewId: string | null;
  linkedRequirementVersionId: string | null;
  linkedPipelineId: string | null;
  errorMessage: string | null;
  artifactRefs: Array<Record<string, unknown>>;
  evidenceRefs: Array<Record<string, unknown>>;
  retryCount: number;
  draft: RequirementIntakeDraft | null;
  preview: RequirementIntakePreview | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
};

export type RequirementIntakeBatch = {
  batchId: string;
  name: string;
  idempotencyKey: string | null;
  status: string;
  environment: string;
  projectId: string | null;
  environmentId: string | null;
  domains: string[];
  riskLevel: string;
  summary: Record<string, unknown>;
  traceId: string | null;
  metadata: Record<string, unknown>;
  sources: RequirementIntakeBatchSource[];
  createdAt: string;
  updatedAt: string;
};

export type RequirementLibraryItemType =
  | "requirement_version"
  | "requirement_intake_draft"
  | "requirement_intake_preview"
  | "requirement_item";

export type RequirementLibraryItem = {
  itemId: string;
  itemType: RequirementLibraryItemType;
  sourceType: string;
  status: string;
  title: string;
  summary: string | null;
  projectId: string | null;
  environmentId: string | null;
  environment: string | null;
  sourceRef: string | null;
  sourceUri: string | null;
  requirementVersionId: string | null;
  linkedRequirementVersionId: string | null;
  requirementItemId: string | null;
  requirementItemIndex: number | null;
  intakeDraftId: string | null;
  intakePreviewId: string | null;
  linkedPipelineId: string | null;
  contentHash: string | null;
  requirementCount: number;
  acceptanceCriteriaCount: number;
  artifactRefs: Array<Record<string, unknown>>;
  evidenceRefs: Array<Record<string, unknown>>;
  traceId: string | null;
  createdAt: string;
  updatedAt: string;
  metadata: Record<string, unknown>;
};

export type RequirementLibraryFilters = {
  projectId?: string | null;
  environmentId?: string | null;
  requirementVersionId?: string | null;
  sourceType?: string | null;
  status?: string | null;
  keyword?: string | null;
  page?: number;
  pageSize?: number;
};

export type RequirementLibraryProjection = {
  schemaVersion: "phase8.requirement-library.v1";
  generatedAt: string;
  filters: {
    projectId: string | null;
    environmentId: string | null;
    requirementVersionId: string | null;
    sourceType: string | null;
    status: string | null;
    keyword: string | null;
  };
  items: RequirementLibraryItem[];
  total: number;
  page: number;
  pageSize: number;
  summary: {
    requirementVersionCount: number;
    intakeDraftCount: number;
    intakePreviewCount: number;
    requirementItemCount: number;
    returnedCount: number;
  };
  capability: {
    required?: string;
    readOnly?: boolean;
    directMutation?: boolean;
  };
};

export type WorkflowRunAction = {
  actionId: string;
  label: string;
  targetRoute: string;
  targetResourceType: string;
  targetResourceId: string;
  mutation: boolean;
};

export type WorkflowRunStageSummary = {
  stageKey: "requirement" | "plan" | "approval" | "execution" | "exploratory" | "regression" | "gate" | "replay";
  label: string;
  status: string;
  statusReason: string | null;
  refs: Record<string, unknown>;
  checkpointRefs: Array<Record<string, unknown>>;
  governanceRefs?: Record<string, unknown>;
};

export type WorkflowRunProjection = {
  schemaVersion: "phase8.workflow-run-projection.v1";
  generatedAt: string;
  runId: string;
  source: string;
  triggerType: string;
  status: string;
  currentStep: string;
  currentState: string;
  blocked: boolean;
  blockedReason: string | null;
  currentBlocker: {
    category: string;
    blocked: boolean;
    reason: string | null;
    sourceStep: string;
    approvalId: string | null;
  };
  requestId: string | null;
  traceId: string | null;
  linkedResources: {
    requirement: Record<string, unknown> | null;
    plan: Record<string, unknown> | null;
    executionPlan: Record<string, unknown> | null;
    execution: Record<string, unknown> | null;
    exploratorySessions: Array<Record<string, unknown>>;
    regressionPlan: Record<string, unknown> | null;
    approval: Record<string, unknown> | null;
    gate: Record<string, unknown> | null;
    replay: Record<string, unknown> | null;
  };
  testDomains: Array<{ domain: string; status: string; refs: Record<string, unknown> }>;
  executionStrategies: Array<{ strategy: string; status: string; requiredCapability: string | null; refs: Record<string, unknown> }>;
  governanceStatus: {
    requiredCapabilities?: string[];
    currentUserCapabilityState?: Record<string, string>;
    activeSkillBindings?: Array<Record<string, unknown>>;
    skillInvocationRefs?: Array<Record<string, unknown>>;
    approvalState?: string;
    approvalRefs?: Array<Record<string, unknown>>;
    guardrailEventRefs?: Array<Record<string, unknown>>;
    auditRefs?: Array<Record<string, unknown>>;
    traceRefs?: string[];
    replayRefs?: Array<Record<string, unknown>>;
    gatePolicyEvidence?: Record<string, unknown> | null;
    [key: string]: unknown;
  };
  stageSummaries: WorkflowRunStageSummary[];
  nextActions: WorkflowRunAction[];
  checkpointCount: number;
  resultSummary: Record<string, unknown>;
  errorMessage: string | null;
  startedAt: string | null;
  endedAt: string | null;
  createdAt: string;
  updatedAt: string;
  checkpoints?: Array<Record<string, unknown>>;
};

export type RequirementClarification = {
  clarificationId: string;
  questionKey: string;
  question: string;
  priority: string;
  status: string;
  answer: string | null;
  createdAt: string;
  answeredAt: string | null;
  metadata: Record<string, unknown>;
};

export type ExecutionPayload = {
  planId: string;
  executionPlanId?: string | null;
  environment: string;
  triggeredBy?: string | null;
  options?: {
    runFunctional: boolean;
    runPerformance: boolean;
    runSecurity: boolean;
    enableTriage: boolean;
    enableHealing: boolean;
    parallelism: number;
  };
};

export async function fetchPlans() {
  return request<{ items: PlanRecord[]; total: number }>("/test-plans");
}

export async function createPlan(payload: PlanPayload) {
  return request<PlanRecord>("/test-plans", { method: "POST", body: payload });
}

export async function updatePlan(planId: string, payload: PlanUpdatePayload) {
  return request<PlanRecord>(`/test-plans/${encodeURIComponent(planId)}`, { method: "PUT", body: payload });
}

export async function deletePlan(planId: string) {
  return request<PlanRecord>(`/test-plans/${encodeURIComponent(planId)}`, { method: "DELETE" });
}

export async function triggerPlanGenerate(planId: string) {
  return request<{ jobId: string; planId: string; status: string }>(`/test-plans/${encodeURIComponent(planId)}/generate`, { method: "POST" });
}

export async function createRequirementPipeline(payload: RequirementPipelinePayload) {
  return request<RequirementPipelineState>("/requirements/pipelines", { method: "POST", body: payload });
}

export async function createRequirementLibraryPipeline(payload: RequirementLibraryPipelinePayload) {
  return request<RequirementPipelineState>("/requirements/library/pipelines", { method: "POST", body: payload });
}

export async function createRequirementIntakeDraft(payload: RequirementIntakeDraftPayload) {
  return request<RequirementIntakeDraft>("/requirement-intake/drafts", { method: "POST", body: payload });
}

export async function uploadRequirementIntakeSource(payload: RequirementIntakeUploadPayload) {
  const formData = new FormData();
  formData.append("file", payload.file);
  formData.append("name", payload.name);
  formData.append("environment", payload.environment);
  formData.append("domains", JSON.stringify(payload.domains));
  formData.append("riskLevel", payload.riskLevel);
  formData.append("metadata", JSON.stringify(payload.metadata ?? {}));
  if (payload.sourceRef) {
    formData.append("sourceRef", payload.sourceRef);
  }
  if (payload.projectId) {
    formData.append("projectId", payload.projectId);
  }
  if (payload.environmentId) {
    formData.append("environmentId", payload.environmentId);
  }
  return request<RequirementIntakeUploadResult>("/requirement-intake/uploads", { method: "POST", body: formData });
}

export async function uploadRequirementIntakeOcrSource(payload: RequirementIntakeUploadPayload) {
  const formData = new FormData();
  formData.append("file", payload.file);
  formData.append("name", payload.name);
  formData.append("environment", payload.environment);
  formData.append("domains", JSON.stringify(payload.domains));
  formData.append("riskLevel", payload.riskLevel);
  formData.append("metadata", JSON.stringify(payload.metadata ?? {}));
  if (payload.sourceRef) {
    formData.append("sourceRef", payload.sourceRef);
  }
  if (payload.projectId) {
    formData.append("projectId", payload.projectId);
  }
  if (payload.environmentId) {
    formData.append("environmentId", payload.environmentId);
  }
  return request<RequirementIntakeUploadResult>("/requirement-intake/ocr-uploads", { method: "POST", body: formData });
}

export async function fetchRequirementIntakeBatches(page = 1, pageSize = 20) {
  return request<{ items: RequirementIntakeBatch[]; page: number; pageSize: number; total: number }>(
    withQuery("/requirement-intake/batches", { page, page_size: pageSize }),
  );
}

export async function createRequirementIntakeBatch(payload: RequirementIntakeBatchPayload) {
  return request<RequirementIntakeBatch>("/requirement-intake/batches", { method: "POST", body: payload });
}

export async function uploadRequirementIntakeBatchSources(payload: RequirementIntakeBatchUploadPayload) {
  const formData = new FormData();
  payload.files.forEach((file) => formData.append("files", file));
  formData.append("name", payload.name);
  formData.append("environment", payload.environment);
  formData.append("domains", JSON.stringify(payload.domains));
  formData.append("riskLevel", payload.riskLevel);
  formData.append("metadata", JSON.stringify(payload.metadata ?? {}));
  if (payload.sourceRef) {
    formData.append("sourceRef", payload.sourceRef);
  }
  if (payload.projectId) {
    formData.append("projectId", payload.projectId);
  }
  if (payload.environmentId) {
    formData.append("environmentId", payload.environmentId);
  }
  if (payload.idempotencyKey) {
    formData.append("idempotencyKey", payload.idempotencyKey);
  }
  return request<RequirementIntakeBatch>("/requirement-intake/batches/uploads", { method: "POST", body: formData });
}

export async function fetchRequirementIntakeBatch(batchId: string) {
  return request<RequirementIntakeBatch>(`/requirement-intake/batches/${encodeURIComponent(batchId)}`);
}

export async function confirmRequirementIntakeBatch(batchId: string, payload?: RequirementIntakeBatchConfirmPayload) {
  return request<RequirementIntakeBatch>(`/requirement-intake/batches/${encodeURIComponent(batchId)}/confirm`, {
    method: "POST",
    body: payload,
  });
}

export async function retryRequirementIntakeBatchSource(
  batchId: string,
  sourceId: string,
  payload?: RequirementIntakeBatchSourceRetryPayload,
) {
  return request<RequirementIntakeBatch>(
    `/requirement-intake/batches/${encodeURIComponent(batchId)}/sources/${encodeURIComponent(sourceId)}/retry`,
    { method: "POST", body: payload },
  );
}

export async function fetchRequirementIntakeDraft(draftId: string) {
  return request<RequirementIntakeDraft>(`/requirement-intake/drafts/${encodeURIComponent(draftId)}`);
}

export async function createRequirementIntakePreview(draftId: string) {
  return request<RequirementIntakePreview>(`/requirement-intake/drafts/${encodeURIComponent(draftId)}/preview`, {
    method: "POST",
    body: {},
  });
}

export async function fetchRequirementIntakePreview(previewId: string) {
  return request<RequirementIntakePreview>(`/requirement-intake/previews/${encodeURIComponent(previewId)}`);
}

export async function confirmRequirementIntakePreview(previewId: string, payload?: RequirementIntakeConfirmPayload) {
  return request<RequirementIntakeConfirmResult>(`/requirement-intake/previews/${encodeURIComponent(previewId)}/confirm`, {
    method: "POST",
    body: payload,
  });
}

export async function fetchRequirementLibrary(filters: RequirementLibraryFilters = {}) {
  return request<RequirementLibraryProjection>(
    withQuery("/requirements/library", {
      projectId: filters.projectId,
      environmentId: filters.environmentId,
      requirementVersionId: filters.requirementVersionId,
      sourceType: filters.sourceType,
      status: filters.status,
      keyword: filters.keyword,
      page: filters.page,
      pageSize: filters.pageSize,
    }),
  );
}

export async function fetchRequirementPipeline(runId: string) {
  return request<RequirementPipelineState>(`/requirements/pipelines/${encodeURIComponent(runId)}`);
}

export async function fetchWorkflowRuns(filters: { source?: string; status?: string; pageSize?: number } = {}) {
  return request<{
    items: WorkflowRunProjection[];
    total: number;
    page: number;
    pageSize: number;
  }>(
    withQuery("/workflow-runs", {
      source: filters.source,
      status: filters.status,
      page_size: filters.pageSize ?? 20,
    }),
  );
}

export async function fetchWorkflowRun(runId: string) {
  return request<WorkflowRunProjection>(`/workflow-runs/${encodeURIComponent(runId)}`);
}

export async function fetchRequirementPipelineReplay(runId: string) {
  return request<Record<string, unknown>>(`/requirements/pipelines/${encodeURIComponent(runId)}/replay`);
}

export async function fetchRequirementClarifications(runId: string) {
  return request<{ items: RequirementClarification[] }>(`/requirements/pipelines/${encodeURIComponent(runId)}/clarifications`);
}

export async function answerRequirementClarification(runId: string, clarificationId: string, answer: string) {
  return request<RequirementPipelineState>(
    `/requirements/pipelines/${encodeURIComponent(runId)}/clarifications/${encodeURIComponent(clarificationId)}/answer`,
    { method: "POST", body: { answer } },
  );
}

export type MissingLink = {
  code: string;
  fromType: string;
  fromId: string;
  expectedTargetType: string;
  severity: string;
  blocksCoverage: boolean;
};

export type CoverageSummary = {
  schemaVersion: string;
  requirementVersionId: string;
  requirementVersionIds: string[];
  scope: RequirementScope & { activeInScopeRequirementItems: number };
  status: string;
  reason: string | null;
  requirementCoverage: number | null;
  testPointCoverage: number | null;
  testCaseCoverage: number | null;
  evidenceCoverage: number | null;
  findingTraceCoverage: number | null;
  gateImpactCoverage: number | null;
  missingLinks: MissingLink[];
  calculatedAt: string;
};

export type CoverageMatrixRow = {
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
  missingLinks: MissingLink[];
};

export type CoverageMatrix = {
  schemaVersion: string;
  requirementVersionId: string;
  requirementVersionIds: string[];
  summary: CoverageSummary;
  rows: CoverageMatrixRow[];
  missingLinks: MissingLink[];
  status: string;
  scope: CoverageSummary["scope"];
  calculatedAt: string;
  pagination: { page: number; pageSize: number; total: number };
  filters: Record<string, unknown>;
};

export type CoverageProofRelationRef = {
  table: string;
  id: string;
  status: string;
  source: string;
  scopeId: string;
  confidence: number;
};

export type CoverageProofEdge = {
  relationRef: CoverageProofRelationRef;
  sourceId: string;
  targetId: string;
  relationType: string;
  frozenStatus: string;
  currentStatus: string;
};

export type CoverageProofChain = {
  testPointId: string | null;
  testCaseId: string | null;
  executionTaskId: string | null;
  proofEdges: CoverageProofEdge[];
  evidenceArtifactRefs: Array<Record<string, unknown>>;
  rawFindingRefs: Array<Record<string, unknown>>;
  normalizedFindingRefs: Array<Record<string, unknown>>;
  gateDecisionRef: string | null;
  gateInputSnapshotRef: string | null;
  policySnapshotRef: string | null;
  approvalRefs: Array<Record<string, unknown>>;
  traceRefs: string[];
  auditRefs: Array<Record<string, unknown>>;
  traceabilitySnapshotRef: string;
  traceabilitySnapshotHash: string;
  coverageMatrixSnapshotRef: string;
  coverageMatrixSnapshotHash: string;
  replayExportRef: string | null;
  replayExportHash: string | null;
  proofIssues: string[];
};

export type CoverageProofBundle = {
  schemaVersion: string;
  generatedAt: string;
  requirementVersionId: string;
  primaryRequirementVersionId?: string | null;
  requirementVersionIds: string[];
  requirementItemId: string;
  requirementScope: RequirementScope | null;
  coverageStatus: string;
  proofStatus: string;
  proofChain: CoverageProofChain[];
  proofIssues: string[];
  traceId: string | null;
};

// P15 supplies backend-owned read projections for P16. The frontend may
// render these values, but it never derives Graph Coverage or proof validity.
export type GraphTraceabilityRef = {
  type: string;
  id: string;
  ref: string | null;
  label: string | null;
  status: string | null;
  contentHash: string | null;
  available: boolean;
  unavailableReason: string | null;
  redacted: boolean;
};

export type GraphCoverageMetric = {
  dimension: "requirement" | "canonical_path" | "node" | "risk" | "change_impact";
  total: number;
  applicable: number;
  covered: number;
  partial: number;
  uncovered: number;
  excluded: number;
  unknown: number;
  coverageRatio: number | null;
  partialCreditRatio: number | null;
  weightedCoverageRatio: number | null;
  status: "covered" | "partial" | "uncovered" | "not_applicable" | "unknown";
  denominatorExplanation: string;
  exclusionReasons: Array<Record<string, unknown>>;
  items: Array<Record<string, unknown>>;
};

export type GraphCoverageProjection = {
  schemaVersion: "phase8.graph-coverage-result.v1";
  computedAt: string;
  algorithmVersion: string;
  inputFingerprint: string;
  snapshotId: string;
  snapshotRef: string;
  snapshotHash: string;
  coverageProofRef: GraphTraceabilityRef;
  status: "covered" | "partial" | "uncovered" | "not_applicable" | "unknown";
  metrics: GraphCoverageMetric[];
  gaps: Array<Record<string, unknown>>;
  rawFindingRefs: Array<Record<string, unknown>>;
  findingCandidates: Array<Record<string, unknown>>;
  normalizedFindingRefs: [];
  traceabilityProjection: Record<string, unknown>;
  replayable: boolean;
  frontendAuthoritative: false;
  deduplicated: boolean;
};

export async function fetchGraphCoverage(
  projectId: string,
  graphId: string,
  graphVersionId: string,
  requirementVersionId: string,
  executionId?: string | null,
) {
  return request<GraphCoverageProjection>(
    withQuery(
      `/internal/projects/${encodeURIComponent(projectId)}/execution-graphs/${encodeURIComponent(graphId)}/versions/${encodeURIComponent(graphVersionId)}/coverage`,
      { requirementVersionId, executionId },
    ),
  );
}

export async function fetchGraphCoverageSnapshot(projectId: string, snapshotId: string) {
  return request<GraphCoverageProjection>(
    `/internal/projects/${encodeURIComponent(projectId)}/graph-coverage-snapshots/${encodeURIComponent(snapshotId)}`,
  );
}

export type CegStableRef = {
  type: string;
  id: string;
  ref: string | null;
  label: string | null;
  available: boolean;
  unavailableReason: string | null;
  redacted: boolean;
};

export type CegProjectionPage = {
  pageSize: number;
  returned: number;
  nextCursor: string | null;
  hasMore: boolean;
};

export type CegCapabilities = {
  read: boolean;
  candidateRead: boolean;
  coverageRead: boolean;
  stalenessRead: boolean;
  evidenceRead: boolean;
  rawRead: boolean;
  proposeCorrection: boolean;
  readOnly: true;
  backendAuthorization: true;
};

export type CegCoverageBadge = {
  status: "covered" | "partial" | "uncovered" | "not_applicable" | "unknown";
  ratio: number | null;
  covered: number;
  total: number;
  snapshotId: string | null;
  snapshotRef: string | null;
  computedAt: string | null;
  reasonCodes: string[];
};

export type CegStalenessBadge = {
  status: "fresh" | "suspect" | "stale" | "invalid" | "unknown";
  assessmentId: string | null;
  assessedAt: string | null;
  reasonCodes: string[];
  automaticPromotionEligible: boolean;
  autonomySuspended: boolean;
};

export type CegGraphSummaryItem = {
  graphId: string;
  graphRef: string;
  graphKey: string;
  name: string;
  description: string | null;
  projectId: string;
  environmentId: string | null;
  scopeType: "project" | "environment";
  scopeId: string;
  status: string;
  graphVersionId: string | null;
  graphVersionRef: string | null;
  versionNumber: number | null;
  versionStatus: string | null;
  versionSource: "observed" | "candidate" | "canonical" | null;
  contentHash: string | null;
  topology: { nodes: number; edges: number; paths: number; steps: number };
  staleness: CegStalenessBadge;
  coverage: CegCoverageBadge;
  learning: {
    graphLearningMode: "learn_only" | "human_supervised" | "controlled_autonomy";
    autonomyPaused: boolean;
    pauseReasonCode: string | null;
    bindingId: string | null;
    policyVersionId: string | null;
    fallbackReason: string;
  };
  updatedAt: string;
  sourceRefs: CegStableRef[];
};

export type CegGraphSummaryProjection = {
  schemaVersion: "phase8.ceg-graph-summary-projection.v1";
  generatedAt: string;
  projectId: string;
  availability: "available" | "partial" | "unavailable";
  unavailableReason: string | null;
  filters: Record<string, unknown>;
  capabilities: CegCapabilities;
  items: CegGraphSummaryItem[];
  page: CegProjectionPage;
  readOnly: true;
  frontendAuthoritative: false;
};

export type CegPromotionEligibility = {
  eligible: boolean | null;
  automaticPromotionAllowed: boolean;
  humanReviewRequired: boolean;
  reasonCodes: string[];
  assessmentId: string | null;
  promotionType: string | null;
  humanApproval: boolean | null;
  policyDecisionRefs: CegStableRef[];
  approvalRefs: CegStableRef[];
};

export type CegPathItem = {
  graphId: string;
  graphVersionId: string;
  pathId: string;
  pathRef: string;
  pathKey: string;
  name: string;
  description: string | null;
  identity: "observed" | "candidate" | "canonical";
  riskLevel: "low" | "medium" | "high";
  applicability: Record<string, unknown>;
  applicabilityStatus: "applicable" | "excluded" | "unknown";
  confidence: number;
  stepCount: number;
  capabilityRefs: CegStableRef[];
  coverage: CegCoverageBadge;
  promotion: CegPromotionEligibility;
  sourceRefs: CegStableRef[];
};

export type CegPathProjection = {
  schemaVersion: "phase8.ceg-path-projection.v1";
  generatedAt: string;
  projectId: string;
  graphId: string;
  graphVersionId: string;
  availability: "available" | "partial" | "unavailable";
  unavailableReason: string | null;
  filters: Record<string, unknown>;
  capabilities: CegCapabilities;
  items: CegPathItem[];
  page: CegProjectionPage;
  sourceRefs: CegStableRef[];
  readOnly: true;
  frontendAuthoritative: false;
};

export type CegNodeDetailProjection = {
  schemaVersion: "phase8.ceg-node-detail-projection.v1";
  generatedAt: string;
  projectId: string;
  graphId: string;
  graphVersionId: string;
  pathId: string;
  availability: "available" | "partial" | "unavailable";
  unavailableReason: string | null;
  path: CegPathItem;
  nodes: Array<{
    nodeId: string;
    nodeRef: string;
    semanticKey: string;
    nodeType: string;
    label: string;
    riskLevel: "low" | "medium" | "high";
    identity: "observed" | "candidate" | "canonical";
    confidence: number;
    attributes: Record<string, unknown>;
    sourceRefs: CegStableRef[];
  }>;
  edges: Array<{
    edgeId: string;
    edgeRef: string;
    edgeType: string;
    sourceNodeId: string;
    targetNodeId: string;
    condition: Record<string, unknown> | null;
    riskLevel: "low" | "medium" | "high";
    reviewStatus: string;
    identity: "observed" | "candidate" | "canonical";
    sourceRefs: CegStableRef[];
  }>;
  steps: Array<{
    stepId: string;
    stepRef: string;
    order: number;
    nodeId: string;
    viaEdgeId: string | null;
    conditions: Array<Record<string, unknown>>;
    outcome: string | null;
    retryCount: number;
    fallbackTypes: string[];
    verificationStatus: string | null;
    exceptionRefs: CegStableRef[];
    sourceRefs: CegStableRef[];
  }>;
  orphanNodeRefs: CegStableRef[];
  cycleDetected: boolean;
  truncated: boolean;
  limits: Record<string, number>;
  sourceRefs: CegStableRef[];
  readOnly: true;
  frontendAuthoritative: false;
};

export type CegEvidenceProjection = {
  schemaVersion: "phase8.ceg-evidence-projection.v1";
  generatedAt: string;
  projectId: string;
  graphId: string;
  graphVersionId: string;
  pathId: string | null;
  availability: "available" | "partial" | "unavailable";
  unavailableReason: string | null;
  capabilities: CegCapabilities;
  items: Array<{
    evidenceId: string;
    type: string;
    ref: string | null;
    title: string;
    summary: string | null;
    status: string;
    occurredAt: string | null;
    contentHash: string | null;
    sourceRefs: CegStableRef[];
    redacted: boolean;
    rawProjection: Record<string, unknown> | null;
    unavailableReason: string | null;
  }>;
  proposals: Array<Record<string, unknown>>;
  promotions: Array<Record<string, unknown>>;
  stalenessReviews: Array<Record<string, unknown>>;
  rollbackRefs: CegStableRef[];
  versionHistory: Array<{
    graphVersionId: string;
    versionRef: string;
    versionNumber: number;
    parentVersionId: string | null;
    status: string;
    identity: "observed" | "candidate" | "canonical";
    contentHash: string;
    promotionType: string | null;
    humanApproval: boolean | null;
    createdAt: string;
    sourceRefs: CegStableRef[];
  }>;
  traceability: Record<string, unknown> | null;
  page: CegProjectionPage;
  sourceRefs: CegStableRef[];
  redaction: Record<string, unknown>;
  readOnly: true;
  frontendAuthoritative: false;
};

export async function fetchCegGraphSummary(
  projectId: string,
  filters: { search?: string; status?: string; environmentId?: string; identity?: string; pageSize?: number; cursor?: string } = {},
) {
  return request<CegGraphSummaryProjection>(
    withQuery(`/projects/${encodeURIComponent(projectId)}/ceg/projection`, filters),
  );
}

export async function fetchCegPaths(
  projectId: string,
  graphId: string,
  versionId: string,
  filters: { search?: string; riskLevel?: string; identity?: string; coverageStatus?: string; pageSize?: number; cursor?: string } = {},
) {
  return request<CegPathProjection>(
    withQuery(
      `/projects/${encodeURIComponent(projectId)}/ceg/graphs/${encodeURIComponent(graphId)}/versions/${encodeURIComponent(versionId)}/paths`,
      filters,
    ),
  );
}

export async function fetchCegPathDetail(
  projectId: string,
  graphId: string,
  versionId: string,
  pathId: string,
) {
  return request<CegNodeDetailProjection>(
    `/projects/${encodeURIComponent(projectId)}/ceg/graphs/${encodeURIComponent(graphId)}/versions/${encodeURIComponent(versionId)}/paths/${encodeURIComponent(pathId)}`,
  );
}

export async function fetchCegEvidence(
  projectId: string,
  graphId: string,
  versionId: string,
  filters: { pathId?: string; evidenceType?: string; pageSize?: number; cursor?: string } = {},
) {
  return request<CegEvidenceProjection>(
    withQuery(
      `/projects/${encodeURIComponent(projectId)}/ceg/graphs/${encodeURIComponent(graphId)}/versions/${encodeURIComponent(versionId)}/evidence`,
      filters,
    ),
  );
}

export async function fetchCoverageSummary(requirementVersionId: string, filters: { selectedRequirementItemIds?: string[]; scopeId?: string | null } = {}) {
  return request<CoverageSummary>(
    withQuery("/coverage/summary", {
      requirementVersionId,
      scopeId: filters.scopeId,
      selectedRequirementItemIds: filters.selectedRequirementItemIds?.join(","),
    }),
  );
}

export async function fetchCoverageProof(
  requirementVersionId: string,
  requirementItemId: string,
  options: { replayExportHash?: string | null; selectedRequirementItemIds?: string[]; scopeId?: string | null } = {},
) {
  return request<CoverageProofBundle>(
    withQuery("/coverage/proof", {
      requirementVersionId,
      scopeId: options.scopeId,
      requirementItemId,
      replayExportHash: options.replayExportHash,
      selectedRequirementItemIds: options.selectedRequirementItemIds?.join(","),
    }),
  );
}

export async function fetchCoverageMatrix(
  requirementVersionId: string,
  filters: { page?: number; pageSize?: number; coverageStatus?: string; riskStatus?: string; missingLinkCode?: string; requirementItemId?: string; selectedRequirementItemIds?: string[]; scopeId?: string | null } = {},
) {
  return request<CoverageMatrix>(
    withQuery("/coverage/matrix", {
      requirementVersionId,
      scopeId: filters.scopeId,
      page: filters.page,
      pageSize: filters.pageSize,
      coverageStatus: filters.coverageStatus,
      riskStatus: filters.riskStatus,
      missingLinkCode: filters.missingLinkCode,
      requirementItemId: filters.requirementItemId,
      selectedRequirementItemIds: filters.selectedRequirementItemIds?.join(","),
    }),
  );
}

export type ExecutionRuntimeProjection = {
  schemaVersion: string;
  queueMode: string;
  executionStatus: string;
  executionStage: string;
  counts: {
    taskCount: number;
    completedTaskCount: number;
    failedTaskCount: number;
    artifactRefCount: number;
    rawMetricRefCount: number;
    rawFindingRefCount: number;
    normalizedFindingRefCount: number;
    gateDecisionCount: number;
  };
  refs: {
    artifactRefs: Array<Record<string, unknown>>;
    rawMetricRefs: Array<Record<string, unknown>>;
    rawFindingRefs: Array<Record<string, unknown>>;
    findingRefs: Array<Record<string, unknown>>;
    gateDecisionRef: string | null;
    latestJobRef: Record<string, unknown> | null;
  };
  refProjection: {
    limit: number | null;
    truncated: {
      artifactRefs: boolean;
      rawMetricRefs: boolean;
      rawFindingRefs: boolean;
      findingRefs: boolean;
    };
  };
  readiness: {
    rawEvidencePersisted: boolean;
    allTasksTerminal: boolean;
    normalizeCompleted: boolean;
    allRawFindingsNormalized: boolean;
    gateReady: boolean;
    gateCompleted: boolean;
    replayConsumable: boolean;
    replayExportConsumable: boolean;
  };
  consumerContract: Record<string, unknown>;
};

export async function fetchExecutions() {
  return request<{
    items: Array<{
      id: string;
      planId: string;
      status: string;
      stage: string;
      environment: string;
      summary: Record<string, string>;
      startedAt: string | null;
      endedAt: string | null;
      runtime: ExecutionRuntimeProjection | null;
    }>;
    total: number;
  }>("/executions");
}

export async function createExecution(payload: ExecutionPayload) {
  return request<{ id: string; jobId: string; status: string; stage: string }>("/executions", { method: "POST", body: payload });
}

export async function cancelExecution(executionId: string) {
  return request<{ id: string; status: string }>(`/executions/${encodeURIComponent(executionId)}/cancel`, { method: "POST" });
}

export async function retryExecution(executionId: string, scope = "failed_only") {
  return request<Record<string, unknown>>(`/executions/${encodeURIComponent(executionId)}/retry`, {
    method: "POST",
    body: { scope },
  });
}

export async function healExecution(executionId: string, mode = "suggest_only") {
  return request<Record<string, unknown>>(`/executions/${encodeURIComponent(executionId)}/heal`, {
    method: "POST",
    body: { mode },
  });
}

export async function gateExecution(executionId: string) {
  return request<{
    executionId: string;
    jobId?: string;
    status?: string;
    overall?: string;
    functional?: string;
    performance?: string;
    security?: string;
    reasons?: string[];
    reasonCodes?: string[];
    matchedRules?: string[];
    completeness?: Record<string, unknown>;
    confidence?: number;
    policyVersionId?: string | null;
    policyVersionHash?: string | null;
    policyBindingRef?: string | null;
    inputFingerprint?: string | null;
    decisionSnapshotHash?: string | null;
    evaluatorVersion?: string;
  }>(`/executions/${encodeURIComponent(executionId)}/gate`, {
    method: "POST",
  });
}

export async function fetchExecutionProgress(executionId: string) {
  return request<{
    executionId: string;
    status: string;
    stage: string;
    progress: number;
    currentTask: string | null;
    completedTasks: number;
    totalTasks: number;
  }>(`/executions/${encodeURIComponent(executionId)}/progress`);
}

export type ExecutionTaskRecord = {
  id: string;
  executionId: string;
  parentTaskId: string | null;
  domain: string;
  taskType: string;
  runner: string;
  status: string;
  stage: string | null;
  retryCount: number;
  errorMessage: string | null;
  resultPayload: Record<string, unknown>;
  startedAt: string | null;
  endedAt: string | null;
};

export type ExecutionTaskArtifact = {
  id: string;
  taskId: string | null;
  artifactType: string;
  uri: string;
  summary: string | null;
  redactionStatus: string;
  redactedUri: string | null;
  expiresAt: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
};

export type ExecutionTaskLog = {
  id: string;
  taskId: string | null;
  level: string;
  message: string;
  context: Record<string, unknown>;
  createdAt: string;
};

export type ExecutionTaskMetric = {
  id: string;
  taskId: string | null;
  metricName: string;
  metricValue: number;
  metricUnit: string | null;
  thresholdValue: number | null;
  baselineValue: number | null;
  metadata: Record<string, unknown>;
};

export async function fetchExecutionTasks(executionId: string) {
  return request<{ items: ExecutionTaskRecord[]; total: number }>(`/executions/${encodeURIComponent(executionId)}/tasks`);
}

export async function fetchExecutionTask(taskId: string) {
  return request<ExecutionTaskRecord>(`/tasks/${encodeURIComponent(taskId)}`);
}

export async function fetchExecutionTaskArtifacts(taskId: string) {
  return request<{ items: ExecutionTaskArtifact[]; total: number }>(`/tasks/${encodeURIComponent(taskId)}/artifacts`);
}

export async function fetchExecutionTaskLogs(taskId: string) {
  return request<{ items: ExecutionTaskLog[]; total: number }>(`/tasks/${encodeURIComponent(taskId)}/logs`);
}

export async function fetchExecutionTaskMetrics(taskId: string) {
  return request<{ items: ExecutionTaskMetric[]; total: number }>(`/tasks/${encodeURIComponent(taskId)}/metrics`);
}

export async function fetchExecutionFindings(
  executionId: string,
  page = 1,
  pageSize = 100,
) {
  return request<{
    items: Array<{
      id: string;
      executionId: string;
      taskId: string | null;
      domain: string;
      source: string;
      severity: string;
      status: string;
      category: string;
      title: string;
      summary: string;
      confidence: number | null;
      externalIssueLink: ExternalIssueLink | null;
    }>;
    total: number;
    page: number;
    pageSize: number;
  }>(
    `/executions/${encodeURIComponent(executionId)}/findings?page=${encodeURIComponent(String(page))}&page_size=${encodeURIComponent(String(pageSize))}`,
  );
}

export async function syncFindingExternalIssue(findingId: string, payload: IssueSyncPayload) {
  return request<ExternalIssueLink>(`/findings/${encodeURIComponent(findingId)}/external-issues/sync`, {
    method: "POST",
    body: {
      ...payload,
      issueType: payload.issueType ?? "Bug",
      labels: payload.labels ?? [],
      extraFields: payload.extraFields ?? {},
    },
  });
}

export async function refreshFindingExternalIssueStatus(findingId: string, payload: IssueSyncPayload) {
  return request<ExternalIssueLink>(`/findings/${encodeURIComponent(findingId)}/external-issues/refresh-status`, {
    method: "POST",
    body: {
      ...payload,
      issueType: payload.issueType ?? "Bug",
      labels: payload.labels ?? [],
      extraFields: payload.extraFields ?? {},
    },
  });
}

export async function fetchExecutionHealing(executionId: string) {
  return request<{
    executionId: string;
    suggestions: Array<{
      taskId: string | null;
      type: string;
      summary: string;
      patch: string | null;
    }>;
  }>(`/executions/${encodeURIComponent(executionId)}/healing`);
}

export async function fetchCiGate(executionId: string) {
  return request<{
    overall: string;
    functional: string;
    performance: string;
    security: string;
    reasons?: string[];
    reasonCodes?: string[];
    matchedRules?: string[];
    completeness?: Record<string, unknown>;
    confidence?: number;
    decisionSnapshotHash?: string | null;
    evaluatorVersion?: string;
  }>(`/integrations/ci/gate/${encodeURIComponent(executionId)}`);
}

export async function fetchAgentRuns() {
  return request<{
    items: Array<{
      id: string;
      executionId: string | null;
      taskId: string | null;
      agentName: string;
      status: string;
      modelId: string | null;
      createdAt: string;
    }>;
    total: number;
  }>("/agent-runs?page_size=24");
}

export async function fetchSkills() {
  return request<{
    items: Array<{
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
    }>;
    total: number;
  }>("/skills?page_size=50");
}

export type CommunityLocalSkillManifest = {
  fileName: string;
  valid: boolean;
  error?: string;
  skillId?: string;
  displayName?: string;
  version?: string;
  extensionPoints?: string[];
  manifestHash?: string;
};

export async function fetchCommunityLocalSkillManifests() {
  return request<{
    schemaVersion: string;
    configuredDirectory: string;
    codeUploadAllowed: false;
    remoteFetchAllowed: false;
    items: CommunityLocalSkillManifest[];
    total: number;
  }>("/community/skills/local-manifests");
}

export async function registerCommunityLocalSkillManifest(fileName: string) {
  return request<Record<string, unknown>>(
    `/community/skills/local-manifests/${encodeURIComponent(fileName)}/register`,
    { method: "POST" },
  );
}

export async function fetchSkillInvocations(filters: { executionId?: string; skillId?: string; pageSize?: number } = {}) {
  return request<{
    items: Array<{
      id: string;
      skillId: string;
      version: string;
      manifestHash: string;
      status: string;
      idempotencyKey: string | null;
      traceId: string | null;
      executionId: string | null;
      extensionPointId: string | null;
      bindingId: string | null;
      sourceWorkflow: string | null;
      resolutionSnapshot: Record<string, unknown>;
      inputSnapshot?: Record<string, unknown>;
      outputSnapshot?: Record<string, unknown>;
      policySnapshot?: Record<string, unknown>;
      connectorBindingSnapshot: Record<string, unknown>;
      approvalRefs: Array<Record<string, unknown>>;
      artifactRefs: Array<Record<string, unknown>>;
      toolCallRefs: Array<Record<string, unknown>>;
      connectorCallRefs: Array<Record<string, unknown>>;
      createdAt: string;
    }>;
    total: number;
  }>(
    withQuery("/skill-invocations", {
      page_size: filters.pageSize ?? 24,
      executionId: filters.executionId,
      skillId: filters.skillId,
    }),
  );
}

export async function fetchWorkflowCapabilityGraph() {
  return request<{
    nodes: Array<{
      lifecycleStage: string;
      extensionPointId: string;
      label: string;
      bindable: boolean;
      currentBindingSummary: Record<string, unknown> | null;
      requiredCapability: string | null;
      requiredEdition: string | null;
      unavailableReason: string | null;
    }>;
    scope: Record<string, unknown>;
  }>("/workflow-capability-graph");
}

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
  pendingChange: Record<string, unknown>;
  approvalRefs: Array<Record<string, unknown>>;
  guardrailEventRefs: Array<Record<string, unknown>>;
  auditRefs: Array<Record<string, unknown>>;
  approvalRequired: boolean;
  approvalEnvelope: Record<string, unknown> | null;
  createdAt: string;
  updatedAt: string;
};

export async function fetchCapabilityBindings(filters: { extensionPointId?: string; status?: string; pageSize?: number } = {}) {
  return request<{
    items: CapabilityBindingItem[];
    total: number;
  }>(
    withQuery("/capability-bindings", {
      page_size: filters.pageSize ?? 50,
      extensionPointId: filters.extensionPointId,
      status: filters.status,
    }),
  );
}

export async function changeCommunityBindingLifecycle(binding: CapabilityBindingItem, action: "enable" | "disable") {
  return request<CapabilityBindingMutationResult>(`/community/capability-bindings/${binding.id}/lifecycle`, {
    method: "POST",
    body: { action, expectedStateHash: binding.stateHash, idempotencyKey: crypto.randomUUID() },
  });
}

export async function createCommunityCapabilityBinding(payload: CapabilityBindingMutationPayload) {
  return request<CapabilityBindingMutationResult>("/capability-bindings", { method: "POST", body: payload });
}

export type RegressionPresentation = {
  recommendedRegressionSuite: Array<Record<string, unknown>>;
  metadata: {
    skillInvocationId?: string;
    resolvedSkillId?: string;
    communityView?: {
      groupBy: string;
      caseCount: number;
      groups: Array<{ label: string; count: number; caseIds?: string[] }>;
    };
  };
};

export async function createRegressionPresentation(executionId: string) {
  return request<RegressionPresentation>(`/executions/${executionId}/regression-plan`, { method: "POST" });
}

export type CapabilityBindingMutationPayload = {
  extensionPointId: string;
  skillId: string;
  version?: string | null;
  manifestHash?: string | null;
  scopeType: string;
  scopeId?: string | null;
  projectId?: string | null;
  environment?: string | null;
  stage?: string | null;
  domain?: string | null;
  status: string;
  priority: number;
  bindingConfig: Record<string, unknown>;
};

export type CapabilityBindingMutationResult = {
  id?: string;
  approvalRequired?: boolean;
  approvalEnvelope?: Record<string, unknown> | null;
  pendingChange?: Record<string, unknown>;
  approvalRefs?: Array<Record<string, unknown>>;
  guardrailEventRefs?: Array<Record<string, unknown>>;
  auditRefs?: Array<Record<string, unknown>>;
};

export async function searchMemories(query: string, filters: { type?: string; scope?: string; namespace?: string } = {}) {
  return request<{
    items: Array<{
      id: string;
      type: string;
      scope: string;
      namespace: string;
      content: string;
      metadata: Record<string, unknown>;
    }>;
    total: number;
  }>(
    withQuery("/memories/search", {
      q: query,
      type: filters.type,
      scope: filters.scope,
      namespace: filters.namespace,
      page_size: 24,
    }),
  );
}

export async function triggerMemorySummarize(scope: string, namespace: string) {
  return request<{ jobId: string; status: string }>("/memories/summarize", {
    method: "POST",
    body: { scope, namespace },
  });
}

export async function triggerMemoryCompress(scope: string, namespace: string) {
  return request<{ jobId: string; status: string }>("/memories/compress", {
    method: "POST",
    body: { scope, namespace },
  });
}

export async function fetchTraces() {
  return request<{
    items: Array<{
      id: string;
      executionId: string | null;
      rootSpanName: string | null;
      spanCount: number;
      modelInvocationCount: number;
      agentRunCount: number;
      skillInvocationCount: number;
      guardrailEventCount: number;
      createdAt: string;
    }>;
    total: number;
  }>("/traces");
}

export type DecisionTimelineLifecycleStage =
  | "PREPARE"
  | "EXECUTE"
  | "OBSERVE"
  | "ANALYZE"
  | "NORMALIZE"
  | "GATE";

export type DecisionTimelineUnavailableCode =
  | "PERMISSION_RESTRICTED"
  | "SOURCE_NOT_RECORDED_OR_RETAINED"
  | "SOURCE_PENDING"
  | "EXECUTION_NOT_REACHED"
  | "EXECUTION_IN_PROGRESS"
  | "LEGACY_SCOPE_UNAVAILABLE"
  | "LEGACY_STAGE_LINK_MISSING"
  | "REFERENCE_NOT_FOUND"
  | "REFERENCE_RETAINED_OR_PURGED"
  | "CROSS_SCOPE_REFERENCE_BLOCKED";

export type DecisionTimelineUnavailableReason = {
  code: DecisionTimelineUnavailableCode;
  sourceType: string;
  detailKey: string;
  lifecycleStage: DecisionTimelineLifecycleStage | null;
  referenceType: string | null;
  referenceId: string | null;
  retryable: boolean;
};

export type DecisionTimelineReference = {
  referenceType: string;
  referenceId: string;
  relationship: string;
  available: boolean;
  visibility: "full" | "redacted" | "restricted";
  unavailableReasonCode: string | null;
  href: string | null;
};

export type ExplanationMessage = {
  messageKey: string;
  parameters: Record<string, string | number | boolean | null>;
};

export type ExplanationPlainView = {
  schemaVersion: "phase8.execution-explanation-plain.v1";
  eventId: string;
  sourceRefs: DecisionTimelineReference[];
  available: true;
  requiredCapability: "replay.read";
  unavailableReasonCode: null;
  reasonCode: string;
  sourceMessageKey: string;
  whatHappened: ExplanationMessage;
  why: ExplanationMessage;
  impact: ExplanationMessage;
  nextAction: ExplanationMessage;
  evidenceCount: number;
  cegPathMeaning: ExplanationMessage | null;
};

export type ExplanationProfessionalView = {
  schemaVersion: "phase8.execution-explanation-professional.v1";
  eventId: string;
  sourceRefs: DecisionTimelineReference[];
  available: boolean;
  requiredCapability: "audit.logs.read";
  unavailableReasonCode: "PERMISSION_RESTRICTED" | null;
  reasonCode: string | null;
  reasonCodes: string[];
  ruleIds: string[];
  policy: { policyId: string | null; versionId: string | null; versionHash: string | null } | null;
  promotionType: string | null;
  graphLearningMode: string | null;
  policyDecisionRefs: DecisionTimelineReference[];
  approvalState: string | null;
  humanApproved: boolean;
  approvalRefs: DecisionTimelineReference[];
  findingRefs: DecisionTimelineReference[];
  metricRefs: DecisionTimelineReference[];
  evidenceRefs: DecisionTimelineReference[];
  integrityStatus: "complete" | "partial" | "unavailable" | null;
};

export type ExplanationRawView = {
  schemaVersion: "phase8.execution-explanation-raw.v1";
  eventId: string;
  sourceRefs: DecisionTimelineReference[];
  available: boolean;
  requiredCapability: "replay.export.read";
  unavailableReasonCode: "PERMISSION_RESTRICTED" | null;
  redactionStatus: "backend_redacted";
  labelKey: "executionExplanation.authorizedRedactedRaw";
  source: {
    sourceType: string;
    sourceTimestamp: string;
    projectedAt: string;
    integrityStatus: "complete" | "partial" | "unavailable";
    retentionStatus: "retained" | "partial" | "unavailable";
  } | null;
  projection: Record<string, unknown> | null;
  truncated: boolean;
};

export type ExplainViewProjection = {
  schemaVersion: "phase8.execution-explanation-views.v1";
  eventId: string;
  sourceRefs: DecisionTimelineReference[];
  availableViews: Array<"plain" | "professional" | "raw">;
  plain: ExplanationPlainView;
  professional: ExplanationProfessionalView;
  raw: ExplanationRawView;
};

export type DecisionTimelineEvent = {
  eventId: string;
  eventType: string;
  lifecycleStage: DecisionTimelineLifecycleStage;
  sequence: number;
  sourceSequence: number | null;
  sortKey: string;
  occurredAt: string;
  status: string;
  actorType: string;
  actorRef: DecisionTimelineReference | null;
  plainSummaryKey: string;
  professionalSummary: string | null;
  refs: DecisionTimelineReference[];
  explainView: ExplainViewProjection;
  traceId: string | null;
  executionId: string;
  skillInvocationId: string | null;
  toolCallId: string | null;
  connectorCallId: string | null;
  agentRunId: string | null;
  modelInvocationId: string | null;
  gateDecisionId: string | null;
  approvalId: string | null;
  replayId: string | null;
  visibility: "full" | "redacted" | "restricted";
  unavailableReason: DecisionTimelineUnavailableReason | null;
  cegEventKind: "observed" | "candidate" | "validation" | "promotion" | "suspension" | "rollback" | null;
  graphLearningMode: string | null;
  promotionType: string | null;
  policyDecisionRefs: DecisionTimelineReference[];
  approvalRefs: DecisionTimelineReference[];
};

export type DecisionTimelineProjection = {
  schemaVersion: "phase8.decision-timeline.v1";
  generatedAt: string;
  executionId: string;
  projectId: string | null;
  authoritative: true;
  readOnly: true;
  writesDecision: false;
  sortOrder: string[];
  appliedFilters: Record<string, unknown>;
  capabilityProjection: Record<string, boolean> & {
    explanationPlain: boolean;
    explanationProfessional: boolean;
    explanationRaw: boolean;
  };
  stageGroups: Array<{
    lifecycleStage: DecisionTimelineLifecycleStage;
    sequence: number;
    status: "pending" | "running" | "completed" | "failed" | "cancelled" | "unavailable";
    eventCount: number;
    pageEventCount: number;
    events: DecisionTimelineEvent[];
    unavailableReason: DecisionTimelineUnavailableReason | null;
  }>;
  unavailableReasons: DecisionTimelineUnavailableReason[];
  pagination: {
    pageSize: number;
    totalEvents: number;
    returnedEvents: number;
    hasMore: boolean;
    nextCursor: string | null;
    snapshotAt: string;
  };
};

export type DecisionTimelineQuery = {
  traceId?: string;
  lifecycleStages?: DecisionTimelineLifecycleStage[];
  eventTypes?: string[];
  statuses?: string[];
  actorTypes?: string[];
  occurredAfter?: string;
  occurredBefore?: string;
  cursor?: string;
  snapshotAt?: string;
  pageSize?: number;
};

export async function fetchExecutionDecisionTimeline(
  executionId: string,
  query: DecisionTimelineQuery = {},
) {
  return request<DecisionTimelineProjection>(
    withQuery(`/observability/executions/${encodeURIComponent(executionId)}/decision-timeline`, {
      traceId: query.traceId,
      lifecycleStage: query.lifecycleStages,
      eventType: query.eventTypes,
      eventStatus: query.statuses,
      actorType: query.actorTypes,
      occurredAfter: query.occurredAfter,
      occurredBefore: query.occurredBefore,
      cursor: query.cursor,
      snapshotAt: query.snapshotAt,
      page_size: query.pageSize,
    }),
  );
}

export type EvidenceSourceType =
  | "execution"
  | "finding"
  | "gate"
  | "policy"
  | "trace"
  | "replay"
  | "graph"
  | "artifact";

export type EvidenceIndexEntry = {
  schemaVersion: "phase8.evidence-index-entry.v1";
  entryId: string;
  tenantId: string;
  workspaceId: string;
  projectId: string;
  sourceType: EvidenceSourceType;
  sourceId: string;
  sourceVersion: string;
  contentHash: string;
  title: string;
  summary: string;
  facets: Record<string, unknown>;
  evidenceRefs: Array<Record<string, unknown>>;
  artifactRefs: Array<Record<string, unknown>>;
  classification: "public" | "internal" | "confidential" | "restricted";
  redactionVersion: string;
  indexedAt: string;
  sourceUpdatedAt: string | null;
  stale: boolean;
  retentionState: "active" | "archived" | "purge_eligible" | "purged" | "legal_hold";
  unavailableReasonCode: string | null;
};

export type EvidenceCitation = {
  citationId: string;
  entryId: string;
  sourceType: EvidenceSourceType;
  sourceId: string;
  sourceVersion: string;
  contentHash: string;
  title: string;
  snippet: string;
  evidenceRefs: Array<Record<string, unknown>>;
  artifactRefs: Array<Record<string, unknown>>;
  classification: EvidenceIndexEntry["classification"];
  available: boolean;
  unavailableReasonCode: string | null;
  href: string | null;
};

export type EvidenceQueryPayload = {
  projectId: string;
  question: string;
  queryMode?: "keyword" | "semantic" | "hybrid";
  filters?: {
    sourceTypes?: EvidenceSourceType[];
    classifications?: EvidenceIndexEntry["classification"][];
    executionIds?: string[];
    lifecycleStages?: Array<"PREPARE" | "EXECUTE" | "OBSERVE" | "ANALYZE" | "NORMALIZE" | "GATE">;
    includeStale?: boolean;
  };
  limit?: number;
  cursor?: string | null;
  includeAnswer?: boolean;
};

export type EvidenceQueryResult = {
  schemaVersion: "phase8.evidence-query-result.v1";
  queryHash: string;
  projectId: string;
  answer: string | null;
  citations: EvidenceCitation[];
  matchedEntries: Array<{
    entry: EvidenceIndexEntry;
    score: number;
    matchedTerms: string[];
  }>;
  confidence: number;
  limitations: string[];
  unavailableReasons: Array<Record<string, unknown>>;
  traceId: string;
  modelInvocationRef: Record<string, unknown> | null;
  guardrailEventRefs: Array<Record<string, unknown>>;
  nextCursor: string | null;
  snapshotAt: string;
  readOnly: true;
  writesCanonicalDecision: false;
};

export type EvidenceIndexStatus = {
  schemaVersion: "phase8.evidence-index-status.v1";
  projectId: string;
  sourceTypes: EvidenceSourceType[];
  entryCount: number;
  activeEntryCount: number;
  staleEntryCount: number;
  redactionVersion: string;
  latestJob: Record<string, unknown> | null;
  readOnly: true;
};

export type EvidenceRawProjection = {
  schemaVersion: "phase8.evidence-raw-projection.v1";
  entryId: string;
  sourceType: EvidenceSourceType;
  sourceId: string;
  sourceVersion: string;
  contentHash: string;
  redactionStatus: "backend_redacted";
  projection: Record<string, unknown>;
  traceId: string;
  readOnly: true;
};

export async function queryEvidence(payload: EvidenceQueryPayload) {
  return request<EvidenceQueryResult>("/evidence/query", {
    method: "POST",
    body: payload,
  });
}

export async function fetchEvidenceIndexStatus(projectId: string) {
  return request<EvidenceIndexStatus>(
    `/projects/${encodeURIComponent(projectId)}/evidence-index/status`,
  );
}

export async function fetchEvidenceIndexEntry(projectId: string, entryId: string) {
  return request<EvidenceIndexEntry>(
    `/projects/${encodeURIComponent(projectId)}/evidence-index/entries/${encodeURIComponent(entryId)}`,
  );
}

export async function fetchEvidenceRawProjection(projectId: string, entryId: string) {
  return request<EvidenceRawProjection>(
    `/projects/${encodeURIComponent(projectId)}/evidence-index/entries/${encodeURIComponent(entryId)}/raw`,
  );
}

export async function fetchExecutionReplay(
  executionId: string,
  options: { compact?: boolean } = {},
) {
  return request<{
    executionId: string;
    traceCount: number;
    timeline: Array<{ kind: string; label: string; status: string; timestamp: string; details?: Record<string, unknown> }>;
    findings: Array<{ id: string; severity: string; title: string; summary?: string; category?: string; externalIssueLink?: ExternalIssueLink | null }>;
    rawFindings: Array<Record<string, unknown>>;
    metrics: Array<Record<string, unknown>>;
    correctionRecords: Array<Record<string, unknown>>;
    correctionGovernance: Array<{
      correctionProposalId: string;
      proposalType: string;
      status: string;
      overallStatus: string;
      riskLevel: string;
      approvalRefs: Array<Record<string, unknown>>;
      evidenceRefs: Array<Record<string, unknown>>;
      traceRefs: string[];
      applications: Array<Record<string, unknown>>;
      validations: Array<Record<string, unknown>>;
      rollbackRecords: Array<Record<string, unknown>>;
      approvals: Array<Record<string, unknown>>;
      promotionRefs: Array<Record<string, unknown>>;
      promotedAt: string | null;
      timeline: Array<{ kind: string; status: string; timestamp: string; details: Record<string, unknown> }>;
      metadata: Record<string, unknown>;
    }>;
    skillInvocations: Array<{
      id: string;
      skillId: string;
      version: string;
      manifestHash: string;
      status: string;
      idempotencyKey: string | null;
      traceId: string | null;
      executionId: string | null;
      extensionPointId: string | null;
      bindingId: string | null;
      sourceWorkflow: string | null;
      resolutionSnapshot: Record<string, unknown>;
      inputSnapshot: Record<string, unknown>;
      outputSnapshot: Record<string, unknown>;
      policySnapshot: Record<string, unknown>;
      connectorBindingSnapshot: Record<string, unknown>;
      approvalRefs: Array<Record<string, unknown>>;
      artifactRefs: Array<Record<string, unknown>>;
      toolCallRefs: Array<Record<string, unknown>>;
      connectorCallRefs: Array<Record<string, unknown>>;
      createdAt: string;
    }>;
    visualGroundingAttempts: Array<{
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
    }>;
    verificationResults: Array<{
      id: string;
      verificationType: string;
      status: string;
      confidence: number | null;
      normalizedFindingId: string | null;
    }>;
    guardrailEvents: Array<{ id: string; ruleId: string; decision: string; reason: string; createdAt: string }>;
    gate: { overall: string; reasons: string[]; functional?: string; performance?: string; security?: string } | null;
    orchestrator?: { checkpointCount: number; status: string } | null;
  }>(withQuery(`/executions/${encodeURIComponent(executionId)}/replay`, {
    compact: options.compact ? "true" : undefined,
  }));
}

export type GraphCoverageReplaySnapshot = {
    snapshotId: string;
    snapshotRef: string;
    snapshotHash: string;
    inputFingerprint: string;
    algorithmVersion: string;
    graphVersionId: string;
    coverageProofRef: GraphTraceabilityRef;
    requirementVersionId: string;
    status: GraphCoverageProjection["status"];
    metrics: GraphCoverageMetric[];
    gaps: Array<Record<string, unknown>>;
    rawFindingRefs: Array<Record<string, unknown>>;
    normalizedFindingRefs: Array<Record<string, unknown>>;
    traceabilityProjection: Record<string, unknown>;
};

export type ReplayExport = {
    exportId?: string;
    schemaVersion: string;
    exportedAt: string;
    requestId: string;
    executionId: string;
    traceRefs: string[];
    storageRef: string | null;
    exportArtifactRef: string | null;
    exportHash: string;
    exportPayloadHash: string;
    redactionStatus: string;
    auditRefs: Array<Record<string, unknown>>;
    traceabilitySnapshotRef: string | null;
    traceabilitySnapshotHash: string | null;
    coverageSummarySnapshot: Record<string, unknown> | null;
    coverageMatrixSnapshotRef: string | null;
    graphCoverageSnapshot: GraphCoverageReplaySnapshot | null;
    replay: Record<string, unknown>;
    auditLogs: Array<Record<string, unknown>>;
    persistedAt?: string;
    createdBy?: string | null;
};

export async function fetchExecutionReplayExport(executionId: string) {
  return request<ReplayExport>(`/executions/${encodeURIComponent(executionId)}/replay/export`);
}

export type ReplayExportRecord = Omit<ReplayExport, "replay" | "auditLogs"> & {
  exportId: string;
  persistedAt: string;
  createdBy: string | null;
};

export async function fetchReplayExports(filters: { executionId?: string; pageSize?: number } = {}) {
  return request<{
    items: ReplayExportRecord[];
    total: number;
    page: number;
    pageSize: number;
  }>(
    withQuery("/replay-exports", {
      executionId: filters.executionId,
      page_size: filters.pageSize ?? 12,
    }),
  );
}

export type ReplayRepositorySection = {
  sectionName: string;
  storageRef: string;
  contentHash: string;
  byteSize: number;
  compression: string;
  redactionStatus: string;
};

export type ReplayRepositoryEntry = {
  schemaVersion: string;
  replayId: string;
  executionId: string;
  frozenAt: string;
  sourceReplayExportHash: string;
  manifestHash: string;
  payloadHash: string;
  storageAdapter: string;
  redactionStatus: string;
  validityStatus: string;
  approvalMode: "always" | "policy_only" | "threshold";
  approvalState: string;
  retentionState: Record<string, unknown>;
  summaryProjection: Record<string, unknown>;
  sectionIndex: ReplayRepositorySection[];
  auditRefs: Array<Record<string, unknown>>;
  approvalRefs: Array<Record<string, unknown>>;
  guardrailEventRefs: Array<Record<string, unknown>>;
  manifest?: Record<string, unknown>;
};

export type ReplayRepositoryFreezeResult = {
  approvalRequired: boolean;
  approvalMode: "always" | "policy_only" | "threshold";
  approvalId?: string;
  status: string;
  sourceReplayExportHash?: string;
  replay?: ReplayRepositoryEntry;
};

export type ReplayRepositoryRetentionPolicy = {
  retentionPolicy: string;
  defaultRetentionDays: number;
  legalHoldSupported: boolean;
  dryRunRequiredBeforeDestructiveAction: boolean;
  approvalMode: "always" | "policy_only" | "threshold";
  thresholdLevel?: "low" | "medium" | "high";
  policyRules?: Record<string, unknown>;
  systemHardRules?: Record<string, unknown>;
  historicalMigration?: Record<string, unknown>;
  adminExecution?: Record<string, unknown>;
  supportedModes: Array<"always" | "policy_only" | "threshold">;
};

export type ReplayGovernancePolicy = {
  scopeType: string;
  scopeId: string;
  approvalMode: "always" | "policy_only" | "threshold";
  thresholdLevel: "low" | "medium" | "high";
  policyRules: Record<string, unknown>;
  systemHardRules: Record<string, unknown>;
  historicalMigration: Record<string, unknown>;
  adminExecution: Record<string, unknown>;
  updatedAt: string | null;
  auditRefs?: Array<Record<string, unknown>>;
  approvalRefs?: Array<Record<string, unknown>>;
};

export type ReplayRepositoryVisualizationProjection = {
  schemaVersion: string;
  generatedAt: string;
  totalReplays: number;
  validityCounts: Record<string, number>;
  retentionCounts: Record<string, number>;
  storageAdapterCounts: Record<string, number>;
  approvalModeCounts: Record<string, number>;
  approvalStateCounts: Record<string, number>;
  sectionCountTotal: number;
  recentReplays: Array<Record<string, unknown>>;
  evidenceOnly: boolean;
  writesDecision: boolean;
  canonicalDecisionSources: Record<string, string>;
};

export type ObservabilityMetric = {
  name: string;
  status: string;
  value: number | null;
  metadata: Record<string, unknown>;
};

export type StructuredLogItem = {
  id: string;
  source: string;
  timestamp: string;
  level: string;
  component: string;
  service: string;
  traceId: string | null;
  spanId: string | null;
  executionId: string | null;
  taskId: string | null;
  requestId: string | null;
  resourceType?: string | null;
  resourceId?: string | null;
  message: string;
  metadata: Record<string, unknown>;
  retentionState?: Record<string, unknown>;
};

export type StructuredLogProjection = {
  schemaVersion: "phase8.structured-log-projection.v1";
  generatedAt: string;
  scope: {
    executionId: string | null;
    traceId: string | null;
    resourceType: string | null;
    resourceId: string | null;
  };
  filters: {
    level: string | null;
    component: string | null;
    resourceType: string | null;
    resourceId: string | null;
    page: number;
    pageSize: number;
  };
  supportedFilters: string[];
  summary: {
    total: number;
    executionLogCount: number;
    auditLogCount: number;
    traceRefCount: number;
    executionRefCount: number;
    resourceScopedCount: number;
    errorCount: number;
    warnCount: number;
  };
  sourceCounts: Record<string, number>;
  levelCounts: Record<string, number>;
  componentCounts: Record<string, number>;
  serviceCounts: Record<string, number>;
  resourceTypeCounts: Record<string, number>;
  traceRefs: string[];
  executionRefs: string[];
  retentionProjection: {
    policy: string;
    retentionDays: number;
    readOnly: boolean;
    destructiveActionsExposed: boolean;
    manageCapability: string;
  };
  items: StructuredLogItem[];
  total: number;
  page: number;
  pageSize: number;
  evidenceOnly: boolean;
  writesDecision: boolean;
  capability: {
    required: string;
    frontendBoundary: string;
    authorizationBoundary: string;
  };
};

export type AuditLogProjection = {
  schemaVersion: "phase8.audit-log-projection.v1";
  generatedAt: string;
  scope: {
    executionId: string | null;
    traceId: string | null;
    resourceType: string | null;
    resourceId: string | null;
  };
  filters: {
    level: string | null;
    component: string | null;
    page: number;
    pageSize: number;
  };
  supportedFilters: string[];
  summary: {
    total: number;
    executionLogCount: number;
    auditLogCount: number;
    traceRefCount: number;
    executionRefCount: number;
    resourceScopedCount: number;
  };
  sourceCounts: Record<string, number>;
  levelCounts: Record<string, number>;
  resourceTypeCounts: Record<string, number>;
  retentionProjection: {
    policy: string;
    retentionDays: number;
    readOnly: boolean;
    destructiveActionsExposed: boolean;
    manageCapability: string;
  };
  items: StructuredLogItem[];
  total: number;
  page: number;
  pageSize: number;
  evidenceOnly: boolean;
  writesDecision: boolean;
  capability: {
    required: string;
    frontendBoundary: string;
    authorizationBoundary: string;
  };
};

export type AuditRetentionPolicy = {
  schemaVersion: string;
  generatedAt: string;
  retentionPolicy: string;
  defaultRetentionDays: number;
  supportedActions: Array<"archive" | "purge" | "set_legal_hold" | "clear_legal_hold">;
  statusCounts: Record<string, number>;
  capability: {
    read: string;
    manage: string;
    authorizationBoundary: string;
    frontendBoundary: string;
  };
  approval: Record<string, unknown>;
  guardrail: Record<string, unknown>;
  audit: Record<string, unknown>;
  approvalRefs: Array<Record<string, unknown>>;
  readOnlyProjectionRemainsReadOnly: boolean;
};

export async function fetchAuditRetentionPolicy() {
  return request<AuditRetentionPolicy>("/observability/audit-retention/policy");
}

export async function requestAuditRetentionAction(payload: {
  auditLogId: string;
  action: "archive" | "purge" | "set_legal_hold" | "clear_legal_hold";
  dryRun: boolean;
  retentionUntil?: string | null;
  reason?: string | null;
  idempotencyKey?: string | null;
}) {
  return request<Record<string, unknown>>("/observability/audit-retention/actions", {
    method: "POST",
    body: payload,
  });
}

export type QualityDashboard = {
  scope: { executionId: string | null };
  generatedAt: string;
  metrics: ObservabilityMetric[];
  executionQuality: Record<string, unknown>;
  skillQuality: Array<Record<string, unknown>>;
  modelQuality: Array<Record<string, unknown>>;
  costSummary: Record<string, unknown>;
  failureReasons: Array<Record<string, unknown>>;
  qualitySignals: Array<Record<string, unknown>>;
  evidenceOnly: boolean;
  writesDecision: boolean;
};

export type ReplayComparison = {
  schemaVersion: string;
  comparedAt: string;
  baselineReplay: Record<string, unknown>;
  candidateReplay: Record<string, unknown>;
  metricDiff: Array<Record<string, unknown>>;
  findingDiff: Record<string, unknown>;
  gateDiff: Record<string, unknown>;
  judgeDiff: Record<string, unknown>;
  costDiff: Record<string, unknown>;
  latencyDiff: Record<string, unknown>;
  evidenceOnly: boolean;
  writesDecision: boolean;
};

export async function fetchObservabilityMetrics(executionId?: string | null) {
  return request<{
    scope: { executionId: string | null };
    metrics: ObservabilityMetric[];
    statusValues: string[];
  }>(
    withQuery("/observability/metrics", {
      executionId,
    }),
  );
}

export async function fetchStructuredLogs(filters: { executionId?: string | null; traceId?: string | null; level?: string; component?: string; resourceType?: string; resourceId?: string } = {}) {
  return request<StructuredLogProjection>(
    withQuery("/observability/logs", {
      executionId: filters.executionId,
      traceId: filters.traceId,
      level: filters.level,
      component: filters.component,
      resourceType: filters.resourceType,
      resourceId: filters.resourceId,
      page_size: 30,
    }),
  );
}

export async function fetchAuditLogProjection(filters: { executionId?: string | null; traceId?: string | null; level?: string; component?: string; resourceType?: string; resourceId?: string } = {}) {
  return request<AuditLogProjection>(
    withQuery("/observability/audit-log-projection", {
      executionId: filters.executionId,
      traceId: filters.traceId,
      level: filters.level,
      component: filters.component,
      resourceType: filters.resourceType,
      resourceId: filters.resourceId,
      page_size: 30,
    }),
  );
}

export async function fetchQualityDashboard(executionId?: string | null) {
  return request<QualityDashboard>(
    withQuery("/observability/quality-dashboard", {
      executionId,
    }),
  );
}

export async function fetchReplayComparison(candidateExecutionId: string, baselineExecutionId: string) {
  return request<ReplayComparison>(
    withQuery(`/executions/${encodeURIComponent(candidateExecutionId)}/replay/compare`, {
      baselineExecutionId,
    }),
  );
}

export async function fetchJobs(filters: { status?: string; jobType?: string; pageSize?: number } = {}) {
  return request<{
    items: Array<{
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
    }>;
    total: number;
  }>(
    withQuery("/jobs", {
      page_size: filters.pageSize ?? 20,
      status: filters.status,
      jobType: filters.jobType,
    }),
  );
}

export async function fetchGuardrailPolicies() {
  return request<{
    items: Array<{
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
    }>;
    total: number;
  }>("/guardrails/policies?page_size=20");
}

export async function updateGuardrailPolicy(
  ruleId: string,
  payload: {
    enabled: boolean;
    decisionOverrides: Record<string, string>;
  },
) {
  return request<{
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
  }>(`/guardrails/policies/${encodeURIComponent(ruleId)}`, {
    method: "PATCH",
    body: payload,
  });
}

export async function fetchGuardrailEvents() {
  return request<{
    items: Array<{
      id: string;
      traceId: string | null;
      executionId: string | null;
      actorId: string | null;
      skillInvocationId: string | null;
      connectorBindingId: string | null;
      toolCallId: string | null;
      requestId: string | null;
      resourceType: string;
      resourceId: string;
      ruleId: string;
      decision: string;
      reason: string;
      evidence: string[];
      metadata: Record<string, unknown>;
      createdAt: string;
    }>;
    total: number;
    summary: { allow: number; warn: number; block: number };
  }>("/guardrails/events?page_size=12");
}

export async function fetchApprovals(filters: { status?: string; type?: string; resourceType?: string; pageSize?: number } = {}) {
  return request<{
    items: Array<{
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
    }>;
    total: number;
  }>(
    withQuery("/approvals", {
      page_size: filters.pageSize ?? 20,
      status: filters.status,
      type: filters.type,
      resourceType: filters.resourceType,
    }),
  );
}

export async function approveApproval(approvalId: string, comment?: string | null) {
  return request<Record<string, unknown>>(`/approvals/${encodeURIComponent(approvalId)}/approve`, {
    method: "POST",
    body: { comment: comment ?? null },
  });
}

export async function rejectApproval(approvalId: string, comment?: string | null) {
  return request<Record<string, unknown>>(`/approvals/${encodeURIComponent(approvalId)}/reject`, {
    method: "POST",
    body: { comment: comment ?? null },
  });
}

export async function cancelApproval(approvalId: string, comment?: string | null) {
  return request<Record<string, unknown>>(`/approvals/${encodeURIComponent(approvalId)}/cancel`, {
    method: "POST",
    body: { comment: comment ?? null },
  });
}
export type GatePolicyValidationStatus = "not_validated" | "valid" | "invalid";

export type GatePolicyGovernanceStatus =
  | "draft"
  | "review_pending"
  | "review_approved"
  | "review_rejected"
  | "review_cancelled"
  | "review_expired"
  | "transition_pending"
  | "transition_applied"
  | "transition_rejected"
  | "transition_cancelled"
  | "transition_expired";

export interface GatePolicyValidationProjection {
  schemaVersion: "phase8.gate-policy-validation.v1";
  status: GatePolicyValidationStatus;
  contentHash: string;
  validatedAt: string | null;
  validatedBy: string | null;
  errors: Array<{ errorCode: string; field: string | null; issueType: string | null }>;
  warnings: Array<{ errorCode: string; field: string | null; issueType: string | null }>;
  writesGateDecision: false;
}

export interface GatePolicyVersionProjection {
  versionId: string;
  versionRef: string;
  versionNumber: number;
  schemaVersion: "gate-policy.v1";
  status: "draft" | "active" | "disabled" | "deprecated" | "archived";
  governanceStatus: GatePolicyGovernanceStatus;
  contentHash: string;
  lockVersion: number;
  validation: GatePolicyValidationProjection;
  currentApproval: {
    approvalId: string;
    resourceType: "gate_policy_version_review" | "gate_policy_version_lifecycle";
    action: "gate_policy.review" | "gate_policy.lifecycle";
    status: "pending" | "approved" | "rejected" | "cancelled" | "expired";
    targetStatus: "disabled" | "deprecated" | "archived" | null;
  } | null;
  approvalRefs: Array<Record<string, unknown>>;
  guardrailRefs: Array<Record<string, unknown>>;
  auditRefs: Array<Record<string, unknown>>;
  traceRefs: string[];
  document: Record<string, unknown> | null;
  createdAt: string;
  updatedAt: string;
}

export interface GatePolicyProjection {
  policyId: string;
  policyRef: string;
  projectId: string;
  tenantId: string;
  workspaceId: string;
  policyKey: string;
  name: string;
  description: string | null;
  status: "draft" | "active" | "disabled" | "deprecated" | "archived";
  lockVersion: number;
  versions: GatePolicyVersionProjection[];
  createdAt: string;
  updatedAt: string;
  executesGate: false;
  activatesProduction: false;
}

export interface CreateGatePolicyDraftRequest {
  document: Record<string, unknown>;
  idempotencyKey: string;
  expectedContentHash?: string;
}

export interface UpdateGatePolicyDraftRequest {
  document: Record<string, unknown>;
  expectedVersion: number;
  expectedContentHash?: string;
}

export interface SubmitGatePolicyReviewRequest {
  expectedVersion: number;
  idempotencyKey: string;
  reason: string;
}

export interface GatePolicyLifecycleRequest {
  targetStatus: "disabled" | "deprecated" | "archived";
  expectedVersion: number;
  idempotencyKey: string;
  reason: string;
}

export type GatePolicyValidationIssue = {
  path: string;
  code: string;
  severity: "error" | "warning";
  messageKey: string;
  parameters: Record<string, unknown>;
};

export type GatePolicyStructuredDiff = {
  schemaVersion: "phase8.gate-policy-structured-diff.v1";
  changes: Array<{ operation: "add" | "remove" | "change"; path: string; before: unknown; after: unknown }>;
  summary: { add: number; remove: number; change: number };
  redacted: true;
  computedBy: "backend";
};

export type GatePolicyImportPreview = {
  schemaVersion: "phase8.gate-policy-import-preview.v1";
  format: "json" | "yaml";
  valid: boolean;
  contentHash: string | null;
  validationIssues: GatePolicyValidationIssue[];
  canonicalPolicy: Record<string, unknown> | null;
  diff: GatePolicyStructuredDiff;
  limits: Record<string, number>;
  activatesProduction: false;
  executesGate: false;
};

export async function fetchGatePolicies(projectId: string) {
  return request<{ items: GatePolicyProjection[]; total: number; page: number; pageSize: number; readOnly: boolean; executesGate: false }>(
    `/projects/${encodeURIComponent(projectId)}/gate-policies?page_size=100`,
  );
}

export async function previewGatePolicyImport(projectId: string, input: File | string, format: "json" | "yaml", baseline?: { policyId: string; versionId: string }) {
  const form = new FormData();
  const file = typeof input === "string" ? new File([input], `pasted-policy.${format}`, { type: format === "json" ? "application/json" : "application/yaml" }) : input;
  form.append("file", file);
  form.append("format", format);
  if (baseline) {
    form.append("policyId", baseline.policyId);
    form.append("versionId", baseline.versionId);
  }
  return request<GatePolicyImportPreview>(`/projects/${encodeURIComponent(projectId)}/gate-policies/imports/preview`, { method: "POST", body: form });
}

export async function createGatePolicyImportDraft(projectId: string, preview: GatePolicyImportPreview, idempotencyKey: string) {
  return request<GatePolicyProjection>(`/projects/${encodeURIComponent(projectId)}/gate-policies`, {
    method: "POST",
    body: { document: preview.canonicalPolicy, expectedContentHash: preview.contentHash, idempotencyKey },
  });
}

export async function updateGatePolicyImportDraft(projectId: string, policyId: string, versionId: string, preview: GatePolicyImportPreview, expectedVersion: number) {
  return request<GatePolicyVersionProjection>(`/projects/${encodeURIComponent(projectId)}/gate-policies/${encodeURIComponent(policyId)}/versions/${encodeURIComponent(versionId)}`, {
    method: "PATCH",
    body: { document: preview.canonicalPolicy, expectedContentHash: preview.contentHash, expectedVersion },
  });
}

export type GatePolicyMode = "observe" | "shadow" | "enforce";
export type GatePolicySimulationStatus = "queued" | "running" | "completed" | "partial" | "failed" | "cancelled" | "timed_out";

export interface GatePolicyModeProjection {
  schemaVersion: "phase8.gate-policy-mode-projection.v1";
  projectId: string;
  mode: GatePolicyMode;
  bindingId: string | null;
  policyVersionId: string | null;
  policyVersionHash: string | null;
  active: boolean;
  authoritative: boolean;
  blocksGate: boolean;
  effectiveFrom: string | null;
  historyRef: string | null;
}

export interface GatePolicyRollbackTargetProjection {
  schemaVersion: "phase8.gate-policy-rollback-target.v1";
  policyId: string;
  policyVersionId: string;
  policyVersionHash: string;
  previousBindingId: string;
  lastEnforcedAt: string;
  available: boolean;
  unavailableReason: "current" | "archived" | "unavailable" | "corrupted" | null;
}

export interface GatePolicySimulationCaseDiff {
  schemaVersion: "phase8.gate-policy-simulation-case-diff.v1";
  caseId: string;
  caseIndex: number;
  gateDecisionId: string | null;
  executionId: string | null;
  gateInputSnapshotRef: string;
  gateInputSnapshotHash: string;
  inputFingerprint: string | null;
  status: "completed" | "unavailable" | "failed";
  oldDecision: "pass" | "warn" | "fail" | "blocked" | null;
  newDecision: "pass" | "warn" | "fail" | "blocked" | null;
  addedReasonCodes: string[];
  removedReasonCodes: string[];
  falsePassRisk: boolean;
  newBlock: boolean;
  errorCode: string | null;
  authoritative: false;
}

export interface GatePolicySimulationSummary {
  schemaVersion: "phase8.gate-policy-simulation-summary.v1";
  totalCases: number;
  completedCases: number;
  changedCases: number;
  unchangedCases: number;
  falsePassRiskCount: number;
  newBlockCount: number;
  unavailableCases: number;
  failedCases: number;
  decisionTransitions: Record<string, number>;
  complete: boolean;
  authoritative: false;
}

export interface GatePolicySimulationRun {
  schemaVersion: "phase8.gate-policy-simulation-run.v1";
  simulationRunId: string;
  projectId: string;
  policyId: string;
  sourcePolicyVersionId: string | null;
  policyVersionId: string;
  policyVersionHash: string;
  evaluatorVersion: string;
  runType: "historical" | "shadow";
  status: GatePolicySimulationStatus;
  datasetFingerprint: string;
  totalCases: number;
  completedCases: number;
  unavailableCases: number;
  failedCases: number;
  summary: GatePolicySimulationSummary | null;
  cases: GatePolicySimulationCaseDiff[];
  jobId: string | null;
  traceRef: string | null;
  errorCode: string | null;
  retentionUntil: string;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
  authoritative: false;
  writesGateDecision: false;
}

export interface GatePolicyActivationResult {
  schemaVersion: "phase8.gate-policy-activation-result.v1";
  activationRequestId: string;
  status: "approval_pending" | "applied";
  projectId: string;
  policyId: string;
  policyVersionId: string;
  policyVersionHash: string;
  simulationRunId: string;
  approvalId: string;
  bindingId: string | null;
  previousBindingId: string | null;
  traceRef: string;
  authoritative: boolean;
  effectiveFrom: string | null;
}

export interface GatePolicyRollbackResult {
  schemaVersion: "phase8.gate-policy-rollback-result.v1";
  rollbackRequestId: string;
  status: "approval_pending" | "applied";
  projectId: string;
  targetPolicyVersionId: string;
  approvalId: string;
  bindingId: string | null;
  replacedBindingId: string | null;
  traceRef: string;
  authoritative: boolean;
  effectiveFrom: string | null;
}

export async function fetchGatePolicyModes(projectId: string) {
  return request<{ schemaVersion: string; projectId: string; items: GatePolicyModeProjection[]; rollbackTargets: GatePolicyRollbackTargetProjection[]; semantics: Record<GatePolicyMode, string>; computedBy: "backend" }>(
    `/projects/${encodeURIComponent(projectId)}/gate-policy-modes`,
  );
}

export async function fetchGatePolicySimulations(projectId: string) {
  return request<{ items: GatePolicySimulationRun[]; total: number; page: number; pageSize: number }>(
    `/projects/${encodeURIComponent(projectId)}/gate-policy-simulations?page_size=100`,
  );
}

export async function fetchGatePolicySimulation(projectId: string, simulationRunId: string) {
  return request<GatePolicySimulationRun>(
    `/projects/${encodeURIComponent(projectId)}/gate-policy-simulations/${encodeURIComponent(simulationRunId)}`,
  );
}

export async function createGatePolicySimulation(projectId: string, policyId: string, policyVersionId: string, idempotencyKey: string) {
  return request<GatePolicySimulationRun>(
    `/projects/${encodeURIComponent(projectId)}/gate-policies/${encodeURIComponent(policyId)}/simulations`,
    { method: "POST", body: { policyVersionId, maxCases: 100, timeoutSeconds: 300, idempotencyKey } },
  );
}

export async function cancelGatePolicySimulation(projectId: string, simulationRunId: string, expectedStatus: "queued" | "running", reason: string) {
  return request<GatePolicySimulationRun>(
    `/projects/${encodeURIComponent(projectId)}/gate-policy-simulations/${encodeURIComponent(simulationRunId)}/cancel`,
    { method: "POST", body: { expectedStatus, reason } },
  );
}

export async function setGatePolicyMode(projectId: string, policyId: string, versionId: string, mode: "observe" | "shadow", expectedCurrentBindingId: string | null, idempotencyKey: string, reason: string) {
  return request<GatePolicyModeProjection>(
    `/projects/${encodeURIComponent(projectId)}/gate-policies/${encodeURIComponent(policyId)}/versions/${encodeURIComponent(versionId)}/mode`,
    { method: "POST", body: { mode, expectedCurrentBindingId, idempotencyKey, reason } },
  );
}

export async function requestGatePolicyActivation(projectId: string, policyId: string, versionId: string, simulationRunId: string, expectedCurrentBindingId: string | null, expectedCurrentPolicyVersionId: string | null, idempotencyKey: string, reason: string) {
  return request<GatePolicyActivationResult>(
    `/projects/${encodeURIComponent(projectId)}/gate-policies/${encodeURIComponent(policyId)}/versions/${encodeURIComponent(versionId)}/activation-requests`,
    { method: "POST", body: { simulationRunId, expectedCurrentBindingId, expectedCurrentPolicyVersionId, maxFalsePassRiskCount: 0, maxNewBlockCount: 100, idempotencyKey, reason } },
  );
}

export async function requestGatePolicyRollback(projectId: string, targetPolicyVersionId: string, expectedCurrentBindingId: string, expectedCurrentPolicyVersionId: string, idempotencyKey: string, reason: string) {
  return request<GatePolicyRollbackResult>(
    `/projects/${encodeURIComponent(projectId)}/gate-policy-rollback-requests`,
    { method: "POST", body: { targetPolicyVersionId, expectedCurrentBindingId, expectedCurrentPolicyVersionId, idempotencyKey, reason } },
  );
}

export type ChangeSetStatus = "completed" | "partial" | "unknown";
export type ChangeSetType = "requirement" | "code";

export interface ChangeSetSummary {
  changeSetId: string;
  changeSetType: ChangeSetType;
  status: ChangeSetStatus;
  sourceType: string;
  sourceId: string;
  sourceRevision: string;
  sourceContentHash: string | null;
  normalizerVersion: string;
  itemCount: number;
  issueCount: number;
  sensitive: boolean;
  impactAnalysisPerformed: false;
  createdAt: string;
}

export interface ChangeSetIssue {
  schemaVersion: "phase8.normalization-issue.v1";
  issueId: string;
  category: "incomplete" | "ambiguous" | "unsupported" | "sensitive";
  code: string;
  message: string;
  field: string | null;
  recoverable: boolean;
  evidence: Array<Record<string, unknown>>;
}

export interface ChangeSetDetail extends ChangeSetSummary {
  schemaVersion: "phase8.requirement-change-set.v1" | "phase8.code-change-set.v1";
  projectId: string;
  environmentId: string | null;
  sourceSnapshotId: string;
  fingerprint: string;
  sourceRefs: Array<Record<string, unknown>>;
  artifactRefs: Array<Record<string, unknown>>;
  replayRefs: Array<Record<string, unknown>>;
  traceId: string;
  issues: ChangeSetIssue[];
  deduplicated: boolean;
  items?: Array<{
    itemId: string;
    requirementId: string;
    changeType: string;
    changedFields: string[];
    confidence: number;
    relatedRequirementIds: string[];
  }>;
  repositoryRef?: string;
  baseSha?: string;
  headSha?: string;
  files?: Array<{
    fileId: string;
    path: string;
    oldPath: string | null;
    changeType: string;
    language: string | null;
    binary: boolean;
    generated: boolean;
    vendor: boolean;
    submodule: boolean;
    riskHints: string[];
    hunks: Array<{ hunkId: string; header: string; sensitive: boolean; redactionCount: number; symbols: Array<{ symbolId: string; name: string; kind: string; changeType: string }> }>;
  }>;
  fullDiffStoredInDatabase?: false;
}

export async function fetchChangeSets(projectId: string, query: { changeSetType?: ChangeSetType; status?: ChangeSetStatus; pageSize?: number } = {}) {
  return request<{ schemaVersion: "phase8.change-set-list.v1"; items: ChangeSetSummary[]; total: number; page: number; pageSize: number; readOnly: true; impactAnalysisPerformed: false }>(withQuery(
    `/projects/${encodeURIComponent(projectId)}/change-sets`,
    { changeSetType: query.changeSetType, status: query.status, pageSize: query.pageSize ?? 100 },
  ));
}

export async function fetchChangeSet(projectId: string, changeSetId: string) {
  return request<ChangeSetDetail>(
    `/projects/${encodeURIComponent(projectId)}/change-sets/${encodeURIComponent(changeSetId)}`,
  );
}

export type RequirementMatchStatus = "confirmed" | "candidate" | "rejected" | "unknown";

export interface PrContextSummary {
  contextId: string;
  projectId: string;
  provider: "github" | "gitlab" | "mock-scm";
  repositoryRef: string;
  repositoryNativeId: string;
  pullRequestNumber: number;
  state: "open" | "closed" | "merged" | "unknown";
  latestVersion: number;
  headSha: string;
  providerEventAt: string;
  updatedAt: string;
  readOnly: true;
}

export interface RequirementMatchView {
  schemaVersion: "phase8.requirement-match.v1";
  matchId: string;
  candidate: {
    requirementId: string;
    requirementVersionId: string | null;
    requirementVersion: number | null;
    source: "explicit_reference" | "manual_mapping" | "verified_traceability" | "rule" | "history" | "ai_suggestion";
    confidence: number;
    status: RequirementMatchStatus;
    reviewRequired: boolean;
    reasons: Array<{ code: string; layer: string; explanationKey: string }>;
  };
  matchHash: string;
  createdAt: string;
}

export interface PrContextDetail {
  context: {
    schemaVersion: "phase8.pr-context.v1";
    contextId: string;
    versionId: string;
    version: number;
    provider: string;
    projectId: string;
    repositoryRef: string;
    pullRequestNumber: number;
    revision: { baseRef: string; baseSha: string; headRef: string; headSha: string; previousHeadSha: string | null; forcePush: boolean };
    authorRef: string;
    draft: boolean;
    state: string;
    action: string;
    fork: boolean;
    labels: string[];
    changedFiles: Array<{ path: string; changeType: string; previousPath: string | null }>;
    changeSetRef: { type: string; ref: string; contentHash: string | null } | null;
    explicitRequirementRefs: string[];
    contextHash: string;
    readOnly: true;
    gateDecision: null;
    executionCreated: false;
  };
  requirementMatch: {
    snapshotId: string;
    status: "confirmed" | "candidate" | "conflict" | "unknown";
    matches: RequirementMatchView[];
    explicitUnknownRefs: string[];
    snapshotHash: string;
    reviewRequired: boolean;
    readOnly: true;
    gateDecision: null;
    executionCreated: false;
  } | null;
  readOnly: true;
  admissionImplemented: true;
  gateDecisionCreated: false;
  executionCreated: false;
}

export async function fetchPrContexts(projectId: string) {
  return request<{ items: PrContextSummary[]; total: number; page: number; pageSize: number; readOnly: true; admissionImplemented: true }>(
    `/projects/${encodeURIComponent(projectId)}/pr-contexts`,
  );
}

export async function fetchPrContext(projectId: string, contextId: string) {
  return request<PrContextDetail>(
    `/projects/${encodeURIComponent(projectId)}/pr-contexts/${encodeURIComponent(contextId)}`,
  );
}

export type AdmissionRunStatus = "queued" | "running" | "completed" | "failed" | "partial" | "unavailable" | "cancelled" | "stale";
export type AdmissionMode = "observe" | "shadow" | "enforce";
export type CIStatus = "pending" | "in_progress" | "success" | "failure" | "neutral" | "cancelled" | "stale";

export interface AdmissionArtifactRef {
  type: string;
  ref: string;
  contentHash?: string | null;
  redactionStatus?: string;
}

export interface AdmissionToolResult {
  tool: string;
  toolVersion: string | null;
  status: "completed" | "failed" | "partial" | "unavailable" | "cancelled";
  toolStatus: string;
  actualExecution: boolean;
  sandboxed: true;
  exitCode: number;
  durationMs: number;
  unavailableReason: string | null;
  artifactRefs: Array<{ type: string; ref: string; redactionStatus: string }>;
  rawFindingRefs: Array<{ type: string; ref: string; redactionStatus: string }>;
}

export interface AdmissionRunProjection {
  schemaVersion: "phase8.admission-run.v3";
  admissionRunId: string;
  projectId: string;
  repositoryRef: string;
  pullRequestNumber: number;
  prContextVersionId: string;
  selectiveReplayPlanId: string;
  executionId: string;
  environmentId: string | null;
  mode: AdmissionMode;
  workflowVersion: string;
  nonAuthoritative: boolean;
  status: AdmissionRunStatus;
  baseSha: string;
  sourceHeadSha: string;
  inputFingerprint: string;
  staticScan: {
    status: "completed" | "failed" | "partial" | "unavailable" | "cancelled";
    toolResults: AdmissionToolResult[];
    artifactRefs: Array<{ type: string; ref: string }>;
    rawFindingRefs: Array<{ type: string; ref: string }>;
    normalizedFindingRefs: Array<{ type: string; ref: string }>;
    analyzeCompleted: boolean;
    normalizeCompleted: boolean;
    gateDecisionCreated: false;
  } | null;
  smokePlan: { tests: Array<{ taskRef: string; recipe: string }>; unsupportedTests: Array<{ testRef: string; reasonCode: string }> };
  smokeResult: {
    status: "completed" | "failed" | "partial" | "unavailable" | "cancelled";
    toolResults: AdmissionToolResult[];
    artifactRefs: Array<{ type: string; ref: string }>;
    rawFindingRefs: Array<{ type: string; ref: string }>;
    normalizedFindingRefs: Array<{ type: string; ref: string }>;
    analyzeCompleted: boolean;
    normalizeCompleted: boolean;
    gateDecisionCreated: false;
  } | null;
  requirementMatchRef: AdmissionArtifactRef | null;
  impactResultRef: AdmissionArtifactRef | null;
  changeSetRef: AdmissionArtifactRef | null;
  selectiveReplayPlanRef: AdmissionArtifactRef;
  stages: AdmissionStageProjection[];
  stageSnapshotHash: string;
  admissionResult: AdmissionResultProjection | null;
  review: AdmissionReviewProjection;
  retry: Record<string, unknown>;
  replaySnapshot: Record<string, unknown>;
  guardrailEventRefs: AdmissionArtifactRef[];
  auditRefs: AdmissionArtifactRef[];
  traceRefs: string[];
  rootTraceRef: string;
  createdAt: string;
  updatedAt: string;
  sandboxProfile: { profileId: string; engine: "docker"; networkMode: string; readOnlySource: true; memoryMB: number; pidsLimit: number; timeoutSeconds: number };
  readOnly: true;
  admissionDecision: Record<string, unknown> | null;
  gateDecisionCreated: boolean;
  ciWriteback: CIWritebackResult | null;
  enforcementReadiness: CIEnforcementReadiness;
  frontendAuthoritative: false;
  deduplicated?: boolean;
  executionStatus?: string;
  resultSnapshot?: Record<string, unknown>;
}

export interface AdmissionStageProjection {
  schemaVersion: "phase8.admission-stage.v1";
  sequence: number;
  lifecycleStage: "PREPARE" | "EXECUTE" | "OBSERVE" | "ANALYZE" | "NORMALIZE" | "GATE";
  status: "pending" | "running" | "completed" | "partial" | "failed" | "skipped" | "unavailable" | "cancelled" | "stale";
  reasonCode: string | null;
  startedAt: string | null;
  endedAt: string | null;
  traceRefs: string[];
  evidenceRefs: AdmissionArtifactRef[];
  summary: Record<string, unknown>;
  nonAuthoritative: boolean;
}

export interface AdmissionShadowGateProjection {
  schemaVersion: "phase8.admission-shadow-gate.v1";
  status: "completed" | "unavailable";
  decision: "pass" | "warn" | "fail" | "blocked" | null;
  domainResults: Array<Record<string, unknown>>;
  reasonCodes: string[];
  completeness: Record<string, unknown>;
  confidence: number | null;
  policyRef: AdmissionArtifactRef | null;
  inputFingerprint: string | null;
  decisionSnapshotHash: string | null;
  evaluatorVersion: string | null;
  evaluatedAt: string;
  reasonCode: string | null;
  nonAuthoritative: true;
  gateDecisionCreated: false;
  ciWriteback: false;
  mergeBlocking: false;
}

export interface AdmissionResultProjection {
  schemaVersion: "phase8.admission-result.v2";
  mode: AdmissionMode;
  conclusion: "observed" | "would_pass" | "would_warn" | "would_fail" | "would_block" | "passed" | "warned" | "failed" | "blocked" | "partial" | "unavailable" | "cancelled" | "stale";
  reasonCodes: string[];
  normalizedFindingRefs: AdmissionArtifactRef[];
  evidenceRefs: AdmissionArtifactRef[];
  shadowGate: AdmissionShadowGateProjection | null;
  enforceGate: {
    schemaVersion: "phase8.admission-enforce-gate.v1";
    status: "completed" | "unavailable";
    decision: "pass" | "warn" | "fail" | "blocked" | null;
    reasonCodes: string[];
    gateDecisionId: string | null;
    gateDecisionRef: string | null;
    inputFingerprint: string | null;
    decisionSnapshotHash: string | null;
    evaluatorVersion: string | null;
    evaluatedAt: string;
    reasonCode: string | null;
    nonAuthoritative: false;
    gateDecisionCreated: boolean;
  } | null;
  resultHash: string;
  nonAuthoritative: boolean;
  authoritativeAdmissionDecision: Record<string, unknown> | null;
  gateDecisionCreated: boolean;
  ciWriteback: boolean;
  mergeBlocking: boolean;
}

export interface CIConclusion {
  schemaVersion: "phase8.ci-conclusion.v1";
  status: CIStatus;
  admissionMode: AdmissionMode;
  gateResult: "pass" | "warn" | "fail" | "blocked" | null;
  authoritative: boolean;
  blocking: boolean;
  summary: string;
  reasonCodes: string[];
  evidenceLinks: Array<{ label: string; href: string }>;
  platformRunLink: string;
}

export interface CIWritebackResult {
  schemaVersion: "phase8.ci-writeback-result.v1";
  writebackAttemptId: string;
  admissionRunId: string;
  status: CIStatus;
  writeStatus: "completed" | "failed" | "suppressed" | "unknown";
  checkName: string;
  headSha: string;
  conclusion: CIConclusion;
  enforcement: { mode: AdmissionMode; authoritative: boolean; nonAuthoritative: boolean; blocksMerge: boolean; branchProtectionConfigured: boolean; branchProtectionExternallyManaged: true; reasonCodes: string[] };
  staleRevision: { status: "current" | "stale" | "unavailable"; expectedHeadSha: string; currentHeadSha: string | null; writeSuppressed: boolean; reasonCode: string | null; checkedAt: string };
  externalAction: { provider: string; externalId: string | null; url: string | null; connectorCallRef: string } | null;
  legacyFieldNotice: { fieldsPresent: Array<"shouldMerge" | "exitCode">; ignored: true; reasonCode: "DEPRECATED_SKILL_DECISION_FIELD_IGNORED" } | null;
  reasonCodes: string[];
  attemptCount: number;
  idempotentReplay: boolean;
}

export interface CIEnforcementReadiness {
  ready: boolean;
  mode: AdmissionMode;
  status: "active" | "approval_pending" | "disabled";
  policyHash?: string;
  branchProtectionConfigured: boolean;
  branchProtectionExternallyManaged: true;
  approvalRef?: string | null;
  unavailableReason: string | null;
  requiredCapabilities: Array<"ci.write" | "enforce.manage" | "ci.retry">;
}

export interface AdmissionReviewProjection {
  schemaVersion: "phase8.admission-review.v1";
  admissionRunId: string;
  state: "not_requested" | "pending" | "approved" | "rejected" | "expired";
  intent: "acknowledge_evidence" | "request_follow_up" | null;
  approvalRef: AdmissionArtifactRef | null;
  requestedBy: string | null;
  decidedBy: string | null;
  requestedAt: string | null;
  decidedAt: string | null;
  commentPresent: boolean;
  effect: "annotation_only";
  mutatesCanonicalFinding: false;
  mutatesGateDecision: false;
  changesMergeState: false;
  readOnly: true;
}

export interface AdmissionTimelineProjection {
  schemaVersion: "phase8.admission-timeline.v1";
  admissionRunId: string;
  rootTraceRef: string;
  mode: AdmissionMode;
  workflowVersion: string;
  stages: AdmissionStageProjection[];
  stageSnapshotHash: string;
  nonAuthoritative: boolean;
  readOnly: true;
}

export async function fetchAdmissionRuns(
  projectId: string,
  prContextVersionId?: string | null,
  environmentId?: string | null,
  mode?: AdmissionMode | null,
  status?: AdmissionRunStatus | null,
) {
  return request<{ schemaVersion: "phase8.admission-run-list.v3"; items: AdmissionRunProjection[]; total: number; page: number; pageSize: number; readOnly: true; observeShadowImplemented: true; enforceImplemented: true; authoritativeAdmissionDecisionImplemented: true; ciWritebackImplemented: true }>(withQuery(
    `/projects/${encodeURIComponent(projectId)}/admission-runs`,
    { pr_context_version_id: prContextVersionId ?? undefined, environment_id: environmentId ?? undefined, mode: mode ?? undefined, status: status ?? undefined, page_size: 50 },
  ));
}

export async function fetchAdmissionRun(projectId: string, admissionRunId: string) {
  return request<AdmissionRunProjection>(`/projects/${encodeURIComponent(projectId)}/admission-runs/${encodeURIComponent(admissionRunId)}`);
}

export async function fetchAdmissionTimeline(projectId: string, admissionRunId: string) {
  return request<AdmissionTimelineProjection>(`/projects/${encodeURIComponent(projectId)}/admission-runs/${encodeURIComponent(admissionRunId)}/timeline`);
}

export async function fetchAdmissionReview(projectId: string, admissionRunId: string) {
  return request<AdmissionReviewProjection>(`/projects/${encodeURIComponent(projectId)}/admission-runs/${encodeURIComponent(admissionRunId)}/review`);
}

export async function requestAdmissionReview(projectId: string, admissionRunId: string, payload: { intent: "acknowledge_evidence" | "request_follow_up"; comment?: string | null; idempotencyKey: string }) {
  return request<AdmissionReviewProjection>(`/projects/${encodeURIComponent(projectId)}/admission-runs/${encodeURIComponent(admissionRunId)}/review`, {
    method: "POST",
    body: { schemaVersion: "phase8.admission-review-request.v1", ...payload },
  });
}

export async function retryAdmissionRun(projectId: string, admissionRunId: string, scope: "failed_only" | "all") {
  return request<{ schemaVersion: "phase8.admission-retry.v1"; admissionRunId: string; rootTraceRef: string; scope: string; approvalRequired: boolean; approvalRef: string | null; jobRef: string | null; nonAuthoritative: true; ciWriteback: false; mergeBlocking: false }>(`/projects/${encodeURIComponent(projectId)}/admission-runs/${encodeURIComponent(admissionRunId)}/retry`, {
    method: "POST",
    body: { schemaVersion: "phase8.admission-retry-request.v1", scope },
  });
}

export async function changeCIEnforcementPolicy(projectId: string, payload: { repositoryRef: string; targetMode: AdmissionMode; branchProtectionConfigured: boolean; reason: string; idempotencyKey: string }) {
  return request<{ schemaVersion: "phase8.ci-enforcement-policy.v1"; mode: AdmissionMode; status: "active" | "approval_pending" | "disabled"; approvalRef: string | null; ready: boolean }>(`/projects/${encodeURIComponent(projectId)}/ci-enforcement`, {
    method: "POST",
    body: { schemaVersion: "phase8.ci-enforcement-change-request.v1", ...payload },
  });
}

export async function retryCIWriteback(projectId: string, admissionRunId: string, reason: string) {
  return request<{ approvalRequired: true; approvalId: string; status: string }>(`/projects/${encodeURIComponent(projectId)}/admission-runs/${encodeURIComponent(admissionRunId)}/ci-writeback/retry`, {
    method: "POST",
    body: { schemaVersion: "phase8.ci-writeback-retry-request.v1", reason, idempotencyKey: `ci-retry-${admissionRunId}-${Date.now()}` },
  });
}

export type LessonType =
  | "false_positive"
  | "false_negative"
  | "repeated_failure"
  | "flaky"
  | "environment_issue"
  | "test_issue"
  | "human_override"
  | "graph_correction"
  | "gate_disagreement"
  | "admission_outcome"
  | "auto_promotion_conflict"
  | "auto_promotion_rollback"
  | "promotion_policy_too_strict"
  | "promotion_policy_too_loose";

export type LessonStatus = "candidate" | "under_review" | "accepted" | "rejected" | "promoted" | "expired";
export type LessonFeedbackType = "confirm" | "refute" | "supplement" | "uncertain";

export type LessonRef = {
  type?: string;
  id?: string;
  ref?: string;
  contentHash?: string | null;
  [key: string]: unknown;
}

export type LessonCandidateProjection = {
  schemaVersion: "phase8.lesson-candidate.v1";
  candidateId: string;
  projectId: string;
  lessonType: LessonType;
  sourceEvent: { kind: string; id: string; version: string | null; expectedHash: string | null };
  sourceEventHash: string;
  scope: { type: "project" | "environment" | "repository"; id: string };
  summary: string;
  observations: Array<{ observationType: "fact" | "signal" | "context"; field: string; value: unknown; sourceRef?: string | null }>;
  evidenceRefs: LessonRef[];
  rawRefs: LessonRef[];
  confidence: number;
  frequency: number;
  impact: "low" | "medium" | "high" | "critical";
  status: LessonStatus;
  dedupeKey: string;
  clusterKey: string;
  clusterSize: number;
  feedbackSummary: Record<LessonFeedbackType, number>;
  feedbackConflict: boolean;
  reviewRefs: LessonRef[];
  promotionRefs: LessonRef[];
  traceRefs: string[];
  auditRefs: LessonRef[];
  lockVersion: number;
  expiresAt: string | null;
  createdAt: string;
  updatedAt: string;
  readOnly: boolean;
}

export type LessonEvidenceProjection = {
  schemaVersion: "phase8.lesson-evidence.v1";
  lessonEvidenceId: string;
  candidateId: string;
  evidenceRef: LessonRef;
  rawRef: LessonRef;
  contentHash: string;
  retentionState: "active" | "missing" | "purged" | "expired";
  classification: "public" | "internal" | "confidential" | "restricted";
  redactionStatus: "not_required" | "redacted" | "unavailable";
  capturedAt: string;
}

export type LessonFeedbackProjection = {
  schemaVersion: "phase8.lesson-feedback.v1";
  lessonFeedbackId: string;
  candidateId: string;
  feedbackType: LessonFeedbackType;
  reason: string;
  observations: LessonCandidateProjection["observations"];
  evidenceRefs: LessonRef[];
  actorRef: LessonRef;
  idempotencyKey: string;
  createdAt: string;
}

export type LessonReviewProjection = {
  schemaVersion: "phase8.lesson-review.v1";
  lessonReviewId: string;
  candidateId: string;
  decision: "accepted" | "rejected" | "needs_evidence";
  confirmedFact: boolean;
  reason: string;
  evidenceRefs: LessonRef[];
  reviewerRef: LessonRef;
  candidateLockVersion: number;
  reviewedAt: string;
}

export type LessonPromotionProjection = {
  schemaVersion: "phase8.lesson-promotion-result.v1";
  promotionResultId: string;
  candidateId: string;
  status: "approval_pending" | "promoted" | "rejected" | "failed" | "partial";
  memoryType: "episodic" | "semantic" | "procedural";
  memoryRef: LessonRef;
  approvalRefs: LessonRef[];
  approvalState: "pending" | "satisfied" | "not_required" | "rejected";
  guardrailEventRefs: LessonRef[];
  auditRefs: LessonRef[];
  evidenceRefs: LessonRef[];
  rawRefs: LessonRef[];
  policySnapshot: Record<string, unknown>;
  projectionState: "skipped" | "projected" | "projection_failed";
  reasonCode: string | null;
  traceId: string;
  createdAt: string;
}

export type LessonCandidateDetail = {
  schemaVersion: "phase8.lesson-candidate-detail.v1";
  candidate: LessonCandidateProjection;
  taxonomy: { lessonType: LessonType; sourceKinds: string[]; reviewRequired: true; promotionEligible: boolean };
  evidence: LessonEvidenceProjection[];
  feedback: LessonFeedbackProjection[];
  reviews: LessonReviewProjection[];
  promotions: LessonPromotionProjection[];
  memoryBoundary: { candidateWritesMemory: false; feedbackWritesMemory: false; reviewWritesMemory: false; explicitPromotionRequired: true; confirmedFactsOnly: true };
  improvementProposal: { status: "implemented"; mutatesGraphLearningPolicy: false; resumesAutonomy: false; automaticProductionApply: false; route: "/improvement-proposals" };
}

export async function fetchLessons(projectId: string) {
  return request<{ schemaVersion: "phase8.lesson-candidate-list.v1"; items: LessonCandidateProjection[]; total: number; page: number; pageSize: number; taxonomyStructured: true; candidateAutoPromotes: false; readOnly: boolean }>(
    `/projects/${encodeURIComponent(projectId)}/lessons?page_size=100`,
  );
}

export async function fetchLesson(projectId: string, candidateId: string) {
  return request<LessonCandidateDetail>(`/projects/${encodeURIComponent(projectId)}/lessons/${encodeURIComponent(candidateId)}`);
}

export type ImprovementTargetType = "skill" | "gate_policy" | "graph" | "graph_learning_policy" | "test_case" | "test_step" | "tool_config" | "connector_config";
export type ImprovementStatus = "draft" | "validation_failed" | "validated" | "review_pending" | "review_approved" | "review_rejected" | "routed" | "effectiveness_pending" | "effective" | "ineffective" | "inconclusive" | "rollback_pending" | "rollback_routed" | "partial" | "failed" | "archived";

export type ImprovementProposalProjection = {
  schemaVersion: "phase8.improvement-proposal.v1";
  proposalId: string;
  projectId: string;
  sourceLessonRefs: LessonRef[];
  targetType: ImprovementTargetType;
  target: { targetId: string; targetKey: string; baseVersion: string; baseHash: string };
  changeSpec: { schemaVersion: "phase8.improvement-change-spec.v1"; summary: string; operations: Array<Record<string, unknown>>; authorityRequest: Record<string, unknown>; rollbackSpec: Record<string, unknown> };
  changeHash: string;
  rationale: string;
  evidenceRefs: LessonRef[];
  requestedRisk: "low" | "medium" | "high" | "critical";
  evaluatedRisk: "low" | "medium" | "high" | "critical";
  confidence: number;
  validationPlan: Record<string, unknown>;
  validationRefs: LessonRef[];
  status: ImprovementStatus;
  approvalRefs: LessonRef[];
  routeRefs: LessonRef[];
  effectivenessRefs: LessonRef[];
  rollbackRefs: LessonRef[];
  traceRefs: string[];
  auditRefs: LessonRef[];
  effectivenessWindow: { startsAt: string; endsAt: string; minimumSamples: number };
  lockVersion: number;
  createdAt: string;
  updatedAt: string;
  readOnly: boolean;
  productionAppliedByProposalService: false;
  automaticSelfEvolution: false;
};

export type ImprovementValidationProjection = {
  schemaVersion: "phase8.improvement-validation-result.v1";
  validationResultId: string;
  proposalId: string;
  proposalVersion: number;
  status: "passed" | "failed" | "insufficient" | "unavailable";
  checks: Array<{ check: string; state: string; passed: boolean; evidenceRefs: LessonRef[] }>;
  historicalSimulation: Record<string, unknown>;
  counterexampleRegression: Record<string, unknown> | null;
  evidenceRefs: LessonRef[];
  resultHash: string;
  validatorVersion: string;
  validatedAt: string;
};

export type ImprovementEffectivenessProjection = {
  schemaVersion: "phase8.improvement-effectiveness-result.v1";
  effectivenessResultId: string;
  proposalId: string;
  status: "effective" | "ineffective" | "inconclusive";
  beforeMetrics: Record<string, number>;
  afterMetrics: Record<string, number>;
  deltas: Record<string, number>;
  sampleSize: number;
  rollbackRequired: boolean;
  targetOutcomeRef: LessonRef;
  evidenceRefs: LessonRef[];
  measuredAt: string;
};

export type ImprovementProposalDetail = {
  schemaVersion: "phase8.improvement-proposal-detail.v1";
  proposal: ImprovementProposalProjection;
  versions: Array<{ proposalVersionId: string; versionNumber: number; contentHash: string; snapshot: Record<string, unknown> }>;
  validations: ImprovementValidationProjection[];
  effectiveness: ImprovementEffectivenessProjection[];
  authoritativeRoute: { authorityService: string; authorityOperation: string; requiredCapability: string; productionAppliedByProposalService: false };
  stateMachine: string[];
};

export async function fetchImprovementProposals(projectId: string) {
  return request<{ schemaVersion: "phase8.improvement-proposal-list.v1"; items: ImprovementProposalProjection[]; total: number; page: number; pageSize: number; targetTypes: ImprovementTargetType[]; productionAppliedByProposalService: false; automaticSelfEvolution: false; readOnly: boolean }>(
    `/projects/${encodeURIComponent(projectId)}/improvement-proposals?page_size=100`,
  );
}

export async function fetchImprovementProposal(projectId: string, proposalId: string) {
  return request<ImprovementProposalDetail>(`/projects/${encodeURIComponent(projectId)}/improvement-proposals/${encodeURIComponent(proposalId)}`);
}

export type ImpactRiskLevel = "low" | "medium" | "high";

export interface ImpactRef {
  type: string;
  ref: string;
  contentHash: string | null;
}

export interface ImpactPropagationStep {
  order: number;
  entityType: string;
  entityRef: string;
  viaRelation: string | null;
  direction: "seed" | "forward" | "reverse" | "mapping";
  confidence: number;
  evidenceRefs: ImpactRef[];
}

export interface ImpactEntity {
  entityType: "capability" | "risk_domain";
  entityRef: string;
  label: string | null;
  riskLevel: ImpactRiskLevel;
  confidence: number;
  mappingSource: string;
  evidenceRefs: ImpactRef[];
  propagationPath: ImpactPropagationStep[];
}

export interface ImpactPath {
  pathId: string;
  pathRef: string;
  name: string;
  riskLevel: ImpactRiskLevel;
  confidence: number;
  evidenceRefs: ImpactRef[];
  propagationPath: ImpactPropagationStep[];
}

export interface ImpactTest {
  testRef: string;
  testKind: string | null;
  riskLevel: ImpactRiskLevel;
  confidence: number;
  evidenceRefs: ImpactRef[];
  propagationPath: ImpactPropagationStep[];
}

export interface ImpactUncertainty {
  code: string;
  areaType: string;
  areaRef: string | null;
  messageKey: string;
  riskLevel: ImpactRiskLevel;
  evidenceRefs: ImpactRef[];
  reviewRequired: boolean;
}

export interface ImpactResult {
  schemaVersion: "phase8.impact-result.v1";
  impactResultId: string;
  projectId: string;
  status: "complete" | "partial" | "unknown";
  riskLevel: ImpactRiskLevel;
  confidence: number;
  graphStaleness: "fresh" | "suspect" | "stale" | "invalid" | "unknown";
  algorithmVersion: "p18.impact-propagation.v1";
  impactedCapabilities: ImpactEntity[];
  impactedPaths: ImpactPath[];
  impactedTests: ImpactTest[];
  impactedRiskDomains: ImpactEntity[];
  unknownAreas: ImpactUncertainty[];
  recommendedFallbacks: Array<{ code: string; reason: string; recommendedAction: string }>;
  aiSuggestions: Array<{ sourceEntityRef: string; suggestedCapabilityRef: string; confidence: number; rationale: string; canonical: false; reviewRequired: true }>;
  reviewRequired: boolean;
  approvalRef: ImpactRef | null;
  truncated: boolean;
  visitedNodeCount: number;
  changeSetRefs: ImpactRef[];
  graphRef: ImpactRef;
  graphVersionRef: ImpactRef;
  mappingVersionRefs: ImpactRef[];
  modelInvocationRefs: ImpactRef[];
  guardrailEventRefs: ImpactRef[];
  auditRefs: ImpactRef[];
  traceId: string;
  createdAt: string;
}

export async function fetchImpactResults(projectId: string, changeSetId?: string) {
  return request<{ schemaVersion: "phase8.impact-result-list.v1"; items: ImpactResult[]; total: number; page: number; pageSize: number; readOnly: true; backendComputed: true }>(withQuery(
    `/projects/${encodeURIComponent(projectId)}/impact-results`,
    { changeSetId, pageSize: 100 },
  ));
}

export type ReplayPlanRef = { type: string; ref: string; contentHash: string | null };

export interface SelectiveReplayPlan {
  schemaVersion: "phase8.selective-replay-plan.v1";
  planId: string;
  projectId: string;
  status: "ready" | "fallback";
  algorithmVersion: "p19.selective-replay.v1";
  planHash: string;
  inputFingerprint: string;
  selectedPaths: Array<{ pathId: string; pathRef: string; name: string; riskLevel: ImpactRiskLevel; confidence: number; selectionReasonCodes: string[]; evidenceRefs: ReplayPlanRef[] }>;
  selectedTests: Array<{ testRef: string; assetId: string | null; taskRef: string | null; domain: string; riskLevel: ImpactRiskLevel; confidence: number; selectionReasonCodes: string[]; estimatedSeconds: number; evidenceRefs: ReplayPlanRef[] }>;
  selectionReasons: Array<{ code: string; category: string; priority: number; explanationKey: string; sourceRefs: ReplayPlanRef[] }>;
  riskSummary: { overallRisk: ImpactRiskLevel; selectedByRisk: Record<string, number>; highRiskOmitted: false; approvalRequiredForExecution: boolean };
  coverageSummary: { status: string; pathCoverageRatio: number | null; changeImpactCoverageRatio: number | null; gapCount: number; sourceRef: ReplayPlanRef | null };
  excludedTests: Array<{ testRef: string; riskLevel: ImpactRiskLevel; reasonCode: string; evidenceRefs: ReplayPlanRef[] }>;
  unknownAreas: Array<{ code: string; areaRef: string | null; riskLevel: ImpactRiskLevel; sourceRefs: ReplayPlanRef[] }>;
  estimatedCost: { selectedTestCount: number; estimatedSeconds: number; withinBudget: boolean; overBudgetByTests: number; overBudgetBySeconds: number };
  fallback: { used: boolean; reasonCodes: string[]; strategy: "none" | "existing_regression_plan"; sourcePlanRef: ReplayPlanRef | null; conservativeSelectionPreserved: boolean };
  validity: { state: "active" | "expired" | "stale"; reasonCodes: string[]; requiresRegeneration: boolean };
  expiresAt: string;
  executionCreated: false;
  frontendAuthoritative: false;
}

export interface SelectiveReplayConfirmation {
  schemaVersion: "phase8.selective-replay-confirmation.v1";
  planId: string;
  planHash: string;
  validity: SelectiveReplayPlan["validity"];
  canContinue: boolean;
  requiredCapability: "executions.manage";
  nextBoundary: "service-managed-execution-workflow";
  executionCreated: false;
  approvalRequiredForExecution: boolean;
  approvalRefs: ReplayPlanRef[];
  readOnly: true;
}

export async function fetchSelectiveReplayPlans(projectId: string, impactResultId?: string) {
  return request<{ schemaVersion: "phase8.selective-replay-plan-list.v1"; items: SelectiveReplayPlan[]; total: number; page: number; pageSize: number; readOnly: true; backendComputed: true; executionCreated: false }>(withQuery(
    `/projects/${encodeURIComponent(projectId)}/selective-replay-plans`,
    { impactResultId, pageSize: 100 },
  ));
}

export async function fetchSelectiveReplayConfirmation(projectId: string, planId: string, currentHeadRevision?: string) {
  return request<SelectiveReplayConfirmation>(
    withQuery(
      `/projects/${encodeURIComponent(projectId)}/selective-replay-plans/${encodeURIComponent(planId)}/confirmation`,
      { currentHeadRevision },
    ),
  );
}
