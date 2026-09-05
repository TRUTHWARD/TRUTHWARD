# SPDX-License-Identifier: Apache-2.0
from enum import StrEnum


class ProviderType(StrEnum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    VLLM = "vllm"
    OPENAI_COMPATIBLE = "openai_compatible"
    CUSTOM = "custom"


class ModelRole(StrEnum):
    PRIMARY = "PRIMARY"
    CHALLENGER = "CHALLENGER"
    JUDGE = "JUDGE"
    LOCAL_FALLBACK = "LOCAL_FALLBACK"


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CoverageStatus(StrEnum):
    COVERED = "covered"
    PARTIAL = "partial"
    NOT_COVERED = "not_covered"
    BLOCKED = "blocked"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class CoverageRiskStatus(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class TraceabilityRelationStatus(StrEnum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    SYSTEM_VERIFIED = "system_verified"
    STALE = "stale"
    INVALID = "invalid"
    REJECTED = "rejected"


class ProofStatus(StrEnum):
    VALID = "valid"
    STALE = "stale"
    BROKEN = "broken"
    SUPERSEDED = "superseded"


class ProofEdgeCurrentStatus(StrEnum):
    CONFIRMED = "confirmed"
    SYSTEM_VERIFIED = "system_verified"
    STALE = "stale"
    INVALID = "invalid"
    MISSING = "missing"
    SUPERSEDED = "superseded"


class TraceabilityRelationSource(StrEnum):
    MANUAL = "manual"
    APPROVAL = "approval"
    DETERMINISTIC_RULE = "deterministic_rule"
    EXECUTION_RESULT = "execution_result"
    IMPORT = "import"
    MODEL_CANDIDATE = "model_candidate"
    METADATA_CANDIDATE = "metadata_candidate"
    STRING_MATCH_CANDIDATE = "string_match_candidate"


class TaskStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ExecutionStage(StrEnum):
    PREPARE = "PREPARE"
    EXECUTE = "EXECUTE"
    OBSERVE = "OBSERVE"
    ANALYZE = "ANALYZE"
    NORMALIZE = "NORMALIZE"
    GATE = "GATE"


class PlanStatus(StrEnum):
    DRAFT = "draft"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TestDomain(StrEnum):
    FUNCTIONAL = "functional"
    PERFORMANCE = "performance"
    SECURITY = "security"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    OPEN = "open"
    IGNORED = "ignored"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    RESOLVED = "resolved"


class FindingSource(StrEnum):
    PLAYWRIGHT = "playwright"
    VISUAL_GROUNDING = "visual_grounding"
    K6 = "k6"
    ZAP = "zap"
    SEMGREP = "semgrep"
    NUCLEI = "nuclei"
    SYSTEM = "system"
    AGENT = "agent"
    MANUAL = "manual"
    CUSTOM = "custom"


class FindingCategory(StrEnum):
    FUNCTIONAL_UI = "functional_ui"
    FUNCTIONAL_API = "functional_api"
    PERFORMANCE_LATENCY = "performance_latency"
    PERFORMANCE_CAPACITY = "performance_capacity"
    DAST = "dast"
    SAST = "sast"
    TEMPLATE_SCAN = "template_scan"
    NETWORK = "network"
    RELIABILITY = "reliability"
    CONFIGURATION = "configuration"
    AUTHORIZATION = "authorization"
    AUTHENTICATION = "authentication"
    OTHER = "other"


class MemoryType(StrEnum):
    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    PROCEDURAL = "procedural"


class MemoryScope(StrEnum):
    SESSION = "session"
    PROJECT = "project"
    ORG = "org"


class ArtifactType(StrEnum):
    TRACE = "trace"
    SCREENSHOT = "screenshot"
    DOM_SNAPSHOT = "dom_snapshot"
    ACCESSIBILITY_TREE = "accessibility_tree"
    VISION_ANNOTATION = "vision_annotation"
    OCR_OUTPUT = "ocr_output"
    VIDEO = "video"
    LOG = "log"
    REPORT = "report"
    HAR = "har"
    CONSOLE = "console"
    NETWORK = "network"
    PATCH = "patch"
    OTHER = "other"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class ApprovalType(StrEnum):
    HEALING_PATCH = "healing_patch"
    GATE_OVERRIDE = "gate_override"
    ACCEPTED_RISK = "accepted_risk"
    MANUAL_RERUN = "manual_rerun"
    VISUAL_ACTION = "visual_action"
    OTHER = "other"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentRunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TriageCategory(StrEnum):
    BUG = "bug"
    FLAKY = "flaky"
    ENV = "env"
    TEST_ISSUE = "test_issue"
    PERFORMANCE_ISSUE = "performance_issue"
    SECURITY_ISSUE = "security_issue"
    UNKNOWN = "unknown"


class GateResult(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    BLOCKED = "blocked"


class GatePolicyStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"


class GatePolicyScopeType(StrEnum):
    GLOBAL = "global"
    WORKSPACE = "workspace"
    PROJECT = "project"
    ENVIRONMENT = "environment"
    STAGE = "stage"
    DOMAIN = "domain"


class GatePolicyMode(StrEnum):
    OBSERVE = "observe"
    SHADOW = "shadow"
    ENFORCE = "enforce"


class GraphStatus(StrEnum):
    DRAFT = "draft"
    CANDIDATE = "candidate"
    UNDER_REVIEW = "under_review"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"


class GraphScope(StrEnum):
    PROJECT = "project"
    ENVIRONMENT = "environment"


class GraphSource(StrEnum):
    OBSERVED = "observed"
    CANDIDATE = "candidate"
    CANONICAL = "canonical"


class GuardrailDecisionType(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


class GuardrailScope(StrEnum):
    REQUEST = "request"
    ROUTING = "routing"
    AGENT_OUTPUT = "agent_output"
    MEMORY_WRITE = "memory_write"
    ACTION = "action"
    TOOL = "tool"
    SKILL = "skill"
    CONNECTOR = "connector"
    SYSTEM = "system"


class GuardrailPolicyStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    DISABLED = "disabled"
    ARCHIVED = "archived"


class UserRole(StrEnum):
    ADMIN = "admin"
    USER = "user"
    SYSTEM = "system"
    AGENT = "agent"


class UserStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DISABLED = "disabled"


class SourceType(StrEnum):
    PR = "pr"
    MANUAL = "manual"
    SCHEDULE = "schedule"
    API = "api"


class IntegrationEventStatus(StrEnum):
    RECEIVED = "received"
    PROCESSED = "processed"
    FAILED = "failed"
