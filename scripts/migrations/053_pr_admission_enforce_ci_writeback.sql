-- P23 Service-owned CI conclusion, approval-backed Enforce, and exact-head writeback.
-- Historical ci-gate SkillVersion/output snapshots are intentionally not updated.

ALTER TABLE admission_runs ALTER COLUMN workflow_version SET DEFAULT 'p23.ci-enforce.v1';
ALTER TABLE admission_runs DROP CONSTRAINT IF EXISTS chk_admission_runs_mode;
ALTER TABLE admission_runs
  ADD CONSTRAINT chk_admission_runs_mode CHECK (admission_mode IN ('observe', 'shadow', 'enforce'));
ALTER TABLE admission_runs DROP CONSTRAINT IF EXISTS chk_admission_runs_non_authoritative;
ALTER TABLE admission_runs
  ADD CONSTRAINT chk_admission_runs_non_authoritative CHECK (
    (admission_mode = 'enforce' AND non_authoritative = FALSE) OR
    (admission_mode <> 'enforce' AND non_authoritative = TRUE)
  );

CREATE TABLE IF NOT EXISTS ci_enforcement_policies (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  repository_ref VARCHAR(1000) NOT NULL,
  check_name VARCHAR(120) NOT NULL,
  mode VARCHAR(16) NOT NULL,
  status VARCHAR(24) NOT NULL,
  branch_protection_configured BOOLEAN NOT NULL DEFAULT FALSE,
  policy_hash VARCHAR(80) NOT NULL,
  activation_approval_id UUID REFERENCES approvals(id) ON DELETE RESTRICT,
  pending_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  idempotency_key VARCHAR(255) NOT NULL,
  lock_version INTEGER NOT NULL DEFAULT 1,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_ci_enforcement_policy_scope UNIQUE (tenant_id, workspace_id, project_id, repository_ref, check_name),
  CONSTRAINT chk_ci_enforcement_policy_mode CHECK (mode IN ('observe', 'shadow', 'enforce')),
  CONSTRAINT chk_ci_enforcement_policy_status CHECK (status IN ('active', 'approval_pending', 'disabled')),
  CONSTRAINT chk_ci_enforcement_policy_hash CHECK (length(policy_hash) = 71 AND policy_hash LIKE 'sha256:%'),
  CONSTRAINT chk_ci_enforcement_policy_lock CHECK (lock_version > 0)
);
CREATE INDEX IF NOT EXISTS idx_ci_enforcement_policy_scope
  ON ci_enforcement_policies(tenant_id, workspace_id, project_id, repository_ref);
CREATE TRIGGER trg_ci_enforcement_policies_updated_at
BEFORE UPDATE ON ci_enforcement_policies
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS ci_writeback_attempts (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  admission_run_id UUID NOT NULL REFERENCES admission_runs(id) ON DELETE RESTRICT,
  connector_binding_id UUID NOT NULL REFERENCES skill_connector_bindings(id) ON DELETE RESTRICT,
  provider VARCHAR(32) NOT NULL,
  repository_ref VARCHAR(1000) NOT NULL,
  pull_request_number INTEGER NOT NULL,
  head_sha VARCHAR(64) NOT NULL,
  check_name VARCHAR(120) NOT NULL,
  admission_mode VARCHAR(16) NOT NULL,
  policy_hash VARCHAR(80) NOT NULL,
  idempotency_key VARCHAR(80) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'pending',
  conclusion_snapshot JSONB NOT NULL,
  enforcement_snapshot JSONB NOT NULL,
  stale_revision_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  request_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  response_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  external_action_ref JSONB,
  legacy_field_notice JSONB,
  connector_call_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  attempt_count INTEGER NOT NULL DEFAULT 1,
  last_error_code VARCHAR(160),
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_ci_writeback_attempt_idempotency UNIQUE (idempotency_key),
  CONSTRAINT chk_ci_writeback_attempt_status CHECK (status IN ('pending', 'in_progress', 'success', 'failure', 'neutral', 'cancelled', 'stale', 'write_failed', 'unknown')),
  CONSTRAINT chk_ci_writeback_attempt_provider CHECK (provider IN ('github', 'gitlab', 'mock-scm')),
  CONSTRAINT chk_ci_writeback_attempt_mode CHECK (admission_mode IN ('observe', 'shadow', 'enforce')),
  CONSTRAINT chk_ci_writeback_attempt_count CHECK (attempt_count > 0),
  CONSTRAINT chk_ci_writeback_attempt_request_hash CHECK (length(request_hash) = 71 AND request_hash LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS idx_ci_writeback_attempt_scope
  ON ci_writeback_attempts(tenant_id, workspace_id, project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ci_writeback_attempt_pr_head
  ON ci_writeback_attempts(project_id, repository_ref, pull_request_number, head_sha, check_name);
CREATE INDEX IF NOT EXISTS idx_ci_writeback_attempt_admission
  ON ci_writeback_attempts(admission_run_id, created_at DESC);
CREATE TRIGGER trg_ci_writeback_attempts_updated_at
BEFORE UPDATE ON ci_writeback_attempts
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('ci.write', 'integrations', 'Write a Service-owned Admission CI conclusion through a scoped SCM Connector binding.', 'high', TRUE),
  ('enforce.manage', 'integrations', 'Request and approve governed PR Admission Enforce policy changes.', 'high', TRUE),
  ('ci.retry', 'integrations', 'Request an approval-backed retry of a failed or unknown CI writeback attempt.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = TRUE;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('enterprise', 'ci.write', TRUE),
  ('enterprise', 'enforce.manage', TRUE),
  ('enterprise', 'ci.retry', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;

COMMENT ON TABLE ci_enforcement_policies IS
  'P23 Service-owned CI writeback mode policy. Enforce activation requires Approval; branch protection remains externally managed.';
COMMENT ON TABLE ci_writeback_attempts IS
  'P23 exact-head, idempotent, redacted Connector writeback facts. No PR close, merge, branch delete, or code mutation semantics.';
COMMENT ON TABLE admission_runs IS
  'P23 Service-owned PR Admission. Observe/Shadow are non-authoritative; only approved Enforce persists an authoritative Gate and may emit blocking CI failure.';
