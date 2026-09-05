-- P21 PR static scan, selective smoke, and untrusted-code sandbox execution refs.
-- Execution tasks, tool calls, artifacts, raw findings, and canonical findings reuse existing tables.

CREATE TABLE IF NOT EXISTS admission_runs (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  pr_context_version_id UUID NOT NULL REFERENCES scm_pr_context_versions(id) ON DELETE RESTRICT,
  requirement_match_snapshot_id UUID REFERENCES requirement_match_snapshots(id) ON DELETE RESTRICT,
  selective_replay_plan_id UUID NOT NULL REFERENCES selective_replay_plans(id) ON DELETE RESTRICT,
  environment_id UUID REFERENCES project_environments(id) ON DELETE RESTRICT,
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE RESTRICT,
  source_head_sha VARCHAR(64) NOT NULL,
  input_fingerprint VARCHAR(80) NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'queued',
  sandbox_profile JSONB NOT NULL,
  plan_snapshot JSONB NOT NULL,
  result_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  replay_snapshot JSONB NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_admission_runs_fingerprint UNIQUE (tenant_id, workspace_id, project_id, input_fingerprint),
  CONSTRAINT uq_admission_runs_idempotency UNIQUE (tenant_id, workspace_id, project_id, idempotency_key),
  CONSTRAINT uq_admission_runs_execution UNIQUE (execution_id),
  CONSTRAINT chk_admission_runs_status CHECK (status IN ('queued', 'running', 'completed', 'failed', 'partial', 'unavailable', 'cancelled', 'stale')),
  CONSTRAINT chk_admission_runs_fingerprint CHECK (length(input_fingerprint) = 71 AND input_fingerprint LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS idx_admission_runs_scope ON admission_runs(tenant_id, workspace_id, project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admission_runs_pr_context ON admission_runs(pr_context_version_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admission_runs_status ON admission_runs(status, updated_at DESC);

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('admission.read', 'integrations', 'Read PR scan, smoke, sandbox, and normalized evidence projections.', 'low', TRUE),
  ('admission.execute', 'integrations', 'Start the fixed service-managed PR scan and selective smoke workflow.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET category = EXCLUDED.category, description = EXCLUDED.description, risk_level = EXCLUDED.risk_level, is_active = TRUE;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'admission.read', TRUE),
  ('pro', 'admission.read', TRUE),
  ('enterprise', 'admission.read', TRUE),
  ('enterprise', 'admission.execute', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;

COMMENT ON TABLE admission_runs IS 'P21 minimal orchestration refs and frozen snapshots. No Gate or P22 admission decision is stored here.';
