-- P06: historical Gate Policy simulation, Observe/Shadow/Enforce modes,
-- approval-backed atomic activation, and auditable rollback.
-- Forward-only: historical gate_results and gate_input_snapshots are never updated.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'gate_policy_mode') THEN
    CREATE TYPE gate_policy_mode AS ENUM ('observe', 'shadow', 'enforce');
  END IF;
END $$;

ALTER TABLE gate_policy_bindings
  ADD COLUMN IF NOT EXISTS mode gate_policy_mode NOT NULL DEFAULT 'enforce';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_gate_policy_bindings_mode'
  ) THEN
    ALTER TABLE gate_policy_bindings
      ADD CONSTRAINT chk_gate_policy_bindings_mode
      CHECK (mode IN ('observe', 'shadow', 'enforce'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_gate_policy_bindings_mode_resolution
  ON gate_policy_bindings(tenant_id, workspace_id, scope_type, scope_key, mode, status);

CREATE TABLE IF NOT EXISTS gate_policy_simulation_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  policy_id UUID NOT NULL REFERENCES gate_policies(id) ON DELETE RESTRICT,
  source_policy_version_id UUID REFERENCES gate_policy_versions(id) ON DELETE SET NULL,
  policy_version_id UUID NOT NULL REFERENCES gate_policy_versions(id) ON DELETE RESTRICT,
  policy_version_hash VARCHAR(80) NOT NULL,
  evaluator_version VARCHAR(80) NOT NULL,
  run_type VARCHAR(24) NOT NULL DEFAULT 'historical',
  status VARCHAR(24) NOT NULL DEFAULT 'queued',
  dataset_fingerprint VARCHAR(80) NOT NULL,
  case_snapshot_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  total_cases INTEGER NOT NULL DEFAULT 0,
  completed_cases INTEGER NOT NULL DEFAULT 0,
  unavailable_cases INTEGER NOT NULL DEFAULT 0,
  failed_cases INTEGER NOT NULL DEFAULT 0,
  error_code VARCHAR(120),
  job_id UUID REFERENCES jobs(id) ON DELETE SET NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  retention_until TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_gate_policy_simulation_run_idempotency UNIQUE (tenant_id, workspace_id, run_type, idempotency_key),
  CONSTRAINT chk_gate_policy_simulation_run_type CHECK (run_type IN ('historical', 'shadow')),
  CONSTRAINT chk_gate_policy_simulation_run_status CHECK (status IN ('queued', 'running', 'completed', 'partial', 'failed', 'cancelled', 'timed_out')),
  CONSTRAINT chk_gate_policy_simulation_dataset_hash_length CHECK (length(dataset_fingerprint) = 71),
  CONSTRAINT chk_gate_policy_simulation_dataset_hash_prefix CHECK (substr(dataset_fingerprint, 1, 7) = 'sha256:'),
  CONSTRAINT chk_gate_policy_simulation_policy_hash_length CHECK (length(policy_version_hash) = 71),
  CONSTRAINT chk_gate_policy_simulation_policy_hash_prefix CHECK (substr(policy_version_hash, 1, 7) = 'sha256:'),
  CONSTRAINT chk_gate_policy_simulation_request_hash_length CHECK (length(request_hash) = 71),
  CONSTRAINT chk_gate_policy_simulation_request_hash_prefix CHECK (substr(request_hash, 1, 7) = 'sha256:'),
  CONSTRAINT chk_gate_policy_simulation_counts CHECK (total_cases >= 0 AND completed_cases >= 0 AND unavailable_cases >= 0 AND failed_cases >= 0),
  CONSTRAINT chk_gate_policy_simulation_case_refs_array CHECK (jsonb_typeof(case_snapshot_refs) = 'array'),
  CONSTRAINT chk_gate_policy_simulation_summary_object CHECK (jsonb_typeof(summary) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_gate_policy_simulation_project ON gate_policy_simulation_runs(project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_gate_policy_simulation_version ON gate_policy_simulation_runs(policy_version_id, status);
CREATE INDEX IF NOT EXISTS idx_gate_policy_simulation_retention ON gate_policy_simulation_runs(retention_until);

CREATE TABLE IF NOT EXISTS gate_policy_simulation_cases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  simulation_run_id UUID NOT NULL REFERENCES gate_policy_simulation_runs(id) ON DELETE CASCADE,
  case_index INTEGER NOT NULL,
  gate_input_snapshot_id UUID REFERENCES gate_input_snapshots(id) ON DELETE SET NULL,
  gate_decision_id UUID REFERENCES gate_results(id) ON DELETE SET NULL,
  execution_id UUID REFERENCES executions(id) ON DELETE SET NULL,
  gate_input_snapshot_ref VARCHAR(500) NOT NULL,
  gate_input_snapshot_hash VARCHAR(80) NOT NULL,
  input_fingerprint VARCHAR(80),
  case_snapshot_hash VARCHAR(80) NOT NULL,
  status VARCHAR(24) NOT NULL,
  old_decision VARCHAR(24),
  new_decision VARCHAR(24),
  old_decision_snapshot_hash VARCHAR(80),
  new_decision_snapshot_hash VARCHAR(80),
  reason_diff JSONB NOT NULL DEFAULT '{}'::jsonb,
  false_pass_risk BOOLEAN NOT NULL DEFAULT FALSE,
  new_block BOOLEAN NOT NULL DEFAULT FALSE,
  error_code VARCHAR(120),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_gate_policy_simulation_case_index UNIQUE (simulation_run_id, case_index),
  CONSTRAINT uq_gate_policy_simulation_case_snapshot UNIQUE (simulation_run_id, gate_input_snapshot_ref),
  CONSTRAINT chk_gate_policy_simulation_case_status CHECK (status IN ('completed', 'unavailable', 'failed')),
  CONSTRAINT chk_gate_policy_simulation_reason_diff_object CHECK (jsonb_typeof(reason_diff) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_gate_policy_simulation_case_run ON gate_policy_simulation_cases(simulation_run_id, case_index);
CREATE INDEX IF NOT EXISTS idx_gate_policy_simulation_case_gate ON gate_policy_simulation_cases(gate_decision_id);

CREATE TABLE IF NOT EXISTS gate_policy_binding_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  action VARCHAR(24) NOT NULL,
  mode gate_policy_mode NOT NULL,
  status VARCHAR(24) NOT NULL,
  binding_id UUID NOT NULL REFERENCES gate_policy_bindings(id) ON DELETE RESTRICT,
  previous_binding_id UUID REFERENCES gate_policy_bindings(id) ON DELETE SET NULL,
  policy_version_id UUID NOT NULL REFERENCES gate_policy_versions(id) ON DELETE RESTRICT,
  previous_policy_version_id UUID REFERENCES gate_policy_versions(id) ON DELETE SET NULL,
  simulation_run_id UUID REFERENCES gate_policy_simulation_runs(id) ON DELETE SET NULL,
  approval_id UUID REFERENCES approvals(id) ON DELETE SET NULL,
  before_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  after_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_gate_policy_binding_history_idempotency UNIQUE (tenant_id, workspace_id, action, idempotency_key),
  CONSTRAINT chk_gate_policy_binding_history_action CHECK (action IN ('mode_change', 'activation', 'rollback')),
  CONSTRAINT chk_gate_policy_binding_history_mode CHECK (mode IN ('observe', 'shadow', 'enforce')),
  CONSTRAINT chk_gate_policy_binding_history_status CHECK (status IN ('applied', 'failed')),
  CONSTRAINT chk_gate_policy_binding_history_before_object CHECK (jsonb_typeof(before_snapshot) = 'object'),
  CONSTRAINT chk_gate_policy_binding_history_after_object CHECK (jsonb_typeof(after_snapshot) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_gate_policy_binding_history_project ON gate_policy_binding_history(project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_gate_policy_binding_history_binding ON gate_policy_binding_history(binding_id);

DROP TRIGGER IF EXISTS trg_gate_policy_simulation_runs_updated_at ON gate_policy_simulation_runs;
CREATE TRIGGER trg_gate_policy_simulation_runs_updated_at
BEFORE UPDATE ON gate_policy_simulation_runs
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE OR REPLACE FUNCTION prevent_gate_policy_binding_history_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Gate Policy binding history is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_gate_policy_binding_history_immutable ON gate_policy_binding_history;
CREATE TRIGGER trg_gate_policy_binding_history_immutable
BEFORE UPDATE OR DELETE ON gate_policy_binding_history
FOR EACH ROW EXECUTE FUNCTION prevent_gate_policy_binding_history_mutation();

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('gate_policy.simulate', 'gate_policy', 'Run non-authoritative Gate Policy simulation against frozen historical inputs.', 'high', TRUE),
  ('gate_policy.mode.manage', 'gate_policy', 'Manage Observe and Shadow Gate Policy modes.', 'high', TRUE),
  ('gate_policy.activate', 'gate_policy', 'Request approval-backed Enforce activation.', 'high', TRUE),
  ('gate_policy.rollback', 'gate_policy', 'Request approval-backed rollback to an immutable Gate Policy version.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = EXCLUDED.is_active;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('enterprise', 'gate_policy.simulate', TRUE),
  ('enterprise', 'gate_policy.mode.manage', TRUE),
  ('enterprise', 'gate_policy.activate', TRUE),
  ('enterprise', 'gate_policy.rollback', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = EXCLUDED.enabled;

INSERT INTO rbac_role_capabilities (role_name, capability_key, effect)
VALUES
  ('admin', 'gate_policy.simulate', 'allow'),
  ('admin', 'gate_policy.mode.manage', 'allow'),
  ('admin', 'gate_policy.activate', 'allow'),
  ('admin', 'gate_policy.rollback', 'allow'),
  ('system', 'gate_policy.simulate', 'allow'),
  ('system', 'gate_policy.mode.manage', 'allow'),
  ('system', 'gate_policy.activate', 'allow'),
  ('system', 'gate_policy.rollback', 'allow')
ON CONFLICT (role_name, capability_key) DO UPDATE SET effect = EXCLUDED.effect;

COMMENT ON TABLE gate_policy_simulation_runs IS 'P06 immutable-dataset, non-authoritative historical and Shadow Gate Policy simulation runs.';
COMMENT ON TABLE gate_policy_simulation_cases IS 'P06 backend-computed old/new Gate diffs; never authoritative Gate decisions.';
COMMENT ON TABLE gate_policy_binding_history IS 'P06 append-only mode/activation/rollback binding history.';
