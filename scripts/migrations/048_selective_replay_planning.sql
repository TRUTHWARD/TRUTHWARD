-- P19 Selective Replay planning snapshots. Planning never creates execution tasks or retries.

CREATE TABLE IF NOT EXISTS selective_replay_plans (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  impact_result_id UUID NOT NULL REFERENCES impact_results(id) ON DELETE RESTRICT,
  base_execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE RESTRICT,
  coverage_snapshot_id UUID NOT NULL REFERENCES graph_coverage_snapshots(id) ON DELETE RESTRICT,
  environment_id UUID REFERENCES project_environments(id) ON DELETE RESTRICT,
  graph_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  graph_assessment_id UUID REFERENCES canonical_graph_staleness_assessments(id) ON DELETE RESTRICT,
  algorithm_version VARCHAR(80) NOT NULL,
  input_fingerprint VARCHAR(80) NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  plan_hash VARCHAR(80) NOT NULL,
  status VARCHAR(24) NOT NULL,
  risk_level VARCHAR(20) NOT NULL,
  fallback_used BOOLEAN NOT NULL DEFAULT FALSE,
  selected_test_count INTEGER NOT NULL,
  estimated_seconds INTEGER NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  plan_snapshot JSONB NOT NULL,
  replay_snapshot JSONB NOT NULL,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_selective_replay_plans_fingerprint UNIQUE (tenant_id, workspace_id, project_id, input_fingerprint),
  CONSTRAINT uq_selective_replay_plans_idempotency UNIQUE (tenant_id, workspace_id, project_id, idempotency_key),
  CONSTRAINT uq_selective_replay_plans_hash UNIQUE (plan_hash),
  CONSTRAINT chk_selective_replay_plans_status CHECK (status IN ('ready', 'fallback')),
  CONSTRAINT chk_selective_replay_plans_risk CHECK (risk_level IN ('low', 'medium', 'high')),
  CONSTRAINT chk_selective_replay_plans_nonempty CHECK (selected_test_count > 0),
  CONSTRAINT chk_selective_replay_plans_cost CHECK (estimated_seconds > 0),
  CONSTRAINT chk_selective_replay_plans_fingerprint CHECK (length(input_fingerprint) = 71 AND input_fingerprint LIKE 'sha256:%'),
  CONSTRAINT chk_selective_replay_plans_plan_hash CHECK (length(plan_hash) = 71 AND plan_hash LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS idx_selective_replay_plans_scope ON selective_replay_plans(tenant_id, workspace_id, project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_selective_replay_plans_impact ON selective_replay_plans(impact_result_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_selective_replay_plans_execution ON selective_replay_plans(base_execution_id, created_at DESC);

CREATE OR REPLACE FUNCTION protect_selective_replay_plan_mutation()
RETURNS TRIGGER AS $$ BEGIN
  RAISE EXCEPTION 'Selective Replay plan snapshots are immutable' USING ERRCODE = '55000';
END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_selective_replay_plan_immutable ON selective_replay_plans;
CREATE TRIGGER trg_selective_replay_plan_immutable BEFORE UPDATE OR DELETE ON selective_replay_plans FOR EACH ROW EXECUTE FUNCTION protect_selective_replay_plan_mutation();

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('replay.plan.read', 'replay', 'Read backend-computed Selective Replay plans.', 'low', TRUE),
  ('replay.plan.create', 'replay', 'Create an immutable Selective Replay plan without executing it.', 'low', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET category = EXCLUDED.category, description = EXCLUDED.description, risk_level = EXCLUDED.risk_level, is_active = TRUE;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'replay.plan.read', TRUE),
  ('pro', 'replay.plan.read', TRUE),
  ('enterprise', 'replay.plan.read', TRUE),
  ('enterprise', 'replay.plan.create', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;

COMMENT ON TABLE selective_replay_plans IS 'P19 immutable planning facts only. Service-managed execution remains the sole task creation and execution boundary.';
