-- Replay Governance Approval Mode P1 policy baseline.
-- No backfill is required. Absence of a row means the service default remains approval mode always.

CREATE TABLE IF NOT EXISTS replay_governance_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scope_type VARCHAR(40) NOT NULL DEFAULT 'global',
  scope_id VARCHAR(120) NOT NULL DEFAULT 'global',
  approval_mode VARCHAR(40) NOT NULL DEFAULT 'always',
  threshold_level VARCHAR(40) NOT NULL DEFAULT 'high',
  policy_rules JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_replay_governance_policies_scope UNIQUE (scope_type, scope_id),
  CONSTRAINT chk_replay_governance_policies_approval_mode CHECK (approval_mode IN ('always', 'policy_only', 'threshold')),
  CONSTRAINT chk_replay_governance_policies_threshold_level CHECK (threshold_level IN ('low', 'medium', 'high')),
  CONSTRAINT chk_replay_governance_policies_rules_object CHECK (jsonb_typeof(policy_rules) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_replay_governance_policies_scope
  ON replay_governance_policies(scope_type, scope_id);

DROP TRIGGER IF EXISTS trg_replay_governance_policies_updated_at ON replay_governance_policies;
CREATE TRIGGER trg_replay_governance_policies_updated_at
BEFORE UPDATE ON replay_governance_policies
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
