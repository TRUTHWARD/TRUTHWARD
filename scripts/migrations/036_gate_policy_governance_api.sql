-- P04 Gate Policy governance API, authorization, review, and lifecycle closure.
-- This migration does not activate a policy, execute Gate, or rewrite Replay.

ALTER TABLE gate_policies
  ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS idx_gate_policies_project
  ON gate_policies(project_id);

ALTER TABLE gate_policy_versions
  ADD COLUMN IF NOT EXISTS validation_status VARCHAR(32) NOT NULL DEFAULT 'not_validated',
  ADD COLUMN IF NOT EXISTS validation_report JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS validated_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS governance_status VARCHAR(40) NOT NULL DEFAULT 'draft',
  ADD COLUMN IF NOT EXISTS current_approval_id UUID REFERENCES approvals(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS submitted_by UUID REFERENCES users(id) ON DELETE SET NULL;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_gate_policy_versions_validation_status') THEN
    ALTER TABLE gate_policy_versions
      ADD CONSTRAINT chk_gate_policy_versions_validation_status
      CHECK (validation_status IN ('not_validated', 'valid', 'invalid'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_gate_policy_versions_governance_status') THEN
    ALTER TABLE gate_policy_versions
      ADD CONSTRAINT chk_gate_policy_versions_governance_status
      CHECK (governance_status IN (
        'draft', 'review_pending', 'review_approved', 'review_rejected',
        'review_cancelled', 'review_expired', 'transition_pending',
        'transition_applied', 'transition_rejected', 'transition_cancelled', 'transition_expired'
      ));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_gate_policy_versions_governance
  ON gate_policy_versions(tenant_id, workspace_id, governance_status);
CREATE INDEX IF NOT EXISTS idx_gate_policy_versions_current_approval
  ON gate_policy_versions(current_approval_id);

CREATE TABLE IF NOT EXISTS gate_policy_governance_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  operation VARCHAR(80) NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  resource_type VARCHAR(100) NOT NULL,
  resource_id VARCHAR(255) NOT NULL,
  approval_id UUID REFERENCES approvals(id) ON DELETE SET NULL,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_gate_policy_governance_request_idempotency
    UNIQUE (tenant_id, workspace_id, operation, idempotency_key),
  CONSTRAINT chk_gate_policy_governance_tenant_not_blank CHECK (length(trim(tenant_id)) > 0),
  CONSTRAINT chk_gate_policy_governance_workspace_not_blank CHECK (length(trim(workspace_id)) > 0),
  CONSTRAINT chk_gate_policy_governance_hash_length CHECK (length(request_hash) = 71),
  CONSTRAINT chk_gate_policy_governance_hash_prefix CHECK (substr(request_hash, 1, 7) = 'sha256:')
);

CREATE INDEX IF NOT EXISTS idx_gate_policy_governance_project
  ON gate_policy_governance_requests(project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_gate_policy_governance_resource
  ON gate_policy_governance_requests(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_gate_policy_governance_approval
  ON gate_policy_governance_requests(approval_id);

DROP TRIGGER IF EXISTS trg_gate_policy_governance_requests_updated_at
  ON gate_policy_governance_requests;
CREATE TRIGGER trg_gate_policy_governance_requests_updated_at
BEFORE UPDATE ON gate_policy_governance_requests
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Frozen content remains immutable after publication. P04 permits only the
-- explicit, approval-backed status/governance fields to transition.
CREATE OR REPLACE FUNCTION prevent_published_gate_policy_version_update()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.status <> 'draft' AND (
    NEW.policy_id IS DISTINCT FROM OLD.policy_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
    OR NEW.version_number IS DISTINCT FROM OLD.version_number
    OR NEW.version_ref IS DISTINCT FROM OLD.version_ref
    OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
    OR NEW.policy_snapshot IS DISTINCT FROM OLD.policy_snapshot
    OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
    OR NEW.capability_ref IS DISTINCT FROM OLD.capability_ref
    OR NEW.approval_policy_ref IS DISTINCT FROM OLD.approval_policy_ref
  ) THEN
    RAISE EXCEPTION 'published Gate Policy versions are immutable'
      USING ERRCODE = '55000';
  END IF;

  IF NEW.status <> 'draft' AND (
    NEW.policy_id IS DISTINCT FROM OLD.policy_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
    OR NEW.version_number IS DISTINCT FROM OLD.version_number
    OR NEW.version_ref IS DISTINCT FROM OLD.version_ref
    OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
    OR NEW.policy_snapshot IS DISTINCT FROM OLD.policy_snapshot
    OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
    OR NEW.capability_ref IS DISTINCT FROM OLD.capability_ref
    OR NEW.approval_policy_ref IS DISTINCT FROM OLD.approval_policy_ref
  ) THEN
    RAISE EXCEPTION 'publishing a Gate Policy version cannot change its frozen content'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('gate_policy.read', 'gate_policy', 'Read project-scoped Gate Policy governance projections.', 'low', TRUE),
  ('gate_policy.draft.write', 'gate_policy', 'Create, update, and validate Gate Policy drafts.', 'high', TRUE),
  ('gate_policy.submit', 'gate_policy', 'Submit validated Gate Policy drafts for review.', 'high', TRUE),
  ('gate_policy.review', 'gate_policy', 'Approve or reject Gate Policy governance reviews.', 'high', TRUE),
  ('gate_policy.lifecycle.manage', 'gate_policy', 'Request disable, deprecate, or archive transitions.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = EXCLUDED.is_active;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'gate_policy.read', TRUE),
  ('pro', 'gate_policy.read', TRUE),
  ('enterprise', 'gate_policy.read', TRUE),
  ('enterprise', 'gate_policy.draft.write', TRUE),
  ('enterprise', 'gate_policy.submit', TRUE),
  ('enterprise', 'gate_policy.review', TRUE),
  ('enterprise', 'gate_policy.lifecycle.manage', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = EXCLUDED.enabled;

INSERT INTO rbac_role_capabilities (role_name, capability_key, effect)
VALUES
  ('user', 'gate_policy.read', 'allow'),
  ('admin', 'gate_policy.read', 'allow'),
  ('admin', 'gate_policy.draft.write', 'allow'),
  ('admin', 'gate_policy.submit', 'allow'),
  ('admin', 'gate_policy.review', 'allow'),
  ('admin', 'gate_policy.lifecycle.manage', 'allow'),
  ('system', 'gate_policy.read', 'allow'),
  ('system', 'gate_policy.draft.write', 'allow'),
  ('system', 'gate_policy.submit', 'allow'),
  ('system', 'gate_policy.review', 'allow'),
  ('system', 'gate_policy.lifecycle.manage', 'allow')
ON CONFLICT (role_name, capability_key) DO UPDATE SET effect = EXCLUDED.effect;

COMMENT ON TABLE gate_policy_governance_requests IS
  'P04 Service-owned idempotency journal for Gate Policy management operations; never executes Gate or Skill.';
