-- P25 typed Improvement Proposal Governance.
-- Proposal routing creates target-authority drafts/proposals only; it never applies production changes.

ALTER TABLE skill_versions
  ADD COLUMN IF NOT EXISTS governance_status VARCHAR(24) NOT NULL DEFAULT 'active';
ALTER TABLE skill_versions DROP CONSTRAINT IF EXISTS chk_skill_versions_governance_status;
ALTER TABLE skill_versions ADD CONSTRAINT chk_skill_versions_governance_status
  CHECK (governance_status IN ('draft', 'active', 'rejected', 'deprecated', 'archived'));

CREATE TABLE IF NOT EXISTS improvement_proposals (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  source_lesson_refs JSONB NOT NULL,
  source_lessons_hash VARCHAR(80) NOT NULL,
  target_type VARCHAR(48) NOT NULL,
  target_id VARCHAR(255) NOT NULL,
  target_key VARCHAR(255) NOT NULL,
  target_base_version VARCHAR(255) NOT NULL,
  target_base_hash VARCHAR(80) NOT NULL,
  target_snapshot JSONB NOT NULL,
  structured_change JSONB NOT NULL,
  change_hash VARCHAR(80) NOT NULL,
  rationale TEXT NOT NULL,
  evidence_refs JSONB NOT NULL,
  requested_risk VARCHAR(16) NOT NULL,
  evaluated_risk VARCHAR(16) NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  validation_plan JSONB NOT NULL,
  validation_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  status VARCHAR(40) NOT NULL DEFAULT 'draft',
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  route_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  effectiveness_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  rollback_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  effectiveness_window JSONB NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  lock_version INTEGER NOT NULL DEFAULT 1,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_improvement_proposal_idempotency UNIQUE (tenant_id, workspace_id, project_id, idempotency_key),
  CONSTRAINT chk_improvement_proposals_target_type CHECK (target_type IN (
    'skill', 'gate_policy', 'graph', 'graph_learning_policy',
    'test_case', 'test_step', 'tool_config', 'connector_config'
  )),
  CONSTRAINT chk_improvement_proposals_status CHECK (status IN (
    'draft', 'validation_failed', 'validated', 'review_pending',
    'review_approved', 'review_rejected', 'routed', 'effectiveness_pending',
    'effective', 'ineffective', 'inconclusive', 'rollback_pending',
    'rollback_routed', 'partial', 'failed', 'archived'
  )),
  CONSTRAINT chk_improvement_proposals_risk CHECK (
    requested_risk IN ('low', 'medium', 'high', 'critical') AND
    evaluated_risk IN ('low', 'medium', 'high', 'critical')
  ),
  CONSTRAINT chk_improvement_proposals_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_improvement_proposals_lock CHECK (lock_version > 0)
);
CREATE INDEX IF NOT EXISTS idx_improvement_proposals_scope_status
  ON improvement_proposals(tenant_id, workspace_id, project_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_improvement_proposals_target
  ON improvement_proposals(tenant_id, workspace_id, project_id, target_type, target_id);
DROP TRIGGER IF EXISTS trg_improvement_proposals_updated_at ON improvement_proposals;
CREATE TRIGGER trg_improvement_proposals_updated_at
BEFORE UPDATE ON improvement_proposals
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS improvement_proposal_versions (
  id UUID PRIMARY KEY,
  proposal_id UUID NOT NULL REFERENCES improvement_proposals(id) ON DELETE CASCADE,
  version_number INTEGER NOT NULL,
  content_hash VARCHAR(80) NOT NULL,
  source_lesson_refs JSONB NOT NULL,
  target_base_version VARCHAR(255) NOT NULL,
  target_base_hash VARCHAR(80) NOT NULL,
  snapshot JSONB NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_improvement_proposal_version UNIQUE (proposal_id, version_number),
  CONSTRAINT uq_improvement_proposal_version_hash UNIQUE (proposal_id, content_hash)
);
CREATE INDEX IF NOT EXISTS idx_improvement_proposal_versions_proposal
  ON improvement_proposal_versions(proposal_id, version_number);

CREATE TABLE IF NOT EXISTS improvement_validation_results (
  id UUID PRIMARY KEY,
  proposal_id UUID NOT NULL REFERENCES improvement_proposals(id) ON DELETE CASCADE,
  proposal_version INTEGER NOT NULL,
  status VARCHAR(24) NOT NULL,
  checks JSONB NOT NULL,
  historical_simulation JSONB NOT NULL,
  counterexample_regression JSONB,
  evidence_refs JSONB NOT NULL,
  metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
  result_hash VARCHAR(80) NOT NULL,
  validator_version VARCHAR(80) NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  validated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_improvement_validation_idempotency UNIQUE (proposal_id, idempotency_key),
  CONSTRAINT chk_improvement_validation_status CHECK (status IN ('passed', 'failed', 'insufficient', 'unavailable'))
);
CREATE INDEX IF NOT EXISTS idx_improvement_validation_proposal
  ON improvement_validation_results(proposal_id, validated_at);

CREATE TABLE IF NOT EXISTS improvement_effectiveness_results (
  id UUID PRIMARY KEY,
  proposal_id UUID NOT NULL REFERENCES improvement_proposals(id) ON DELETE RESTRICT,
  status VARCHAR(24) NOT NULL,
  target_outcome_ref JSONB NOT NULL,
  before_metrics JSONB NOT NULL,
  after_metrics JSONB NOT NULL,
  deltas JSONB NOT NULL,
  sample_size INTEGER NOT NULL,
  rollback_required BOOLEAN NOT NULL DEFAULT FALSE,
  evidence_refs JSONB NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  measured_by UUID REFERENCES users(id) ON DELETE SET NULL,
  measured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_improvement_effectiveness_idempotency UNIQUE (proposal_id, idempotency_key),
  CONSTRAINT chk_improvement_effectiveness_status CHECK (status IN ('effective', 'ineffective', 'inconclusive'))
);
CREATE INDEX IF NOT EXISTS idx_improvement_effectiveness_proposal
  ON improvement_effectiveness_results(proposal_id, measured_at);

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('improvement.read', 'knowledge', 'Read project-scoped typed Improvement Proposal projections.', 'low', TRUE),
  ('improvement.create', 'knowledge', 'Create, edit, and validate evidence-backed Improvement Proposals.', 'high', TRUE),
  ('improvement.review', 'knowledge', 'Submit and assess Improvement Proposals and effectiveness evidence.', 'high', TRUE),
  ('improvement.route', 'knowledge', 'Route an approved Improvement Proposal into its target authority workflow.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = TRUE;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'improvement.read', TRUE),
  ('pro', 'improvement.read', TRUE),
  ('enterprise', 'improvement.read', TRUE),
  ('enterprise', 'improvement.create', TRUE),
  ('enterprise', 'improvement.review', TRUE),
  ('enterprise', 'improvement.route', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;

COMMENT ON TABLE improvement_proposals IS
  'P25 typed Lesson-derived proposals. Routing is approval-backed and cannot directly apply a production change.';
COMMENT ON TABLE improvement_proposal_versions IS
  'Immutable P25 proposal snapshots for validation, Replay, conflict detection and rollback provenance.';
COMMENT ON TABLE improvement_effectiveness_results IS
  'Evidence-backed before/after outcomes. Ineffective results require governed target-authority rollback routing.';
