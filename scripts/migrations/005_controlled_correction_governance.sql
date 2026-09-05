-- Controlled Correction Governance runtime storage for PostgreSQL 15+.
-- Keeps legacy correction_records separate from governed proposal/application/validation/rollback records.

CREATE TABLE IF NOT EXISTS correction_proposals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  proposal_type VARCHAR(80) NOT NULL,
  status VARCHAR(40) NOT NULL DEFAULT 'draft',
  proposed_change JSONB NOT NULL DEFAULT '{}'::jsonb,
  requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE SET NULL,
  execution_id UUID REFERENCES executions(id) ON DELETE SET NULL,
  finding_id UUID,
  attribution_id VARCHAR(255),
  risk_level risk_level NOT NULL,
  requester_ref JSONB NOT NULL DEFAULT '{}'::jsonb,
  requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  promotion_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  promoted_at TIMESTAMPTZ,
  contract_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  request_id VARCHAR(255),
  idempotency_key VARCHAR(255) UNIQUE,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_correction_proposals_status CHECK (
    status IN ('draft', 'pending_approval', 'approved', 'rejected', 'cancelled')
  )
);

CREATE INDEX IF NOT EXISTS idx_correction_proposals_requirement ON correction_proposals(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_correction_proposals_execution ON correction_proposals(execution_id);
CREATE INDEX IF NOT EXISTS idx_correction_proposals_status ON correction_proposals(status);
CREATE INDEX IF NOT EXISTS idx_correction_proposals_type ON correction_proposals(proposal_type);

CREATE TRIGGER trg_correction_proposals_updated_at
BEFORE UPDATE ON correction_proposals
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS correction_applications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  correction_proposal_id UUID NOT NULL REFERENCES correction_proposals(id) ON DELETE CASCADE,
  idempotency_key VARCHAR(255) NOT NULL,
  request_id VARCHAR(255) NOT NULL,
  status VARCHAR(40) NOT NULL DEFAULT 'pending',
  applied_change_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  side_effect_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  contract_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  applied_by UUID REFERENCES users(id) ON DELETE SET NULL,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_correction_applications_status CHECK (
    status IN ('pending', 'applying', 'applied', 'failed_to_apply')
  ),
  CONSTRAINT uq_correction_applications_proposal_idempotency UNIQUE (correction_proposal_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_correction_applications_proposal ON correction_applications(correction_proposal_id);
CREATE INDEX IF NOT EXISTS idx_correction_applications_status ON correction_applications(status);
CREATE INDEX IF NOT EXISTS idx_correction_applications_request ON correction_applications(request_id);

CREATE TRIGGER trg_correction_applications_updated_at
BEFORE UPDATE ON correction_applications
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS correction_validations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  correction_proposal_id UUID NOT NULL REFERENCES correction_proposals(id) ON DELETE CASCADE,
  correction_application_id UUID NOT NULL REFERENCES correction_applications(id) ON DELETE CASCADE,
  idempotency_key VARCHAR(255) NOT NULL,
  request_id VARCHAR(255) NOT NULL,
  status VARCHAR(40) NOT NULL DEFAULT 'pending',
  result JSONB NOT NULL DEFAULT '{}'::jsonb,
  trace_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  contract_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_correction_validations_status CHECK (
    status IN ('pending', 'running', 'validated', 'validation_failed', 'cancelled', 'error')
  ),
  CONSTRAINT uq_correction_validations_application_idempotency UNIQUE (correction_application_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_correction_validations_proposal ON correction_validations(correction_proposal_id);
CREATE INDEX IF NOT EXISTS idx_correction_validations_application ON correction_validations(correction_application_id);
CREATE INDEX IF NOT EXISTS idx_correction_validations_status ON correction_validations(status);
CREATE INDEX IF NOT EXISTS idx_correction_validations_request ON correction_validations(request_id);

CREATE TRIGGER trg_correction_validations_updated_at
BEFORE UPDATE ON correction_validations
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS rollback_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  correction_proposal_id UUID NOT NULL REFERENCES correction_proposals(id) ON DELETE CASCADE,
  correction_application_id UUID REFERENCES correction_applications(id) ON DELETE SET NULL,
  correction_validation_id UUID REFERENCES correction_validations(id) ON DELETE SET NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  request_id VARCHAR(255) NOT NULL,
  status VARCHAR(40) NOT NULL,
  rollback_reason TEXT NOT NULL,
  rollback_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  contract_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_rollback_records_status CHECK (
    status IN ('rollback_not_required', 'rolling_back', 'rolled_back', 'rollback_failed')
  ),
  CONSTRAINT uq_rollback_records_proposal_idempotency UNIQUE (correction_proposal_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_rollback_records_proposal ON rollback_records(correction_proposal_id);
CREATE INDEX IF NOT EXISTS idx_rollback_records_application ON rollback_records(correction_application_id);
CREATE INDEX IF NOT EXISTS idx_rollback_records_validation ON rollback_records(correction_validation_id);
CREATE INDEX IF NOT EXISTS idx_rollback_records_status ON rollback_records(status);
CREATE INDEX IF NOT EXISTS idx_rollback_records_request ON rollback_records(request_id);

CREATE TRIGGER trg_rollback_records_updated_at
BEFORE UPDATE ON rollback_records
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
