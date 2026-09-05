-- CCG Knowledge Promotion implemented Follow-up P0 storage for PostgreSQL 15+.
-- Persists append-only governance facts and optional projection state.

CREATE TABLE IF NOT EXISTS knowledge_promotion_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source VARCHAR(80) NOT NULL,
  source_correction_id UUID NOT NULL REFERENCES correction_proposals(id) ON DELETE CASCADE,
  correction_validation_id UUID NOT NULL REFERENCES correction_validations(id) ON DELETE RESTRICT,
  replay_validation_id VARCHAR(255),
  replay_validation_ref JSONB NOT NULL DEFAULT '{}'::jsonb,
  coverage_proof_bundle_id UUID NOT NULL REFERENCES coverage_proof_bundles(id) ON DELETE RESTRICT,
  coverage_proof_ref JSONB NOT NULL DEFAULT '{}'::jsonb,
  knowledge_entry_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  approval_state VARCHAR(40) NOT NULL,
  policy_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  rollback_ref JSONB NOT NULL DEFAULT '{}'::jsonb,
  supersede_ref JSONB NOT NULL DEFAULT '{}'::jsonb,
  projection_state VARCHAR(40) NOT NULL DEFAULT 'skipped',
  projection_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  status VARCHAR(40) NOT NULL DEFAULT 'pending',
  promoted_at TIMESTAMPTZ,
  promoted_by UUID REFERENCES users(id) ON DELETE SET NULL,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  contract_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  request_id VARCHAR(255) NOT NULL,
  idempotency_key VARCHAR(255),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_knowledge_promotion_records_status CHECK (
    status IN ('pending', 'promoted', 'rejected', 'rolled_back', 'superseded')
  ),
  CONSTRAINT chk_knowledge_promotion_records_approval_state CHECK (
    approval_state IN ('satisfied', 'not_required')
  ),
  CONSTRAINT chk_knowledge_promotion_records_projection_state CHECK (
    projection_state IN ('skipped', 'projected', 'projection_failed', 'retry')
  ),
  CONSTRAINT uq_knowledge_promotion_records_proposal_idempotency UNIQUE (source_correction_id, idempotency_key)
);

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'uq_knowledge_promotion_records_idempotency'
      AND conrelid = 'knowledge_promotion_records'::regclass
  ) THEN
    ALTER TABLE knowledge_promotion_records
      DROP CONSTRAINT uq_knowledge_promotion_records_idempotency;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'uq_knowledge_promotion_records_proposal_idempotency'
      AND conrelid = 'knowledge_promotion_records'::regclass
  ) THEN
    ALTER TABLE knowledge_promotion_records
      ADD CONSTRAINT uq_knowledge_promotion_records_proposal_idempotency
      UNIQUE (source_correction_id, idempotency_key);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_knowledge_promotion_records_source
  ON knowledge_promotion_records(source_correction_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_promotion_records_validation
  ON knowledge_promotion_records(correction_validation_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_promotion_records_coverage_proof
  ON knowledge_promotion_records(coverage_proof_bundle_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_promotion_records_status
  ON knowledge_promotion_records(status);

DROP TRIGGER IF EXISTS trg_knowledge_promotion_records_updated_at ON knowledge_promotion_records;

CREATE TRIGGER trg_knowledge_promotion_records_updated_at
BEFORE UPDATE ON knowledge_promotion_records
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
