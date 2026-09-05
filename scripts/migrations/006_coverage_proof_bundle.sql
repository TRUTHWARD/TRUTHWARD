-- Coverage Proof Bundle implemented follow-up P0 storage for PostgreSQL 15+.
-- Persists frozen traceability/coverage snapshots, gate input snapshots, proof bundles, and replay proof refs.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'coverage_status') THEN
    CREATE TYPE coverage_status AS ENUM (
      'covered',
      'partial',
      'not_covered',
      'blocked',
      'not_applicable',
      'unknown'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'proof_status') THEN
    CREATE TYPE proof_status AS ENUM (
      'valid',
      'stale',
      'broken',
      'superseded'
    );
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS traceability_snapshots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE CASCADE,
  scope_id VARCHAR(255) NOT NULL,
  traceability_snapshot_ref VARCHAR(255) NOT NULL,
  traceability_snapshot_hash VARCHAR(80) NOT NULL,
  traceability_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  coverage_summary_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  coverage_matrix_snapshot_ref VARCHAR(255) NOT NULL,
  coverage_matrix_snapshot_hash VARCHAR(80) NOT NULL,
  coverage_matrix_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  relation_snapshot JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_traceability_snapshots_hash UNIQUE (traceability_snapshot_hash)
);

CREATE INDEX IF NOT EXISTS idx_traceability_snapshots_requirement ON traceability_snapshots(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_traceability_snapshots_scope ON traceability_snapshots(scope_id);

CREATE TABLE IF NOT EXISTS gate_input_snapshots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  gate_decision_id UUID NOT NULL REFERENCES gate_results(id) ON DELETE CASCADE,
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  gate_input_snapshot_ref VARCHAR(255) NOT NULL,
  gate_input_snapshot_hash VARCHAR(80) NOT NULL,
  gate_input_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  policy_snapshot_ref VARCHAR(255),
  policy_snapshot_hash VARCHAR(80),
  policy_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_gate_input_snapshots_hash UNIQUE (gate_input_snapshot_hash)
);

CREATE INDEX IF NOT EXISTS idx_gate_input_snapshots_gate ON gate_input_snapshots(gate_decision_id);
CREATE INDEX IF NOT EXISTS idx_gate_input_snapshots_execution ON gate_input_snapshots(execution_id);

CREATE TABLE IF NOT EXISTS coverage_proof_bundles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE CASCADE,
  requirement_item_id VARCHAR(255) NOT NULL,
  traceability_snapshot_id UUID NOT NULL REFERENCES traceability_snapshots(id) ON DELETE RESTRICT,
  gate_input_snapshot_id UUID REFERENCES gate_input_snapshots(id) ON DELETE SET NULL,
  coverage_status coverage_status NOT NULL,
  proof_status proof_status NOT NULL,
  proof_bundle JSONB NOT NULL DEFAULT '{}'::jsonb,
  proof_chain JSONB NOT NULL DEFAULT '[]'::jsonb,
  proof_issues JSONB NOT NULL DEFAULT '[]'::jsonb,
  replay_export_ref VARCHAR(255),
  replay_export_hash VARCHAR(80),
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_coverage_proof_bundles_requirement
  ON coverage_proof_bundles(requirement_version_id, requirement_item_id);
CREATE INDEX IF NOT EXISTS idx_coverage_proof_bundles_snapshot
  ON coverage_proof_bundles(traceability_snapshot_id);
CREATE INDEX IF NOT EXISTS idx_coverage_proof_bundles_status
  ON coverage_proof_bundles(coverage_status, proof_status);

CREATE TABLE IF NOT EXISTS coverage_proof_replay_refs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  coverage_proof_bundle_id UUID NOT NULL REFERENCES coverage_proof_bundles(id) ON DELETE CASCADE,
  replay_export_ref VARCHAR(255) NOT NULL,
  replay_export_hash VARCHAR(80) NOT NULL,
  traceability_snapshot_ref VARCHAR(255) NOT NULL,
  traceability_snapshot_hash VARCHAR(80) NOT NULL,
  coverage_matrix_snapshot_ref VARCHAR(255) NOT NULL,
  coverage_matrix_snapshot_hash VARCHAR(80) NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_coverage_proof_replay_refs_bundle_hash UNIQUE (coverage_proof_bundle_id, replay_export_hash)
);

CREATE INDEX IF NOT EXISTS idx_coverage_proof_replay_refs_bundle
  ON coverage_proof_replay_refs(coverage_proof_bundle_id);
CREATE INDEX IF NOT EXISTS idx_coverage_proof_replay_refs_export
  ON coverage_proof_replay_refs(replay_export_ref);
CREATE INDEX IF NOT EXISTS idx_coverage_proof_replay_refs_hash
  ON coverage_proof_replay_refs(replay_export_hash);
