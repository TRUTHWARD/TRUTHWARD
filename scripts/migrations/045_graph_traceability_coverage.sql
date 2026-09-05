-- P15 authoritative CEG traceability projection and Graph Coverage snapshots.
-- Extends the existing traceability/Coverage Proof authority; this is not a second Proof system.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS graph_coverage_snapshots (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  graph_id UUID NOT NULL REFERENCES canonical_execution_graphs(id) ON DELETE RESTRICT,
  graph_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  coverage_proof_bundle_id UUID REFERENCES coverage_proof_bundles(id) ON DELETE SET NULL,
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE RESTRICT,
  execution_id UUID REFERENCES executions(id) ON DELETE SET NULL,
  staleness_assessment_id UUID REFERENCES canonical_graph_staleness_assessments(id) ON DELETE SET NULL,
  algorithm_version VARCHAR(80) NOT NULL,
  input_fingerprint VARCHAR(80) NOT NULL,
  snapshot_ref VARCHAR(500) NOT NULL UNIQUE,
  snapshot_hash VARCHAR(80) NOT NULL,
  status VARCHAR(32) NOT NULL,
  input_snapshot JSONB NOT NULL,
  result_snapshot JSONB NOT NULL,
  coverage_proof_ref JSONB,
  traceability_snapshot JSONB NOT NULL,
  metric_snapshot JSONB NOT NULL,
  gap_snapshot JSONB NOT NULL,
  raw_finding_refs JSONB NOT NULL,
  normalized_finding_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_graph_coverage_snapshots_input UNIQUE (tenant_id, workspace_id, input_fingerprint),
  CONSTRAINT uq_graph_coverage_snapshots_hash UNIQUE (snapshot_hash),
  CONSTRAINT chk_graph_coverage_snapshots_status CHECK (
    status IN ('covered', 'partial', 'uncovered', 'not_applicable', 'unknown')
  ),
  CONSTRAINT chk_graph_coverage_snapshots_input_hash CHECK (
    length(input_fingerprint) = 71 AND input_fingerprint LIKE 'sha256:%'
  ),
  CONSTRAINT chk_graph_coverage_snapshots_snapshot_hash CHECK (
    length(snapshot_hash) = 71 AND snapshot_hash LIKE 'sha256:%'
  )
);

CREATE INDEX IF NOT EXISTS idx_graph_coverage_snapshots_graph
  ON graph_coverage_snapshots(
    tenant_id, workspace_id, project_id, graph_version_id, computed_at DESC
  );
CREATE INDEX IF NOT EXISTS idx_graph_coverage_snapshots_execution
  ON graph_coverage_snapshots(execution_id);
CREATE INDEX IF NOT EXISTS idx_graph_coverage_snapshots_requirement
  ON graph_coverage_snapshots(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_graph_coverage_snapshots_proof
  ON graph_coverage_snapshots(coverage_proof_bundle_id);

CREATE OR REPLACE FUNCTION protect_graph_coverage_snapshot_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Graph Coverage snapshots are immutable'
    USING ERRCODE = '55000';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_graph_coverage_snapshot_immutable ON graph_coverage_snapshots;
CREATE TRIGGER trg_graph_coverage_snapshot_immutable
BEFORE UPDATE OR DELETE ON graph_coverage_snapshots
FOR EACH ROW EXECUTE FUNCTION protect_graph_coverage_snapshot_mutation();

COMMENT ON TABLE graph_coverage_snapshots IS
  'Immutable P15 CEG dimension snapshot linked to the existing Coverage Proof authority; not a second Coverage Proof truth.';
