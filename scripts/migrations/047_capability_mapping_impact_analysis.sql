-- P18 evidence-backed Capability Mapping and bounded impact propagation.
-- This extends the existing orchestrator Service boundary and never writes Gate, Memory, or test execution state.

CREATE TABLE IF NOT EXISTS capability_mappings (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  mapping_key VARCHAR(80) NOT NULL,
  version INTEGER NOT NULL,
  source_entity_type VARCHAR(40) NOT NULL,
  source_entity_ref VARCHAR(1000) NOT NULL,
  capability_ref VARCHAR(1000) NOT NULL,
  mapping_source VARCHAR(40) NOT NULL,
  source_priority INTEGER NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'active',
  repository_ref VARCHAR(1000),
  graph_version_id UUID REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  content_hash VARCHAR(80) NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_capability_mappings_version UNIQUE (tenant_id, workspace_id, project_id, mapping_key, version),
  CONSTRAINT uq_capability_mappings_idempotency UNIQUE (tenant_id, workspace_id, project_id, idempotency_key),
  CONSTRAINT chk_capability_mappings_entity_type CHECK (source_entity_type IN ('requirement', 'code_path', 'code_symbol', 'test')),
  CONSTRAINT chk_capability_mappings_source CHECK (mapping_source IN ('manual', 'explicit_configuration', 'verified_traceability', 'static_symbol_coverage', 'historical_evidence')),
  CONSTRAINT chk_capability_mappings_status CHECK (status IN ('active', 'superseded', 'disabled')),
  CONSTRAINT chk_capability_mappings_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_capability_mappings_priority CHECK (source_priority >= 0),
  CONSTRAINT chk_capability_mappings_version CHECK (version > 0),
  CONSTRAINT chk_capability_mappings_content_hash CHECK (length(content_hash) = 71 AND content_hash LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS idx_capability_mappings_scope_source ON capability_mappings(tenant_id, workspace_id, project_id, source_entity_type, source_entity_ref);
CREATE INDEX IF NOT EXISTS idx_capability_mappings_capability ON capability_mappings(project_id, capability_ref, status);
CREATE INDEX IF NOT EXISTS idx_capability_mappings_repository ON capability_mappings(project_id, repository_ref, status);

CREATE TABLE IF NOT EXISTS impact_results (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  change_set_ids JSONB NOT NULL,
  graph_id UUID NOT NULL REFERENCES canonical_execution_graphs(id) ON DELETE RESTRICT,
  graph_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  graph_assessment_id UUID REFERENCES canonical_graph_staleness_assessments(id) ON DELETE SET NULL,
  graph_staleness VARCHAR(24) NOT NULL,
  input_fingerprint VARCHAR(80) NOT NULL,
  mapping_snapshot_hash VARCHAR(80) NOT NULL,
  mapping_version_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  algorithm_version VARCHAR(80) NOT NULL,
  model_invocation_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  status VARCHAR(24) NOT NULL,
  risk_level VARCHAR(20) NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  review_required BOOLEAN NOT NULL DEFAULT FALSE,
  approval_id UUID REFERENCES approvals(id) ON DELETE SET NULL,
  truncated BOOLEAN NOT NULL DEFAULT FALSE,
  visited_node_count INTEGER NOT NULL DEFAULT 0,
  result_snapshot JSONB NOT NULL,
  replay_snapshot JSONB NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_impact_results_fingerprint UNIQUE (tenant_id, workspace_id, project_id, input_fingerprint),
  CONSTRAINT chk_impact_results_status CHECK (status IN ('complete', 'partial', 'unknown')),
  CONSTRAINT chk_impact_results_risk CHECK (risk_level IN ('low', 'medium', 'high')),
  CONSTRAINT chk_impact_results_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_impact_results_visited CHECK (visited_node_count >= 0),
  CONSTRAINT chk_impact_results_fingerprint CHECK (length(input_fingerprint) = 71 AND input_fingerprint LIKE 'sha256:%'),
  CONSTRAINT chk_impact_results_mapping_hash CHECK (length(mapping_snapshot_hash) = 71 AND mapping_snapshot_hash LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS idx_impact_results_scope ON impact_results(tenant_id, workspace_id, project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_impact_results_change_sets ON impact_results(project_id);
CREATE INDEX IF NOT EXISTS idx_impact_results_graph_version ON impact_results(graph_version_id, created_at);

CREATE OR REPLACE FUNCTION protect_impact_snapshot_mutation()
RETURNS TRIGGER AS $$ BEGIN
  RAISE EXCEPTION 'Capability Mapping versions and Impact Result snapshots are immutable' USING ERRCODE = '55000';
END; $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_capability_mapping_immutable ON capability_mappings;
CREATE TRIGGER trg_capability_mapping_immutable BEFORE UPDATE OR DELETE ON capability_mappings FOR EACH ROW EXECUTE FUNCTION protect_impact_snapshot_mutation();
DROP TRIGGER IF EXISTS trg_impact_result_immutable ON impact_results;
CREATE TRIGGER trg_impact_result_immutable BEFORE UPDATE OR DELETE ON impact_results FOR EACH ROW EXECUTE FUNCTION protect_impact_snapshot_mutation();

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('impact.read', 'impact', 'Read backend-computed Capability Mapping and Impact Result projections.', 'low', TRUE),
  ('impact.analyze', 'impact', 'Run bounded evidence-backed impact analysis from frozen Change Set and CEG inputs.', 'medium', TRUE),
  ('impact.manage_mapping', 'impact', 'Create versioned canonical Capability Mappings; AI suggestions are excluded.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET category = EXCLUDED.category, description = EXCLUDED.description, risk_level = EXCLUDED.risk_level, is_active = TRUE;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'impact.read', TRUE),
  ('pro', 'impact.read', TRUE),
  ('enterprise', 'impact.read', TRUE),
  ('enterprise', 'impact.analyze', TRUE),
  ('enterprise', 'impact.manage_mapping', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;

COMMENT ON TABLE capability_mappings IS 'P18 canonical evidence-backed mapping versions. AI suggestions are never persisted here.';
COMMENT ON TABLE impact_results IS 'P18 frozen impact evaluation inputs/results for downstream P19 admission input; not Gate, Memory, Replay selection, or test execution.';
