-- P12 controlled Observed Trace to Candidate Path conversion.
-- Reuses P10/P11 candidate versions; does not add a service or Promotion authority.

CREATE TABLE IF NOT EXISTS candidate_graph_build_runs (
  id UUID PRIMARY KEY,
  build_ref VARCHAR(500) NOT NULL UNIQUE,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL,
  graph_id UUID NOT NULL,
  scope_id UUID NOT NULL,
  candidate_version_id UUID NOT NULL,
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE RESTRICT,
  source_identity_hash VARCHAR(80) NOT NULL,
  semantic_path_hash VARCHAR(80) NOT NULL,
  transformer_version VARCHAR(80) NOT NULL,
  config_hash VARCHAR(80) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'running',
  outcome VARCHAR(32) NOT NULL DEFAULT 'unknown',
  source_revision_hash VARCHAR(80),
  source_environment VARCHAR(100) NOT NULL,
  source_observed_at TIMESTAMPTZ NOT NULL,
  action_count INTEGER NOT NULL,
  verified_action_count INTEGER NOT NULL DEFAULT 0,
  retry_count INTEGER NOT NULL DEFAULT 0,
  coordinate_click_count INTEGER NOT NULL DEFAULT 0,
  fallback_types JSONB NOT NULL DEFAULT '[]'::jsonb,
  observed_trace_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  ambiguities JSONB NOT NULL DEFAULT '[]'::jsonb,
  model_suggestion JSONB NOT NULL DEFAULT '{}'::jsonb,
  model_invocation_id UUID REFERENCES model_invocations(id) ON DELETE SET NULL,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  canonical BOOLEAN NOT NULL DEFAULT FALSE,
  active BOOLEAN NOT NULL DEFAULT FALSE,
  promotion_performed BOOLEAN NOT NULL DEFAULT FALSE,
  error_code VARCHAR(120),
  started_at TIMESTAMPTZ NOT NULL,
  finished_at TIMESTAMPTZ,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_candidate_builds_version_scope FOREIGN KEY (
    candidate_version_id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) REFERENCES canonical_execution_graph_versions(
    id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) ON DELETE RESTRICT,
  CONSTRAINT uq_candidate_builds_idempotency UNIQUE (
    tenant_id, workspace_id, graph_id, execution_id, transformer_version, config_hash
  ),
  CONSTRAINT chk_candidate_builds_status CHECK (status IN ('running', 'completed', 'failed')),
  CONSTRAINT chk_candidate_builds_outcome CHECK (outcome IN ('success', 'failure', 'partial', 'unknown')),
  CONSTRAINT chk_candidate_builds_config_hash CHECK (length(config_hash) = 71 AND config_hash LIKE 'sha256:%'),
  CONSTRAINT chk_candidate_builds_request_hash CHECK (length(request_hash) = 71 AND request_hash LIKE 'sha256:%'),
  CONSTRAINT chk_candidate_builds_source_identity_hash CHECK (length(source_identity_hash) = 71 AND source_identity_hash LIKE 'sha256:%'),
  CONSTRAINT chk_candidate_builds_semantic_path_hash CHECK (length(semantic_path_hash) = 71 AND semantic_path_hash LIKE 'sha256:%'),
  CONSTRAINT chk_candidate_builds_revision_hash CHECK (source_revision_hash IS NULL OR (length(source_revision_hash) = 71 AND source_revision_hash LIKE 'sha256:%')),
  CONSTRAINT chk_candidate_builds_action_count CHECK (action_count > 0),
  CONSTRAINT chk_candidate_builds_verified_count CHECK (verified_action_count >= 0 AND verified_action_count <= action_count),
  CONSTRAINT chk_candidate_builds_counts CHECK (retry_count >= 0 AND coordinate_click_count >= 0),
  CONSTRAINT chk_candidate_builds_never_canonical CHECK (
    canonical = FALSE AND active = FALSE AND promotion_performed = FALSE
  ),
  CONSTRAINT chk_candidate_builds_fallback_array CHECK (jsonb_typeof(fallback_types) = 'array'),
  CONSTRAINT chk_candidate_builds_observed_object CHECK (jsonb_typeof(observed_trace_snapshot) = 'object'),
  CONSTRAINT chk_candidate_builds_summary_object CHECK (jsonb_typeof(evidence_summary) = 'object'),
  CONSTRAINT chk_candidate_builds_ambiguities_array CHECK (jsonb_typeof(ambiguities) = 'array'),
  CONSTRAINT chk_candidate_builds_model_object CHECK (jsonb_typeof(model_suggestion) = 'object'),
  CONSTRAINT chk_candidate_builds_guardrail_array CHECK (jsonb_typeof(guardrail_event_refs) = 'array'),
  CONSTRAINT chk_candidate_builds_audit_array CHECK (jsonb_typeof(audit_refs) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_candidate_builds_scope
  ON candidate_graph_build_runs(tenant_id, workspace_id, project_id, graph_id);
CREATE INDEX IF NOT EXISTS idx_candidate_builds_execution
  ON candidate_graph_build_runs(execution_id);
CREATE INDEX IF NOT EXISTS idx_candidate_builds_semantic_path
  ON candidate_graph_build_runs(graph_id, semantic_path_hash, created_at);
CREATE INDEX IF NOT EXISTS idx_candidate_builds_version
  ON candidate_graph_build_runs(candidate_version_id);

CREATE TABLE IF NOT EXISTS candidate_graph_source_mappings (
  id UUID PRIMARY KEY,
  build_id UUID NOT NULL REFERENCES candidate_graph_build_runs(id) ON DELETE CASCADE,
  candidate_version_id UUID NOT NULL,
  graph_id UUID NOT NULL,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL,
  scope_id UUID NOT NULL,
  entity_type VARCHAR(32) NOT NULL,
  entity_id UUID NOT NULL,
  entity_ref VARCHAR(500) NOT NULL,
  source_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  observation_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  transformer_version VARCHAR(80) NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  ambiguities JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_candidate_mappings_version_scope FOREIGN KEY (
    candidate_version_id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) REFERENCES canonical_execution_graph_versions(
    id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) ON DELETE CASCADE,
  CONSTRAINT uq_candidate_mappings_build_entity UNIQUE (build_id, entity_type, entity_id),
  CONSTRAINT chk_candidate_mappings_entity_type CHECK (entity_type IN ('node', 'edge', 'path', 'path_step')),
  CONSTRAINT chk_candidate_mappings_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_candidate_mappings_source_array CHECK (jsonb_typeof(source_event_refs) = 'array'),
  CONSTRAINT chk_candidate_mappings_evidence_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
  CONSTRAINT chk_candidate_mappings_observation_object CHECK (jsonb_typeof(observation_summary) = 'object'),
  CONSTRAINT chk_candidate_mappings_ambiguities_array CHECK (jsonb_typeof(ambiguities) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_candidate_mappings_build
  ON candidate_graph_source_mappings(build_id, entity_type);
CREATE INDEX IF NOT EXISTS idx_candidate_mappings_version_entity
  ON candidate_graph_source_mappings(candidate_version_id, entity_type, entity_id);

DROP TRIGGER IF EXISTS trg_candidate_builds_updated_at ON candidate_graph_build_runs;
CREATE TRIGGER trg_candidate_builds_updated_at BEFORE UPDATE ON candidate_graph_build_runs
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE OR REPLACE FUNCTION protect_candidate_graph_build_mutation()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Candidate build provenance cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
    OR NEW.build_ref IS DISTINCT FROM OLD.build_ref
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
    OR NEW.project_id IS DISTINCT FROM OLD.project_id
    OR NEW.graph_id IS DISTINCT FROM OLD.graph_id
    OR NEW.scope_id IS DISTINCT FROM OLD.scope_id
    OR NEW.candidate_version_id IS DISTINCT FROM OLD.candidate_version_id
    OR NEW.execution_id IS DISTINCT FROM OLD.execution_id
    OR NEW.source_identity_hash IS DISTINCT FROM OLD.source_identity_hash
    OR NEW.semantic_path_hash IS DISTINCT FROM OLD.semantic_path_hash
    OR NEW.transformer_version IS DISTINCT FROM OLD.transformer_version
    OR NEW.config_hash IS DISTINCT FROM OLD.config_hash
    OR NEW.request_hash IS DISTINCT FROM OLD.request_hash
    OR NEW.observed_trace_snapshot IS DISTINCT FROM OLD.observed_trace_snapshot
    OR NEW.ambiguities IS DISTINCT FROM OLD.ambiguities
    OR NEW.model_suggestion IS DISTINCT FROM OLD.model_suggestion
    OR NEW.model_invocation_id IS DISTINCT FROM OLD.model_invocation_id
    OR NEW.guardrail_event_refs IS DISTINCT FROM OLD.guardrail_event_refs
    OR NEW.trace_id IS DISTINCT FROM OLD.trace_id
    OR NEW.canonical IS DISTINCT FROM OLD.canonical
    OR NEW.active IS DISTINCT FROM OLD.active
    OR NEW.promotion_performed IS DISTINCT FROM OLD.promotion_performed THEN
    RAISE EXCEPTION 'Candidate build facts and source identity are immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_candidate_builds_immutable ON candidate_graph_build_runs;
CREATE TRIGGER trg_candidate_builds_immutable
BEFORE UPDATE OR DELETE ON candidate_graph_build_runs
FOR EACH ROW EXECUTE FUNCTION protect_candidate_graph_build_mutation();

CREATE OR REPLACE FUNCTION protect_candidate_source_mapping_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Candidate source mappings are append-only' USING ERRCODE = '55000';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_candidate_mappings_append_only ON candidate_graph_source_mappings;
CREATE TRIGGER trg_candidate_mappings_append_only
BEFORE UPDATE OR DELETE ON candidate_graph_source_mappings
FOR EACH ROW EXECUTE FUNCTION protect_candidate_source_mapping_mutation();

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('graph.candidate.read', 'graph', 'Read Trace-derived Candidate Path observations.', 'low', TRUE),
  ('graph.candidate.create', 'graph', 'Run the internal Trace-to-Candidate transformation.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = EXCLUDED.is_active;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'graph.candidate.read', TRUE),
  ('pro', 'graph.candidate.read', TRUE),
  ('enterprise', 'graph.candidate.read', TRUE),
  ('enterprise', 'graph.candidate.create', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = EXCLUDED.enabled;

INSERT INTO rbac_role_capabilities (role_name, capability_key, effect)
VALUES
  ('user', 'graph.candidate.read', 'allow'),
  ('admin', 'graph.candidate.read', 'allow'),
  ('admin', 'graph.candidate.create', 'allow'),
  ('system', 'graph.candidate.read', 'allow'),
  ('system', 'graph.candidate.create', 'allow')
ON CONFLICT (role_name, capability_key) DO UPDATE SET effect = EXCLUDED.effect;

COMMENT ON TABLE candidate_graph_build_runs IS
  'P12 Trace-to-Candidate build/audit state. A build can never be active canonical and performs no Promotion.';
COMMENT ON TABLE candidate_graph_source_mappings IS
  'P12 per-element provenance and observation summaries; sensitive source payloads remain referenced, not copied.';
