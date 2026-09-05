-- P13 structured Graph Correction, learning modes, and controlled Canonical Promotion.
-- Extends P10-P12 CEG and the existing CCG/Approval/Audit/Replay boundaries.

CREATE TABLE IF NOT EXISTS graph_correction_proposals (
  id UUID PRIMARY KEY,
  correction_proposal_id UUID NOT NULL UNIQUE REFERENCES correction_proposals(id) ON DELETE CASCADE,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  environment_id UUID REFERENCES project_environments(id) ON DELETE RESTRICT,
  graph_id UUID NOT NULL REFERENCES canonical_execution_graphs(id) ON DELETE RESTRICT,
  base_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  base_version_hash VARCHAR(80) NOT NULL CHECK (base_version_hash LIKE 'sha256:%'),
  base_version_lock_version INTEGER NOT NULL CHECK (base_version_lock_version > 0),
  candidate_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  candidate_version_hash VARCHAR(80) NOT NULL CHECK (candidate_version_hash LIKE 'sha256:%'),
  candidate_build_id UUID NOT NULL REFERENCES candidate_graph_build_runs(id) ON DELETE RESTRICT,
  structured_patch JSONB NOT NULL,
  patch_hash VARCHAR(80) NOT NULL CHECK (patch_hash LIKE 'sha256:%'),
  rationale_code VARCHAR(120) NOT NULL,
  risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('low', 'medium', 'high')),
  status VARCHAR(32) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'validated', 'invalid', 'pending_review', 'promoted', 'rejected')),
  validation_report JSONB NOT NULL DEFAULT '{}'::jsonb,
  validation_hash VARCHAR(80),
  validator_version VARCHAR(80),
  validated_at TIMESTAMPTZ,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  policy_decision_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  rollback_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  latest_assessment_id UUID,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL CHECK (request_hash LIKE 'sha256:%'),
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  lock_version INTEGER NOT NULL DEFAULT 1 CHECK (lock_version > 0),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_graph_corrections_idempotency UNIQUE (tenant_id, workspace_id, idempotency_key),
  CONSTRAINT chk_graph_corrections_status CHECK (status IN ('draft', 'validated', 'invalid', 'pending_review', 'promoted', 'rejected')),
  CONSTRAINT chk_graph_corrections_risk CHECK (risk_level IN ('low', 'medium', 'high')),
  CONSTRAINT chk_graph_corrections_lock_version CHECK (lock_version > 0)
);
CREATE INDEX IF NOT EXISTS idx_graph_corrections_graph ON graph_correction_proposals(graph_id, created_at);
CREATE INDEX IF NOT EXISTS idx_graph_corrections_candidate ON graph_correction_proposals(candidate_version_id);
CREATE INDEX IF NOT EXISTS idx_graph_corrections_status ON graph_correction_proposals(status);

CREATE TABLE IF NOT EXISTS graph_learning_policies (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  policy_key VARCHAR(128) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'disabled', 'deprecated', 'archived')),
  lock_version INTEGER NOT NULL DEFAULT 1 CHECK (lock_version > 0),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_graph_learning_policy_key UNIQUE (tenant_id, workspace_id, project_id, policy_key),
  CONSTRAINT chk_graph_learning_policy_status CHECK (status IN ('draft', 'active', 'disabled', 'deprecated', 'archived')),
  CONSTRAINT chk_graph_learning_policy_lock CHECK (lock_version > 0)
);
CREATE INDEX IF NOT EXISTS idx_graph_learning_policy_scope ON graph_learning_policies(tenant_id, workspace_id, project_id);

CREATE TABLE IF NOT EXISTS graph_learning_policy_versions (
  id UUID PRIMARY KEY,
  policy_id UUID NOT NULL REFERENCES graph_learning_policies(id) ON DELETE RESTRICT,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  version_number INTEGER NOT NULL CHECK (version_number > 0),
  status VARCHAR(32) NOT NULL CHECK (status IN ('draft', 'active', 'disabled', 'deprecated', 'archived')),
  policy_document JSONB NOT NULL,
  content_hash VARCHAR(80) NOT NULL CHECK (content_hash LIKE 'sha256:%'),
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL CHECK (request_hash LIKE 'sha256:%'),
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  lock_version INTEGER NOT NULL DEFAULT 1 CHECK (lock_version > 0),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_graph_learning_policy_version UNIQUE (policy_id, version_number),
  CONSTRAINT uq_graph_learning_policy_hash UNIQUE (policy_id, content_hash),
  CONSTRAINT uq_graph_learning_policy_version_idempotency UNIQUE (tenant_id, workspace_id, idempotency_key),
  CONSTRAINT chk_graph_learning_policy_version_status CHECK (status IN ('draft', 'active', 'disabled', 'deprecated', 'archived')),
  CONSTRAINT chk_graph_learning_policy_version_numbers CHECK (version_number > 0 AND lock_version > 0)
);
CREATE INDEX IF NOT EXISTS idx_graph_learning_policy_version_scope ON graph_learning_policy_versions(tenant_id, workspace_id, project_id, status);

CREATE TABLE IF NOT EXISTS graph_learning_policy_bindings (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  environment_id UUID REFERENCES project_environments(id) ON DELETE CASCADE,
  scope_type VARCHAR(32) NOT NULL CHECK (scope_type IN ('project', 'environment')),
  scope_id UUID NOT NULL,
  policy_version_id UUID NOT NULL REFERENCES graph_learning_policy_versions(id) ON DELETE RESTRICT,
  policy_version_hash VARCHAR(80) NOT NULL CHECK (policy_version_hash LIKE 'sha256:%'),
  learning_mode VARCHAR(40) NOT NULL DEFAULT 'human_supervised' CHECK (learning_mode IN ('learn_only', 'human_supervised', 'controlled_autonomy')),
  status VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'deprecated', 'archived')),
  autonomy_paused BOOLEAN NOT NULL DEFAULT FALSE,
  pause_reason_code VARCHAR(120),
  paused_at TIMESTAMPTZ,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL CHECK (request_hash LIKE 'sha256:%'),
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  lock_version INTEGER NOT NULL DEFAULT 1 CHECK (lock_version > 0),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_graph_learning_binding_scope UNIQUE (tenant_id, workspace_id, project_id, scope_type, scope_id),
  CONSTRAINT uq_graph_learning_binding_idempotency UNIQUE (tenant_id, workspace_id, idempotency_key),
  CONSTRAINT chk_graph_learning_binding_scope_identity CHECK (
    (scope_type = 'project' AND environment_id IS NULL AND scope_id = project_id) OR
    (scope_type = 'environment' AND environment_id IS NOT NULL AND scope_id = environment_id)
  ),
  CONSTRAINT chk_graph_learning_binding_scope CHECK (scope_type IN ('project', 'environment')),
  CONSTRAINT chk_graph_learning_binding_mode CHECK (learning_mode IN ('learn_only', 'human_supervised', 'controlled_autonomy')),
  CONSTRAINT chk_graph_learning_binding_status CHECK (status IN ('active', 'disabled', 'deprecated', 'archived')),
  CONSTRAINT chk_graph_learning_binding_lock CHECK (lock_version > 0)
);
CREATE INDEX IF NOT EXISTS idx_graph_learning_binding_resolve ON graph_learning_policy_bindings(tenant_id, workspace_id, project_id, environment_id, status);

CREATE TABLE IF NOT EXISTS graph_promotion_eligibility_assessments (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  proposal_id UUID NOT NULL REFERENCES graph_correction_proposals(id) ON DELETE CASCADE,
  graph_id UUID NOT NULL REFERENCES canonical_execution_graphs(id) ON DELETE RESTRICT,
  candidate_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  base_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  learning_mode VARCHAR(40) NOT NULL CHECK (learning_mode IN ('learn_only', 'human_supervised', 'controlled_autonomy')),
  risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('low', 'medium', 'high')),
  eligible BOOLEAN NOT NULL,
  automatic_promotion_allowed BOOLEAN NOT NULL,
  human_review_required BOOLEAN NOT NULL,
  checks_snapshot JSONB NOT NULL,
  reason_codes JSONB NOT NULL,
  input_snapshot JSONB NOT NULL,
  policy_version_id UUID REFERENCES graph_learning_policy_versions(id) ON DELETE RESTRICT,
  policy_version_hash VARCHAR(80) NOT NULL,
  binding_id UUID REFERENCES graph_learning_policy_bindings(id) ON DELETE RESTRICT,
  eligibility_hash VARCHAR(80) NOT NULL CHECK (eligibility_hash LIKE 'sha256:%'),
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL CHECK (request_hash LIKE 'sha256:%'),
  policy_decision_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  evaluated_at TIMESTAMPTZ NOT NULL,
  evaluated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_graph_promotion_assessment_idempotency UNIQUE (tenant_id, workspace_id, proposal_id, idempotency_key),
  CONSTRAINT chk_graph_promotion_assessment_mode CHECK (learning_mode IN ('learn_only', 'human_supervised', 'controlled_autonomy')),
  CONSTRAINT chk_graph_promotion_assessment_risk CHECK (risk_level IN ('low', 'medium', 'high'))
);
CREATE INDEX IF NOT EXISTS idx_graph_promotion_assessment_proposal ON graph_promotion_eligibility_assessments(proposal_id, evaluated_at);

CREATE TABLE IF NOT EXISTS canonical_graph_promotion_records (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  graph_id UUID NOT NULL REFERENCES canonical_execution_graphs(id) ON DELETE RESTRICT,
  proposal_id UUID NOT NULL REFERENCES graph_correction_proposals(id) ON DELETE RESTRICT,
  assessment_id UUID NOT NULL REFERENCES graph_promotion_eligibility_assessments(id) ON DELETE RESTRICT,
  before_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  before_version_hash VARCHAR(80) NOT NULL,
  candidate_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  target_version_id UUID NOT NULL UNIQUE REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  target_version_hash VARCHAR(80) NOT NULL,
  promotion_type VARCHAR(48) NOT NULL CHECK (promotion_type IN ('human_approved_promotion', 'policy_approved_auto_promotion', 'human_approved_rollback')),
  actor_type VARCHAR(16) NOT NULL CHECK (actor_type IN ('human', 'system')),
  actor_ref VARCHAR(500) NOT NULL,
  human_approval BOOLEAN NOT NULL,
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  policy_decision_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  eligibility_snapshot JSONB NOT NULL,
  policy_version_id UUID REFERENCES graph_learning_policy_versions(id) ON DELETE RESTRICT,
  policy_version_hash VARCHAR(80) NOT NULL,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  shadow_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  rollback_target_version_id UUID REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  status VARCHAR(24) NOT NULL CHECK (status IN ('promoted', 'rolled_back')),
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  promoted_at TIMESTAMPTZ NOT NULL,
  promoted_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_canonical_graph_promotion_idempotency UNIQUE (tenant_id, workspace_id, idempotency_key),
  CONSTRAINT chk_canonical_graph_promotion_type CHECK (promotion_type IN ('human_approved_promotion', 'policy_approved_auto_promotion', 'human_approved_rollback')),
  CONSTRAINT chk_canonical_graph_promotion_actor CHECK (actor_type IN ('human', 'system')),
  CONSTRAINT chk_canonical_graph_promotion_status CHECK (status IN ('promoted', 'rolled_back')),
  CONSTRAINT chk_canonical_graph_promotion_actor_ref CHECK (
    (actor_type = 'system' AND actor_ref = 'system://controlled-graph-promotion') OR
    (actor_type = 'human' AND actor_ref LIKE 'user://users/%')
  ),
  CONSTRAINT chk_canonical_graph_promotion_approval_truth CHECK (
    (promotion_type = 'policy_approved_auto_promotion' AND human_approval = FALSE) OR
    (promotion_type <> 'policy_approved_auto_promotion' AND human_approval = TRUE)
  ),
  CONSTRAINT chk_canonical_graph_promotion_approval_refs_truth CHECK (
    (promotion_type = 'policy_approved_auto_promotion' AND jsonb_array_length(approval_refs) = 0) OR
    (promotion_type <> 'policy_approved_auto_promotion' AND jsonb_array_length(approval_refs) > 0)
  )
);
CREATE INDEX IF NOT EXISTS idx_canonical_graph_promotion_graph ON canonical_graph_promotion_records(graph_id, promoted_at);
CREATE INDEX IF NOT EXISTS idx_canonical_graph_promotion_proposal ON canonical_graph_promotion_records(proposal_id);

CREATE OR REPLACE FUNCTION protect_graph_promotion_fact_mutation()
RETURNS TRIGGER AS $$ BEGIN
  RAISE EXCEPTION 'Graph Promotion eligibility and result facts are immutable' USING ERRCODE = '55000';
END; $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_graph_promotion_assessment_immutable ON graph_promotion_eligibility_assessments;
CREATE TRIGGER trg_graph_promotion_assessment_immutable BEFORE UPDATE OR DELETE ON graph_promotion_eligibility_assessments FOR EACH ROW EXECUTE FUNCTION protect_graph_promotion_fact_mutation();
DROP TRIGGER IF EXISTS trg_canonical_graph_promotion_immutable ON canonical_graph_promotion_records;
CREATE TRIGGER trg_canonical_graph_promotion_immutable BEFORE UPDATE OR DELETE ON canonical_graph_promotion_records FOR EACH ROW EXECUTE FUNCTION protect_graph_promotion_fact_mutation();

-- P13 automatic eligibility consumes these P12 columns as immutable facts.
-- evidence_summary remains mutable because P12 refreshes the derived aggregate
-- projection whenever another independent build is appended.
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
    OR NEW.status IS DISTINCT FROM OLD.status
    OR NEW.outcome IS DISTINCT FROM OLD.outcome
    OR NEW.source_revision_hash IS DISTINCT FROM OLD.source_revision_hash
    OR NEW.source_environment IS DISTINCT FROM OLD.source_environment
    OR NEW.source_observed_at IS DISTINCT FROM OLD.source_observed_at
    OR NEW.action_count IS DISTINCT FROM OLD.action_count
    OR NEW.verified_action_count IS DISTINCT FROM OLD.verified_action_count
    OR NEW.retry_count IS DISTINCT FROM OLD.retry_count
    OR NEW.coordinate_click_count IS DISTINCT FROM OLD.coordinate_click_count
    OR NEW.fallback_types IS DISTINCT FROM OLD.fallback_types
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

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('graph.correction.read', 'graph', 'Read Graph Correction and controlled Promotion projections.', 'low', TRUE),
  ('graph.correction.propose', 'graph', 'Create or edit structured Graph Correction proposals.', 'high', TRUE),
  ('graph.correction.validate', 'graph', 'Validate structured Graph Correction proposals.', 'high', TRUE),
  ('graph.promotion.assess', 'graph', 'Evaluate Graph Promotion eligibility from persisted evidence.', 'high', TRUE),
  ('graph.promotion.promote', 'graph', 'Promote a validated Graph candidate through controlled governance.', 'high', TRUE),
  ('graph.learning_policy.manage', 'graph', 'Manage versioned Graph Learning Policy and Binding.', 'high', TRUE),
  ('graph.autonomy.pause', 'graph', 'Pause or resume controlled Graph autonomy.', 'high', TRUE),
  ('graph.promotion.rollback', 'graph', 'Rollback to an immutable Canonical Graph version.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = TRUE;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES ('basic', 'graph.correction.read', TRUE),
       ('pro', 'graph.correction.read', TRUE),
       ('enterprise', 'graph.correction.read', TRUE),
       ('enterprise', 'graph.correction.propose', TRUE),
       ('enterprise', 'graph.correction.validate', TRUE),
       ('enterprise', 'graph.promotion.assess', TRUE),
       ('enterprise', 'graph.promotion.promote', TRUE),
       ('enterprise', 'graph.learning_policy.manage', TRUE),
       ('enterprise', 'graph.autonomy.pause', TRUE),
       ('enterprise', 'graph.promotion.rollback', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;

COMMENT ON TABLE graph_correction_proposals IS 'P13 graph-specific extension of existing CCG proposals; structured operations and stable version refs only.';
COMMENT ON TABLE graph_promotion_eligibility_assessments IS 'Immutable fail-closed P13 eligibility snapshots; unknown and unavailable checks never pass.';
COMMENT ON TABLE canonical_graph_promotion_records IS 'Immutable controlled Canonical Graph Promotion facts; policy outcomes are distinct from human Approval.';

CREATE OR REPLACE FUNCTION prevent_ceg_version_content_update()
RETURNS TRIGGER AS $$
DECLARE
  content_changed BOOLEAN;
  controlled_promotion_transition BOOLEAN;
BEGIN
  IF OLD.status = 'archived' THEN
    RAISE EXCEPTION 'archived Canonical Execution Graph versions are immutable' USING ERRCODE = '55000';
  END IF;
  content_changed :=
    NEW.graph_id IS DISTINCT FROM OLD.graph_id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
    NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.project_id IS DISTINCT FROM OLD.project_id OR
    NEW.environment_id IS DISTINCT FROM OLD.environment_id OR NEW.scope_type IS DISTINCT FROM OLD.scope_type OR
    NEW.scope_id IS DISTINCT FROM OLD.scope_id OR NEW.version_number IS DISTINCT FROM OLD.version_number OR
    NEW.version_ref IS DISTINCT FROM OLD.version_ref OR NEW.parent_version_id IS DISTINCT FROM OLD.parent_version_id OR
    NEW.source IS DISTINCT FROM OLD.source OR NEW.schema_version IS DISTINCT FROM OLD.schema_version OR
    NEW.content_hash IS DISTINCT FROM OLD.content_hash OR NEW.source_refs IS DISTINCT FROM OLD.source_refs OR
    NEW.applicability IS DISTINCT FROM OLD.applicability OR NEW.metadata IS DISTINCT FROM OLD.metadata;
  IF (OLD.is_frozen OR OLD.status NOT IN ('draft', 'candidate')) AND content_changed THEN
    RAISE EXCEPTION 'frozen or published Canonical Execution Graph version content is immutable' USING ERRCODE = '55000';
  END IF;
  controlled_promotion_transition :=
    OLD.is_frozen = FALSE AND OLD.status IN ('draft', 'candidate') AND
    NEW.is_frozen = TRUE AND NEW.status = 'active' AND NEW.source = 'canonical' AND
    NEW.metadata->>'promotionType' IN ('human_approved_promotion', 'policy_approved_auto_promotion', 'human_approved_rollback');
  IF (NEW.is_frozen OR NEW.status NOT IN ('draft', 'candidate')) AND content_changed AND NOT controlled_promotion_transition THEN
    RAISE EXCEPTION 'freezing or publishing a Canonical Execution Graph version cannot change content' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
