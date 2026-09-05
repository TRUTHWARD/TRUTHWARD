-- P14 Canonical Execution Graph staleness and applicability governance.
-- Service-owned sidecars only; canonical graph versions and historical Replay remain immutable.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS canonical_graph_staleness_assessments (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  graph_id UUID NOT NULL REFERENCES canonical_execution_graphs(id) ON DELETE RESTRICT,
  graph_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  status VARCHAR(24) NOT NULL,
  applicability_range JSONB NOT NULL,
  signals_snapshot JSONB NOT NULL,
  source_fingerprint VARCHAR(80) NOT NULL,
  rule_version VARCHAR(80) NOT NULL,
  reason_codes JSONB NOT NULL,
  impact_snapshot JSONB NOT NULL,
  automatic_promotion_eligible BOOLEAN NOT NULL DEFAULT FALSE,
  assessment_hash VARCHAR(80) NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  assessed_at TIMESTAMPTZ NOT NULL,
  assessed_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_ceg_staleness_source_fingerprint UNIQUE (tenant_id, workspace_id, graph_version_id, source_fingerprint),
  CONSTRAINT uq_ceg_staleness_idempotency UNIQUE (tenant_id, workspace_id, graph_version_id, idempotency_key),
  CONSTRAINT chk_ceg_staleness_status CHECK (status IN ('fresh', 'suspect', 'stale', 'invalid', 'unknown')),
  CONSTRAINT chk_ceg_staleness_source_fingerprint CHECK (length(source_fingerprint) = 71 AND source_fingerprint LIKE 'sha256:%'),
  CONSTRAINT chk_ceg_staleness_assessment_hash CHECK (length(assessment_hash) = 71 AND assessment_hash LIKE 'sha256:%'),
  CONSTRAINT chk_ceg_staleness_applicability_object CHECK (jsonb_typeof(applicability_range) = 'object'),
  CONSTRAINT chk_ceg_staleness_signals_array CHECK (jsonb_typeof(signals_snapshot) = 'array'),
  CONSTRAINT chk_ceg_staleness_reasons_array CHECK (jsonb_typeof(reason_codes) = 'array'),
  CONSTRAINT chk_ceg_staleness_impact_object CHECK (jsonb_typeof(impact_snapshot) = 'object'),
  CONSTRAINT chk_ceg_staleness_fresh_only_autonomy CHECK (automatic_promotion_eligible = FALSE OR status = 'fresh')
);

CREATE INDEX IF NOT EXISTS idx_ceg_staleness_current
  ON canonical_graph_staleness_assessments(tenant_id, workspace_id, project_id, graph_version_id, assessed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ceg_staleness_status
  ON canonical_graph_staleness_assessments(status, assessed_at DESC);

CREATE TABLE IF NOT EXISTS canonical_graph_staleness_reviews (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  graph_id UUID NOT NULL REFERENCES canonical_execution_graphs(id) ON DELETE RESTRICT,
  graph_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  assessment_id UUID NOT NULL REFERENCES canonical_graph_staleness_assessments(id) ON DELETE RESTRICT,
  action VARCHAR(24) NOT NULL,
  requested_status VARCHAR(24),
  reason_code VARCHAR(120) NOT NULL,
  evidence_refs JSONB NOT NULL,
  expires_at TIMESTAMPTZ,
  status VARCHAR(24) NOT NULL DEFAULT 'pending',
  approval_id UUID NOT NULL REFERENCES approvals(id) ON DELETE RESTRICT,
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  lock_version INTEGER NOT NULL DEFAULT 1,
  requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
  applied_at TIMESTAMPTZ,
  applied_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_ceg_staleness_review_idempotency UNIQUE (tenant_id, workspace_id, graph_version_id, idempotency_key),
  CONSTRAINT chk_ceg_staleness_review_action CHECK (action IN ('confirm', 'override', 'deprecate')),
  CONSTRAINT chk_ceg_staleness_review_status CHECK (status IN ('pending', 'applied', 'rejected', 'expired')),
  CONSTRAINT chk_ceg_staleness_review_requested_status CHECK (requested_status IS NULL OR requested_status IN ('fresh', 'suspect', 'stale', 'invalid', 'unknown')),
  CONSTRAINT chk_ceg_staleness_review_override_expiry CHECK (
    (action = 'override' AND requested_status IS NOT NULL AND expires_at IS NOT NULL)
    OR (action <> 'override' AND requested_status IS NULL)
  ),
  CONSTRAINT chk_ceg_staleness_review_lock CHECK (lock_version > 0)
);

CREATE INDEX IF NOT EXISTS idx_ceg_staleness_review_version
  ON canonical_graph_staleness_reviews(graph_version_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ceg_staleness_review_status
  ON canonical_graph_staleness_reviews(status, expires_at);

CREATE OR REPLACE FUNCTION protect_ceg_staleness_assessment_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Canonical Graph staleness assessments are immutable'
    USING ERRCODE = '55000';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ceg_staleness_assessment_immutable ON canonical_graph_staleness_assessments;
CREATE TRIGGER trg_ceg_staleness_assessment_immutable
BEFORE UPDATE OR DELETE ON canonical_graph_staleness_assessments
FOR EACH ROW EXECUTE FUNCTION protect_ceg_staleness_assessment_mutation();

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

INSERT INTO canonical_graph_staleness_assessments (
  id, tenant_id, workspace_id, project_id, graph_id, graph_version_id, status,
  applicability_range, signals_snapshot, source_fingerprint, rule_version,
  reason_codes, impact_snapshot, automatic_promotion_eligible, assessment_hash,
  idempotency_key, request_hash, trace_id, assessed_at
)
SELECT
  gen_random_uuid(), v.tenant_id, v.workspace_id, v.project_id, v.graph_id, v.id,
  'unknown', '{}'::jsonb,
  jsonb_build_array(jsonb_build_object(
    'signalId', 'legacy-applicability-missing',
    'source', 'system',
    'type', 'missing',
    'ref', 'ceg-version://versions/' || v.id::text,
    'severity', 'high',
    'confidence', 1.0,
    'evidence', jsonb_build_array(jsonb_build_object(
      'type', 'graph_version',
      'ref', 'ceg-version://versions/' || v.id::text
    ))
  )),
  'sha256:' || encode(digest('p14-backfill:' || v.id::text || ':' || v.content_hash, 'sha256'), 'hex'),
  'graph-staleness-rules.v1',
  '["GRAPH_STALENESS_LEGACY_APPLICABILITY_UNKNOWN"]'::jsonb,
  jsonb_build_object(
    'autoPromotionSuspended', TRUE,
    'alertRequired', FALSE,
    'reviewRequired', TRUE,
    'historicalVersionRetained', TRUE,
    'reason', 'legacy_active_version_requires_assessment'
  ),
  FALSE,
  'sha256:' || encode(digest('p14-backfill-assessment:' || v.id::text || ':' || v.content_hash, 'sha256'), 'hex'),
  'p14-backfill:' || v.id::text,
  'sha256:' || encode(digest('p14-backfill-request:' || v.id::text, 'sha256'), 'hex'),
  NULL,
  NOW()
FROM canonical_execution_graph_versions v
WHERE v.status = 'active'
  AND v.source = 'canonical'
  AND v.is_frozen = TRUE
  AND NOT EXISTS (
    SELECT 1 FROM canonical_graph_staleness_assessments a
    WHERE a.graph_version_id = v.id
  );

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('graph.staleness.read', 'graph', 'Read Canonical Graph applicability, staleness, and selection projections.', 'low', TRUE),
  ('graph.staleness.assess', 'graph', 'Assess Canonical Graph applicability and staleness from persisted signals.', 'high', TRUE),
  ('graph.staleness.review', 'graph', 'Request and apply human staleness confirmation or bounded override.', 'high', TRUE),
  ('graph.staleness.deprecate', 'graph', 'Request and apply approval-backed Canonical Graph deprecation.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = EXCLUDED.is_active;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'graph.staleness.read', TRUE),
  ('pro', 'graph.staleness.read', TRUE),
  ('enterprise', 'graph.staleness.read', TRUE),
  ('enterprise', 'graph.staleness.assess', TRUE),
  ('enterprise', 'graph.staleness.review', TRUE),
  ('enterprise', 'graph.staleness.deprecate', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = EXCLUDED.enabled;

INSERT INTO rbac_role_capabilities (role_name, capability_key, effect)
SELECT 'admin', capability_key, 'allow'
FROM capability_registry
WHERE capability_key IN (
  'graph.staleness.read', 'graph.staleness.assess',
  'graph.staleness.review', 'graph.staleness.deprecate'
)
ON CONFLICT (role_name, capability_key) DO UPDATE SET effect = EXCLUDED.effect;

COMMENT ON TABLE canonical_graph_staleness_assessments IS
  'Immutable P14 applicability/staleness facts. unknown is fail-closed and only fresh may qualify controlled autonomy.';
COMMENT ON TABLE canonical_graph_staleness_reviews IS
  'Approval-backed human confirmation, bounded override, or deprecation. Overrides never restore controlled autonomy.';
