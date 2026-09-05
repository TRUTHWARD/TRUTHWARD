-- P20 verified SCM Webhook intake, immutable PR Context versions, and requirement matches.
-- This remains inside existing services; no integration-service microservice is introduced.

CREATE TABLE IF NOT EXISTS scm_webhook_receipts (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  connector_binding_id UUID NOT NULL REFERENCES skill_connector_bindings(id) ON DELETE RESTRICT,
  provider VARCHAR(32) NOT NULL,
  delivery_id VARCHAR(255) NOT NULL,
  event_type VARCHAR(80) NOT NULL,
  action VARCHAR(80) NOT NULL,
  installation_ref VARCHAR(500) NOT NULL,
  repository_ref VARCHAR(1000) NOT NULL,
  repository_native_id VARCHAR(255) NOT NULL,
  pull_request_number INTEGER NOT NULL,
  head_sha VARCHAR(64),
  provider_event_at TIMESTAMPTZ NOT NULL,
  received_at TIMESTAMPTZ NOT NULL,
  payload_hash VARCHAR(80) NOT NULL,
  idempotency_key VARCHAR(80) NOT NULL,
  envelope_snapshot JSONB NOT NULL,
  binding_snapshot JSONB NOT NULL,
  status VARCHAR(40) NOT NULL DEFAULT 'queued',
  attempt_count INTEGER NOT NULL DEFAULT 0,
  error_code VARCHAR(160),
  pr_context_version_id UUID,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_scm_webhook_receipts_delivery UNIQUE (connector_binding_id, provider, delivery_id),
  CONSTRAINT uq_scm_webhook_receipts_idempotency UNIQUE (idempotency_key),
  CONSTRAINT chk_scm_webhook_receipts_provider CHECK (provider IN ('github', 'gitlab', 'mock-scm')),
  CONSTRAINT chk_scm_webhook_receipts_status CHECK (status IN ('queued', 'processing', 'processed', 'ignored_out_of_order', 'failed')),
  CONSTRAINT chk_scm_webhook_receipts_attempt_count CHECK (attempt_count >= 0),
  CONSTRAINT chk_scm_webhook_receipts_payload_hash CHECK (length(payload_hash) = 71 AND payload_hash LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS idx_scm_webhook_receipts_scope ON scm_webhook_receipts(tenant_id, workspace_id, project_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_scm_webhook_receipts_status ON scm_webhook_receipts(status, created_at);
CREATE INDEX IF NOT EXISTS idx_scm_webhook_receipts_pr ON scm_webhook_receipts(project_id, repository_ref, pull_request_number);

CREATE TABLE IF NOT EXISTS scm_pr_contexts (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  connector_binding_id UUID NOT NULL REFERENCES skill_connector_bindings(id) ON DELETE RESTRICT,
  provider VARCHAR(32) NOT NULL,
  repository_ref VARCHAR(1000) NOT NULL,
  repository_native_id VARCHAR(255) NOT NULL,
  pull_request_number INTEGER NOT NULL,
  state VARCHAR(20) NOT NULL,
  latest_version INTEGER NOT NULL DEFAULT 1,
  latest_head_sha VARCHAR(64) NOT NULL,
  latest_provider_event_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_scm_pr_contexts_identity UNIQUE (tenant_id, workspace_id, project_id, provider, repository_ref, pull_request_number),
  CONSTRAINT chk_scm_pr_contexts_state CHECK (state IN ('open', 'closed', 'merged', 'unknown')),
  CONSTRAINT chk_scm_pr_contexts_version CHECK (latest_version > 0)
);
CREATE INDEX IF NOT EXISTS idx_scm_pr_contexts_scope ON scm_pr_contexts(tenant_id, workspace_id, project_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_scm_pr_contexts_repository ON scm_pr_contexts(project_id, repository_ref, pull_request_number);

CREATE TABLE IF NOT EXISTS scm_pr_context_versions (
  id UUID PRIMARY KEY,
  context_id UUID NOT NULL REFERENCES scm_pr_contexts(id) ON DELETE RESTRICT,
  webhook_receipt_id UUID NOT NULL REFERENCES scm_webhook_receipts(id) ON DELETE RESTRICT,
  version INTEGER NOT NULL,
  base_ref VARCHAR(500) NOT NULL,
  base_sha VARCHAR(64) NOT NULL,
  head_ref VARCHAR(500) NOT NULL,
  head_sha VARCHAR(64) NOT NULL,
  change_set_id UUID REFERENCES change_sets(id) ON DELETE RESTRICT,
  skill_invocation_id UUID REFERENCES skill_invocations(id) ON DELETE SET NULL,
  context_hash VARCHAR(80) NOT NULL,
  context_snapshot JSONB NOT NULL,
  replay_snapshot JSONB NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_scm_pr_context_versions_number UNIQUE (context_id, version),
  CONSTRAINT uq_scm_pr_context_versions_receipt UNIQUE (webhook_receipt_id),
  CONSTRAINT uq_scm_pr_context_versions_hash UNIQUE (context_hash),
  CONSTRAINT chk_scm_pr_context_versions_version CHECK (version > 0),
  CONSTRAINT chk_scm_pr_context_versions_hash CHECK (length(context_hash) = 71 AND context_hash LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS idx_scm_pr_context_versions_context ON scm_pr_context_versions(context_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_scm_pr_context_versions_head ON scm_pr_context_versions(context_id, head_sha);

CREATE TABLE IF NOT EXISTS requirement_match_snapshots (
  id UUID PRIMARY KEY,
  pr_context_version_id UUID NOT NULL REFERENCES scm_pr_context_versions(id) ON DELETE RESTRICT,
  algorithm_version VARCHAR(80) NOT NULL,
  status VARCHAR(24) NOT NULL,
  review_required BOOLEAN NOT NULL,
  explicit_unknown_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  model_invocation_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  snapshot_hash VARCHAR(80) NOT NULL,
  replay_snapshot JSONB NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_requirement_match_snapshots_context_version UNIQUE (pr_context_version_id),
  CONSTRAINT uq_requirement_match_snapshots_hash UNIQUE (snapshot_hash),
  CONSTRAINT chk_requirement_match_snapshots_status CHECK (status IN ('confirmed', 'candidate', 'conflict', 'unknown')),
  CONSTRAINT chk_requirement_match_snapshots_hash CHECK (length(snapshot_hash) = 71 AND snapshot_hash LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS idx_requirement_match_snapshots_context ON requirement_match_snapshots(pr_context_version_id, created_at DESC);

CREATE TABLE IF NOT EXISTS requirement_matches (
  id UUID PRIMARY KEY,
  snapshot_id UUID NOT NULL REFERENCES requirement_match_snapshots(id) ON DELETE RESTRICT,
  ordinal INTEGER NOT NULL,
  requirement_id VARCHAR(255) NOT NULL,
  requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE RESTRICT,
  source VARCHAR(40) NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  status VARCHAR(24) NOT NULL,
  review_required BOOLEAN NOT NULL,
  reasons JSONB NOT NULL,
  evidence_refs JSONB NOT NULL,
  model_invocation_ref JSONB,
  match_hash VARCHAR(80) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_requirement_matches_ordinal UNIQUE (snapshot_id, ordinal),
  CONSTRAINT uq_requirement_matches_hash UNIQUE (match_hash),
  CONSTRAINT chk_requirement_matches_source CHECK (source IN ('explicit_reference', 'manual_mapping', 'verified_traceability', 'rule', 'history', 'ai_suggestion')),
  CONSTRAINT chk_requirement_matches_status CHECK (status IN ('confirmed', 'candidate', 'rejected', 'unknown')),
  CONSTRAINT chk_requirement_matches_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_requirement_matches_confirmed_confidence CHECK (status <> 'confirmed' OR confidence >= 0.8),
  CONSTRAINT chk_requirement_matches_no_implicit_confirmation CHECK (NOT (source IN ('rule', 'history', 'ai_suggestion') AND status = 'confirmed')),
  CONSTRAINT chk_requirement_matches_hash CHECK (length(match_hash) = 71 AND match_hash LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS idx_requirement_matches_snapshot ON requirement_matches(snapshot_id, ordinal);
CREATE INDEX IF NOT EXISTS idx_requirement_matches_requirement ON requirement_matches(requirement_id, status);

ALTER TABLE scm_webhook_receipts
  DROP CONSTRAINT IF EXISTS fk_scm_webhook_receipts_context_version;
ALTER TABLE scm_webhook_receipts
  ADD CONSTRAINT fk_scm_webhook_receipts_context_version
  FOREIGN KEY (pr_context_version_id) REFERENCES scm_pr_context_versions(id) ON DELETE SET NULL;

CREATE OR REPLACE FUNCTION protect_scm_context_fact_mutation()
RETURNS TRIGGER AS $$ BEGIN
  RAISE EXCEPTION 'PR Context versions and Requirement Match snapshots are immutable' USING ERRCODE = '55000';
END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_scm_pr_context_version_immutable ON scm_pr_context_versions;
CREATE TRIGGER trg_scm_pr_context_version_immutable BEFORE UPDATE OR DELETE ON scm_pr_context_versions FOR EACH ROW EXECUTE FUNCTION protect_scm_context_fact_mutation();
DROP TRIGGER IF EXISTS trg_requirement_match_snapshot_immutable ON requirement_match_snapshots;
CREATE TRIGGER trg_requirement_match_snapshot_immutable BEFORE UPDATE OR DELETE ON requirement_match_snapshots FOR EACH ROW EXECUTE FUNCTION protect_scm_context_fact_mutation();
DROP TRIGGER IF EXISTS trg_requirement_match_immutable ON requirement_matches;
CREATE TRIGGER trg_requirement_match_immutable BEFORE UPDATE OR DELETE ON requirement_matches FOR EACH ROW EXECUTE FUNCTION protect_scm_context_fact_mutation();

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('webhook.service', 'integrations', 'Authenticate and admit verified SCM Webhook deliveries.', 'high', TRUE),
  ('pr.read', 'integrations', 'Read provider-neutral PR Context and Requirement Match projections.', 'low', TRUE),
  ('match.review', 'integrations', 'Review Requirement Match candidates through a governed follow-up workflow.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET category = EXCLUDED.category, description = EXCLUDED.description, risk_level = EXCLUDED.risk_level, is_active = TRUE;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'pr.read', TRUE),
  ('pro', 'pr.read', TRUE),
  ('enterprise', 'pr.read', TRUE),
  ('enterprise', 'match.review', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;

INSERT INTO rbac_role_capabilities (role_name, capability_key, effect)
VALUES ('system', 'webhook.service', 'allow')
ON CONFLICT (role_name, capability_key) DO UPDATE SET effect = 'allow';

COMMENT ON TABLE scm_webhook_receipts IS 'P20 verified delivery receipts; raw webhook payloads and secret values are never persisted.';
COMMENT ON TABLE scm_pr_context_versions IS 'P20 immutable provider-neutral PR Context versions; never a Gate or execution decision.';
COMMENT ON TABLE requirement_match_snapshots IS 'P20 ordered matching snapshot. Rule/history/AI results remain review candidates.';
