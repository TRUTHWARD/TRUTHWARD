-- P09: Service-owned Evidence Index metadata and controlled-query capability seeds.
-- Original evidence/artifact/replay payloads remain in their existing owners.

CREATE TABLE IF NOT EXISTS evidence_index_entries (
  entry_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  source_type VARCHAR(40) NOT NULL,
  source_id VARCHAR(255) NOT NULL,
  source_version VARCHAR(255) NOT NULL,
  content_hash VARCHAR(80) NOT NULL,
  title VARCHAR(500) NOT NULL,
  summary TEXT NOT NULL,
  search_text TEXT NOT NULL,
  facets JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  classification VARCHAR(40) NOT NULL,
  redaction_version VARCHAR(80) NOT NULL,
  indexed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  source_updated_at TIMESTAMPTZ,
  stale BOOLEAN NOT NULL DEFAULT FALSE,
  retention_state VARCHAR(40) NOT NULL DEFAULT 'active',
  unavailable_reason_code VARCHAR(120),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT uq_evidence_index_source_version_hash UNIQUE (
    tenant_id,
    workspace_id,
    project_id,
    source_type,
    source_id,
    source_version,
    content_hash,
    redaction_version
  ),
  CONSTRAINT chk_evidence_index_source_type CHECK (
    source_type IN ('execution', 'finding', 'gate', 'policy', 'trace', 'replay', 'graph', 'artifact')
  ),
  CONSTRAINT chk_evidence_index_classification CHECK (
    classification IN ('public', 'internal', 'confidential', 'restricted')
  ),
  CONSTRAINT chk_evidence_index_retention_state CHECK (
    retention_state IN ('active', 'archived', 'purge_eligible', 'purged', 'legal_hold')
  ),
  CONSTRAINT chk_evidence_index_content_hash CHECK (
    content_hash ~ '^sha256:[0-9a-f]{64}$'
  )
);

CREATE INDEX IF NOT EXISTS idx_evidence_index_scope
  ON evidence_index_entries(tenant_id, workspace_id, project_id, stale);
CREATE INDEX IF NOT EXISTS idx_evidence_index_source
  ON evidence_index_entries(source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_evidence_index_classification
  ON evidence_index_entries(classification);
CREATE INDEX IF NOT EXISTS idx_evidence_index_indexed_at
  ON evidence_index_entries(indexed_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_index_retention
  ON evidence_index_entries(retention_state);
CREATE INDEX IF NOT EXISTS idx_evidence_index_facets_gin
  ON evidence_index_entries USING GIN(facets);
CREATE INDEX IF NOT EXISTS idx_evidence_index_search_fts
  ON evidence_index_entries USING GIN(to_tsvector('simple', search_text));

CREATE TABLE IF NOT EXISTS evidence_index_jobs (
  job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  job_type VARCHAR(40) NOT NULL DEFAULT 'incremental',
  status VARCHAR(40) NOT NULL DEFAULT 'queued',
  idempotency_key VARCHAR(255) NOT NULL,
  source_types JSONB NOT NULL DEFAULT '[]'::jsonb,
  scanned_count INTEGER NOT NULL DEFAULT 0,
  upserted_count INTEGER NOT NULL DEFAULT 0,
  unchanged_count INTEGER NOT NULL DEFAULT 0,
  stale_count INTEGER NOT NULL DEFAULT 0,
  redaction_version VARCHAR(80) NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  error_code VARCHAR(120),
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_evidence_index_jobs_scope_idempotency UNIQUE (
    tenant_id, workspace_id, project_id, idempotency_key
  ),
  CONSTRAINT chk_evidence_index_jobs_type CHECK (
    job_type IN ('incremental', 'rebuild', 'redaction_reindex')
  ),
  CONSTRAINT chk_evidence_index_jobs_status CHECK (
    status IN ('queued', 'running', 'completed', 'failed')
  ),
  CONSTRAINT chk_evidence_index_jobs_counts CHECK (
    scanned_count >= 0 AND upserted_count >= 0 AND unchanged_count >= 0 AND stale_count >= 0
  )
);

CREATE INDEX IF NOT EXISTS idx_evidence_index_jobs_scope
  ON evidence_index_jobs(tenant_id, workspace_id, project_id);
CREATE INDEX IF NOT EXISTS idx_evidence_index_jobs_status
  ON evidence_index_jobs(status, created_at DESC);

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('evidence.read', 'evidence', 'Read redacted Evidence Index entries and status.', 'low', TRUE),
  ('evidence.query', 'evidence', 'Run controlled read-only Evidence queries.', 'low', TRUE),
  ('evidence.raw.read', 'evidence', 'Read backend-redacted raw evidence projections.', 'medium', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = EXCLUDED.is_active;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'evidence.read', TRUE),
  ('basic', 'evidence.query', TRUE),
  ('pro', 'evidence.read', TRUE),
  ('pro', 'evidence.query', TRUE),
  ('enterprise', 'evidence.read', TRUE),
  ('enterprise', 'evidence.query', TRUE),
  ('enterprise', 'evidence.raw.read', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = EXCLUDED.enabled;

INSERT INTO rbac_role_capabilities (role_name, capability_key, effect)
VALUES
  ('admin', 'evidence.read', 'allow'),
  ('admin', 'evidence.query', 'allow'),
  ('admin', 'evidence.raw.read', 'allow'),
  ('system', 'evidence.read', 'allow'),
  ('system', 'evidence.query', 'allow'),
  ('system', 'evidence.raw.read', 'allow'),
  ('user', 'evidence.read', 'allow'),
  ('user', 'evidence.query', 'allow'),
  ('agent', 'evidence.read', 'allow'),
  ('agent', 'evidence.query', 'allow')
ON CONFLICT (role_name, capability_key) DO UPDATE SET effect = EXCLUDED.effect;
