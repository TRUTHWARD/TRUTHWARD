-- P17 governed Requirement/Code Change Set normalization.
-- Connectors remain provider-native adapters; normalization is Service-owned.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS change_source_snapshots (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  environment_id UUID REFERENCES project_environments(id) ON DELETE SET NULL,
  source_type VARCHAR(80) NOT NULL,
  source_id VARCHAR(500) NOT NULL,
  revision VARCHAR(255) NOT NULL,
  content_hash VARCHAR(80) NOT NULL,
  snapshot_ref VARCHAR(1000) NOT NULL UNIQUE,
  source_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  snapshot_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  acquired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT uq_change_source_snapshots_identity UNIQUE (
    tenant_id, workspace_id, project_id, source_type, source_id, revision, content_hash
  ),
  CONSTRAINT chk_change_source_snapshots_content_hash CHECK (length(content_hash) = 71)
);
CREATE INDEX IF NOT EXISTS idx_change_source_snapshots_scope ON change_source_snapshots(tenant_id, workspace_id, project_id, acquired_at);
CREATE INDEX IF NOT EXISTS idx_change_source_snapshots_source ON change_source_snapshots(source_type, source_id, revision);

CREATE TABLE IF NOT EXISTS change_sets (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  environment_id UUID REFERENCES project_environments(id) ON DELETE SET NULL,
  source_snapshot_id UUID NOT NULL REFERENCES change_source_snapshots(id) ON DELETE RESTRICT,
  change_set_type VARCHAR(32) NOT NULL,
  fingerprint VARCHAR(80) NOT NULL,
  normalizer_version VARCHAR(80) NOT NULL,
  status VARCHAR(32) NOT NULL,
  item_count INTEGER NOT NULL DEFAULT 0,
  issue_count INTEGER NOT NULL DEFAULT 0,
  sensitive BOOLEAN NOT NULL DEFAULT FALSE,
  artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_change_sets_fingerprint UNIQUE (tenant_id, workspace_id, project_id, fingerprint),
  CONSTRAINT chk_change_sets_type CHECK (change_set_type IN ('requirement', 'code')),
  CONSTRAINT chk_change_sets_status CHECK (status IN ('completed', 'partial', 'unknown')),
  CONSTRAINT chk_change_sets_counts CHECK (item_count >= 0 AND issue_count >= 0),
  CONSTRAINT chk_change_sets_fingerprint CHECK (length(fingerprint) = 71)
);
CREATE INDEX IF NOT EXISTS idx_change_sets_scope ON change_sets(tenant_id, workspace_id, project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_change_sets_source_snapshot ON change_sets(source_snapshot_id);
CREATE INDEX IF NOT EXISTS idx_change_sets_type_status ON change_sets(change_set_type, status);

CREATE TABLE IF NOT EXISTS requirement_change_sets (
  change_set_id UUID PRIMARY KEY REFERENCES change_sets(id) ON DELETE CASCADE,
  base_requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE RESTRICT,
  head_requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_requirement_change_sets_head ON requirement_change_sets(head_requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_requirement_change_sets_base ON requirement_change_sets(base_requirement_version_id);

CREATE TABLE IF NOT EXISTS requirement_change_items (
  id UUID PRIMARY KEY,
  change_set_id UUID NOT NULL REFERENCES requirement_change_sets(change_set_id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  requirement_id VARCHAR(255) NOT NULL,
  before_requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE RESTRICT,
  after_requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE RESTRICT,
  change_type VARCHAR(32) NOT NULL,
  before_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  after_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  changed_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
  explicit_capability_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  related_requirement_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  confidence NUMERIC(5,4) NOT NULL,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  CONSTRAINT uq_requirement_change_items_ordinal UNIQUE (change_set_id, ordinal),
  CONSTRAINT chk_requirement_change_items_type CHECK (change_type IN ('add', 'update', 'remove', 'rename', 'split', 'merge', 'unknown')),
  CONSTRAINT chk_requirement_change_items_confidence CHECK (confidence >= 0 AND confidence <= 1)
);
CREATE INDEX IF NOT EXISTS idx_requirement_change_items_requirement ON requirement_change_items(requirement_id);

CREATE TABLE IF NOT EXISTS code_change_sets (
  change_set_id UUID PRIMARY KEY REFERENCES change_sets(id) ON DELETE CASCADE,
  repository_ref VARCHAR(1000) NOT NULL,
  base_sha VARCHAR(64) NOT NULL,
  head_sha VARCHAR(64) NOT NULL,
  empty_diff BOOLEAN NOT NULL DEFAULT FALSE,
  force_push BOOLEAN NOT NULL DEFAULT FALSE,
  base_reachable BOOLEAN NOT NULL DEFAULT TRUE,
  CONSTRAINT chk_code_change_sets_revision CHECK (base_sha <> head_sha OR empty_diff = TRUE)
);
CREATE INDEX IF NOT EXISTS idx_code_change_sets_repository ON code_change_sets(repository_ref, head_sha);

CREATE TABLE IF NOT EXISTS code_change_files (
  id UUID PRIMARY KEY,
  change_set_id UUID NOT NULL REFERENCES code_change_sets(change_set_id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  path VARCHAR(2000) NOT NULL,
  old_path VARCHAR(2000),
  change_type VARCHAR(32) NOT NULL,
  language VARCHAR(80),
  "binary" BOOLEAN NOT NULL DEFAULT FALSE,
  generated BOOLEAN NOT NULL DEFAULT FALSE,
  vendor BOOLEAN NOT NULL DEFAULT FALSE,
  submodule BOOLEAN NOT NULL DEFAULT FALSE,
  risk_hints JSONB NOT NULL DEFAULT '[]'::jsonb,
  diff_artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  CONSTRAINT uq_code_change_files_ordinal UNIQUE (change_set_id, ordinal),
  CONSTRAINT uq_code_change_files_path UNIQUE (change_set_id, path),
  CONSTRAINT chk_code_change_files_type CHECK (change_type IN ('add', 'update', 'remove', 'rename', 'copy', 'unknown'))
);
CREATE INDEX IF NOT EXISTS idx_code_change_files_path ON code_change_files(path);

CREATE TABLE IF NOT EXISTS code_change_hunks (
  id UUID PRIMARY KEY,
  file_id UUID NOT NULL REFERENCES code_change_files(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  header VARCHAR(500) NOT NULL,
  old_line_start INTEGER,
  old_line_count INTEGER,
  new_line_start INTEGER,
  new_line_count INTEGER,
  content_hash VARCHAR(80) NOT NULL,
  diff_artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  sensitive BOOLEAN NOT NULL DEFAULT FALSE,
  redaction_count INTEGER NOT NULL DEFAULT 0,
  CONSTRAINT uq_code_change_hunks_ordinal UNIQUE (file_id, ordinal),
  CONSTRAINT chk_code_change_hunks_redaction_count CHECK (redaction_count >= 0),
  CONSTRAINT chk_code_change_hunks_content_hash CHECK (length(content_hash) = 71)
);
CREATE INDEX IF NOT EXISTS idx_code_change_hunks_file ON code_change_hunks(file_id);

CREATE TABLE IF NOT EXISTS code_change_symbols (
  id UUID PRIMARY KEY,
  hunk_id UUID NOT NULL REFERENCES code_change_hunks(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  name VARCHAR(500) NOT NULL,
  kind VARCHAR(80) NOT NULL,
  change_type VARCHAR(32) NOT NULL,
  old_line_start INTEGER,
  old_line_end INTEGER,
  new_line_start INTEGER,
  new_line_end INTEGER,
  confidence NUMERIC(5,4) NOT NULL,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  CONSTRAINT uq_code_change_symbols_ordinal UNIQUE (hunk_id, ordinal),
  CONSTRAINT chk_code_change_symbols_type CHECK (change_type IN ('add', 'update', 'remove', 'unknown')),
  CONSTRAINT chk_code_change_symbols_confidence CHECK (confidence >= 0 AND confidence <= 1)
);
CREATE INDEX IF NOT EXISTS idx_code_change_symbols_name ON code_change_symbols(name);

CREATE TABLE IF NOT EXISTS change_normalization_issues (
  id UUID PRIMARY KEY,
  change_set_id UUID NOT NULL REFERENCES change_sets(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  category VARCHAR(32) NOT NULL,
  code VARCHAR(120) NOT NULL,
  message VARCHAR(1000) NOT NULL,
  field VARCHAR(255),
  recoverable BOOLEAN NOT NULL DEFAULT TRUE,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  CONSTRAINT uq_change_normalization_issues_ordinal UNIQUE (change_set_id, ordinal),
  CONSTRAINT chk_change_normalization_issues_category CHECK (category IN ('incomplete', 'ambiguous', 'unsupported', 'sensitive'))
);
CREATE INDEX IF NOT EXISTS idx_change_normalization_issues_category ON change_normalization_issues(category);

CREATE OR REPLACE FUNCTION protect_change_set_snapshot_mutation()
RETURNS TRIGGER AS $$ BEGIN
  RAISE EXCEPTION 'Change Set snapshots are immutable' USING ERRCODE = '55000';
END; $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_change_source_snapshot_immutable ON change_source_snapshots;
CREATE TRIGGER trg_change_source_snapshot_immutable BEFORE UPDATE OR DELETE ON change_source_snapshots FOR EACH ROW EXECUTE FUNCTION protect_change_set_snapshot_mutation();
DROP TRIGGER IF EXISTS trg_change_set_immutable ON change_sets;
CREATE TRIGGER trg_change_set_immutable BEFORE UPDATE OR DELETE ON change_sets FOR EACH ROW EXECUTE FUNCTION protect_change_set_snapshot_mutation();
DROP TRIGGER IF EXISTS trg_requirement_change_set_immutable ON requirement_change_sets;
CREATE TRIGGER trg_requirement_change_set_immutable BEFORE UPDATE OR DELETE ON requirement_change_sets FOR EACH ROW EXECUTE FUNCTION protect_change_set_snapshot_mutation();
DROP TRIGGER IF EXISTS trg_requirement_change_item_immutable ON requirement_change_items;
CREATE TRIGGER trg_requirement_change_item_immutable BEFORE UPDATE OR DELETE ON requirement_change_items FOR EACH ROW EXECUTE FUNCTION protect_change_set_snapshot_mutation();
DROP TRIGGER IF EXISTS trg_code_change_set_immutable ON code_change_sets;
CREATE TRIGGER trg_code_change_set_immutable BEFORE UPDATE OR DELETE ON code_change_sets FOR EACH ROW EXECUTE FUNCTION protect_change_set_snapshot_mutation();
DROP TRIGGER IF EXISTS trg_code_change_file_immutable ON code_change_files;
CREATE TRIGGER trg_code_change_file_immutable BEFORE UPDATE OR DELETE ON code_change_files FOR EACH ROW EXECUTE FUNCTION protect_change_set_snapshot_mutation();
DROP TRIGGER IF EXISTS trg_code_change_hunk_immutable ON code_change_hunks;
CREATE TRIGGER trg_code_change_hunk_immutable BEFORE UPDATE OR DELETE ON code_change_hunks FOR EACH ROW EXECUTE FUNCTION protect_change_set_snapshot_mutation();
DROP TRIGGER IF EXISTS trg_code_change_symbol_immutable ON code_change_symbols;
CREATE TRIGGER trg_code_change_symbol_immutable BEFORE UPDATE OR DELETE ON code_change_symbols FOR EACH ROW EXECUTE FUNCTION protect_change_set_snapshot_mutation();
DROP TRIGGER IF EXISTS trg_change_normalization_issue_immutable ON change_normalization_issues;
CREATE TRIGGER trg_change_normalization_issue_immutable BEFORE UPDATE OR DELETE ON change_normalization_issues FOR EACH ROW EXECUTE FUNCTION protect_change_set_snapshot_mutation();

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('change.read', 'change', 'Read normalized Requirement and Code Change Sets.', 'low', TRUE),
  ('change.create', 'change', 'Ingest governed sources into normalized Change Sets.', 'medium', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET category = EXCLUDED.category, description = EXCLUDED.description, risk_level = EXCLUDED.risk_level, is_active = TRUE;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'change.read', TRUE),
  ('pro', 'change.read', TRUE),
  ('enterprise', 'change.read', TRUE),
  ('enterprise', 'change.create', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;

COMMENT ON TABLE change_sets IS 'P17 stable normalized input only. It never writes Gate, Memory, or impact conclusions.';
COMMENT ON TABLE code_change_hunks IS 'Hunk metadata and governed artifact refs only; full diff content is not stored in this table.';
