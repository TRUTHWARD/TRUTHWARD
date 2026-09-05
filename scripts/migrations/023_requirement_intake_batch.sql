-- Batch 12: Service-owned multi-source Requirement Intake batch aggregate.

CREATE TABLE IF NOT EXISTS requirement_intake_batches (
  id UUID PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  idempotency_key VARCHAR(120),
  status VARCHAR(32) NOT NULL DEFAULT 'pending',
  environment VARCHAR(100) NOT NULL DEFAULT 'local',
  project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
  environment_id UUID REFERENCES project_environments(id) ON DELETE SET NULL,
  domains JSONB NOT NULL DEFAULT '[]'::jsonb,
  risk_level VARCHAR(20) NOT NULL DEFAULT 'medium',
  summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT chk_requirement_intake_batches_status
    CHECK (status IN ('pending', 'ready', 'partially_failed', 'failed', 'partially_confirmed', 'confirmed')),
  CONSTRAINT chk_requirement_intake_batches_domains_array CHECK (jsonb_typeof(domains) = 'array'),
  CONSTRAINT chk_requirement_intake_batches_summary_object CHECK (jsonb_typeof(summary) = 'object'),
  CONSTRAINT chk_requirement_intake_batches_metadata_object CHECK (jsonb_typeof(metadata) = 'object'),
  CONSTRAINT uq_requirement_intake_batches_created_by_idempotency UNIQUE (created_by, idempotency_key)
);

COMMENT ON TABLE requirement_intake_batches IS 'Service-owned Requirement Intake batch aggregate for multiple independent sources. This is not a new pipeline, skill-service, or integration-service.';
COMMENT ON COLUMN requirement_intake_batches.idempotency_key IS 'Optional client idempotency key scoped by created_by for safe retry of batch creation.';
COMMENT ON COLUMN requirement_intake_batches.summary IS 'Backend-computed source status counts for batch views.';

CREATE INDEX IF NOT EXISTS idx_requirement_intake_batches_status ON requirement_intake_batches(status);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_batches_project ON requirement_intake_batches(project_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_batches_environment ON requirement_intake_batches(environment_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_batches_created_by ON requirement_intake_batches(created_by);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_batches_created_at ON requirement_intake_batches(created_at DESC);

DROP TRIGGER IF EXISTS trg_requirement_intake_batches_updated_at ON requirement_intake_batches;
CREATE TRIGGER trg_requirement_intake_batches_updated_at
BEFORE UPDATE ON requirement_intake_batches
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS requirement_intake_batch_sources (
  id UUID PRIMARY KEY,
  batch_id UUID NOT NULL REFERENCES requirement_intake_batches(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  source_type VARCHAR(32) NOT NULL,
  source_key VARCHAR(180) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'pending',
  draft_id UUID REFERENCES requirement_intake_drafts(id) ON DELETE SET NULL,
  preview_id UUID REFERENCES requirement_intake_previews(id) ON DELETE SET NULL,
  linked_requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE SET NULL,
  linked_pipeline_id UUID REFERENCES orchestration_runs(id) ON DELETE SET NULL,
  error_message TEXT,
  artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  retry_count INTEGER NOT NULL DEFAULT 0,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT chk_requirement_intake_batch_sources_source_type
    CHECK (source_type IN ('paste', 'upload', 'external_link', 'connector')),
  CONSTRAINT chk_requirement_intake_batch_sources_status
    CHECK (status IN ('pending', 'pending_confirm', 'failed', 'confirmed')),
  CONSTRAINT chk_requirement_intake_batch_sources_artifact_refs_array CHECK (jsonb_typeof(artifact_refs) = 'array'),
  CONSTRAINT chk_requirement_intake_batch_sources_evidence_refs_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
  CONSTRAINT chk_requirement_intake_batch_sources_metadata_object CHECK (jsonb_typeof(metadata) = 'object'),
  CONSTRAINT uq_requirement_intake_batch_sources_key UNIQUE (batch_id, source_key)
);

COMMENT ON TABLE requirement_intake_batch_sources IS 'One independent source inside a Requirement Intake batch. Each source links to its own Draft and Preview and keeps independent evidence, artifacts, status, and error state.';
COMMENT ON COLUMN requirement_intake_batch_sources.draft_id IS 'Independent single-source Draft created through the existing RequirementIntakeService boundary.';
COMMENT ON COLUMN requirement_intake_batch_sources.preview_id IS 'Independent single-source Preview; confirm reuses the existing requirement pipeline through RequirementIntakeService.confirm_preview.';
COMMENT ON COLUMN requirement_intake_batch_sources.evidence_refs IS 'Per-source evidence refs copied from the independent Draft/Preview. Documents are never concatenated into one Draft.';

CREATE INDEX IF NOT EXISTS idx_requirement_intake_batch_sources_batch ON requirement_intake_batch_sources(batch_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_batch_sources_status ON requirement_intake_batch_sources(status);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_batch_sources_source_type ON requirement_intake_batch_sources(source_type);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_batch_sources_draft ON requirement_intake_batch_sources(draft_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_batch_sources_preview ON requirement_intake_batch_sources(preview_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_batch_sources_pipeline ON requirement_intake_batch_sources(linked_pipeline_id);

DROP TRIGGER IF EXISTS trg_requirement_intake_batch_sources_updated_at ON requirement_intake_batch_sources;
CREATE TRIGGER trg_requirement_intake_batch_sources_updated_at
BEFORE UPDATE ON requirement_intake_batch_sources
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
