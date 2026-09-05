-- Batch 2 Requirement Intake upload sourceType.
-- Upload supports text artifacts only and stores payloads through StorageAdapter refs.

ALTER TABLE requirement_intake_drafts
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_drafts_source_type;

ALTER TABLE requirement_intake_drafts
  ADD COLUMN IF NOT EXISTS storage_ref VARCHAR(500),
  ADD COLUMN IF NOT EXISTS content_hash VARCHAR(80),
  ADD COLUMN IF NOT EXISTS mime_type VARCHAR(120),
  ADD COLUMN IF NOT EXISTS byte_size INTEGER,
  ADD COLUMN IF NOT EXISTS artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS redaction_status VARCHAR(32) NOT NULL DEFAULT 'not_required';

ALTER TABLE requirement_intake_drafts
  ADD CONSTRAINT chk_requirement_intake_drafts_source_type CHECK (source_type IN ('paste', 'upload'));

ALTER TABLE requirement_intake_drafts
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_drafts_redaction_status;

ALTER TABLE requirement_intake_drafts
  ADD CONSTRAINT chk_requirement_intake_drafts_redaction_status
  CHECK (redaction_status IN ('not_required', 'redacted', 'pending'));

ALTER TABLE requirement_intake_drafts
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_drafts_artifact_refs_array;

ALTER TABLE requirement_intake_drafts
  ADD CONSTRAINT chk_requirement_intake_drafts_artifact_refs_array CHECK (jsonb_typeof(artifact_refs) = 'array');

COMMENT ON TABLE requirement_intake_drafts IS 'Service-owned Requirement Intake drafts for paste and text upload. This is not a connector import, skill-service, or second requirement pipeline.';
COMMENT ON COLUMN requirement_intake_drafts.raw_content IS 'Redacted paste text only; upload drafts keep this empty and reference StorageAdapter artifacts.';
COMMENT ON COLUMN requirement_intake_drafts.storage_ref IS 'StorageAdapter reference for upload source payloads. DB stores metadata only, not binary payloads.';
COMMENT ON COLUMN requirement_intake_drafts.artifact_refs IS 'Upload artifact refs are metadata refs only; raw upload payloads must remain in StorageAdapter.';

CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_source_type ON requirement_intake_drafts(source_type);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_content_hash ON requirement_intake_drafts(content_hash);

ALTER TABLE requirement_intake_previews
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_previews_source_type;

ALTER TABLE requirement_intake_previews
  ADD COLUMN IF NOT EXISTS storage_ref VARCHAR(500),
  ADD COLUMN IF NOT EXISTS content_hash VARCHAR(80),
  ADD COLUMN IF NOT EXISTS mime_type VARCHAR(120),
  ADD COLUMN IF NOT EXISTS byte_size INTEGER,
  ADD COLUMN IF NOT EXISTS artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS redaction_status VARCHAR(32) NOT NULL DEFAULT 'not_required';

ALTER TABLE requirement_intake_previews
  ADD CONSTRAINT chk_requirement_intake_previews_source_type CHECK (source_type IN ('paste', 'upload'));

ALTER TABLE requirement_intake_previews
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_previews_redaction_status;

ALTER TABLE requirement_intake_previews
  ADD CONSTRAINT chk_requirement_intake_previews_redaction_status
  CHECK (redaction_status IN ('not_required', 'redacted', 'pending'));

ALTER TABLE requirement_intake_previews
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_previews_artifact_refs_array;

ALTER TABLE requirement_intake_previews
  ADD CONSTRAINT chk_requirement_intake_previews_artifact_refs_array CHECK (jsonb_typeof(artifact_refs) = 'array');

COMMENT ON COLUMN requirement_intake_previews.storage_ref IS 'StorageAdapter reference used to generate this upload preview.';
COMMENT ON COLUMN requirement_intake_previews.artifact_refs IS 'Upload preview artifact refs are metadata refs only; raw payloads must not be embedded.';

CREATE INDEX IF NOT EXISTS idx_requirement_intake_previews_source_type ON requirement_intake_previews(source_type);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_previews_content_hash ON requirement_intake_previews(content_hash);
