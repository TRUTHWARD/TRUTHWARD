-- Batch 3: Requirement Intake external_link source support.

ALTER TABLE requirement_intake_drafts
  ADD COLUMN IF NOT EXISTS source_uri VARCHAR(2048);

ALTER TABLE requirement_intake_drafts
  ADD COLUMN IF NOT EXISTS evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE requirement_intake_drafts
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_drafts_source_type;

ALTER TABLE requirement_intake_drafts
  ADD CONSTRAINT chk_requirement_intake_drafts_source_type
  CHECK (source_type IN ('paste', 'upload', 'external_link'));

ALTER TABLE requirement_intake_drafts
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_drafts_evidence_refs_array;

ALTER TABLE requirement_intake_drafts
  ADD CONSTRAINT chk_requirement_intake_drafts_evidence_refs_array
  CHECK (jsonb_typeof(evidence_refs) = 'array');

COMMENT ON TABLE requirement_intake_drafts IS 'Service-owned Requirement Intake drafts for paste, text upload, and controlled external HTTP/HTTPS text link sources. This is not a connector import, skill-service, integration-service, or second requirement pipeline.';
COMMENT ON COLUMN requirement_intake_drafts.source_uri IS 'Sanitized external_link source URI only. Credentials, cookies, tokens, and URL fragments must not be persisted.';
COMMENT ON COLUMN requirement_intake_drafts.evidence_refs IS 'Service-generated evidence refs for imported source artifacts and guardrail/redaction preflight.';

CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_source_uri ON requirement_intake_drafts(source_uri);

ALTER TABLE requirement_intake_previews
  ADD COLUMN IF NOT EXISTS source_uri VARCHAR(2048);

ALTER TABLE requirement_intake_previews
  ADD COLUMN IF NOT EXISTS evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE requirement_intake_previews
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_previews_source_type;

ALTER TABLE requirement_intake_previews
  ADD CONSTRAINT chk_requirement_intake_previews_source_type
  CHECK (source_type IN ('paste', 'upload', 'external_link'));

ALTER TABLE requirement_intake_previews
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_previews_evidence_refs_array;

ALTER TABLE requirement_intake_previews
  ADD CONSTRAINT chk_requirement_intake_previews_evidence_refs_array
  CHECK (jsonb_typeof(evidence_refs) = 'array');

COMMENT ON COLUMN requirement_intake_previews.source_uri IS 'Sanitized external_link source URI copied from Draft.';
COMMENT ON COLUMN requirement_intake_previews.evidence_refs IS 'Evidence refs copied from Draft for preview and confirm replayability.';

CREATE INDEX IF NOT EXISTS idx_requirement_intake_previews_source_uri ON requirement_intake_previews(source_uri);
