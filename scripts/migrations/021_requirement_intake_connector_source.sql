-- Batch 4: Requirement Intake connector sourceType with mock requirement document connector.

ALTER TABLE requirement_intake_drafts
  ADD COLUMN IF NOT EXISTS skill_invocation_id UUID;

ALTER TABLE requirement_intake_drafts
  ADD COLUMN IF NOT EXISTS connector_binding_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE requirement_intake_drafts
  ADD COLUMN IF NOT EXISTS connector_call_refs JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE requirement_intake_drafts
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_drafts_source_type;

ALTER TABLE requirement_intake_drafts
  ADD CONSTRAINT chk_requirement_intake_drafts_source_type
  CHECK (source_type IN ('paste', 'upload', 'external_link', 'connector'));

ALTER TABLE requirement_intake_drafts
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_drafts_connector_snapshot_object;

ALTER TABLE requirement_intake_drafts
  ADD CONSTRAINT chk_requirement_intake_drafts_connector_snapshot_object
  CHECK (jsonb_typeof(connector_binding_snapshot) = 'object');

ALTER TABLE requirement_intake_drafts
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_drafts_connector_call_refs_array;

ALTER TABLE requirement_intake_drafts
  ADD CONSTRAINT chk_requirement_intake_drafts_connector_call_refs_array
  CHECK (jsonb_typeof(connector_call_refs) = 'array');

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_requirement_intake_drafts_skill_invocation_id'
  ) THEN
    ALTER TABLE requirement_intake_drafts
      ADD CONSTRAINT fk_requirement_intake_drafts_skill_invocation_id
      FOREIGN KEY (skill_invocation_id) REFERENCES skill_invocations(id) ON DELETE SET NULL;
  END IF;
END $$;

COMMENT ON TABLE requirement_intake_drafts IS 'Service-owned Requirement Intake drafts for paste, text upload, controlled external HTTP/HTTPS text link, and mock requirement document connector sources. This is not a skill-service, integration-service, or second requirement pipeline.';
COMMENT ON COLUMN requirement_intake_drafts.skill_invocation_id IS 'Service-managed integration-intake Skill Invocation used for connector source normalization.';
COMMENT ON COLUMN requirement_intake_drafts.connector_binding_snapshot IS 'Frozen connector binding snapshot for connector source replay; must contain only refs, never plaintext credentials.';
COMMENT ON COLUMN requirement_intake_drafts.connector_call_refs IS 'Frozen connector call refs for connector source replay.';

CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_skill_invocation ON requirement_intake_drafts(skill_invocation_id);

ALTER TABLE requirement_intake_previews
  ADD COLUMN IF NOT EXISTS skill_invocation_id UUID;

ALTER TABLE requirement_intake_previews
  ADD COLUMN IF NOT EXISTS connector_binding_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE requirement_intake_previews
  ADD COLUMN IF NOT EXISTS connector_call_refs JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE requirement_intake_previews
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_previews_source_type;

ALTER TABLE requirement_intake_previews
  ADD CONSTRAINT chk_requirement_intake_previews_source_type
  CHECK (source_type IN ('paste', 'upload', 'external_link', 'connector'));

ALTER TABLE requirement_intake_previews
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_previews_connector_snapshot_object;

ALTER TABLE requirement_intake_previews
  ADD CONSTRAINT chk_requirement_intake_previews_connector_snapshot_object
  CHECK (jsonb_typeof(connector_binding_snapshot) = 'object');

ALTER TABLE requirement_intake_previews
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_previews_connector_call_refs_array;

ALTER TABLE requirement_intake_previews
  ADD CONSTRAINT chk_requirement_intake_previews_connector_call_refs_array
  CHECK (jsonb_typeof(connector_call_refs) = 'array');

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_requirement_intake_previews_skill_invocation_id'
  ) THEN
    ALTER TABLE requirement_intake_previews
      ADD CONSTRAINT fk_requirement_intake_previews_skill_invocation_id
      FOREIGN KEY (skill_invocation_id) REFERENCES skill_invocations(id) ON DELETE SET NULL;
  END IF;
END $$;

COMMENT ON COLUMN requirement_intake_previews.skill_invocation_id IS 'Service-managed integration-intake Skill Invocation copied from connector Draft.';
COMMENT ON COLUMN requirement_intake_previews.connector_binding_snapshot IS 'Frozen connector binding snapshot copied from Draft for replay.';
COMMENT ON COLUMN requirement_intake_previews.connector_call_refs IS 'Frozen connector call refs copied from Draft for replay.';

CREATE INDEX IF NOT EXISTS idx_requirement_intake_previews_skill_invocation ON requirement_intake_previews(skill_invocation_id);
