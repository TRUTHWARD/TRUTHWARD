-- Batch 14: independent Service-managed OCR requirement intake source.

ALTER TABLE requirement_intake_drafts
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_drafts_source_type;

ALTER TABLE requirement_intake_drafts
  ADD CONSTRAINT chk_requirement_intake_drafts_source_type
  CHECK (source_type IN ('paste', 'upload', 'ocr_upload', 'external_link', 'connector'));

ALTER TABLE requirement_intake_drafts
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_drafts_status;

ALTER TABLE requirement_intake_drafts
  ADD CONSTRAINT chk_requirement_intake_drafts_status
  CHECK (status IN ('draft', 'previewed', 'review_required', 'blocked', 'confirmed', 'discarded'));

ALTER TABLE requirement_intake_previews
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_previews_source_type;

ALTER TABLE requirement_intake_previews
  ADD CONSTRAINT chk_requirement_intake_previews_source_type
  CHECK (source_type IN ('paste', 'upload', 'ocr_upload', 'external_link', 'connector'));

ALTER TABLE requirement_intake_previews
  DROP CONSTRAINT IF EXISTS chk_requirement_intake_previews_status;

ALTER TABLE requirement_intake_previews
  ADD CONSTRAINT chk_requirement_intake_previews_status
  CHECK (status IN ('generated', 'review_required', 'blocked', 'confirmed', 'superseded'));

COMMENT ON TABLE requirement_intake_drafts IS 'Service-owned Requirement Intake drafts for paste, text/document upload, independent OCR upload, controlled external link, and connector sources. OCR binary stays behind StorageAdapter refs.';
COMMENT ON COLUMN requirement_intake_drafts.normalized_document IS 'Redacted text for paste and OCR sources only; OCR images/PDF binary must never be stored here.';
COMMENT ON TABLE requirement_intake_previews IS 'Requirement Intake Preview records including OCR confidence/review projections in metadata; Confirm still calls the existing requirement pipeline.';
