-- Batch 1 Requirement Intake Draft/Preview workbench.
-- Paste mode only; confirm reuses the existing Service-owned requirement pipeline.

CREATE TABLE IF NOT EXISTS requirement_intake_drafts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_type VARCHAR(32) NOT NULL DEFAULT 'paste',
  source_ref VARCHAR(255) NOT NULL,
  name VARCHAR(255) NOT NULL,
  raw_content TEXT NOT NULL,
  normalized_document TEXT NOT NULL,
  project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
  environment_id UUID REFERENCES project_environments(id) ON DELETE SET NULL,
  environment VARCHAR(100) NOT NULL DEFAULT 'local',
  domains JSONB NOT NULL DEFAULT '[]'::jsonb,
  risk_level risk_level NOT NULL DEFAULT 'medium',
  status VARCHAR(32) NOT NULL DEFAULT 'draft',
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_requirement_intake_drafts_source_type CHECK (source_type = 'paste'),
  CONSTRAINT chk_requirement_intake_drafts_status CHECK (status IN ('draft', 'previewed', 'confirmed', 'discarded')),
  CONSTRAINT chk_requirement_intake_drafts_domains_array CHECK (jsonb_typeof(domains) = 'array'),
  CONSTRAINT chk_requirement_intake_drafts_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

COMMENT ON TABLE requirement_intake_drafts IS 'Service-owned Requirement Intake paste drafts. This is not a connector import, upload pipeline, skill-service, or second requirement pipeline.';
COMMENT ON COLUMN requirement_intake_drafts.raw_content IS 'Redacted paste text; obvious plaintext credentials must not be persisted.';

CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_source_ref ON requirement_intake_drafts(source_ref);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_project ON requirement_intake_drafts(project_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_environment ON requirement_intake_drafts(environment_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_status ON requirement_intake_drafts(status);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_created_by ON requirement_intake_drafts(created_by);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_created_at ON requirement_intake_drafts(created_at DESC);

DROP TRIGGER IF EXISTS trg_requirement_intake_drafts_updated_at ON requirement_intake_drafts;
CREATE TRIGGER trg_requirement_intake_drafts_updated_at
BEFORE UPDATE ON requirement_intake_drafts
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS requirement_intake_previews (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  draft_id UUID NOT NULL REFERENCES requirement_intake_drafts(id) ON DELETE CASCADE,
  source_type VARCHAR(32) NOT NULL DEFAULT 'paste',
  source_ref VARCHAR(255) NOT NULL,
  document TEXT NOT NULL,
  requirements JSONB NOT NULL DEFAULT '[]'::jsonb,
  acceptance_criteria JSONB NOT NULL DEFAULT '[]'::jsonb,
  pipeline_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
  status VARCHAR(32) NOT NULL DEFAULT 'generated',
  linked_requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE SET NULL,
  linked_pipeline_id UUID REFERENCES orchestration_runs(id) ON DELETE SET NULL,
  confirmed_at TIMESTAMPTZ,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_requirement_intake_previews_source_type CHECK (source_type = 'paste'),
  CONSTRAINT chk_requirement_intake_previews_status CHECK (status IN ('generated', 'confirmed', 'superseded')),
  CONSTRAINT chk_requirement_intake_previews_requirements_array CHECK (jsonb_typeof(requirements) = 'array'),
  CONSTRAINT chk_requirement_intake_previews_acceptance_array CHECK (jsonb_typeof(acceptance_criteria) = 'array'),
  CONSTRAINT chk_requirement_intake_previews_pipeline_payload_object CHECK (jsonb_typeof(pipeline_payload) = 'object'),
  CONSTRAINT chk_requirement_intake_previews_warnings_array CHECK (jsonb_typeof(warnings) = 'array'),
  CONSTRAINT chk_requirement_intake_previews_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

COMMENT ON TABLE requirement_intake_previews IS 'Requirement Intake Preview records. Confirmed previews call OrchestratorService.run_requirement_pipeline and link to existing RequirementVersion and OrchestrationRun records.';

CREATE INDEX IF NOT EXISTS idx_requirement_intake_previews_draft ON requirement_intake_previews(draft_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_previews_pipeline ON requirement_intake_previews(linked_pipeline_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_previews_requirement ON requirement_intake_previews(linked_requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_previews_status ON requirement_intake_previews(status);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_previews_created_by ON requirement_intake_previews(created_by);

DROP TRIGGER IF EXISTS trg_requirement_intake_previews_updated_at ON requirement_intake_previews;
CREATE TRIGGER trg_requirement_intake_previews_updated_at
BEFORE UPDATE ON requirement_intake_previews
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

