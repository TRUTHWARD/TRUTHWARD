-- Replay Repository P0: empty repository schema only.
-- There is no historical replay migration/backfill; immutability starts with the first frozen record.

CREATE TABLE IF NOT EXISTS replay_repository_entries (
  id UUID PRIMARY KEY,
  replay_id VARCHAR(120) NOT NULL,
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE RESTRICT,
  schema_version VARCHAR(80) NOT NULL DEFAULT 'phase8.replay-repository.v1',
  source_replay_export_hash VARCHAR(80) NOT NULL,
  export_payload_hash VARCHAR(80) NOT NULL,
  manifest_hash VARCHAR(80) NOT NULL,
  payload_hash VARCHAR(80) NOT NULL,
  manifest JSONB NOT NULL DEFAULT '{}'::jsonb,
  summary_projection JSONB NOT NULL DEFAULT '{}'::jsonb,
  section_index JSONB NOT NULL DEFAULT '[]'::jsonb,
  storage_adapter VARCHAR(40) NOT NULL DEFAULT 'local',
  redaction_status VARCHAR(40) NOT NULL DEFAULT 'redacted',
  validity_status VARCHAR(40) NOT NULL DEFAULT 'valid',
  approval_mode VARCHAR(40) NOT NULL DEFAULT 'always',
  approval_state VARCHAR(40) NOT NULL DEFAULT 'approved',
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  retention_policy VARCHAR(80) NOT NULL DEFAULT 'default',
  retention_until TIMESTAMPTZ,
  legal_hold BOOLEAN NOT NULL DEFAULT FALSE,
  archived_at TIMESTAMPTZ,
  purge_eligible_at TIMESTAMPTZ,
  retention_status VARCHAR(40) NOT NULL DEFAULT 'active',
  frozen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_replay_repository_entries_replay_id UNIQUE (replay_id),
  CONSTRAINT uq_replay_repository_entries_export_hash UNIQUE (source_replay_export_hash),
  CONSTRAINT chk_replay_repository_entries_approval_mode CHECK (approval_mode IN ('always', 'policy_only', 'threshold')),
  CONSTRAINT chk_replay_repository_entries_approval_state CHECK (approval_state IN ('pending', 'approved', 'not_required', 'rejected', 'cancelled')),
  CONSTRAINT chk_replay_repository_entries_retention_status CHECK (retention_status IN ('active', 'archived', 'purge_eligible', 'purged', 'legal_hold')),
  CONSTRAINT chk_replay_repository_entries_validity_status CHECK (validity_status IN ('valid', 'invalid', 'unknown')),
  CONSTRAINT chk_replay_repository_entries_manifest_object CHECK (jsonb_typeof(manifest) = 'object'),
  CONSTRAINT chk_replay_repository_entries_summary_object CHECK (jsonb_typeof(summary_projection) = 'object'),
  CONSTRAINT chk_replay_repository_entries_section_index_array CHECK (jsonb_typeof(section_index) = 'array'),
  CONSTRAINT chk_replay_repository_entries_approval_refs_array CHECK (jsonb_typeof(approval_refs) = 'array'),
  CONSTRAINT chk_replay_repository_entries_guardrail_refs_array CHECK (jsonb_typeof(guardrail_event_refs) = 'array'),
  CONSTRAINT chk_replay_repository_entries_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_replay_repository_entries_execution
  ON replay_repository_entries(execution_id);
CREATE INDEX IF NOT EXISTS idx_replay_repository_entries_created_at
  ON replay_repository_entries(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_replay_repository_entries_retention
  ON replay_repository_entries(retention_status);

DROP TRIGGER IF EXISTS trg_replay_repository_entries_updated_at ON replay_repository_entries;
CREATE TRIGGER trg_replay_repository_entries_updated_at
BEFORE UPDATE ON replay_repository_entries
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS replay_repository_sections (
  id UUID PRIMARY KEY,
  replay_entry_id UUID NOT NULL REFERENCES replay_repository_entries(id) ON DELETE CASCADE,
  section_name VARCHAR(120) NOT NULL,
  storage_ref VARCHAR(500) NOT NULL,
  content_hash VARCHAR(80) NOT NULL,
  byte_size INTEGER NOT NULL DEFAULT 0,
  compression VARCHAR(40) NOT NULL DEFAULT 'none',
  redaction_status VARCHAR(40) NOT NULL DEFAULT 'redacted',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_replay_repository_sections_entry_section UNIQUE (replay_entry_id, section_name),
  CONSTRAINT chk_replay_repository_sections_byte_size CHECK (byte_size >= 0)
);

CREATE INDEX IF NOT EXISTS idx_replay_repository_sections_entry
  ON replay_repository_sections(replay_entry_id);
CREATE INDEX IF NOT EXISTS idx_replay_repository_sections_name
  ON replay_repository_sections(section_name);
