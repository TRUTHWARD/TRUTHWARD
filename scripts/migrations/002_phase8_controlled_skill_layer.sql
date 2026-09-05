-- Phase 8 Controlled Skill Layer incremental migration for PostgreSQL 15+.
-- Apply after the Phase 7 Visual Grounding migration. The canonical fresh-install
-- schema is DB_SCHEMA.sql; this file is the upgrade path for existing databases.

ALTER TYPE guardrail_scope ADD VALUE IF NOT EXISTS 'skill';
ALTER TYPE guardrail_scope ADD VALUE IF NOT EXISTS 'connector';

CREATE TABLE IF NOT EXISTS skills (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  skill_id VARCHAR(128) NOT NULL UNIQUE,
  display_name VARCHAR(255) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE skills IS 'Phase 8 logical Skill catalog. This is not a skill-service boundary.';

CREATE TABLE IF NOT EXISTS skill_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  skill_ref_id UUID NOT NULL REFERENCES skills(id) ON DELETE CASCADE,
  version VARCHAR(64) NOT NULL,
  manifest_hash VARCHAR(128) NOT NULL,
  manifest_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  capabilities JSONB NOT NULL DEFAULT '{}'::jsonb,
  input_schema JSONB NOT NULL DEFAULT '{}'::jsonb,
  output_schema JSONB NOT NULL DEFAULT '{}'::jsonb,
  allowed_tools JSONB NOT NULL DEFAULT '[]'::jsonb,
  allowed_connectors JSONB NOT NULL DEFAULT '[]'::jsonb,
  risk_profile JSONB NOT NULL DEFAULT '{}'::jsonb,
  approval_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
  data_access_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
  replay_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_skill_manifest UNIQUE(skill_ref_id, version, manifest_hash),
  CONSTRAINT chk_skill_versions_allowed_tools_array CHECK (jsonb_typeof(allowed_tools) = 'array'),
  CONSTRAINT chk_skill_versions_allowed_connectors_array CHECK (jsonb_typeof(allowed_connectors) = 'array')
);

COMMENT ON TABLE skill_versions IS 'Immutable Skill Manifest snapshots used by Replay Freeze.';

CREATE TABLE IF NOT EXISTS skill_connector_bindings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  connector_name VARCHAR(128) NOT NULL,
  secret_ref TEXT NOT NULL,
  credential_ref TEXT,
  scope JSONB NOT NULL DEFAULT '{}'::jsonb,
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_skill_connector_bindings_scope_object CHECK (jsonb_typeof(scope) = 'object')
);

COMMENT ON TABLE skill_connector_bindings IS 'Connector credential references only; never store plaintext secrets.';

CREATE TABLE IF NOT EXISTS skill_invocations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  execution_id UUID REFERENCES executions(id) ON DELETE SET NULL,
  agent_run_id UUID REFERENCES agent_runs(id) ON DELETE SET NULL,
  skill_version_id UUID NOT NULL REFERENCES skill_versions(id) ON DELETE RESTRICT,
  status VARCHAR(32) NOT NULL DEFAULT 'queued',
  idempotency_key VARCHAR(255) UNIQUE,
  input_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  output_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  policy_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  connector_binding_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  tool_call_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  connector_call_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_skill_invocations_artifact_refs_array CHECK (jsonb_typeof(artifact_refs) = 'array'),
  CONSTRAINT chk_skill_invocations_tool_call_refs_array CHECK (jsonb_typeof(tool_call_refs) = 'array'),
  CONSTRAINT chk_skill_invocations_connector_call_refs_array CHECK (jsonb_typeof(connector_call_refs) = 'array')
);

COMMENT ON TABLE skill_invocations IS 'Service-managed Skill Invocation snapshots. Skills do not write this table directly.';

CREATE TABLE IF NOT EXISTS skill_tool_calls (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  skill_invocation_id UUID NOT NULL REFERENCES skill_invocations(id) ON DELETE CASCADE,
  tool_name VARCHAR(128) NOT NULL,
  tool_call_ref TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS skill_connector_calls (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  skill_invocation_id UUID NOT NULL REFERENCES skill_invocations(id) ON DELETE CASCADE,
  connector_name VARCHAR(128) NOT NULL,
  connector_call_ref TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE skill_invocations
  ADD COLUMN IF NOT EXISTS agent_run_id UUID,
  ADD COLUMN IF NOT EXISTS idempotency_key VARCHAR(255),
  ADD COLUMN IF NOT EXISTS status VARCHAR(32) NOT NULL DEFAULT 'queued',
  ADD COLUMN IF NOT EXISTS error_message TEXT;

ALTER TABLE guardrail_events
  ADD COLUMN IF NOT EXISTS skill_invocation_id UUID,
  ADD COLUMN IF NOT EXISTS connector_binding_id UUID,
  ADD COLUMN IF NOT EXISTS tool_call_id UUID;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'uq_skill_invocations_idempotency_key'
  ) THEN
    ALTER TABLE skill_invocations
      ADD CONSTRAINT uq_skill_invocations_idempotency_key UNIQUE(idempotency_key);
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_skill_invocations_agent_run_id'
  ) THEN
    ALTER TABLE skill_invocations
      ADD CONSTRAINT fk_skill_invocations_agent_run_id
      FOREIGN KEY (agent_run_id) REFERENCES agent_runs(id) ON DELETE SET NULL;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_guardrail_events_skill_invocation_id'
  ) THEN
    ALTER TABLE guardrail_events
      ADD CONSTRAINT fk_guardrail_events_skill_invocation_id
      FOREIGN KEY (skill_invocation_id) REFERENCES skill_invocations(id) ON DELETE SET NULL;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_guardrail_events_connector_binding_id'
  ) THEN
    ALTER TABLE guardrail_events
      ADD CONSTRAINT fk_guardrail_events_connector_binding_id
      FOREIGN KEY (connector_binding_id) REFERENCES skill_connector_bindings(id) ON DELETE SET NULL;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_guardrail_events_tool_call_id'
  ) THEN
    ALTER TABLE guardrail_events
      ADD CONSTRAINT fk_guardrail_events_tool_call_id
      FOREIGN KEY (tool_call_id) REFERENCES skill_tool_calls(id) ON DELETE SET NULL;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_skill_versions_skill_ref_id ON skill_versions(skill_ref_id);
CREATE INDEX IF NOT EXISTS idx_skill_versions_manifest_hash ON skill_versions(manifest_hash);
CREATE INDEX IF NOT EXISTS idx_skill_invocations_execution_id ON skill_invocations(execution_id);
CREATE INDEX IF NOT EXISTS idx_skill_invocations_trace_id ON skill_invocations(trace_id);
CREATE INDEX IF NOT EXISTS idx_skill_invocations_skill_version_id ON skill_invocations(skill_version_id);
CREATE INDEX IF NOT EXISTS idx_skill_invocations_idempotency_key ON skill_invocations(idempotency_key);
CREATE INDEX IF NOT EXISTS idx_skill_tool_calls_invocation_id ON skill_tool_calls(skill_invocation_id);
CREATE INDEX IF NOT EXISTS idx_skill_connector_calls_invocation_id ON skill_connector_calls(skill_invocation_id);
CREATE INDEX IF NOT EXISTS idx_skill_connector_bindings_connector_name ON skill_connector_bindings(connector_name);
CREATE INDEX IF NOT EXISTS idx_guardrail_events_skill_invocation_id ON guardrail_events(skill_invocation_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_events_connector_binding_id ON guardrail_events(connector_binding_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_events_tool_call_id ON guardrail_events(tool_call_id);
