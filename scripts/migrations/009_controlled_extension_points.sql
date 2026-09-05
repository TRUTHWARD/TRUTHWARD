-- Controlled Extension Points / Capability Bindings implementation.
-- Extends the existing Phase 8 Skill tables; does not create a parallel Skill catalog.

ALTER TABLE skill_versions
  ADD COLUMN IF NOT EXISTS extension_points JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS compatibility JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE skill_versions
  ALTER COLUMN extension_points TYPE JSONB USING extension_points::jsonb,
  ALTER COLUMN compatibility TYPE JSONB USING compatibility::jsonb;

ALTER TABLE skill_invocations
  ADD COLUMN IF NOT EXISTS binding_id UUID,
  ADD COLUMN IF NOT EXISTS extension_point_id VARCHAR(160),
  ADD COLUMN IF NOT EXISTS source_workflow VARCHAR(120),
  ADD COLUMN IF NOT EXISTS resolution_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE skill_invocations
  ALTER COLUMN input_snapshot TYPE JSONB USING input_snapshot::jsonb,
  ALTER COLUMN output_snapshot TYPE JSONB USING output_snapshot::jsonb,
  ALTER COLUMN policy_snapshot TYPE JSONB USING policy_snapshot::jsonb,
  ALTER COLUMN resolution_snapshot TYPE JSONB USING resolution_snapshot::jsonb,
  ALTER COLUMN connector_binding_snapshot TYPE JSONB USING connector_binding_snapshot::jsonb,
  ALTER COLUMN approval_refs TYPE JSONB USING approval_refs::jsonb;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_skill_versions_extension_points_array') THEN
    ALTER TABLE skill_versions
      ADD CONSTRAINT chk_skill_versions_extension_points_array CHECK (jsonb_typeof(extension_points::jsonb) = 'array');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_skill_versions_compatibility_object') THEN
    ALTER TABLE skill_versions
      ADD CONSTRAINT chk_skill_versions_compatibility_object CHECK (jsonb_typeof(compatibility::jsonb) = 'object');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_skill_invocations_input_object') THEN
    ALTER TABLE skill_invocations
      ADD CONSTRAINT chk_skill_invocations_input_object CHECK (jsonb_typeof(input_snapshot::jsonb) = 'object');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_skill_invocations_output_object') THEN
    ALTER TABLE skill_invocations
      ADD CONSTRAINT chk_skill_invocations_output_object CHECK (jsonb_typeof(output_snapshot::jsonb) = 'object');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_skill_invocations_policy_object') THEN
    ALTER TABLE skill_invocations
      ADD CONSTRAINT chk_skill_invocations_policy_object CHECK (jsonb_typeof(policy_snapshot::jsonb) = 'object');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_skill_invocations_resolution_object') THEN
    ALTER TABLE skill_invocations
      ADD CONSTRAINT chk_skill_invocations_resolution_object CHECK (jsonb_typeof(resolution_snapshot::jsonb) = 'object');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_skill_invocations_connector_snapshot_object') THEN
    ALTER TABLE skill_invocations
      ADD CONSTRAINT chk_skill_invocations_connector_snapshot_object CHECK (jsonb_typeof(connector_binding_snapshot::jsonb) = 'object');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_skill_invocations_approval_refs_array') THEN
    ALTER TABLE skill_invocations
      ADD CONSTRAINT chk_skill_invocations_approval_refs_array CHECK (jsonb_typeof(approval_refs::jsonb) = 'array');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_skill_invocations_status') THEN
    ALTER TABLE skill_invocations
      ADD CONSTRAINT chk_skill_invocations_status CHECK (status IN ('created', 'queued', 'running', 'completed', 'failed', 'cancelled', 'blocked', 'preflight_blocked', 'pending_approval', 'invalid_output'));
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS capability_bindings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  extension_point_id VARCHAR(160) NOT NULL,
  skill_version_id UUID NOT NULL REFERENCES skill_versions(id) ON DELETE RESTRICT,
  scope_type VARCHAR(40) NOT NULL DEFAULT 'global',
  scope_id VARCHAR(255),
  project_id VARCHAR(255),
  environment VARCHAR(120),
  stage VARCHAR(80),
  domain VARCHAR(80),
  status VARCHAR(32) NOT NULL DEFAULT 'draft',
  priority INTEGER NOT NULL DEFAULT 0,
  binding_config JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_capability_bindings_status CHECK (status IN ('draft', 'active', 'disabled', 'deprecated', 'archived')),
  CONSTRAINT chk_capability_bindings_scope_type CHECK (scope_type IN ('global', 'workspace', 'project', 'environment', 'stage', 'domain')),
  CONSTRAINT chk_capability_bindings_config_object CHECK (jsonb_typeof(binding_config) = 'object')
);

ALTER TABLE capability_bindings
  ALTER COLUMN binding_config TYPE JSONB USING binding_config::jsonb;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_skill_invocations_binding_id'
  ) THEN
    ALTER TABLE skill_invocations
      ADD CONSTRAINT fk_skill_invocations_binding_id
      FOREIGN KEY (binding_id) REFERENCES capability_bindings(id) ON DELETE SET NULL;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS skill_invocation_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  skill_invocation_id UUID NOT NULL REFERENCES skill_invocations(id) ON DELETE CASCADE,
  event_type VARCHAR(80) NOT NULL,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_skill_invocation_events_payload_object CHECK (jsonb_typeof(payload) = 'object')
);

ALTER TABLE skill_invocation_events
  ALTER COLUMN payload TYPE JSONB USING payload::jsonb;

CREATE INDEX IF NOT EXISTS idx_capability_bindings_extension_status ON capability_bindings(extension_point_id, status);
CREATE INDEX IF NOT EXISTS idx_capability_bindings_scope ON capability_bindings(scope_type, scope_id);
CREATE INDEX IF NOT EXISTS idx_capability_bindings_skill_version ON capability_bindings(skill_version_id);
CREATE INDEX IF NOT EXISTS idx_skill_invocations_binding_id ON skill_invocations(binding_id);
CREATE INDEX IF NOT EXISTS idx_skill_invocations_extension_point_id ON skill_invocations(extension_point_id);
CREATE INDEX IF NOT EXISTS idx_skill_invocations_source_workflow ON skill_invocations(source_workflow);
CREATE INDEX IF NOT EXISTS idx_skill_invocation_events_invocation ON skill_invocation_events(skill_invocation_id);
CREATE INDEX IF NOT EXISTS idx_skill_invocation_events_type ON skill_invocation_events(event_type);
CREATE INDEX IF NOT EXISTS idx_skill_invocation_events_trace ON skill_invocation_events(trace_id);

-- Historical compatibility hardening:
-- Empty extension_points means a Skill version is non-bindable, not wildcard-bindable.
UPDATE capability_bindings AS binding
SET
  status = 'disabled',
  binding_config = jsonb_set(
    COALESCE(binding.binding_config, '{}'::jsonb),
    '{disabledReason}',
    '"skill_version_not_bindable"',
    TRUE
  ),
  updated_at = NOW()
FROM skill_versions AS version
WHERE binding.skill_version_id = version.id
  AND binding.status = 'active'
  AND jsonb_typeof(version.extension_points) = 'array'
  AND jsonb_array_length(version.extension_points) = 0;

-- Active bindings whose extension point is not declared by the Skill version are unsafe after
-- schema compatibility checks become enforced; disable them instead of treating them as fallback.
UPDATE capability_bindings AS binding
SET
  status = 'disabled',
  binding_config = jsonb_set(
    COALESCE(binding.binding_config, '{}'::jsonb),
    '{disabledReason}',
    '"extension_point_not_declared_by_skill_version"',
    TRUE
  ),
  updated_at = NOW()
FROM skill_versions AS version
WHERE binding.skill_version_id = version.id
  AND binding.status = 'active'
  AND jsonb_typeof(version.extension_points) = 'array'
  AND NOT (version.extension_points ? binding.extension_point_id);

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('skills.catalog.read', 'skills', 'Read Skill catalog projections.', 'low', TRUE),
  ('skill_invocations.read', 'skills', 'Read Skill Invocation observation records.', 'low', TRUE),
  ('capability_bindings.read', 'skills', 'Read workflow capability bindings and graph projections.', 'low', TRUE),
  ('capability_bindings.write', 'skills', 'Create or update capability bindings.', 'high', TRUE),
  ('capability_bindings.admin', 'skills', 'Administer capability binding lifecycle.', 'high', TRUE),
  ('custom_skills.manage', 'skills', 'Manage custom Skill manifest lifecycle.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = EXCLUDED.is_active;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'skills.catalog.read', TRUE),
  ('basic', 'skill_invocations.read', TRUE),
  ('basic', 'capability_bindings.read', TRUE),
  ('pro', 'skills.catalog.read', TRUE),
  ('pro', 'skill_invocations.read', TRUE),
  ('pro', 'capability_bindings.read', TRUE),
  ('enterprise', 'skills.catalog.read', TRUE),
  ('enterprise', 'skill_invocations.read', TRUE),
  ('enterprise', 'capability_bindings.read', TRUE),
  ('enterprise', 'capability_bindings.write', TRUE),
  ('enterprise', 'capability_bindings.admin', TRUE),
  ('enterprise', 'custom_skills.manage', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET
  enabled = EXCLUDED.enabled;
