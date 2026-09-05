-- Phase 8 License / Capability Boundary incremental migration for PostgreSQL 15+.
-- Implements edition, capability registry, edition mapping, and user entitlement storage.
-- This implemented contract change lands schema, code, tests, and documentation together.

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS edition VARCHAR(32) NOT NULL DEFAULT 'basic';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_users_edition'
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT chk_users_edition CHECK (edition IN ('basic', 'pro', 'enterprise'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_users_edition ON users(edition);
COMMENT ON COLUMN users.edition IS 'Product edition for capability calculation: basic/pro/enterprise';

CREATE TABLE IF NOT EXISTS capability_registry (
  capability_key VARCHAR(120) PRIMARY KEY,
  category VARCHAR(80) NOT NULL,
  description TEXT NOT NULL,
  risk_level VARCHAR(32) NOT NULL DEFAULT 'low',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_capability_registry_risk_level CHECK (risk_level IN ('low', 'medium', 'high'))
);

CREATE INDEX IF NOT EXISTS idx_capability_registry_category ON capability_registry(category);
CREATE INDEX IF NOT EXISTS idx_capability_registry_active ON capability_registry(is_active);

DROP TRIGGER IF EXISTS trg_capability_registry_updated_at ON capability_registry;
CREATE TRIGGER trg_capability_registry_updated_at
BEFORE UPDATE ON capability_registry
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS edition_capabilities (
  edition VARCHAR(32) NOT NULL,
  capability_key VARCHAR(120) NOT NULL REFERENCES capability_registry(capability_key) ON DELETE CASCADE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (edition, capability_key),
  CONSTRAINT chk_edition_capabilities_edition CHECK (edition IN ('basic', 'pro', 'enterprise'))
);

CREATE INDEX IF NOT EXISTS idx_edition_capabilities_capability ON edition_capabilities(capability_key);
CREATE INDEX IF NOT EXISTS idx_edition_capabilities_enabled ON edition_capabilities(enabled);

CREATE TABLE IF NOT EXISTS user_entitlements (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  capability_key VARCHAR(120) NOT NULL REFERENCES capability_registry(capability_key) ON DELETE CASCADE,
  effect VARCHAR(16) NOT NULL DEFAULT 'allow',
  reason TEXT,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_user_entitlements_effect CHECK (effect IN ('allow', 'deny')),
  CONSTRAINT uq_user_entitlements_user_capability UNIQUE (user_id, capability_key)
);

CREATE INDEX IF NOT EXISTS idx_user_entitlements_user_id ON user_entitlements(user_id);
CREATE INDEX IF NOT EXISTS idx_user_entitlements_capability_key ON user_entitlements(capability_key);
CREATE INDEX IF NOT EXISTS idx_user_entitlements_expires_at ON user_entitlements(expires_at);

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('coverage.read', 'coverage', 'Read Coverage Matrix results.', 'low', TRUE),
  ('coverage.proof.read', 'coverage', 'Read Coverage Proof Bundle results.', 'low', TRUE),
  ('replay.read', 'replay', 'Read replay views.', 'low', TRUE),
  ('replay.export.read', 'replay', 'Read replay export packages.', 'low', TRUE),
  ('replay.repository.read', 'replay', 'Read persistent replay repository entries.', 'low', TRUE),
  ('replay.repository.manage', 'replay', 'Manage persistent replay repository entries.', 'high', TRUE),
  ('replay.compare', 'replay', 'Compare replay packages.', 'medium', TRUE),
  ('audit.logs.read', 'audit', 'Read audit and structured logs.', 'low', TRUE),
  ('audit.retention.manage', 'audit', 'Manage audit retention policy.', 'high', TRUE),
  ('correction.read', 'correction', 'Read governed correction records.', 'low', TRUE),
  ('correction.apply', 'correction', 'Apply approved governed corrections.', 'high', TRUE),
  ('correction.validate', 'correction', 'Validate governed corrections.', 'high', TRUE),
  ('correction.rollback', 'correction', 'Rollback governed corrections.', 'high', TRUE),
  ('correction.promote', 'correction', 'Promote validated corrections into CCG knowledge governance.', 'high', TRUE),
  ('knowledge.read', 'knowledge', 'Read governed knowledge records.', 'low', TRUE),
  ('knowledge.promote', 'knowledge', 'Reserved independent knowledge promotion capability.', 'high', TRUE),
  ('knowledge.supersede', 'knowledge', 'Supersede governed knowledge records.', 'high', TRUE),
  ('access_control.manage', 'access_control', 'Manage access control settings.', 'high', TRUE),
  ('project.settings.manage', 'settings', 'Manage project settings.', 'high', TRUE),
  ('environment.settings.manage', 'settings', 'Manage environment settings.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = EXCLUDED.is_active;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'coverage.read', TRUE),
  ('basic', 'coverage.proof.read', TRUE),
  ('basic', 'replay.read', TRUE),
  ('basic', 'replay.export.read', TRUE),
  ('basic', 'audit.logs.read', TRUE),
  ('basic', 'correction.read', TRUE),
  ('basic', 'knowledge.read', TRUE),
  ('pro', 'coverage.read', TRUE),
  ('pro', 'coverage.proof.read', TRUE),
  ('pro', 'replay.read', TRUE),
  ('pro', 'replay.export.read', TRUE),
  ('pro', 'replay.repository.read', TRUE),
  ('pro', 'audit.logs.read', TRUE),
  ('pro', 'correction.read', TRUE),
  ('pro', 'knowledge.read', TRUE),
  ('enterprise', 'coverage.read', TRUE),
  ('enterprise', 'coverage.proof.read', TRUE),
  ('enterprise', 'replay.read', TRUE),
  ('enterprise', 'replay.export.read', TRUE),
  ('enterprise', 'replay.repository.read', TRUE),
  ('enterprise', 'replay.repository.manage', TRUE),
  ('enterprise', 'replay.compare', TRUE),
  ('enterprise', 'audit.logs.read', TRUE),
  ('enterprise', 'audit.retention.manage', TRUE),
  ('enterprise', 'correction.read', TRUE),
  ('enterprise', 'correction.apply', TRUE),
  ('enterprise', 'correction.validate', TRUE),
  ('enterprise', 'correction.rollback', TRUE),
  ('enterprise', 'correction.promote', TRUE),
  ('enterprise', 'knowledge.read', TRUE),
  ('enterprise', 'knowledge.supersede', TRUE),
  ('enterprise', 'access_control.manage', TRUE),
  ('enterprise', 'project.settings.manage', TRUE),
  ('enterprise', 'environment.settings.manage', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET
  enabled = EXCLUDED.enabled;

UPDATE users
SET edition = 'enterprise'
WHERE username = 'admin'
   OR EXISTS (
     SELECT 1
     FROM jsonb_array_elements_text(roles::jsonb) AS role_value(role_name)
     WHERE role_value.role_name = 'admin'
   );
UPDATE users SET edition = 'basic' WHERE username = 'user' AND edition IS NULL;
