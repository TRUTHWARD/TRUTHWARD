-- Phase 8 Model Governance productization closure.
-- Adds persisted capability scan evidence and keeps routing/model governance
-- mutations under the existing model.governance.manage capability.

CREATE TABLE IF NOT EXISTS model_capability_scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  model_id UUID NOT NULL REFERENCES models(id) ON DELETE CASCADE,
  scanner VARCHAR(120) NOT NULL DEFAULT 'model-gateway-config',
  capabilities JSONB NOT NULL DEFAULT '{}'::jsonb,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_model_capability_scans_model_id
  ON model_capability_scans(model_id);

CREATE INDEX IF NOT EXISTS idx_model_capability_scans_scanned_at
  ON model_capability_scans(scanned_at DESC);

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('model.governance.manage', 'model', 'Manage model configuration, health checks, capability scans, and routing policy changes through approval-backed workflow.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = EXCLUDED.is_active;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('enterprise', 'model.governance.manage', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET
  enabled = EXCLUDED.enabled;

INSERT INTO rbac_role_capabilities (role_name, capability_key, effect)
VALUES
  ('admin', 'model.governance.manage', 'allow'),
  ('system', 'model.governance.manage', 'allow')
ON CONFLICT (role_name, capability_key) DO UPDATE SET
  effect = EXCLUDED.effect;
