-- Phase 8 Enterprise Model Governance capability forward seed.
-- Keeps already-migrated environments aligned with the runtime capability registry.

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('model.governance.manage', 'model', 'Manage model governance changes through approval-backed workflow.', 'high', TRUE)
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
