-- Batch 2 productized core workflow entry capabilities.
-- Basic remains read-only; Enterprise/Admin can create requirements, plans, and executions.

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('requirements.manage', 'workflow', 'Create requirement pipelines and answer clarifications.', 'high', TRUE),
  ('test_plans.manage', 'workflow', 'Create, update, delete, and generate test plans.', 'high', TRUE),
  ('executions.manage', 'workflow', 'Start, cancel, retry, heal, and gate executions.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = EXCLUDED.is_active;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('enterprise', 'requirements.manage', TRUE),
  ('enterprise', 'test_plans.manage', TRUE),
  ('enterprise', 'executions.manage', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET
  enabled = EXCLUDED.enabled;

INSERT INTO rbac_role_capabilities (role_name, capability_key, effect)
VALUES
  ('admin', 'requirements.manage', 'allow'),
  ('admin', 'test_plans.manage', 'allow'),
  ('admin', 'executions.manage', 'allow'),
  ('system', 'requirements.manage', 'allow'),
  ('system', 'test_plans.manage', 'allow'),
  ('system', 'executions.manage', 'allow')
ON CONFLICT (role_name, capability_key) DO UPDATE SET
  effect = EXCLUDED.effect;
