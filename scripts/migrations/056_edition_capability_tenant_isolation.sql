-- P26 Edition/Capability projection and centralized tenant/workspace/project/environment isolation.
-- This extends the existing entitlement authority; it does not create another entitlement system.

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('governance.read', 'governance', 'Read project-scoped Edition, Capability, Scope, and governance readiness projections.', 'low', TRUE),
  ('governance.aggregate.read', 'governance', 'Read minimum-visibility cross-project governance trends within an authorized workspace.', 'medium', TRUE),
  ('graph.autonomy.configure', 'graph', 'Request approval-backed controlled Graph autonomy configuration for a project or environment.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = TRUE;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'governance.read', TRUE),
  ('pro', 'governance.read', TRUE),
  ('enterprise', 'governance.read', TRUE),
  ('enterprise', 'governance.aggregate.read', TRUE),
  ('enterprise', 'graph.autonomy.configure', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;

INSERT INTO rbac_role_capabilities (role_name, capability_key, effect)
VALUES
  ('admin', 'governance.read', 'allow'),
  ('admin', 'governance.aggregate.read', 'allow'),
  ('admin', 'graph.autonomy.configure', 'allow'),
  ('system', 'governance.read', 'allow'),
  ('system', 'governance.aggregate.read', 'allow'),
  ('system', 'graph.autonomy.configure', 'allow'),
  ('user', 'governance.read', 'allow')
ON CONFLICT (role_name, capability_key) DO UPDATE SET effect = EXCLUDED.effect;

COMMENT ON TABLE edition_capabilities IS
  'Edition supplies default capabilities only. Backend authorization always uses effective capability decisions.';
COMMENT ON TABLE rbac_role_capabilities IS
  'Role grants and denies participate in effective capability resolution; frontend visibility is never authoritative.';
