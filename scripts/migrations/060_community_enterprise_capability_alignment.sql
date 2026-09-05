-- Keep the commercial Enterprise/admin ceiling aligned after Community added
-- bounded local mutation capabilities in migration 058. This forward-only
-- seed avoids changing an already-applied migration.

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('enterprise', 'project.members.manage', TRUE),
  ('enterprise', 'model.config.manage', TRUE),
  ('enterprise', 'connector_bindings.manage', TRUE),
  ('enterprise', 'community_skills.manage', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;

INSERT INTO rbac_role_capabilities (role_name, capability_key, effect)
VALUES
  ('admin', 'project.members.manage', 'allow'),
  ('admin', 'model.config.manage', 'allow'),
  ('admin', 'connector_bindings.manage', 'allow'),
  ('admin', 'community_skills.manage', 'allow'),
  ('system', 'project.members.manage', 'allow'),
  ('system', 'model.config.manage', 'allow'),
  ('system', 'connector_bindings.manage', 'allow'),
  ('system', 'community_skills.manage', 'allow')
ON CONFLICT (role_name, capability_key) DO UPDATE SET effect = EXCLUDED.effect;
