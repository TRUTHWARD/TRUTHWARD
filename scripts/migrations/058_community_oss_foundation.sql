-- OSS Community foundation. Community is an Apache-2.0 self-hosted edition,
-- not an alias for the commercial read-only Basic edition.

ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(512);

ALTER TABLE users DROP CONSTRAINT IF EXISTS chk_users_edition;
ALTER TABLE users ADD CONSTRAINT chk_users_edition
  CHECK (edition IN ('basic', 'community', 'pro', 'enterprise'));

ALTER TABLE edition_capabilities DROP CONSTRAINT IF EXISTS chk_edition_capabilities_edition;
ALTER TABLE edition_capabilities ADD CONSTRAINT chk_edition_capabilities_edition
  CHECK (edition IN ('basic', 'community', 'pro', 'enterprise'));

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('project.members.manage', 'settings', 'Manage fixed Community project memberships.', 'medium', TRUE),
  ('model.config.manage', 'model', 'Manage project-scoped Community model configuration and role bindings.', 'medium', TRUE),
  ('connector_bindings.manage', 'integrations', 'Manage Community connector bindings within an authorized project.', 'medium', TRUE),
  ('community_skills.manage', 'skills', 'Register and bind trusted low-risk local Community Skills.', 'medium', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = TRUE;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
SELECT 'community', capability_key, TRUE
FROM capability_registry
WHERE capability_key IN (
  'coverage.read',
  'coverage.proof.read',
  'change.read',
  'impact.read',
  'replay.plan.read',
  'replay.read',
  'replay.export.read',
  'audit.logs.read',
  'evidence.read',
  'evidence.query',
  'graph.candidate.read',
  'graph.correction.read',
  'graph.staleness.read',
  'gate_policy.read',
  'correction.read',
  'knowledge.read',
  'lesson.read',
  'improvement.read',
  'governance.read',
  'skills.catalog.read',
  'skill_invocations.read',
  'capability_bindings.read',
  'exploratory_sessions.read',
  'work_items.read',
  'requirements.read',
  'pr.read',
  'admission.read',
  'admission.execute',
  'capability_bindings.write',
  'change.create',
  'community_skills.manage',
  'connector_bindings.manage',
  'environment.settings.manage',
  'executions.manage',
  'exploratory_sessions.manage',
  'model.config.manage',
  'project.members.manage',
  'project.settings.manage',
  'requirements.manage',
  'test_plans.manage',
  'work_items.manage'
)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;

COMMENT ON COLUMN users.password_hash IS
  'Scrypt verifier for local OSS Community authentication; plaintext passwords are never stored.';
COMMENT ON COLUMN users.edition IS
  'Product edition for capability defaults. Community is separate from the Basic commercial tier.';
