-- Phase 8 Enterprise Product Workflow forward capability seed.
-- Keeps runtime CapabilityService definitions and persisted capability mappings aligned
-- without mutating already-applied migration 008.

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('issue_tracker.sync', 'integrations', 'Create, update, and status-sync external issue tracker defects.', 'high', TRUE),
  ('exploratory_sessions.read', 'exploratory', 'Read exploratory testing sessions, candidates, reports, and refs.', 'low', TRUE),
  ('exploratory_sessions.manage', 'exploratory', 'Create and update exploratory testing sessions, notes, evidence refs, and bug candidates.', 'high', TRUE),
  ('work_items.read', 'workflow', 'Read human WorkItem collaboration tasks.', 'low', TRUE),
  ('work_items.manage', 'workflow', 'Create, assign, claim, and transition human WorkItems.', 'high', TRUE),
  ('requirements.read', 'workflow', 'Read Requirement Library projections.', 'low', TRUE),
  ('requirements.manage', 'workflow', 'Create requirement pipelines and answer clarifications.', 'high', TRUE),
  ('test_plans.manage', 'workflow', 'Create, update, delete, and generate test plans.', 'high', TRUE),
  ('executions.manage', 'workflow', 'Start, cancel, retry, heal, and gate executions.', 'high', TRUE),
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
  ('basic', 'exploratory_sessions.read', TRUE),
  ('basic', 'work_items.read', TRUE),
  ('basic', 'requirements.read', TRUE),
  ('pro', 'skills.catalog.read', TRUE),
  ('pro', 'skill_invocations.read', TRUE),
  ('pro', 'capability_bindings.read', TRUE),
  ('pro', 'exploratory_sessions.read', TRUE),
  ('pro', 'work_items.read', TRUE),
  ('pro', 'requirements.read', TRUE),
  ('enterprise', 'issue_tracker.sync', TRUE),
  ('enterprise', 'exploratory_sessions.read', TRUE),
  ('enterprise', 'exploratory_sessions.manage', TRUE),
  ('enterprise', 'work_items.read', TRUE),
  ('enterprise', 'work_items.manage', TRUE),
  ('enterprise', 'requirements.read', TRUE),
  ('enterprise', 'requirements.manage', TRUE),
  ('enterprise', 'test_plans.manage', TRUE),
  ('enterprise', 'executions.manage', TRUE),
  ('enterprise', 'skills.catalog.read', TRUE),
  ('enterprise', 'skill_invocations.read', TRUE),
  ('enterprise', 'capability_bindings.read', TRUE),
  ('enterprise', 'capability_bindings.write', TRUE),
  ('enterprise', 'capability_bindings.admin', TRUE),
  ('enterprise', 'custom_skills.manage', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET
  enabled = EXCLUDED.enabled;
