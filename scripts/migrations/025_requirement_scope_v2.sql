CREATE TABLE IF NOT EXISTS requirement_scopes (
  scope_id VARCHAR(255) PRIMARY KEY,
  schema_version VARCHAR(80) NOT NULL,
  primary_requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE RESTRICT,
  scope_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_requirement_scopes_primary_version
  ON requirement_scopes(primary_requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_requirement_scopes_schema_version
  ON requirement_scopes(schema_version);

CREATE TABLE IF NOT EXISTS requirement_scope_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scope_id VARCHAR(255) NOT NULL REFERENCES requirement_scopes(scope_id) ON DELETE CASCADE,
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE RESTRICT,
  requirement_item_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  UNIQUE (scope_id, requirement_version_id),
  CONSTRAINT chk_requirement_scope_version_items_array CHECK (jsonb_typeof(requirement_item_ids) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_requirement_scope_versions_version
  ON requirement_scope_versions(requirement_version_id);

ALTER TABLE test_plans
  ADD COLUMN IF NOT EXISTS requirement_scope_id VARCHAR(255) REFERENCES requirement_scopes(scope_id) ON DELETE SET NULL;

ALTER TABLE execution_plans
  ADD COLUMN IF NOT EXISTS requirement_scope_id VARCHAR(255) REFERENCES requirement_scopes(scope_id) ON DELETE SET NULL;

ALTER TABLE orchestration_runs
  ADD COLUMN IF NOT EXISTS requirement_scope_id VARCHAR(255) REFERENCES requirement_scopes(scope_id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS requirement_scope JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_test_plans_requirement_scope_id ON test_plans(requirement_scope_id);
CREATE INDEX IF NOT EXISTS idx_execution_plans_requirement_scope_id ON execution_plans(requirement_scope_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_runs_requirement_scope_id ON orchestration_runs(requirement_scope_id);

INSERT INTO requirement_scopes (
  scope_id,
  schema_version,
  primary_requirement_version_id,
  scope_payload,
  created_at
)
SELECT
  requirement_scope->>'scopeId',
  COALESCE(requirement_scope->>'schemaVersion', 'phase8.requirement-scope.v1'),
  requirement_version_id,
  requirement_scope,
  created_at
FROM test_plans
WHERE requirement_version_id IS NOT NULL
  AND requirement_scope <> '{}'::jsonb
  AND NULLIF(requirement_scope->>'scopeId', '') IS NOT NULL
ON CONFLICT (scope_id) DO NOTHING;

INSERT INTO requirement_scope_versions (scope_id, requirement_version_id, requirement_item_ids)
SELECT
  scope_id,
  primary_requirement_version_id,
  COALESCE(scope_payload->'selectedRequirementItemIds', '[]'::jsonb)
FROM requirement_scopes
WHERE schema_version = 'phase8.requirement-scope.v1'
ON CONFLICT (scope_id, requirement_version_id) DO NOTHING;

UPDATE test_plans
SET requirement_scope_id = requirement_scope->>'scopeId'
WHERE NULLIF(requirement_scope->>'scopeId', '') IS NOT NULL;

UPDATE execution_plans
SET requirement_scope_id = requirement_scope->>'scopeId'
WHERE NULLIF(requirement_scope->>'scopeId', '') IS NOT NULL
  AND EXISTS (
    SELECT 1 FROM requirement_scopes scope
    WHERE scope.scope_id = execution_plans.requirement_scope->>'scopeId'
  );
