ALTER TABLE test_plans
  ADD COLUMN IF NOT EXISTS requirement_scope JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE execution_plans
  ADD COLUMN IF NOT EXISTS requirement_scope JSONB NOT NULL DEFAULT '{}'::jsonb;
