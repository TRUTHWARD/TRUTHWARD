-- Compatibility bridge for RequirementScope tables/columns created by
-- SQLAlchemy AUTO_CREATE_TABLES before migration 025 is recorded.

DO $$
DECLARE
  target_table TEXT;
  target_column TEXT;
  default_value TEXT;
BEGIN
  FOR target_table, target_column, default_value IN
    SELECT *
    FROM (VALUES
      ('requirement_scopes', 'scope_payload', '{}'),
      ('requirement_scope_versions', 'requirement_item_ids', '[]'),
      ('test_plans', 'requirement_scope', '{}'),
      ('execution_plans', 'requirement_scope', '{}'),
      ('orchestration_runs', 'requirement_scope', '{}')
    ) AS targets(table_name, column_name, json_default)
  LOOP
    IF EXISTS (
      SELECT 1
      FROM information_schema.columns
      WHERE table_schema = current_schema()
        AND table_name = target_table
        AND column_name = target_column
        AND data_type = 'json'
    ) THEN
      EXECUTE format(
        'ALTER TABLE %I ALTER COLUMN %I DROP DEFAULT',
        target_table,
        target_column
      );
      EXECUTE format(
        'ALTER TABLE %I ALTER COLUMN %I TYPE JSONB USING %I::jsonb',
        target_table,
        target_column,
        target_column
      );
      EXECUTE format(
        'ALTER TABLE %I ALTER COLUMN %I SET DEFAULT %L::jsonb',
        target_table,
        target_column,
        default_value
      );
    END IF;
  END LOOP;
END $$;

