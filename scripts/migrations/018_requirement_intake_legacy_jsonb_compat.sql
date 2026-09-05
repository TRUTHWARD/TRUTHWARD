-- Compatibility bridge for PostgreSQL databases created by SQLAlchemy AUTO_CREATE_TABLES.
-- Generic SQLAlchemy JSON columns are PostgreSQL JSON, while the canonical migrations
-- use JSONB constraints. Normalize only existing Requirement Intake columns before 019.

DO $$
DECLARE
  target_table TEXT;
  target_column TEXT;
BEGIN
  FOREACH target_table IN ARRAY ARRAY[
    'requirement_intake_drafts',
    'requirement_intake_previews'
  ]
  LOOP
    FOREACH target_column IN ARRAY ARRAY[
      'domains',
      'metadata',
      'requirements',
      'acceptance_criteria',
      'pipeline_payload',
      'warnings',
      'artifact_refs',
      'evidence_refs',
      'connector_binding_snapshot',
      'connector_call_refs'
    ]
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
          CASE
            WHEN target_column IN ('metadata', 'pipeline_payload', 'connector_binding_snapshot') THEN '{}'
            ELSE '[]'
          END
        );
      END IF;
    END LOOP;
  END LOOP;
END $$;

