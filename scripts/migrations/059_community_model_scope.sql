-- Community OSS project/environment-scoped model configuration.

ALTER TABLE models
  ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS environment_id UUID REFERENCES project_environments(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_models_project_id ON models(project_id);
CREATE INDEX IF NOT EXISTS idx_models_environment_id ON models(environment_id);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'fk_models_environment_project'
  ) THEN
    ALTER TABLE models
      ADD CONSTRAINT fk_models_environment_project
      FOREIGN KEY (environment_id, project_id)
      REFERENCES project_environments(id, project_id)
      ON DELETE CASCADE;
  END IF;
END;
$$;

COMMENT ON COLUMN models.project_id IS
  'Project scope for Community model configuration; NULL is reserved for legacy full-profile governance records.';
COMMENT ON COLUMN models.environment_id IS
  'Optional environment override within the owning project.';
