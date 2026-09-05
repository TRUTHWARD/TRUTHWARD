-- Batch 1 foundation:
-- Real Project / Environment / Project Member settings and plan project linkage.
-- Connector Binding continues to reuse skill_connector_bindings.

CREATE TABLE IF NOT EXISTS projects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key VARCHAR(80) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_projects_status CHECK (status IN ('active', 'archived')),
  CONSTRAINT chk_projects_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_projects_status ON projects(status);
CREATE INDEX IF NOT EXISTS idx_projects_created_by ON projects(created_by);

DROP TRIGGER IF EXISTS trg_projects_updated_at ON projects;
CREATE TRIGGER trg_projects_updated_at
BEFORE UPDATE ON projects
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS project_environments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  key VARCHAR(80) NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  base_url TEXT,
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  variables JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_project_environments_project_key UNIQUE (project_id, key),
  CONSTRAINT chk_project_environments_status CHECK (status IN ('active', 'disabled', 'archived')),
  CONSTRAINT chk_project_environments_variables_object CHECK (jsonb_typeof(variables) = 'object'),
  CONSTRAINT chk_project_environments_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_project_environments_project ON project_environments(project_id);
CREATE INDEX IF NOT EXISTS idx_project_environments_status ON project_environments(status);
CREATE INDEX IF NOT EXISTS idx_project_environments_created_by ON project_environments(created_by);

DROP TRIGGER IF EXISTS trg_project_environments_updated_at ON project_environments;
CREATE TRIGGER trg_project_environments_updated_at
BEFORE UPDATE ON project_environments
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS project_members (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  role VARCHAR(32) NOT NULL DEFAULT 'viewer',
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_project_members_project_user UNIQUE (project_id, user_id),
  CONSTRAINT chk_project_members_role CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
  CONSTRAINT chk_project_members_status CHECK (status IN ('active', 'inactive')),
  CONSTRAINT chk_project_members_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_project_members_project ON project_members(project_id);
CREATE INDEX IF NOT EXISTS idx_project_members_user ON project_members(user_id);
CREATE INDEX IF NOT EXISTS idx_project_members_role ON project_members(role);

DROP TRIGGER IF EXISTS trg_project_members_updated_at ON project_members;
CREATE TRIGGER trg_project_members_updated_at
BEFORE UPDATE ON project_members
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

ALTER TABLE test_plans
  ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE SET NULL;

ALTER TABLE test_plans
  ADD COLUMN IF NOT EXISTS environment_id UUID REFERENCES project_environments(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_test_plans_project ON test_plans(project_id);
CREATE INDEX IF NOT EXISTS idx_test_plans_environment_ref ON test_plans(environment_id);

COMMENT ON TABLE projects IS 'Real project settings records used by ProjectSwitcher and governance settings.';
COMMENT ON TABLE project_environments IS 'Project-scoped environment settings. Execution visual grounding remains execution-service internal.';
COMMENT ON TABLE project_members IS 'Project member role assignments. Backend capability checks remain the authorization boundary.';
COMMENT ON TABLE skill_connector_bindings IS 'Connector binding metadata for Skill invocation. Stores secretRef/credentialRef only, never plaintext tokens or secrets. Project/environment scope is carried in scope JSON.';
