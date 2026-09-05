-- P10: Canonical Execution Graph identity/version data foundation.
-- CEG remains an orchestrator Service-owned capability, not a Skill, Agent,
-- microservice, execution engine, or lifecycle stage. Node/Edge/Path is P11.

DO $$
BEGIN
  CREATE TYPE graph_status AS ENUM (
    'draft', 'candidate', 'under_review', 'active',
    'superseded', 'deprecated', 'archived'
  );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE TYPE graph_scope AS ENUM ('project', 'environment');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE TYPE graph_source AS ENUM ('observed', 'candidate', 'canonical');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'uq_project_environments_id_project'
  ) THEN
    ALTER TABLE project_environments
      ADD CONSTRAINT uq_project_environments_id_project UNIQUE (id, project_id);
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS canonical_execution_graphs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  environment_id UUID,
  scope_type graph_scope NOT NULL,
  scope_id UUID NOT NULL,
  graph_key VARCHAR(128) NOT NULL,
  graph_ref VARCHAR(500) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  status graph_status NOT NULL DEFAULT 'draft',
  retention_policy VARCHAR(80) NOT NULL DEFAULT 'default',
  retention_until TIMESTAMPTZ,
  retention_status VARCHAR(40) NOT NULL DEFAULT 'active',
  legal_hold BOOLEAN NOT NULL DEFAULT FALSE,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_ceg_graphs_environment_project
    FOREIGN KEY (environment_id, project_id)
    REFERENCES project_environments(id, project_id) ON DELETE RESTRICT,
  CONSTRAINT uq_ceg_graphs_scope_key UNIQUE (
    tenant_id, workspace_id, project_id, scope_type, scope_id, graph_key
  ),
  CONSTRAINT uq_ceg_graphs_scoped_identity UNIQUE (
    id, tenant_id, workspace_id, project_id, scope_type, scope_id
  ),
  CONSTRAINT uq_ceg_graphs_idempotency UNIQUE (
    tenant_id, workspace_id, idempotency_key
  ),
  CONSTRAINT chk_ceg_graphs_tenant_not_blank CHECK (length(trim(tenant_id)) > 0),
  CONSTRAINT chk_ceg_graphs_workspace_not_blank CHECK (length(trim(workspace_id)) > 0),
  CONSTRAINT chk_ceg_graphs_scope_identity CHECK (
    (scope_type = 'project' AND environment_id IS NULL AND scope_id = project_id)
    OR
    (scope_type = 'environment' AND environment_id IS NOT NULL AND scope_id = environment_id)
  ),
  CONSTRAINT chk_ceg_graphs_request_hash_length CHECK (length(request_hash) = 71),
  CONSTRAINT chk_ceg_graphs_request_hash_prefix CHECK (substr(request_hash, 1, 7) = 'sha256:'),
  CONSTRAINT chk_ceg_graphs_lock_version CHECK (lock_version > 0),
  CONSTRAINT chk_ceg_graphs_retention_status CHECK (
    retention_status IN ('active', 'archived', 'purge_eligible', 'legal_hold')
  ),
  CONSTRAINT chk_ceg_graphs_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array'),
  CONSTRAINT chk_ceg_graphs_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_ceg_graphs_scope
  ON canonical_execution_graphs(tenant_id, workspace_id, project_id, scope_type, scope_id);
CREATE INDEX IF NOT EXISTS idx_ceg_graphs_environment
  ON canonical_execution_graphs(environment_id);
CREATE INDEX IF NOT EXISTS idx_ceg_graphs_status
  ON canonical_execution_graphs(status);
CREATE INDEX IF NOT EXISTS idx_ceg_graphs_retention
  ON canonical_execution_graphs(retention_status, retention_until);

CREATE TABLE IF NOT EXISTS canonical_execution_graph_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  graph_id UUID NOT NULL,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL,
  environment_id UUID,
  scope_type graph_scope NOT NULL,
  scope_id UUID NOT NULL,
  version_number INTEGER NOT NULL,
  version_ref VARCHAR(500) NOT NULL UNIQUE,
  parent_version_id UUID,
  status graph_status NOT NULL DEFAULT 'draft',
  source graph_source NOT NULL,
  schema_version VARCHAR(80) NOT NULL DEFAULT 'ceg.v1',
  content_hash VARCHAR(80) NOT NULL,
  source_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  applicability JSONB NOT NULL DEFAULT '{}'::jsonb,
  is_frozen BOOLEAN NOT NULL DEFAULT FALSE,
  frozen_at TIMESTAMPTZ,
  frozen_by UUID REFERENCES users(id) ON DELETE SET NULL,
  retention_policy VARCHAR(80) NOT NULL DEFAULT 'default',
  retention_until TIMESTAMPTZ,
  retention_status VARCHAR(40) NOT NULL DEFAULT 'active',
  legal_hold BOOLEAN NOT NULL DEFAULT FALSE,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_ceg_versions_graph_scope
    FOREIGN KEY (graph_id, tenant_id, workspace_id, project_id, scope_type, scope_id)
    REFERENCES canonical_execution_graphs(
      id, tenant_id, workspace_id, project_id, scope_type, scope_id
    ) ON DELETE RESTRICT,
  CONSTRAINT fk_ceg_versions_environment_project
    FOREIGN KEY (environment_id, project_id)
    REFERENCES project_environments(id, project_id) ON DELETE RESTRICT,
  CONSTRAINT fk_ceg_versions_parent_scope
    FOREIGN KEY (parent_version_id, graph_id, tenant_id, workspace_id, project_id, scope_id)
    REFERENCES canonical_execution_graph_versions(
      id, graph_id, tenant_id, workspace_id, project_id, scope_id
    ) ON DELETE RESTRICT,
  CONSTRAINT uq_ceg_versions_graph_version UNIQUE (graph_id, version_number),
  CONSTRAINT uq_ceg_versions_graph_hash UNIQUE (graph_id, content_hash),
  CONSTRAINT uq_ceg_versions_parent_identity UNIQUE (
    id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ),
  CONSTRAINT uq_ceg_versions_idempotency UNIQUE (
    tenant_id, workspace_id, idempotency_key
  ),
  CONSTRAINT chk_ceg_versions_number CHECK (version_number > 0),
  CONSTRAINT chk_ceg_versions_parent_not_self CHECK (
    parent_version_id IS NULL OR parent_version_id <> id
  ),
  CONSTRAINT chk_ceg_versions_scope_identity CHECK (
    (scope_type = 'project' AND environment_id IS NULL AND scope_id = project_id)
    OR
    (scope_type = 'environment' AND environment_id IS NOT NULL AND scope_id = environment_id)
  ),
  CONSTRAINT chk_ceg_versions_content_hash_length CHECK (length(content_hash) = 71),
  CONSTRAINT chk_ceg_versions_content_hash_prefix CHECK (substr(content_hash, 1, 7) = 'sha256:'),
  CONSTRAINT chk_ceg_versions_request_hash_length CHECK (length(request_hash) = 71),
  CONSTRAINT chk_ceg_versions_request_hash_prefix CHECK (substr(request_hash, 1, 7) = 'sha256:'),
  CONSTRAINT chk_ceg_versions_lock_version CHECK (lock_version > 0),
  CONSTRAINT chk_ceg_versions_retention_status CHECK (
    retention_status IN ('active', 'archived', 'purge_eligible', 'legal_hold')
  ),
  CONSTRAINT chk_ceg_versions_frozen_metadata CHECK (
    (is_frozen = FALSE AND frozen_at IS NULL AND frozen_by IS NULL)
    OR (is_frozen = TRUE AND frozen_at IS NOT NULL)
  ),
  CONSTRAINT chk_ceg_versions_canonical_frozen CHECK (
    source <> 'canonical'
    OR (is_frozen = TRUE AND status IN ('active', 'superseded', 'deprecated', 'archived'))
  ),
  CONSTRAINT chk_ceg_versions_active_canonical CHECK (
    status <> 'active' OR (source = 'canonical' AND is_frozen = TRUE)
  ),
  CONSTRAINT chk_ceg_versions_source_refs_array CHECK (jsonb_typeof(source_refs) = 'array'),
  CONSTRAINT chk_ceg_versions_applicability_object CHECK (jsonb_typeof(applicability) = 'object'),
  CONSTRAINT chk_ceg_versions_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array'),
  CONSTRAINT chk_ceg_versions_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_ceg_versions_graph
  ON canonical_execution_graph_versions(graph_id, version_number);
CREATE INDEX IF NOT EXISTS idx_ceg_versions_scope
  ON canonical_execution_graph_versions(tenant_id, workspace_id, project_id, scope_id);
CREATE INDEX IF NOT EXISTS idx_ceg_versions_parent
  ON canonical_execution_graph_versions(parent_version_id);
CREATE INDEX IF NOT EXISTS idx_ceg_versions_status_source
  ON canonical_execution_graph_versions(status, source);
CREATE INDEX IF NOT EXISTS idx_ceg_versions_hash
  ON canonical_execution_graph_versions(content_hash);
CREATE INDEX IF NOT EXISTS idx_ceg_versions_retention
  ON canonical_execution_graph_versions(retention_status, retention_until);

CREATE OR REPLACE FUNCTION prevent_ceg_identity_scope_update()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.status = 'archived' THEN
    RAISE EXCEPTION 'archived Canonical Execution Graph identities are immutable'
      USING ERRCODE = '55000';
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
    OR NEW.project_id IS DISTINCT FROM OLD.project_id
    OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
    OR NEW.scope_type IS DISTINCT FROM OLD.scope_type
    OR NEW.scope_id IS DISTINCT FROM OLD.scope_id
    OR NEW.graph_key IS DISTINCT FROM OLD.graph_key
    OR NEW.graph_ref IS DISTINCT FROM OLD.graph_ref
  THEN
    RAISE EXCEPTION 'Canonical Execution Graph identity and scope are immutable'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION prevent_ceg_version_content_update()
RETURNS TRIGGER AS $$
DECLARE
  content_changed BOOLEAN;
BEGIN
  IF OLD.status = 'archived' THEN
    RAISE EXCEPTION 'archived Canonical Execution Graph versions are immutable'
      USING ERRCODE = '55000';
  END IF;
  content_changed :=
    NEW.graph_id IS DISTINCT FROM OLD.graph_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
    OR NEW.project_id IS DISTINCT FROM OLD.project_id
    OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
    OR NEW.scope_type IS DISTINCT FROM OLD.scope_type
    OR NEW.scope_id IS DISTINCT FROM OLD.scope_id
    OR NEW.version_number IS DISTINCT FROM OLD.version_number
    OR NEW.version_ref IS DISTINCT FROM OLD.version_ref
    OR NEW.parent_version_id IS DISTINCT FROM OLD.parent_version_id
    OR NEW.source IS DISTINCT FROM OLD.source
    OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
    OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
    OR NEW.source_refs IS DISTINCT FROM OLD.source_refs
    OR NEW.applicability IS DISTINCT FROM OLD.applicability
    OR NEW.metadata IS DISTINCT FROM OLD.metadata;
  IF (OLD.is_frozen OR OLD.status <> 'draft') AND content_changed THEN
    RAISE EXCEPTION 'frozen or published Canonical Execution Graph version content is immutable'
      USING ERRCODE = '55000';
  END IF;
  IF (NEW.is_frozen OR NEW.status <> 'draft') AND content_changed THEN
    RAISE EXCEPTION 'freezing or publishing a Canonical Execution Graph version cannot change content'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION prevent_ceg_published_version_delete()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.is_frozen OR OLD.status <> 'draft' THEN
    RAISE EXCEPTION 'frozen or published Canonical Execution Graph versions cannot be deleted'
      USING ERRCODE = '55000';
  END IF;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ceg_graphs_immutable ON canonical_execution_graphs;
CREATE TRIGGER trg_ceg_graphs_immutable
BEFORE UPDATE ON canonical_execution_graphs
FOR EACH ROW EXECUTE FUNCTION prevent_ceg_identity_scope_update();

DROP TRIGGER IF EXISTS trg_ceg_graphs_updated_at ON canonical_execution_graphs;
CREATE TRIGGER trg_ceg_graphs_updated_at
BEFORE UPDATE ON canonical_execution_graphs
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_ceg_versions_immutable ON canonical_execution_graph_versions;
CREATE TRIGGER trg_ceg_versions_immutable
BEFORE UPDATE ON canonical_execution_graph_versions
FOR EACH ROW EXECUTE FUNCTION prevent_ceg_version_content_update();

DROP TRIGGER IF EXISTS trg_ceg_versions_delete_guard ON canonical_execution_graph_versions;
CREATE TRIGGER trg_ceg_versions_delete_guard
BEFORE DELETE ON canonical_execution_graph_versions
FOR EACH ROW EXECUTE FUNCTION prevent_ceg_published_version_delete();

DROP TRIGGER IF EXISTS trg_ceg_versions_updated_at ON canonical_execution_graph_versions;
CREATE TRIGGER trg_ceg_versions_updated_at
BEFORE UPDATE ON canonical_execution_graph_versions
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('graph.read', 'graph', 'Reserved read access for Canonical Execution Graph foundations.', 'low', TRUE),
  ('graph.manage', 'graph', 'Reserved management access for future CEG governance.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = EXCLUDED.is_active;

COMMENT ON TABLE canonical_execution_graphs IS
  'P10 Service-owned CEG identity. CEG is not a Skill, Agent, service, or lifecycle stage.';
COMMENT ON TABLE canonical_execution_graph_versions IS
  'P10 CEG version metadata and stable refs. Node/Edge/Path and promotion are pending follow-up work.';
