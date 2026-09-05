-- P11 Canonical Execution Graph structured topology and editable-version governance.
-- Extends the P10 identity/version authority; no graph, replay, Gate, Memory, or execution authority is duplicated.

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
  IF (OLD.is_frozen OR OLD.status NOT IN ('draft', 'candidate')) AND content_changed THEN
    RAISE EXCEPTION 'frozen or published Canonical Execution Graph version content is immutable'
      USING ERRCODE = '55000';
  END IF;
  IF (NEW.is_frozen OR NEW.status NOT IN ('draft', 'candidate')) AND content_changed THEN
    RAISE EXCEPTION 'freezing or publishing a Canonical Execution Graph version cannot change content'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION prevent_ceg_published_version_delete()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.is_frozen OR OLD.status NOT IN ('draft', 'candidate') THEN
    RAISE EXCEPTION 'frozen or published Canonical Execution Graph versions cannot be deleted'
      USING ERRCODE = '55000';
  END IF;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS canonical_execution_graph_nodes (
  id UUID PRIMARY KEY,
  node_ref VARCHAR(500) NOT NULL UNIQUE,
  version_id UUID NOT NULL,
  graph_id UUID NOT NULL,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL,
  scope_id UUID NOT NULL,
  client_key VARCHAR(128) NOT NULL,
  semantic_key VARCHAR(256) NOT NULL,
  node_type VARCHAR(40) NOT NULL,
  display_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  external_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  risk_level VARCHAR(20) NOT NULL DEFAULT 'low',
  source VARCHAR(40) NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_ceg_nodes_version_scope FOREIGN KEY (
    version_id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) REFERENCES canonical_execution_graph_versions(
    id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) ON DELETE CASCADE,
  CONSTRAINT uq_ceg_nodes_version_identity UNIQUE (id, version_id),
  CONSTRAINT uq_ceg_nodes_client_key UNIQUE (version_id, client_key),
  CONSTRAINT uq_ceg_nodes_semantic_key UNIQUE (version_id, semantic_key),
  CONSTRAINT chk_ceg_nodes_type CHECK (node_type IN (
    'requirement', 'capability', 'page', 'component', 'element', 'action',
    'assertion', 'data', 'api', 'code', 'test', 'evidence'
  )),
  CONSTRAINT chk_ceg_nodes_risk CHECK (risk_level IN ('low', 'medium', 'high')),
  CONSTRAINT chk_ceg_nodes_source CHECK (source IN ('observed', 'candidate', 'imported', 'manual', 'canonical')),
  CONSTRAINT chk_ceg_nodes_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_ceg_nodes_lock_version CHECK (lock_version > 0),
  CONSTRAINT chk_ceg_nodes_request_hash CHECK (length(request_hash) = 71 AND request_hash LIKE 'sha256:%'),
  CONSTRAINT chk_ceg_nodes_display_object CHECK (jsonb_typeof(display_metadata) = 'object'),
  CONSTRAINT chk_ceg_nodes_attributes_object CHECK (jsonb_typeof(attributes) = 'object'),
  CONSTRAINT chk_ceg_nodes_external_refs_array CHECK (jsonb_typeof(external_refs) = 'array'),
  CONSTRAINT chk_ceg_nodes_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_ceg_nodes_version_type
  ON canonical_execution_graph_nodes(version_id, node_type);
CREATE INDEX IF NOT EXISTS idx_ceg_nodes_scope
  ON canonical_execution_graph_nodes(tenant_id, workspace_id, project_id, scope_id);
CREATE INDEX IF NOT EXISTS idx_ceg_nodes_semantic
  ON canonical_execution_graph_nodes(version_id, semantic_key);

CREATE TABLE IF NOT EXISTS canonical_execution_graph_edges (
  id UUID PRIMARY KEY,
  edge_ref VARCHAR(500) NOT NULL UNIQUE,
  version_id UUID NOT NULL,
  graph_id UUID NOT NULL,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL,
  scope_id UUID NOT NULL,
  client_key VARCHAR(128) NOT NULL,
  edge_type VARCHAR(40) NOT NULL,
  source_node_id UUID NOT NULL,
  target_node_id UUID NOT NULL,
  condition JSONB,
  risk_level VARCHAR(20) NOT NULL DEFAULT 'low',
  review_status VARCHAR(40) NOT NULL DEFAULT 'not_required',
  source VARCHAR(40) NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  semantic_hash VARCHAR(80) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_ceg_edges_version_scope FOREIGN KEY (
    version_id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) REFERENCES canonical_execution_graph_versions(
    id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) ON DELETE CASCADE,
  CONSTRAINT fk_ceg_edges_source_version FOREIGN KEY (source_node_id, version_id)
    REFERENCES canonical_execution_graph_nodes(id, version_id) ON DELETE RESTRICT,
  CONSTRAINT fk_ceg_edges_target_version FOREIGN KEY (target_node_id, version_id)
    REFERENCES canonical_execution_graph_nodes(id, version_id) ON DELETE RESTRICT,
  CONSTRAINT uq_ceg_edges_version_identity UNIQUE (id, version_id),
  CONSTRAINT uq_ceg_edges_client_key UNIQUE (version_id, client_key),
  CONSTRAINT uq_ceg_edges_semantic_hash UNIQUE (version_id, semantic_hash),
  CONSTRAINT chk_ceg_edges_type CHECK (edge_type IN (
    'contains', 'precedes', 'transitions_to', 'depends_on', 'implements',
    'verifies', 'produces', 'evidenced_by', 'changes', 'affects'
  )),
  CONSTRAINT chk_ceg_edges_not_self CHECK (source_node_id <> target_node_id),
  CONSTRAINT chk_ceg_edges_risk CHECK (risk_level IN ('low', 'medium', 'high')),
  CONSTRAINT chk_ceg_edges_review_status CHECK (review_status IN ('not_required', 'pending_review', 'approved', 'rejected')),
  CONSTRAINT chk_ceg_edges_source CHECK (source IN ('observed', 'candidate', 'imported', 'manual', 'canonical')),
  CONSTRAINT chk_ceg_edges_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_ceg_edges_lock_version CHECK (lock_version > 0),
  CONSTRAINT chk_ceg_edges_semantic_hash CHECK (length(semantic_hash) = 71 AND semantic_hash LIKE 'sha256:%'),
  CONSTRAINT chk_ceg_edges_request_hash CHECK (length(request_hash) = 71 AND request_hash LIKE 'sha256:%'),
  CONSTRAINT chk_ceg_edges_condition_object CHECK (condition IS NULL OR jsonb_typeof(condition) = 'object'),
  CONSTRAINT chk_ceg_edges_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_ceg_edges_version_type
  ON canonical_execution_graph_edges(version_id, edge_type);
CREATE INDEX IF NOT EXISTS idx_ceg_edges_source
  ON canonical_execution_graph_edges(version_id, source_node_id);
CREATE INDEX IF NOT EXISTS idx_ceg_edges_target
  ON canonical_execution_graph_edges(version_id, target_node_id);
CREATE INDEX IF NOT EXISTS idx_ceg_edges_scope
  ON canonical_execution_graph_edges(tenant_id, workspace_id, project_id, scope_id);

CREATE TABLE IF NOT EXISTS canonical_execution_graph_paths (
  id UUID PRIMARY KEY,
  path_ref VARCHAR(500) NOT NULL UNIQUE,
  version_id UUID NOT NULL,
  graph_id UUID NOT NULL,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL,
  scope_id UUID NOT NULL,
  client_key VARCHAR(128) NOT NULL,
  path_key VARCHAR(256) NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  entry_node_id UUID NOT NULL,
  exit_node_id UUID NOT NULL,
  preconditions JSONB NOT NULL DEFAULT '[]'::jsonb,
  postconditions JSONB NOT NULL DEFAULT '[]'::jsonb,
  risk_level VARCHAR(20) NOT NULL DEFAULT 'low',
  applicability JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  source VARCHAR(40) NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_ceg_paths_version_scope FOREIGN KEY (
    version_id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) REFERENCES canonical_execution_graph_versions(
    id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) ON DELETE CASCADE,
  CONSTRAINT fk_ceg_paths_entry_version FOREIGN KEY (entry_node_id, version_id)
    REFERENCES canonical_execution_graph_nodes(id, version_id) ON DELETE RESTRICT,
  CONSTRAINT fk_ceg_paths_exit_version FOREIGN KEY (exit_node_id, version_id)
    REFERENCES canonical_execution_graph_nodes(id, version_id) ON DELETE RESTRICT,
  CONSTRAINT uq_ceg_paths_version_identity UNIQUE (id, version_id),
  CONSTRAINT uq_ceg_paths_client_key UNIQUE (version_id, client_key),
  CONSTRAINT uq_ceg_paths_path_key UNIQUE (version_id, path_key),
  CONSTRAINT chk_ceg_paths_risk CHECK (risk_level IN ('low', 'medium', 'high')),
  CONSTRAINT chk_ceg_paths_source CHECK (source IN ('observed', 'candidate', 'imported', 'manual', 'canonical')),
  CONSTRAINT chk_ceg_paths_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_ceg_paths_lock_version CHECK (lock_version > 0),
  CONSTRAINT chk_ceg_paths_request_hash CHECK (length(request_hash) = 71 AND request_hash LIKE 'sha256:%'),
  CONSTRAINT chk_ceg_paths_preconditions_array CHECK (jsonb_typeof(preconditions) = 'array'),
  CONSTRAINT chk_ceg_paths_postconditions_array CHECK (jsonb_typeof(postconditions) = 'array'),
  CONSTRAINT chk_ceg_paths_applicability_object CHECK (jsonb_typeof(applicability) = 'object'),
  CONSTRAINT chk_ceg_paths_evidence_refs_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
  CONSTRAINT chk_ceg_paths_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_ceg_paths_version
  ON canonical_execution_graph_paths(version_id, path_key);
CREATE INDEX IF NOT EXISTS idx_ceg_paths_entry
  ON canonical_execution_graph_paths(version_id, entry_node_id);
CREATE INDEX IF NOT EXISTS idx_ceg_paths_exit
  ON canonical_execution_graph_paths(version_id, exit_node_id);
CREATE INDEX IF NOT EXISTS idx_ceg_paths_scope
  ON canonical_execution_graph_paths(tenant_id, workspace_id, project_id, scope_id);

CREATE TABLE IF NOT EXISTS canonical_execution_graph_path_steps (
  id UUID PRIMARY KEY,
  step_ref VARCHAR(500) NOT NULL UNIQUE,
  path_id UUID NOT NULL,
  version_id UUID NOT NULL,
  graph_id UUID NOT NULL,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL,
  scope_id UUID NOT NULL,
  client_key VARCHAR(128) NOT NULL,
  step_order INTEGER NOT NULL,
  node_id UUID NOT NULL,
  via_edge_id UUID,
  conditions JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_ceg_steps_version_scope FOREIGN KEY (
    version_id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) REFERENCES canonical_execution_graph_versions(
    id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) ON DELETE CASCADE,
  CONSTRAINT fk_ceg_steps_path_version FOREIGN KEY (path_id, version_id)
    REFERENCES canonical_execution_graph_paths(id, version_id) ON DELETE CASCADE,
  CONSTRAINT fk_ceg_steps_node_version FOREIGN KEY (node_id, version_id)
    REFERENCES canonical_execution_graph_nodes(id, version_id) ON DELETE RESTRICT,
  CONSTRAINT fk_ceg_steps_edge_version FOREIGN KEY (via_edge_id, version_id)
    REFERENCES canonical_execution_graph_edges(id, version_id) ON DELETE RESTRICT,
  CONSTRAINT uq_ceg_steps_path_order UNIQUE (path_id, step_order),
  CONSTRAINT uq_ceg_steps_client_key UNIQUE (path_id, client_key),
  CONSTRAINT chk_ceg_steps_order CHECK (step_order > 0),
  CONSTRAINT chk_ceg_steps_lock_version CHECK (lock_version > 0),
  CONSTRAINT chk_ceg_steps_conditions_array CHECK (jsonb_typeof(conditions) = 'array'),
  CONSTRAINT chk_ceg_steps_evidence_refs_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
  CONSTRAINT chk_ceg_steps_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_ceg_steps_version
  ON canonical_execution_graph_path_steps(version_id, path_id);
CREATE INDEX IF NOT EXISTS idx_ceg_steps_node
  ON canonical_execution_graph_path_steps(version_id, node_id);
CREATE INDEX IF NOT EXISTS idx_ceg_steps_edge
  ON canonical_execution_graph_path_steps(version_id, via_edge_id);
CREATE INDEX IF NOT EXISTS idx_ceg_steps_scope
  ON canonical_execution_graph_path_steps(tenant_id, workspace_id, project_id, scope_id);

CREATE OR REPLACE FUNCTION prevent_ceg_topology_on_immutable_version()
RETURNS TRIGGER AS $$
DECLARE
  target_version_id UUID;
  target_status graph_status;
  target_frozen BOOLEAN;
BEGIN
  IF TG_OP = 'DELETE' THEN
    target_version_id := OLD.version_id;
  ELSE
    target_version_id := NEW.version_id;
  END IF;
  SELECT status, is_frozen INTO target_status, target_frozen
  FROM canonical_execution_graph_versions
  WHERE id = target_version_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Canonical Execution Graph topology requires an existing version';
  END IF;
  IF target_frozen OR target_status NOT IN ('draft', 'candidate') THEN
    RAISE EXCEPTION 'canonical or published Canonical Execution Graph topology is immutable';
  END IF;
  IF TG_OP = 'UPDATE' AND (
    OLD.id IS DISTINCT FROM NEW.id OR
    OLD.version_id IS DISTINCT FROM NEW.version_id OR
    OLD.graph_id IS DISTINCT FROM NEW.graph_id OR
    OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR
    OLD.workspace_id IS DISTINCT FROM NEW.workspace_id OR
    OLD.project_id IS DISTINCT FROM NEW.project_id OR
    OLD.scope_id IS DISTINCT FROM NEW.scope_id OR
    OLD.client_key IS DISTINCT FROM NEW.client_key
  ) THEN
    RAISE EXCEPTION 'Canonical Execution Graph topology identity and scope are immutable';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ceg_nodes_version_guard ON canonical_execution_graph_nodes;
CREATE TRIGGER trg_ceg_nodes_version_guard
BEFORE INSERT OR UPDATE OR DELETE ON canonical_execution_graph_nodes
FOR EACH ROW EXECUTE FUNCTION prevent_ceg_topology_on_immutable_version();

DROP TRIGGER IF EXISTS trg_ceg_edges_version_guard ON canonical_execution_graph_edges;
CREATE TRIGGER trg_ceg_edges_version_guard
BEFORE INSERT OR UPDATE OR DELETE ON canonical_execution_graph_edges
FOR EACH ROW EXECUTE FUNCTION prevent_ceg_topology_on_immutable_version();

DROP TRIGGER IF EXISTS trg_ceg_paths_version_guard ON canonical_execution_graph_paths;
CREATE TRIGGER trg_ceg_paths_version_guard
BEFORE INSERT OR UPDATE OR DELETE ON canonical_execution_graph_paths
FOR EACH ROW EXECUTE FUNCTION prevent_ceg_topology_on_immutable_version();

DROP TRIGGER IF EXISTS trg_ceg_steps_version_guard ON canonical_execution_graph_path_steps;
CREATE TRIGGER trg_ceg_steps_version_guard
BEFORE INSERT OR UPDATE OR DELETE ON canonical_execution_graph_path_steps
FOR EACH ROW EXECUTE FUNCTION prevent_ceg_topology_on_immutable_version();

DROP TRIGGER IF EXISTS trg_ceg_nodes_updated_at ON canonical_execution_graph_nodes;
CREATE TRIGGER trg_ceg_nodes_updated_at BEFORE UPDATE ON canonical_execution_graph_nodes
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
DROP TRIGGER IF EXISTS trg_ceg_edges_updated_at ON canonical_execution_graph_edges;
CREATE TRIGGER trg_ceg_edges_updated_at BEFORE UPDATE ON canonical_execution_graph_edges
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
DROP TRIGGER IF EXISTS trg_ceg_paths_updated_at ON canonical_execution_graph_paths;
CREATE TRIGGER trg_ceg_paths_updated_at BEFORE UPDATE ON canonical_execution_graph_paths
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
DROP TRIGGER IF EXISTS trg_ceg_steps_updated_at ON canonical_execution_graph_path_steps;
CREATE TRIGGER trg_ceg_steps_updated_at BEFORE UPDATE ON canonical_execution_graph_path_steps
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

UPDATE capability_registry
SET description = 'Reserved read access for Canonical Execution Graph data.'
WHERE capability_key = 'graph.read';
UPDATE capability_registry
SET description = 'Reserved managed write access for draft/candidate CEG topology.',
    risk_level = 'high'
WHERE capability_key = 'graph.manage';

COMMENT ON TABLE canonical_execution_graph_nodes IS
  'P11 structured semantic CEG nodes; not browser, Tool, SemanticAction, or Visual Grounding executors.';
COMMENT ON TABLE canonical_execution_graph_edges IS
  'P11 controlled CEG relations; high-risk relations remain pending review and do not approve themselves.';
COMMENT ON TABLE canonical_execution_graph_paths IS
  'P11 ordered Canonical Path candidates owned by a single scoped graph version.';
COMMENT ON TABLE canonical_execution_graph_path_steps IS
  'P11 ordered path steps that reference existing same-version nodes and connecting edges.';
