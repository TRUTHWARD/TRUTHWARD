-- P01 Gate Policy Data Foundation.
-- Adds declarative policy identity/version/binding storage only. It does not
-- resolve policies, evaluate Gate inputs, activate versions, or change gate_results.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'gate_policy_status') THEN
    CREATE TYPE gate_policy_status AS ENUM (
      'draft',
      'active',
      'disabled',
      'deprecated',
      'archived'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'gate_policy_scope_type') THEN
    CREATE TYPE gate_policy_scope_type AS ENUM (
      'global',
      'workspace',
      'project',
      'environment',
      'stage',
      'domain'
    );
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS gate_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  policy_key VARCHAR(128) NOT NULL,
  policy_ref VARCHAR(500) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  status gate_policy_status NOT NULL DEFAULT 'draft',
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_gate_policies_scope_key UNIQUE (tenant_id, workspace_id, policy_key),
  CONSTRAINT uq_gate_policies_tenant_identity UNIQUE (id, tenant_id, workspace_id),
  CONSTRAINT chk_gate_policies_tenant_not_blank CHECK (length(trim(tenant_id)) > 0),
  CONSTRAINT chk_gate_policies_workspace_not_blank CHECK (length(trim(workspace_id)) > 0),
  CONSTRAINT chk_gate_policies_lock_version CHECK (lock_version > 0)
);

CREATE INDEX IF NOT EXISTS idx_gate_policies_tenant_workspace
  ON gate_policies(tenant_id, workspace_id);
CREATE INDEX IF NOT EXISTS idx_gate_policies_status
  ON gate_policies(status);

CREATE TABLE IF NOT EXISTS gate_policy_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id UUID NOT NULL,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  version_number INTEGER NOT NULL,
  version_ref VARCHAR(500) NOT NULL UNIQUE,
  schema_version VARCHAR(80) NOT NULL,
  status gate_policy_status NOT NULL,
  policy_snapshot JSONB NOT NULL,
  content_hash VARCHAR(80) NOT NULL,
  capability_ref VARCHAR(500),
  approval_policy_ref VARCHAR(500),
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_gate_policy_versions_policy_scope
    FOREIGN KEY (policy_id, tenant_id, workspace_id)
    REFERENCES gate_policies(id, tenant_id, workspace_id)
    ON DELETE RESTRICT,
  CONSTRAINT uq_gate_policy_versions_policy_version UNIQUE (policy_id, version_number),
  CONSTRAINT uq_gate_policy_versions_policy_hash UNIQUE (policy_id, content_hash),
  CONSTRAINT uq_gate_policy_versions_tenant_identity
    UNIQUE (id, policy_id, tenant_id, workspace_id, content_hash),
  CONSTRAINT chk_gate_policy_versions_number CHECK (version_number > 0),
  CONSTRAINT chk_gate_policy_versions_hash_length CHECK (length(content_hash) = 71),
  CONSTRAINT chk_gate_policy_versions_hash_prefix CHECK (substr(content_hash, 1, 7) = 'sha256:'),
  CONSTRAINT chk_gate_policy_versions_lock_version CHECK (lock_version > 0),
  CONSTRAINT chk_gate_policy_versions_snapshot_object CHECK (jsonb_typeof(policy_snapshot) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_gate_policy_versions_policy_status
  ON gate_policy_versions(policy_id, status);
CREATE INDEX IF NOT EXISTS idx_gate_policy_versions_scope
  ON gate_policy_versions(tenant_id, workspace_id);
CREATE INDEX IF NOT EXISTS idx_gate_policy_versions_hash
  ON gate_policy_versions(content_hash);

CREATE TABLE IF NOT EXISTS gate_policy_bindings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  policy_id UUID NOT NULL,
  policy_version_id UUID NOT NULL,
  policy_version_hash VARCHAR(80) NOT NULL,
  binding_ref VARCHAR(500) NOT NULL UNIQUE,
  scope_type gate_policy_scope_type NOT NULL,
  scope_id VARCHAR(255),
  scope_key VARCHAR(255) NOT NULL,
  status gate_policy_status NOT NULL DEFAULT 'draft',
  effective_from TIMESTAMPTZ NOT NULL,
  effective_until TIMESTAMPTZ,
  capability_ref VARCHAR(500),
  approval_policy_ref VARCHAR(500),
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_gate_policy_bindings_version_scope
    FOREIGN KEY (policy_version_id, policy_id, tenant_id, workspace_id, policy_version_hash)
    REFERENCES gate_policy_versions(id, policy_id, tenant_id, workspace_id, content_hash)
    ON DELETE RESTRICT,
  CONSTRAINT uq_gate_policy_bindings_idempotency
    UNIQUE (tenant_id, workspace_id, idempotency_key),
  CONSTRAINT uq_gate_policy_bindings_effective_scope
    UNIQUE (tenant_id, workspace_id, policy_id, scope_type, scope_key, effective_from),
  CONSTRAINT chk_gate_policy_bindings_tenant_not_blank CHECK (length(trim(tenant_id)) > 0),
  CONSTRAINT chk_gate_policy_bindings_workspace_not_blank CHECK (length(trim(workspace_id)) > 0),
  CONSTRAINT chk_gate_policy_bindings_scope_identity CHECK (
    (scope_type = 'global' AND scope_id IS NULL AND scope_key = 'global')
    OR
    (scope_type <> 'global' AND scope_id IS NOT NULL AND length(trim(scope_id)) > 0 AND scope_key = scope_id)
  ),
  CONSTRAINT chk_gate_policy_bindings_workspace_scope CHECK (
    scope_type <> 'workspace' OR scope_id = workspace_id
  ),
  CONSTRAINT chk_gate_policy_bindings_effective_window CHECK (
    effective_until IS NULL OR effective_until > effective_from
  ),
  CONSTRAINT chk_gate_policy_bindings_hash_length CHECK (length(policy_version_hash) = 71),
  CONSTRAINT chk_gate_policy_bindings_hash_prefix CHECK (substr(policy_version_hash, 1, 7) = 'sha256:'),
  CONSTRAINT chk_gate_policy_bindings_request_hash_length CHECK (length(request_hash) = 71),
  CONSTRAINT chk_gate_policy_bindings_request_hash_prefix CHECK (substr(request_hash, 1, 7) = 'sha256:'),
  CONSTRAINT chk_gate_policy_bindings_lock_version CHECK (lock_version > 0)
);

CREATE INDEX IF NOT EXISTS idx_gate_policy_bindings_resolution
  ON gate_policy_bindings(tenant_id, workspace_id, scope_type, scope_key, status);
CREATE INDEX IF NOT EXISTS idx_gate_policy_bindings_version
  ON gate_policy_bindings(policy_version_id);
CREATE INDEX IF NOT EXISTS idx_gate_policy_bindings_effective
  ON gate_policy_bindings(effective_from, effective_until);

CREATE OR REPLACE FUNCTION prevent_published_gate_policy_version_update()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.status <> 'draft' THEN
    RAISE EXCEPTION 'published Gate Policy versions are immutable'
      USING ERRCODE = '55000';
  END IF;

  IF NEW.status <> 'draft' AND (
    NEW.policy_id IS DISTINCT FROM OLD.policy_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
    OR NEW.version_number IS DISTINCT FROM OLD.version_number
    OR NEW.version_ref IS DISTINCT FROM OLD.version_ref
    OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
    OR NEW.policy_snapshot IS DISTINCT FROM OLD.policy_snapshot
    OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
    OR NEW.capability_ref IS DISTINCT FROM OLD.capability_ref
    OR NEW.approval_policy_ref IS DISTINCT FROM OLD.approval_policy_ref
  ) THEN
    RAISE EXCEPTION 'publishing a Gate Policy version cannot change frozen content'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_gate_policies_updated_at ON gate_policies;
CREATE TRIGGER trg_gate_policies_updated_at
BEFORE UPDATE ON gate_policies
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_gate_policy_versions_updated_at ON gate_policy_versions;
CREATE TRIGGER trg_gate_policy_versions_updated_at
BEFORE UPDATE ON gate_policy_versions
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_gate_policy_versions_immutable ON gate_policy_versions;
CREATE TRIGGER trg_gate_policy_versions_immutable
BEFORE UPDATE ON gate_policy_versions
FOR EACH ROW EXECUTE FUNCTION prevent_published_gate_policy_version_update();

DROP TRIGGER IF EXISTS trg_gate_policy_bindings_updated_at ON gate_policy_bindings;
CREATE TRIGGER trg_gate_policy_bindings_updated_at
BEFORE UPDATE ON gate_policy_bindings
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE gate_policies IS
  'P01 Service-owned Gate Policy identities. This table does not evaluate or write Gate decisions.';
COMMENT ON TABLE gate_policy_versions IS
  'Versioned declarative gate-policy.v1 snapshots with canonical hashes. Published rows are immutable.';
COMMENT ON TABLE gate_policy_bindings IS
  'Tenant/workspace-scoped references to exact Gate Policy versions. Resolver and activation are not implemented by P01.';
