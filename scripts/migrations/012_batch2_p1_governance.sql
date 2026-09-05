-- Batch 2 P1 governance persistence:
-- RBAC role-capability grants, Guardrail Policy Versioning, Replay Export persistence.

CREATE TABLE IF NOT EXISTS rbac_role_capabilities (
  role_name VARCHAR(80) NOT NULL,
  capability_key VARCHAR(120) NOT NULL REFERENCES capability_registry(capability_key) ON DELETE CASCADE,
  effect VARCHAR(16) NOT NULL DEFAULT 'allow',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (role_name, capability_key),
  CONSTRAINT chk_rbac_role_capabilities_effect CHECK (effect IN ('allow', 'deny'))
);

CREATE INDEX IF NOT EXISTS idx_rbac_role_capabilities_capability
  ON rbac_role_capabilities(capability_key);
CREATE INDEX IF NOT EXISTS idx_rbac_role_capabilities_effect
  ON rbac_role_capabilities(effect);

DROP TRIGGER IF EXISTS trg_rbac_role_capabilities_updated_at ON rbac_role_capabilities;
CREATE TRIGGER trg_rbac_role_capabilities_updated_at
BEFORE UPDATE ON rbac_role_capabilities
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS guardrail_policy_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id UUID NOT NULL REFERENCES guardrail_policies(id) ON DELETE CASCADE,
  rule_id VARCHAR(255) NOT NULL,
  version_no INTEGER NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  status guardrail_policy_status NOT NULL,
  decision_override guardrail_decision,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  change_reason TEXT,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_guardrail_policy_versions_policy_version UNIQUE (policy_id, version_no),
  CONSTRAINT chk_guardrail_policy_versions_config_object CHECK (jsonb_typeof(config) = 'object'),
  CONSTRAINT chk_guardrail_policy_versions_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_guardrail_policy_versions_rule
  ON guardrail_policy_versions(rule_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_policy_versions_policy
  ON guardrail_policy_versions(policy_id);

ALTER TABLE guardrail_events
  ADD COLUMN IF NOT EXISTS policy_version_id UUID REFERENCES guardrail_policy_versions(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS replay_exports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  export_id VARCHAR(120) NOT NULL,
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  schema_version VARCHAR(80) NOT NULL DEFAULT 'phase8.replay-export.v1',
  export_hash VARCHAR(80) NOT NULL,
  export_payload_hash VARCHAR(80) NOT NULL,
  storage_ref VARCHAR(500),
  export_artifact_ref VARCHAR(500),
  redaction_status VARCHAR(40) NOT NULL,
  trace_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  request_id VARCHAR(255),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_replay_exports_execution_payload_hash UNIQUE (execution_id, export_payload_hash),
  CONSTRAINT uq_replay_exports_export_id UNIQUE (export_id),
  CONSTRAINT uq_replay_exports_export_hash UNIQUE (export_hash),
  CONSTRAINT chk_replay_exports_trace_refs_array CHECK (jsonb_typeof(trace_refs) = 'array'),
  CONSTRAINT chk_replay_exports_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array'),
  CONSTRAINT chk_replay_exports_payload_object CHECK (jsonb_typeof(payload) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_replay_exports_execution ON replay_exports(execution_id);
CREATE INDEX IF NOT EXISTS idx_replay_exports_created_at ON replay_exports(created_at DESC);
