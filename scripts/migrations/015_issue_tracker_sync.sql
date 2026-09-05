-- Batch 4 issue tracker connector runtime and Finding external issue sync.
-- Stores external issue links for normalized Findings only; no plaintext credentials.

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('issue_tracker.sync', 'integrations', 'Create, update, and status-sync external issue tracker defects.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = EXCLUDED.is_active;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('enterprise', 'issue_tracker.sync', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET
  enabled = EXCLUDED.enabled;

INSERT INTO rbac_role_capabilities (role_name, capability_key, effect)
VALUES
  ('admin', 'issue_tracker.sync', 'allow'),
  ('system', 'issue_tracker.sync', 'allow')
ON CONFLICT (role_name, capability_key) DO UPDATE SET
  effect = EXCLUDED.effect;

CREATE TABLE IF NOT EXISTS external_issue_links (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  connector_binding_id UUID REFERENCES skill_connector_bindings(id) ON DELETE SET NULL,
  connector_name VARCHAR(128) NOT NULL,
  external_issue_id VARCHAR(255),
  external_issue_key VARCHAR(255),
  external_issue_url TEXT,
  external_status VARCHAR(80),
  sync_status VARCHAR(40) NOT NULL DEFAULT 'pending',
  idempotency_key VARCHAR(255) NOT NULL,
  last_synced_at TIMESTAMPTZ,
  last_status_synced_at TIMESTAMPTZ,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  connector_call_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  payload_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_external_issue_links_idempotency_key UNIQUE (idempotency_key),
  CONSTRAINT chk_external_issue_links_status CHECK (sync_status IN ('pending', 'synced', 'failed')),
  CONSTRAINT chk_external_issue_links_evidence_refs_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
  CONSTRAINT chk_external_issue_links_replay_refs_array CHECK (jsonb_typeof(replay_refs) = 'array'),
  CONSTRAINT chk_external_issue_links_trace_refs_array CHECK (jsonb_typeof(trace_refs) = 'array'),
  CONSTRAINT chk_external_issue_links_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array'),
  CONSTRAINT chk_external_issue_links_connector_refs_array CHECK (jsonb_typeof(connector_call_refs) = 'array'),
  CONSTRAINT chk_external_issue_links_payload_object CHECK (jsonb_typeof(payload_snapshot) = 'object')
);

COMMENT ON TABLE external_issue_links IS 'Service-owned normalized Finding to external issue tracker link records. Stores connector binding refs and external issue status only, never plaintext credentials.';

CREATE INDEX IF NOT EXISTS idx_external_issue_links_finding ON external_issue_links(finding_id);
CREATE INDEX IF NOT EXISTS idx_external_issue_links_execution ON external_issue_links(execution_id);
CREATE INDEX IF NOT EXISTS idx_external_issue_links_connector ON external_issue_links(connector_name);
CREATE INDEX IF NOT EXISTS idx_external_issue_links_external_issue ON external_issue_links(connector_name, external_issue_key);
CREATE INDEX IF NOT EXISTS idx_external_issue_links_sync_status ON external_issue_links(sync_status);

DROP TRIGGER IF EXISTS trg_external_issue_links_updated_at ON external_issue_links;
CREATE TRIGGER trg_external_issue_links_updated_at
BEFORE UPDATE ON external_issue_links
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
