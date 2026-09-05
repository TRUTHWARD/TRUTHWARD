-- Batch 6 human WorkItem management.
-- WorkItems are Service-owned human collaboration tasks, not ExecutionTask runner units.
-- They can reference normalized Findings and evidence, but they never write Gate decisions.

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('work_items.read', 'workflow', 'Read human WorkItem collaboration tasks.', 'low', TRUE),
  ('work_items.manage', 'workflow', 'Create, assign, claim, and transition human WorkItems.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = EXCLUDED.is_active;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'work_items.read', TRUE),
  ('pro', 'work_items.read', TRUE),
  ('enterprise', 'work_items.read', TRUE),
  ('enterprise', 'work_items.manage', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET
  enabled = EXCLUDED.enabled;

INSERT INTO rbac_role_capabilities (role_name, capability_key, effect)
VALUES
  ('user', 'work_items.read', 'allow'),
  ('admin', 'work_items.read', 'allow'),
  ('admin', 'work_items.manage', 'allow'),
  ('system', 'work_items.read', 'allow'),
  ('system', 'work_items.manage', 'allow')
ON CONFLICT (role_name, capability_key) DO UPDATE SET
  effect = EXCLUDED.effect;

CREATE TABLE IF NOT EXISTS work_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE SET NULL,
  requirement_item_id VARCHAR(255),
  execution_id UUID REFERENCES executions(id) ON DELETE SET NULL,
  finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
  evidence_artifact_id UUID REFERENCES execution_artifacts(id) ON DELETE SET NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  status VARCHAR(32) NOT NULL DEFAULT 'open',
  priority VARCHAR(32) NOT NULL DEFAULT 'medium',
  assignee_id UUID REFERENCES users(id) ON DELETE SET NULL,
  claimed_by UUID REFERENCES users(id) ON DELETE SET NULL,
  completed_at TIMESTAMPTZ,
  cancelled_at TIMESTAMPTZ,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_work_items_status CHECK (status IN ('open', 'assigned', 'in_progress', 'completed', 'cancelled')),
  CONSTRAINT chk_work_items_priority CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
  CONSTRAINT chk_work_items_evidence_refs_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
  CONSTRAINT chk_work_items_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

COMMENT ON TABLE work_items IS 'Service-owned human collaboration tasks. WorkItems are distinct from execution_tasks and do not write Gate decisions.';
COMMENT ON COLUMN work_items.execution_id IS 'Optional reference to an Execution for context; does not mutate execution lifecycle.';
COMMENT ON COLUMN work_items.finding_id IS 'Optional reference to a canonical Finding after NORMALIZE.';
COMMENT ON COLUMN work_items.evidence_artifact_id IS 'Optional reference to persisted execution evidence.';

CREATE INDEX IF NOT EXISTS idx_work_items_project ON work_items(project_id);
CREATE INDEX IF NOT EXISTS idx_work_items_requirement_version ON work_items(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_work_items_execution ON work_items(execution_id);
CREATE INDEX IF NOT EXISTS idx_work_items_finding ON work_items(finding_id);
CREATE INDEX IF NOT EXISTS idx_work_items_evidence_artifact ON work_items(evidence_artifact_id);
CREATE INDEX IF NOT EXISTS idx_work_items_assignee ON work_items(assignee_id);
CREATE INDEX IF NOT EXISTS idx_work_items_claimed_by ON work_items(claimed_by);
CREATE INDEX IF NOT EXISTS idx_work_items_status ON work_items(status);
CREATE INDEX IF NOT EXISTS idx_work_items_created_at ON work_items(created_at DESC);

DROP TRIGGER IF EXISTS trg_work_items_updated_at ON work_items;
CREATE TRIGGER trg_work_items_updated_at
BEFORE UPDATE ON work_items
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

