-- Phase 8/9 local Core Loop incremental migration for PostgreSQL 15+.
-- The canonical fresh-install schema remains DB_SCHEMA.sql.

CREATE TABLE IF NOT EXISTS requirement_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_ref VARCHAR(255) NOT NULL,
  version_no INTEGER NOT NULL,
  content_hash VARCHAR(80) NOT NULL,
  document TEXT NOT NULL,
  requirements JSONB NOT NULL DEFAULT '[]'::jsonb,
  acceptance_criteria JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_requirement_version_number UNIQUE (source_ref, version_no),
  CONSTRAINT uq_requirement_version_content UNIQUE (source_ref, content_hash),
  CONSTRAINT chk_requirement_versions_requirements_array CHECK (jsonb_typeof(requirements) = 'array'),
  CONSTRAINT chk_requirement_versions_acceptance_array CHECK (jsonb_typeof(acceptance_criteria) = 'array')
);

CREATE TABLE IF NOT EXISTS clarification_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE CASCADE,
  question_key VARCHAR(100) NOT NULL,
  question TEXT NOT NULL,
  priority VARCHAR(10) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'open',
  answer TEXT,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  answered_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_clarification_priority CHECK (priority IN ('P0', 'P1', 'P2')),
  CONSTRAINT chk_clarification_status CHECK (status IN ('open', 'answered', 'closed'))
);

ALTER TABLE test_plans
  ADD COLUMN IF NOT EXISTS requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS test_assets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE CASCADE,
  test_plan_id UUID REFERENCES test_plans(id) ON DELETE SET NULL,
  asset_type VARCHAR(30) NOT NULL,
  domain VARCHAR(50) NOT NULL,
  title VARCHAR(255) NOT NULL,
  objective TEXT NOT NULL,
  requirement_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  status VARCHAR(30) NOT NULL DEFAULT 'draft',
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_test_asset_type CHECK (asset_type IN ('test_point', 'test_case')),
  CONSTRAINT chk_test_asset_status CHECK (status IN ('draft', 'reviewed', 'approved', 'invalidated'))
);

CREATE TABLE IF NOT EXISTS test_asset_reviews (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE CASCADE,
  test_plan_id UUID NOT NULL REFERENCES test_plans(id) ON DELETE CASCADE,
  status VARCHAR(30) NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  issues JSONB NOT NULL DEFAULT '[]'::jsonb,
  coverage_map JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_test_asset_review_status CHECK (status IN ('approved', 'needs_review', 'rejected')),
  CONSTRAINT chk_test_asset_review_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE TABLE IF NOT EXISTS execution_plans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE CASCADE,
  test_plan_id UUID NOT NULL REFERENCES test_plans(id) ON DELETE CASCADE,
  status VARCHAR(30) NOT NULL,
  risk_level risk_level NOT NULL,
  approval_required BOOLEAN NOT NULL DEFAULT FALSE,
  tasks JSONB NOT NULL DEFAULT '[]'::jsonb,
  asset_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  retry_strategy JSONB NOT NULL DEFAULT '{}'::jsonb,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_execution_plan_status CHECK (status IN ('draft', 'approved', 'blocked'))
);

ALTER TABLE executions
  ADD COLUMN IF NOT EXISTS execution_plan_id UUID REFERENCES execution_plans(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS correction_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE CASCADE,
  execution_id UUID REFERENCES executions(id) ON DELETE SET NULL,
  target_type VARCHAR(50) NOT NULL,
  target_id VARCHAR(255) NOT NULL,
  before_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  after_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  reason TEXT NOT NULL,
  actor_ref JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  affected_asset_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS raw_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  task_id UUID REFERENCES execution_tasks(id) ON DELETE CASCADE,
  source VARCHAR(100) NOT NULL,
  category VARCHAR(100) NOT NULL,
  severity VARCHAR(50) NOT NULL,
  title VARCHAR(255) NOT NULL,
  summary TEXT NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  dedupe_key VARCHAR(255) NOT NULL,
  raw_ref VARCHAR(255) NOT NULL,
  location JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  normalized_finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_raw_findings_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE TABLE IF NOT EXISTS domain_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id VARCHAR(100) NOT NULL UNIQUE,
  event_type VARCHAR(100) NOT NULL,
  schema_version VARCHAR(50) NOT NULL,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  correlation_refs JSONB NOT NULL DEFAULT '{}'::jsonb,
  occurred_at TIMESTAMPTZ NOT NULL,
  actor_ref JSONB,
  source_ref JSONB,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb
);

ALTER TABLE orchestration_runs
  ADD COLUMN IF NOT EXISTS linked_requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE SET NULL;

ALTER TABLE integration_events
  ADD COLUMN IF NOT EXISTS linked_requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_requirement_versions_source_ref ON requirement_versions(source_ref);
CREATE INDEX IF NOT EXISTS idx_requirement_versions_content_hash ON requirement_versions(content_hash);
CREATE INDEX IF NOT EXISTS idx_clarification_requirement ON clarification_items(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_clarification_status ON clarification_items(status, priority);
CREATE INDEX IF NOT EXISTS idx_test_plans_requirement_version_id ON test_plans(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_test_assets_requirement ON test_assets(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_test_assets_plan ON test_assets(test_plan_id);
CREATE INDEX IF NOT EXISTS idx_test_asset_reviews_requirement ON test_asset_reviews(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_test_asset_reviews_plan ON test_asset_reviews(test_plan_id);
CREATE INDEX IF NOT EXISTS idx_execution_plans_requirement ON execution_plans(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_execution_plans_test_plan ON execution_plans(test_plan_id);
CREATE INDEX IF NOT EXISTS idx_executions_execution_plan_id ON executions(execution_plan_id);
CREATE INDEX IF NOT EXISTS idx_correction_requirement ON correction_records(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_correction_execution ON correction_records(execution_id);
CREATE INDEX IF NOT EXISTS idx_raw_findings_execution ON raw_findings(execution_id);
CREATE INDEX IF NOT EXISTS idx_raw_findings_task ON raw_findings(task_id);
CREATE INDEX IF NOT EXISTS idx_raw_findings_normalized ON raw_findings(normalized_finding_id);
CREATE INDEX IF NOT EXISTS idx_domain_events_type ON domain_events(event_type);
CREATE INDEX IF NOT EXISTS idx_domain_events_trace ON domain_events(trace_id);
CREATE INDEX IF NOT EXISTS idx_domain_events_occurred_at ON domain_events(occurred_at);
CREATE INDEX IF NOT EXISTS idx_orchestration_runs_requirement_id ON orchestration_runs(linked_requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_integration_events_requirement_id ON integration_events(linked_requirement_version_id);

DROP TRIGGER IF EXISTS trg_requirement_versions_updated_at ON requirement_versions;
CREATE TRIGGER trg_requirement_versions_updated_at BEFORE UPDATE ON requirement_versions
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_clarification_items_updated_at ON clarification_items;
CREATE TRIGGER trg_clarification_items_updated_at BEFORE UPDATE ON clarification_items
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_test_assets_updated_at ON test_assets;
CREATE TRIGGER trg_test_assets_updated_at BEFORE UPDATE ON test_assets
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_test_asset_reviews_updated_at ON test_asset_reviews;
CREATE TRIGGER trg_test_asset_reviews_updated_at BEFORE UPDATE ON test_asset_reviews
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_execution_plans_updated_at ON execution_plans;
CREATE TRIGGER trg_execution_plans_updated_at BEFORE UPDATE ON execution_plans
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_correction_records_updated_at ON correction_records;
CREATE TRIGGER trg_correction_records_updated_at BEFORE UPDATE ON correction_records
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
