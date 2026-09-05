-- P0 Traceability & Coverage Matrix incremental migration for PostgreSQL 15+.
-- Adds explicit valid relationship storage used by Coverage Matrix and Replay snapshots.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'traceability_relation_status') THEN
    CREATE TYPE traceability_relation_status AS ENUM (
      'candidate',
      'confirmed',
      'system_verified',
      'stale',
      'invalid',
      'rejected'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'traceability_relation_source') THEN
    CREATE TYPE traceability_relation_source AS ENUM (
      'manual',
      'approval',
      'deterministic_rule',
      'execution_result',
      'import',
      'model_candidate',
      'metadata_candidate',
      'string_match_candidate'
    );
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS requirement_item_test_points (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requirement_item_id VARCHAR(255) NOT NULL,
  test_point_id UUID NOT NULL REFERENCES test_assets(id) ON DELETE CASCADE,
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE CASCADE,
  relation_type VARCHAR(80) NOT NULL DEFAULT 'covers',
  scope_id VARCHAR(255) NOT NULL,
  status traceability_relation_status NOT NULL DEFAULT 'candidate',
  source traceability_relation_source NOT NULL,
  confidence NUMERIC(5,4) NOT NULL DEFAULT 1.0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  validated_at TIMESTAMPTZ,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  invalidated_at TIMESTAMPTZ,
  invalidated_reason TEXT,
  trace_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_requirement_item_test_points_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE TABLE IF NOT EXISTS test_point_test_cases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  test_point_id UUID NOT NULL REFERENCES test_assets(id) ON DELETE CASCADE,
  test_case_id UUID NOT NULL REFERENCES test_assets(id) ON DELETE CASCADE,
  relation_type VARCHAR(80) NOT NULL DEFAULT 'covers',
  scope_id VARCHAR(255) NOT NULL,
  status traceability_relation_status NOT NULL DEFAULT 'candidate',
  source traceability_relation_source NOT NULL,
  confidence NUMERIC(5,4) NOT NULL DEFAULT 1.0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  validated_at TIMESTAMPTZ,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  invalidated_at TIMESTAMPTZ,
  invalidated_reason TEXT,
  trace_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_test_point_test_cases_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE TABLE IF NOT EXISTS test_case_execution_tasks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  test_case_id UUID NOT NULL REFERENCES test_assets(id) ON DELETE CASCADE,
  execution_task_id UUID NOT NULL REFERENCES execution_tasks(id) ON DELETE CASCADE,
  run_id UUID,
  relation_type VARCHAR(80) NOT NULL DEFAULT 'covers',
  scope_id VARCHAR(255) NOT NULL,
  status traceability_relation_status NOT NULL DEFAULT 'candidate',
  source traceability_relation_source NOT NULL,
  confidence NUMERIC(5,4) NOT NULL DEFAULT 1.0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  validated_at TIMESTAMPTZ,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  invalidated_at TIMESTAMPTZ,
  invalidated_reason TEXT,
  trace_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_test_case_execution_tasks_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE TABLE IF NOT EXISTS execution_task_evidence_artifacts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_task_id UUID NOT NULL REFERENCES execution_tasks(id) ON DELETE CASCADE,
  evidence_artifact_id UUID NOT NULL REFERENCES execution_artifacts(id) ON DELETE CASCADE,
  artifact_type VARCHAR(80) NOT NULL,
  relation_type VARCHAR(80) NOT NULL DEFAULT 'covers',
  scope_id VARCHAR(255) NOT NULL,
  status traceability_relation_status NOT NULL DEFAULT 'candidate',
  source traceability_relation_source NOT NULL,
  confidence NUMERIC(5,4) NOT NULL DEFAULT 1.0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  validated_at TIMESTAMPTZ,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  invalidated_at TIMESTAMPTZ,
  invalidated_reason TEXT,
  trace_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_execution_task_evidence_artifacts_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE TABLE IF NOT EXISTS evidence_raw_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  evidence_artifact_id UUID NOT NULL REFERENCES execution_artifacts(id) ON DELETE CASCADE,
  raw_finding_id UUID NOT NULL REFERENCES raw_findings(id) ON DELETE CASCADE,
  relation_type VARCHAR(80) NOT NULL DEFAULT 'supports',
  scope_id VARCHAR(255) NOT NULL,
  status traceability_relation_status NOT NULL DEFAULT 'candidate',
  source traceability_relation_source NOT NULL,
  confidence NUMERIC(5,4) NOT NULL DEFAULT 1.0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  validated_at TIMESTAMPTZ,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  invalidated_at TIMESTAMPTZ,
  invalidated_reason TEXT,
  trace_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_evidence_raw_findings_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE TABLE IF NOT EXISTS raw_normalized_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  raw_finding_id UUID NOT NULL REFERENCES raw_findings(id) ON DELETE CASCADE,
  normalized_finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  normalization_method VARCHAR(100) NOT NULL,
  dedupe_key VARCHAR(255) NOT NULL,
  merge_group_id VARCHAR(255),
  relation_type VARCHAR(80) NOT NULL DEFAULT 'normalizes',
  scope_id VARCHAR(255) NOT NULL,
  status traceability_relation_status NOT NULL DEFAULT 'candidate',
  source traceability_relation_source NOT NULL,
  confidence NUMERIC(5,4) NOT NULL DEFAULT 1.0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  validated_at TIMESTAMPTZ,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  invalidated_at TIMESTAMPTZ,
  invalidated_reason TEXT,
  trace_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_raw_normalized_findings_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE TABLE IF NOT EXISTS normalized_finding_gate_decisions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  normalized_finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  gate_decision_id UUID NOT NULL REFERENCES gate_results(id) ON DELETE CASCADE,
  impact VARCHAR(80) NOT NULL,
  reason TEXT NOT NULL,
  relation_type VARCHAR(80) NOT NULL DEFAULT 'impacts',
  scope_id VARCHAR(255) NOT NULL,
  status traceability_relation_status NOT NULL DEFAULT 'candidate',
  source traceability_relation_source NOT NULL,
  confidence NUMERIC(5,4) NOT NULL DEFAULT 1.0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  validated_at TIMESTAMPTZ,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  invalidated_at TIMESTAMPTZ,
  invalidated_reason TEXT,
  trace_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_normalized_finding_gate_decisions_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE TABLE IF NOT EXISTS gate_decision_replay_exports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  gate_decision_id UUID NOT NULL REFERENCES gate_results(id) ON DELETE CASCADE,
  replay_export_id VARCHAR(255) NOT NULL,
  export_hash VARCHAR(80) NOT NULL,
  relation_type VARCHAR(80) NOT NULL DEFAULT 'included_in_replay',
  scope_id VARCHAR(255) NOT NULL,
  status traceability_relation_status NOT NULL DEFAULT 'candidate',
  source traceability_relation_source NOT NULL,
  confidence NUMERIC(5,4) NOT NULL DEFAULT 1.0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  validated_at TIMESTAMPTZ,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  invalidated_at TIMESTAMPTZ,
  invalidated_reason TEXT,
  trace_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_gate_decision_replay_exports_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_requirement_item_test_points_effective
  ON requirement_item_test_points(requirement_item_id, test_point_id, relation_type, scope_id)
  WHERE status IN ('confirmed', 'system_verified');
CREATE UNIQUE INDEX IF NOT EXISTS uq_test_point_test_cases_effective
  ON test_point_test_cases(test_point_id, test_case_id, relation_type, scope_id)
  WHERE status IN ('confirmed', 'system_verified');
CREATE UNIQUE INDEX IF NOT EXISTS uq_test_case_execution_tasks_effective
  ON test_case_execution_tasks(test_case_id, execution_task_id, relation_type, scope_id)
  WHERE status IN ('confirmed', 'system_verified');
CREATE UNIQUE INDEX IF NOT EXISTS uq_execution_task_evidence_artifacts_effective
  ON execution_task_evidence_artifacts(execution_task_id, evidence_artifact_id, relation_type, scope_id)
  WHERE status IN ('confirmed', 'system_verified');
CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_raw_findings_effective
  ON evidence_raw_findings(evidence_artifact_id, raw_finding_id, relation_type, scope_id)
  WHERE status IN ('confirmed', 'system_verified');
CREATE UNIQUE INDEX IF NOT EXISTS uq_raw_normalized_findings_effective
  ON raw_normalized_findings(raw_finding_id, normalized_finding_id, relation_type, scope_id)
  WHERE status IN ('confirmed', 'system_verified');
CREATE UNIQUE INDEX IF NOT EXISTS uq_normalized_finding_gate_decisions_effective
  ON normalized_finding_gate_decisions(normalized_finding_id, gate_decision_id, relation_type, scope_id)
  WHERE status IN ('confirmed', 'system_verified');
CREATE UNIQUE INDEX IF NOT EXISTS uq_gate_decision_replay_exports_effective
  ON gate_decision_replay_exports(gate_decision_id, replay_export_id, relation_type, scope_id)
  WHERE status IN ('confirmed', 'system_verified');

CREATE INDEX IF NOT EXISTS idx_requirement_item_test_points_requirement ON requirement_item_test_points(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_requirement_item_test_points_test_point ON requirement_item_test_points(test_point_id);
CREATE INDEX IF NOT EXISTS idx_requirement_item_test_points_status ON requirement_item_test_points(status);
CREATE INDEX IF NOT EXISTS idx_test_point_test_cases_test_point ON test_point_test_cases(test_point_id);
CREATE INDEX IF NOT EXISTS idx_test_point_test_cases_test_case ON test_point_test_cases(test_case_id);
CREATE INDEX IF NOT EXISTS idx_test_point_test_cases_status ON test_point_test_cases(status);
CREATE INDEX IF NOT EXISTS idx_test_case_execution_tasks_test_case ON test_case_execution_tasks(test_case_id);
CREATE INDEX IF NOT EXISTS idx_test_case_execution_tasks_task ON test_case_execution_tasks(execution_task_id);
CREATE INDEX IF NOT EXISTS idx_test_case_execution_tasks_run ON test_case_execution_tasks(run_id);
CREATE INDEX IF NOT EXISTS idx_test_case_execution_tasks_status ON test_case_execution_tasks(status);
CREATE INDEX IF NOT EXISTS idx_execution_task_evidence_artifacts_task ON execution_task_evidence_artifacts(execution_task_id);
CREATE INDEX IF NOT EXISTS idx_execution_task_evidence_artifacts_artifact ON execution_task_evidence_artifacts(evidence_artifact_id);
CREATE INDEX IF NOT EXISTS idx_execution_task_evidence_artifacts_status ON execution_task_evidence_artifacts(status);
CREATE INDEX IF NOT EXISTS idx_evidence_raw_findings_artifact ON evidence_raw_findings(evidence_artifact_id);
CREATE INDEX IF NOT EXISTS idx_evidence_raw_findings_raw ON evidence_raw_findings(raw_finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_raw_findings_status ON evidence_raw_findings(status);
CREATE INDEX IF NOT EXISTS idx_raw_normalized_findings_raw ON raw_normalized_findings(raw_finding_id);
CREATE INDEX IF NOT EXISTS idx_raw_normalized_findings_normalized ON raw_normalized_findings(normalized_finding_id);
CREATE INDEX IF NOT EXISTS idx_raw_normalized_findings_status ON raw_normalized_findings(status);
CREATE INDEX IF NOT EXISTS idx_normalized_finding_gate_decisions_finding ON normalized_finding_gate_decisions(normalized_finding_id);
CREATE INDEX IF NOT EXISTS idx_normalized_finding_gate_decisions_gate ON normalized_finding_gate_decisions(gate_decision_id);
CREATE INDEX IF NOT EXISTS idx_normalized_finding_gate_decisions_status ON normalized_finding_gate_decisions(status);
CREATE INDEX IF NOT EXISTS idx_gate_decision_replay_exports_gate ON gate_decision_replay_exports(gate_decision_id);
CREATE INDEX IF NOT EXISTS idx_gate_decision_replay_exports_export ON gate_decision_replay_exports(replay_export_id);
CREATE INDEX IF NOT EXISTS idx_gate_decision_replay_exports_status ON gate_decision_replay_exports(status);
