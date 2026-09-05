-- Phase 7 Visual Grounding incremental migration for PostgreSQL 15+.
-- Apply after the Phase 6 schema. The canonical fresh-install schema is
-- DB_SCHEMA.sql; this file is the upgrade path for existing databases.

ALTER TYPE finding_source ADD VALUE IF NOT EXISTS 'visual_grounding';
ALTER TYPE artifact_type ADD VALUE IF NOT EXISTS 'dom_snapshot';
ALTER TYPE artifact_type ADD VALUE IF NOT EXISTS 'accessibility_tree';
ALTER TYPE artifact_type ADD VALUE IF NOT EXISTS 'vision_annotation';
ALTER TYPE artifact_type ADD VALUE IF NOT EXISTS 'ocr_output';
ALTER TYPE approval_type ADD VALUE IF NOT EXISTS 'visual_action';

ALTER TABLE execution_artifacts
  ADD COLUMN IF NOT EXISTS redaction_status VARCHAR(50) NOT NULL DEFAULT 'not_required',
  ADD COLUMN IF NOT EXISTS redacted_uri TEXT,
  ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS visual_grounding_attempts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  task_id UUID REFERENCES execution_tasks(id) ON DELETE CASCADE,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  trace_span_id UUID REFERENCES trace_spans(id) ON DELETE SET NULL,
  action_id VARCHAR(150) NOT NULL,
  action_type VARCHAR(50) NOT NULL,
  semantic_action JSONB NOT NULL DEFAULT '{}'::jsonb,
  locator_strategy JSONB NOT NULL DEFAULT '{}'::jsonb,
  fallback_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
  candidate_locators JSONB NOT NULL DEFAULT '[]'::jsonb,
  chosen_locator JSONB NOT NULL DEFAULT '{}'::jsonb,
  confidence NUMERIC(5,4),
  threshold NUMERIC(5,4),
  coordinate_click_allowed BOOLEAN NOT NULL DEFAULT FALSE,
  risk_level risk_level NOT NULL DEFAULT 'medium',
  guardrail_decision guardrail_decision,
  guardrail_event_id UUID REFERENCES guardrail_events(id) ON DELETE SET NULL,
  verification_status VARCHAR(50),
  verification_result JSONB NOT NULL DEFAULT '{}'::jsonb,
  artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  redaction_status VARCHAR(50) NOT NULL DEFAULT 'redacted',
  status VARCHAR(50) NOT NULL DEFAULT 'completed',
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_visual_grounding_confidence_range CHECK (
    confidence IS NULL OR (confidence >= 0 AND confidence <= 1)
  ),
  CONSTRAINT chk_visual_grounding_threshold_range CHECK (
    threshold IS NULL OR (threshold >= 0 AND threshold <= 1)
  ),
  CONSTRAINT chk_visual_grounding_semantic_action_object CHECK (jsonb_typeof(semantic_action) = 'object'),
  CONSTRAINT chk_visual_grounding_candidates_array CHECK (jsonb_typeof(candidate_locators) = 'array'),
  CONSTRAINT chk_visual_grounding_artifact_refs_array CHECK (jsonb_typeof(artifact_refs) = 'array')
);

COMMENT ON TABLE visual_grounding_attempts IS 'Phase 7 execution evidence for visual target resolution; not a business decision table and not a Gate input by itself.';

CREATE INDEX IF NOT EXISTS idx_visual_grounding_attempts_execution_id ON visual_grounding_attempts(execution_id);
CREATE INDEX IF NOT EXISTS idx_visual_grounding_attempts_task_id ON visual_grounding_attempts(task_id);
CREATE INDEX IF NOT EXISTS idx_visual_grounding_attempts_action_id ON visual_grounding_attempts(action_id);
CREATE INDEX IF NOT EXISTS idx_visual_grounding_attempts_trace_id ON visual_grounding_attempts(trace_id);
CREATE INDEX IF NOT EXISTS idx_visual_grounding_attempts_guardrail_event_id ON visual_grounding_attempts(guardrail_event_id);
CREATE INDEX IF NOT EXISTS idx_visual_grounding_attempts_created_at ON visual_grounding_attempts(created_at DESC);

CREATE TABLE IF NOT EXISTS verification_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  task_id UUID REFERENCES execution_tasks(id) ON DELETE CASCADE,
  visual_attempt_id UUID REFERENCES visual_grounding_attempts(id) ON DELETE SET NULL,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  verification_type VARCHAR(100) NOT NULL,
  status VARCHAR(50) NOT NULL,
  confidence NUMERIC(5,4),
  evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
  artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  result_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  normalized_finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_verification_results_confidence_range CHECK (
    confidence IS NULL OR (confidence >= 0 AND confidence <= 1)
  ),
  CONSTRAINT chk_verification_results_evidence_array CHECK (jsonb_typeof(evidence) = 'array'),
  CONSTRAINT chk_verification_results_artifact_refs_array CHECK (jsonb_typeof(artifact_refs) = 'array')
);

COMMENT ON TABLE verification_results IS 'Execution verification outcomes, including Phase 7 visual action verification; failures must normalize into findings or execution failures.';

CREATE INDEX IF NOT EXISTS idx_verification_results_execution_id ON verification_results(execution_id);
CREATE INDEX IF NOT EXISTS idx_verification_results_task_id ON verification_results(task_id);
CREATE INDEX IF NOT EXISTS idx_verification_results_visual_attempt_id ON verification_results(visual_attempt_id);
CREATE INDEX IF NOT EXISTS idx_verification_results_trace_id ON verification_results(trace_id);
CREATE INDEX IF NOT EXISTS idx_verification_results_finding_id ON verification_results(normalized_finding_id);
CREATE INDEX IF NOT EXISTS idx_verification_results_created_at ON verification_results(created_at DESC);
