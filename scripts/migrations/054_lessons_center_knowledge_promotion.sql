-- P24 Service-owned Lessons Center and controlled Knowledge Promotion.
-- Candidates and feedback never write Memory directly; promotion remains an explicit governed action.

CREATE TABLE IF NOT EXISTS lesson_candidates (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  lesson_type VARCHAR(64) NOT NULL,
  source_event_type VARCHAR(40) NOT NULL,
  source_event_id VARCHAR(255) NOT NULL,
  source_version VARCHAR(255),
  source_event_hash VARCHAR(80) NOT NULL,
  scope_type VARCHAR(32) NOT NULL,
  scope_id VARCHAR(1000) NOT NULL,
  summary TEXT NOT NULL,
  observations JSONB NOT NULL,
  evidence_refs JSONB NOT NULL,
  raw_refs JSONB NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  frequency INTEGER NOT NULL,
  impact VARCHAR(16) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'candidate',
  dedupe_key VARCHAR(255) NOT NULL,
  cluster_key VARCHAR(80) NOT NULL,
  expires_at TIMESTAMPTZ,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_lesson_candidate_source_taxonomy_scope_dedupe UNIQUE (
    tenant_id, workspace_id, project_id, source_event_type, source_event_id,
    lesson_type, scope_type, scope_id, dedupe_key
  ),
  CONSTRAINT chk_lesson_candidates_type CHECK (lesson_type IN (
    'false_positive', 'false_negative', 'repeated_failure', 'flaky',
    'environment_issue', 'test_issue', 'human_override', 'graph_correction',
    'gate_disagreement', 'admission_outcome', 'auto_promotion_conflict',
    'auto_promotion_rollback', 'promotion_policy_too_strict',
    'promotion_policy_too_loose'
  )),
  CONSTRAINT chk_lesson_candidates_source_type CHECK (source_event_type IN (
    'finding', 'admission_run', 'gate_decision', 'graph_correction',
    'graph_promotion', 'domain_event'
  )),
  CONSTRAINT chk_lesson_candidates_scope_type CHECK (scope_type IN ('project', 'environment', 'repository')),
  CONSTRAINT chk_lesson_candidates_status CHECK (status IN ('candidate', 'under_review', 'accepted', 'rejected', 'promoted', 'expired')),
  CONSTRAINT chk_lesson_candidates_impact CHECK (impact IN ('low', 'medium', 'high', 'critical')),
  CONSTRAINT chk_lesson_candidates_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_lesson_candidates_frequency CHECK (frequency > 0),
  CONSTRAINT chk_lesson_candidates_lock CHECK (lock_version > 0)
);
CREATE INDEX IF NOT EXISTS idx_lesson_candidates_scope_status
  ON lesson_candidates(tenant_id, workspace_id, project_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_lesson_candidates_cluster
  ON lesson_candidates(tenant_id, workspace_id, project_id, cluster_key);
CREATE INDEX IF NOT EXISTS idx_lesson_candidates_expiry ON lesson_candidates(expires_at);
DROP TRIGGER IF EXISTS trg_lesson_candidates_updated_at ON lesson_candidates;
CREATE TRIGGER trg_lesson_candidates_updated_at
BEFORE UPDATE ON lesson_candidates
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS lesson_evidence (
  id UUID PRIMARY KEY,
  candidate_id UUID NOT NULL REFERENCES lesson_candidates(id) ON DELETE CASCADE,
  evidence_ref JSONB NOT NULL,
  raw_ref JSONB NOT NULL,
  content_hash VARCHAR(80) NOT NULL,
  retention_state VARCHAR(24) NOT NULL DEFAULT 'active',
  classification VARCHAR(24) NOT NULL DEFAULT 'internal',
  redaction_status VARCHAR(24) NOT NULL DEFAULT 'not_required',
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_lesson_evidence_candidate_hash UNIQUE (candidate_id, content_hash),
  CONSTRAINT chk_lesson_evidence_retention CHECK (retention_state IN ('active', 'missing', 'purged', 'expired')),
  CONSTRAINT chk_lesson_evidence_classification CHECK (classification IN ('public', 'internal', 'confidential', 'restricted')),
  CONSTRAINT chk_lesson_evidence_redaction CHECK (redaction_status IN ('not_required', 'redacted', 'unavailable'))
);
CREATE INDEX IF NOT EXISTS idx_lesson_evidence_candidate ON lesson_evidence(candidate_id, captured_at);

CREATE TABLE IF NOT EXISTS lesson_feedback (
  id UUID PRIMARY KEY,
  candidate_id UUID NOT NULL REFERENCES lesson_candidates(id) ON DELETE CASCADE,
  feedback_type VARCHAR(24) NOT NULL,
  reason TEXT NOT NULL,
  observations JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_lesson_feedback_actor_idempotency UNIQUE (candidate_id, created_by, idempotency_key),
  CONSTRAINT chk_lesson_feedback_type CHECK (feedback_type IN ('confirm', 'refute', 'supplement', 'uncertain'))
);
CREATE INDEX IF NOT EXISTS idx_lesson_feedback_candidate ON lesson_feedback(candidate_id, created_at);

CREATE TABLE IF NOT EXISTS lesson_reviews (
  id UUID PRIMARY KEY,
  candidate_id UUID NOT NULL REFERENCES lesson_candidates(id) ON DELETE CASCADE,
  decision VARCHAR(24) NOT NULL,
  confirmed_fact BOOLEAN NOT NULL,
  reason TEXT NOT NULL,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  candidate_lock_version INTEGER NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  reviewed_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  reviewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_lesson_reviews_candidate_idempotency UNIQUE (candidate_id, idempotency_key),
  CONSTRAINT chk_lesson_reviews_decision CHECK (decision IN ('accepted', 'rejected', 'needs_evidence')),
  CONSTRAINT chk_lesson_reviews_confirmed_fact CHECK (
    (decision = 'accepted' AND confirmed_fact = TRUE) OR
    (decision <> 'accepted' AND confirmed_fact = FALSE)
  )
);
CREATE INDEX IF NOT EXISTS idx_lesson_reviews_candidate ON lesson_reviews(candidate_id, reviewed_at);

CREATE TABLE IF NOT EXISTS lesson_promotion_results (
  id UUID PRIMARY KEY,
  candidate_id UUID NOT NULL REFERENCES lesson_candidates(id) ON DELETE RESTRICT,
  status VARCHAR(32) NOT NULL,
  memory_type VARCHAR(24) NOT NULL,
  memory_ref JSONB NOT NULL DEFAULT '{}'::jsonb,
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  approval_state VARCHAR(24) NOT NULL,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL,
  raw_refs JSONB NOT NULL,
  policy_snapshot JSONB NOT NULL,
  projection_state VARCHAR(32) NOT NULL DEFAULT 'skipped',
  reason_code VARCHAR(160),
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_lesson_promotion_candidate_idempotency UNIQUE (candidate_id, idempotency_key),
  CONSTRAINT chk_lesson_promotion_results_status CHECK (status IN ('approval_pending', 'promoted', 'rejected', 'failed', 'partial')),
  CONSTRAINT chk_lesson_promotion_results_memory_type CHECK (memory_type IN ('episodic', 'semantic', 'procedural')),
  CONSTRAINT chk_lesson_promotion_results_approval CHECK (approval_state IN ('pending', 'satisfied', 'not_required', 'rejected')),
  CONSTRAINT chk_lesson_promotion_results_projection CHECK (projection_state IN ('skipped', 'projected', 'projection_failed'))
);
CREATE INDEX IF NOT EXISTS idx_lesson_promotion_candidate ON lesson_promotion_results(candidate_id, created_at);
CREATE INDEX IF NOT EXISTS idx_lesson_promotion_status ON lesson_promotion_results(status, created_at);
DROP TRIGGER IF EXISTS trg_lesson_promotion_results_updated_at ON lesson_promotion_results;
CREATE TRIGGER trg_lesson_promotion_results_updated_at
BEFORE UPDATE ON lesson_promotion_results
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('lesson.read', 'knowledge', 'Read project-scoped Lesson Candidate and governed promotion projections.', 'low', TRUE),
  ('lesson.feedback', 'knowledge', 'Submit project-scoped structured feedback with evidence.', 'high', TRUE),
  ('lesson.review', 'knowledge', 'Review evidence-backed Lesson Candidates.', 'high', TRUE),
  ('lesson.promote', 'knowledge', 'Promote an accepted confirmed Lesson through controlled Knowledge governance.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = TRUE;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'lesson.read', TRUE),
  ('pro', 'lesson.read', TRUE),
  ('enterprise', 'lesson.read', TRUE),
  ('enterprise', 'lesson.feedback', TRUE),
  ('enterprise', 'lesson.review', TRUE),
  ('enterprise', 'lesson.promote', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;

COMMENT ON TABLE lesson_candidates IS
  'P24 project-scoped evidence-backed Lesson Candidates. Candidate state never implies Knowledge or Memory promotion.';
COMMENT ON TABLE lesson_promotion_results IS
  'P24 controlled Knowledge Promotion results. Only explicit reviewed and guarded promotion may project to Memory.';
