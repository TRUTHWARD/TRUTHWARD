-- Batch 5 exploratory testing workbench.
-- Exploratory Session is a Service-owned business workflow, not a Skill.
-- Bug candidates must normalize through raw_findings -> findings before Gate.

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('exploratory_sessions.read', 'exploratory', 'Read exploratory testing sessions, candidates, reports, and refs.', 'low', TRUE),
  ('exploratory_sessions.manage', 'exploratory', 'Create and update exploratory testing sessions, notes, evidence refs, and bug candidates.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = EXCLUDED.is_active;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'exploratory_sessions.read', TRUE),
  ('pro', 'exploratory_sessions.read', TRUE),
  ('enterprise', 'exploratory_sessions.read', TRUE),
  ('enterprise', 'exploratory_sessions.manage', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET
  enabled = EXCLUDED.enabled;

INSERT INTO rbac_role_capabilities (role_name, capability_key, effect)
VALUES
  ('user', 'exploratory_sessions.read', 'allow'),
  ('admin', 'exploratory_sessions.read', 'allow'),
  ('admin', 'exploratory_sessions.manage', 'allow'),
  ('system', 'exploratory_sessions.read', 'allow'),
  ('system', 'exploratory_sessions.manage', 'allow')
ON CONFLICT (role_name, capability_key) DO UPDATE SET
  effect = EXCLUDED.effect;

CREATE TABLE IF NOT EXISTS exploratory_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  environment_id UUID NOT NULL REFERENCES project_environments(id) ON DELETE RESTRICT,
  backing_plan_id UUID NOT NULL REFERENCES test_plans(id) ON DELETE RESTRICT,
  backing_execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE RESTRICT,
  charter TEXT NOT NULL,
  scope JSONB NOT NULL DEFAULT '[]'::jsonb,
  timebox_minutes INTEGER NOT NULL,
  tester_id UUID REFERENCES users(id) ON DELETE SET NULL,
  tester_name VARCHAR(255) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ended_at TIMESTAMPTZ,
  debrief JSONB NOT NULL DEFAULT '{}'::jsonb,
  report_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_exploratory_sessions_status CHECK (status IN ('active', 'completed', 'cancelled')),
  CONSTRAINT chk_exploratory_sessions_timebox CHECK (timebox_minutes > 0),
  CONSTRAINT chk_exploratory_sessions_scope_array CHECK (jsonb_typeof(scope) = 'array'),
  CONSTRAINT chk_exploratory_sessions_replay_refs_array CHECK (jsonb_typeof(replay_refs) = 'array')
);

COMMENT ON TABLE exploratory_sessions IS 'Service-owned exploratory testing sessions. Backing execution anchors evidence, normalized Findings, trace, and replay refs; this is not a Skill workflow.';

CREATE INDEX IF NOT EXISTS idx_exploratory_sessions_project ON exploratory_sessions(project_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_sessions_environment ON exploratory_sessions(environment_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_sessions_execution ON exploratory_sessions(backing_execution_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_sessions_status ON exploratory_sessions(status);
CREATE INDEX IF NOT EXISTS idx_exploratory_sessions_created_at ON exploratory_sessions(created_at DESC);

DROP TRIGGER IF EXISTS trg_exploratory_sessions_updated_at ON exploratory_sessions;
CREATE TRIGGER trg_exploratory_sessions_updated_at
BEFORE UPDATE ON exploratory_sessions
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS exploratory_session_notes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id UUID NOT NULL REFERENCES exploratory_sessions(id) ON DELETE CASCADE,
  note_type VARCHAR(32) NOT NULL,
  content TEXT NOT NULL,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_exploratory_session_notes_type CHECK (note_type IN ('note', 'observation', 'risk', 'question')),
  CONSTRAINT chk_exploratory_session_notes_evidence_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
  CONSTRAINT chk_exploratory_session_notes_replay_array CHECK (jsonb_typeof(replay_refs) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_exploratory_session_notes_session ON exploratory_session_notes(session_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_session_notes_type ON exploratory_session_notes(note_type);
CREATE INDEX IF NOT EXISTS idx_exploratory_session_notes_created_at ON exploratory_session_notes(created_at DESC);

CREATE TABLE IF NOT EXISTS exploratory_bug_candidates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id UUID NOT NULL REFERENCES exploratory_sessions(id) ON DELETE CASCADE,
  raw_finding_id UUID REFERENCES raw_findings(id) ON DELETE SET NULL,
  normalized_finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
  title VARCHAR(255) NOT NULL,
  summary TEXT NOT NULL,
  severity VARCHAR(50) NOT NULL,
  category VARCHAR(100) NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  location JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  status VARCHAR(32) NOT NULL DEFAULT 'candidate',
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_exploratory_bug_candidates_status CHECK (status IN ('candidate', 'normalized', 'rejected')),
  CONSTRAINT chk_exploratory_bug_candidates_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_exploratory_bug_candidates_location_object CHECK (jsonb_typeof(location) = 'object'),
  CONSTRAINT chk_exploratory_bug_candidates_evidence_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
  CONSTRAINT chk_exploratory_bug_candidates_replay_array CHECK (jsonb_typeof(replay_refs) = 'array')
);

COMMENT ON TABLE exploratory_bug_candidates IS 'Exploratory bug candidates. Candidates become canonical Findings only after NORMALIZE creates raw_findings.normalized_finding_id.';

CREATE INDEX IF NOT EXISTS idx_exploratory_bug_candidates_session ON exploratory_bug_candidates(session_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_bug_candidates_raw ON exploratory_bug_candidates(raw_finding_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_bug_candidates_normalized ON exploratory_bug_candidates(normalized_finding_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_bug_candidates_status ON exploratory_bug_candidates(status);

DROP TRIGGER IF EXISTS trg_exploratory_bug_candidates_updated_at ON exploratory_bug_candidates;
CREATE TRIGGER trg_exploratory_bug_candidates_updated_at
BEFORE UPDATE ON exploratory_bug_candidates
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS exploratory_evidence_refs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id UUID NOT NULL REFERENCES exploratory_sessions(id) ON DELETE CASCADE,
  note_id UUID REFERENCES exploratory_session_notes(id) ON DELETE SET NULL,
  candidate_id UUID REFERENCES exploratory_bug_candidates(id) ON DELETE SET NULL,
  artifact_id UUID REFERENCES execution_artifacts(id) ON DELETE SET NULL,
  evidence_type VARCHAR(80) NOT NULL,
  ref TEXT NOT NULL,
  summary TEXT,
  redaction_status VARCHAR(50) NOT NULL DEFAULT 'redacted',
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_exploratory_evidence_refs_redaction CHECK (redaction_status IN ('not_required', 'redacted', 'pending')),
  CONSTRAINT chk_exploratory_evidence_refs_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

COMMENT ON TABLE exploratory_evidence_refs IS 'Reference-only evidence refs for exploratory testing. File upload is intentionally not implemented in this batch.';

CREATE INDEX IF NOT EXISTS idx_exploratory_evidence_refs_session ON exploratory_evidence_refs(session_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_evidence_refs_note ON exploratory_evidence_refs(note_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_evidence_refs_candidate ON exploratory_evidence_refs(candidate_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_evidence_refs_artifact ON exploratory_evidence_refs(artifact_id);
