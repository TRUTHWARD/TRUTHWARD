-- P22 PR Admission orchestration in the existing admission_runs / execution lifecycle.
-- Observe and Shadow are non-authoritative; Enforce and CI/SCM writeback remain absent.

ALTER TABLE admission_runs ADD COLUMN IF NOT EXISTS repository_ref VARCHAR(1000);
ALTER TABLE admission_runs ADD COLUMN IF NOT EXISTS pull_request_number INTEGER;
ALTER TABLE admission_runs ADD COLUMN IF NOT EXISTS base_sha VARCHAR(64);
ALTER TABLE admission_runs ADD COLUMN IF NOT EXISTS admission_mode VARCHAR(16) NOT NULL DEFAULT 'observe';
ALTER TABLE admission_runs ADD COLUMN IF NOT EXISTS workflow_version VARCHAR(120) NOT NULL DEFAULT 'p21.scan-smoke.v1';
ALTER TABLE admission_runs ADD COLUMN IF NOT EXISTS non_authoritative BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE admission_runs ADD COLUMN IF NOT EXISTS stage_snapshot JSONB NOT NULL DEFAULT '[
  {"schemaVersion":"phase8.admission-stage.v1","sequence":1,"lifecycleStage":"PREPARE","status":"unavailable","reasonCode":"ADMISSION_LEGACY_STAGE_FACT_UNAVAILABLE","startedAt":null,"endedAt":null,"traceRefs":[],"evidenceRefs":[],"summary":{},"nonAuthoritative":true},
  {"schemaVersion":"phase8.admission-stage.v1","sequence":2,"lifecycleStage":"EXECUTE","status":"unavailable","reasonCode":"ADMISSION_LEGACY_STAGE_FACT_UNAVAILABLE","startedAt":null,"endedAt":null,"traceRefs":[],"evidenceRefs":[],"summary":{},"nonAuthoritative":true},
  {"schemaVersion":"phase8.admission-stage.v1","sequence":3,"lifecycleStage":"OBSERVE","status":"unavailable","reasonCode":"ADMISSION_LEGACY_STAGE_FACT_UNAVAILABLE","startedAt":null,"endedAt":null,"traceRefs":[],"evidenceRefs":[],"summary":{},"nonAuthoritative":true},
  {"schemaVersion":"phase8.admission-stage.v1","sequence":4,"lifecycleStage":"ANALYZE","status":"unavailable","reasonCode":"ADMISSION_LEGACY_STAGE_FACT_UNAVAILABLE","startedAt":null,"endedAt":null,"traceRefs":[],"evidenceRefs":[],"summary":{},"nonAuthoritative":true},
  {"schemaVersion":"phase8.admission-stage.v1","sequence":5,"lifecycleStage":"NORMALIZE","status":"unavailable","reasonCode":"ADMISSION_LEGACY_STAGE_FACT_UNAVAILABLE","startedAt":null,"endedAt":null,"traceRefs":[],"evidenceRefs":[],"summary":{},"nonAuthoritative":true},
  {"schemaVersion":"phase8.admission-stage.v1","sequence":6,"lifecycleStage":"GATE","status":"skipped","reasonCode":"ADMISSION_OBSERVE_GATE_NOT_EVALUATED","startedAt":null,"endedAt":null,"traceRefs":[],"evidenceRefs":[],"summary":{},"nonAuthoritative":true}
]'::jsonb;
ALTER TABLE admission_runs ADD COLUMN IF NOT EXISTS result_snapshot_hash VARCHAR(80);
ALTER TABLE admission_runs ADD COLUMN IF NOT EXISTS shadow_gate_snapshot JSONB;
ALTER TABLE admission_runs ADD COLUMN IF NOT EXISTS retry_snapshot JSONB NOT NULL DEFAULT '{"attemptCount":1,"state":"not_requested"}'::jsonb;
ALTER TABLE admission_runs ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 1;

UPDATE admission_runs AS admission
SET repository_ref = context.repository_ref,
    pull_request_number = context.pull_request_number,
    base_sha = version.base_sha
FROM scm_pr_context_versions AS version
JOIN scm_pr_contexts AS context ON context.id = version.context_id
WHERE version.id = admission.pr_context_version_id;

-- Preserve legacy P21 rows as p21.scan-smoke.v1, while new direct inserts use P22.
ALTER TABLE admission_runs ALTER COLUMN workflow_version SET DEFAULT 'p22.observe-shadow.v1';
ALTER TABLE admission_runs ALTER COLUMN stage_snapshot SET DEFAULT '[]'::jsonb;

ALTER TABLE admission_runs ALTER COLUMN repository_ref SET NOT NULL;
ALTER TABLE admission_runs ALTER COLUMN pull_request_number SET NOT NULL;
ALTER TABLE admission_runs ALTER COLUMN base_sha SET NOT NULL;
ALTER TABLE admission_runs DROP CONSTRAINT IF EXISTS uq_admission_runs_orchestration;
ALTER TABLE admission_runs
  ADD CONSTRAINT uq_admission_runs_orchestration UNIQUE (
    tenant_id, workspace_id, project_id, repository_ref, pull_request_number,
    source_head_sha, admission_mode, workflow_version
  );
ALTER TABLE admission_runs DROP CONSTRAINT IF EXISTS chk_admission_runs_mode;
ALTER TABLE admission_runs
  ADD CONSTRAINT chk_admission_runs_mode CHECK (admission_mode IN ('observe', 'shadow'));
ALTER TABLE admission_runs DROP CONSTRAINT IF EXISTS chk_admission_runs_non_authoritative;
ALTER TABLE admission_runs
  ADD CONSTRAINT chk_admission_runs_non_authoritative CHECK (non_authoritative = TRUE);
CREATE INDEX IF NOT EXISTS idx_admission_runs_pr_head_mode
  ON admission_runs(project_id, repository_ref, pull_request_number, source_head_sha, admission_mode, created_at DESC);

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('admission.read', 'integrations', 'Read PR Admission Observe/Shadow runs, timelines, evidence, reviews, and non-authoritative results.', 'low', TRUE),
  ('admission.execute', 'integrations', 'Start the fixed service-managed PR Admission workflow.', 'high', TRUE),
  ('admission.review', 'integrations', 'Request and decide governed human review of a non-authoritative Admission result.', 'high', TRUE),
  ('admission.retry', 'integrations', 'Retry Admission execution through the existing approval-backed retry workflow.', 'high', TRUE),
  ('admission.mode.manage', 'integrations', 'Select Observe or Shadow mode for a new Admission run.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = TRUE;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'admission.read', TRUE),
  ('pro', 'admission.read', TRUE),
  ('enterprise', 'admission.read', TRUE),
  ('enterprise', 'admission.execute', TRUE),
  ('enterprise', 'admission.review', TRUE),
  ('enterprise', 'admission.retry', TRUE),
  ('enterprise', 'admission.mode.manage', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;

COMMENT ON TABLE admission_runs IS
  'P22 Service-owned PR Admission Observe/Shadow orchestration over the existing lifecycle. Results are always non-authoritative; Enforce and CI writeback are pending P23.';
