-- Persist a client intent independently of the long-running requirement pipeline.
ALTER TABLE orchestration_runs
  ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS idempotency_key VARCHAR(120),
  ADD COLUMN IF NOT EXISTS request_hash VARCHAR(128);

CREATE UNIQUE INDEX IF NOT EXISTS uq_orchestration_runs_actor_idempotency
  ON orchestration_runs(created_by, idempotency_key);
