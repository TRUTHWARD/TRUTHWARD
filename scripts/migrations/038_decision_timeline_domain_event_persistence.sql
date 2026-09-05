-- P07: provide an immutable persistence-time boundary for cursor snapshots.
-- Existing rows are backfilled by PostgreSQL with the migration timestamp.

ALTER TABLE domain_events
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_domain_events_created_at
  ON domain_events(created_at);
