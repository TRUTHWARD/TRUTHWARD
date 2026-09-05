-- Phase 8 Enterprise Audit Retention governance metadata.
-- Adds Service-owned retention state to audit_logs without changing the
-- read-only audit-log projection contract.

ALTER TABLE audit_logs
  ADD COLUMN IF NOT EXISTS retention_policy VARCHAR(80) NOT NULL DEFAULT 'default-audit-log-retention',
  ADD COLUMN IF NOT EXISTS retention_until TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS legal_hold BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS purge_eligible_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS retention_status VARCHAR(40) NOT NULL DEFAULT 'active';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_audit_logs_retention_status'
  ) THEN
    ALTER TABLE audit_logs
      ADD CONSTRAINT chk_audit_logs_retention_status CHECK (
        retention_status IN ('active', 'archived', 'purge_eligible', 'purged', 'legal_hold')
      );
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_audit_logs_retention_status ON audit_logs(retention_status);
