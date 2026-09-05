-- Batch 18 TST-P1-017: make expired approvals and CCG proposals explicit.

ALTER TYPE approval_status ADD VALUE IF NOT EXISTS 'expired';

ALTER TABLE correction_proposals
  DROP CONSTRAINT IF EXISTS chk_correction_proposals_status;

ALTER TABLE correction_proposals
  ADD CONSTRAINT chk_correction_proposals_status CHECK (
    status IN ('draft', 'pending_approval', 'approved', 'rejected', 'cancelled', 'expired')
  );
