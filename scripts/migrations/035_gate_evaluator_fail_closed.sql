-- P03: Service-owned Policy-driven Gate Evaluator decision metadata.
-- Forward-only: legacy Gate rows remain readable through defaults/nullability.

ALTER TABLE gate_results
  ADD COLUMN IF NOT EXISTS policy_version_id VARCHAR(255),
  ADD COLUMN IF NOT EXISTS policy_version_hash VARCHAR(80),
  ADD COLUMN IF NOT EXISTS policy_binding_ref VARCHAR(500),
  ADD COLUMN IF NOT EXISTS reason_codes JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS matched_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS completeness JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS confidence NUMERIC(5,4) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS input_fingerprint VARCHAR(80),
  ADD COLUMN IF NOT EXISTS decision_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS decision_snapshot_hash VARCHAR(80),
  ADD COLUMN IF NOT EXISTS evaluator_version VARCHAR(80) NOT NULL DEFAULT 'legacy.gate-evaluator.v1';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_gate_reason_codes_is_array') THEN
    ALTER TABLE gate_results
      ADD CONSTRAINT chk_gate_reason_codes_is_array CHECK (jsonb_typeof(reason_codes) = 'array');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_gate_matched_rules_is_array') THEN
    ALTER TABLE gate_results
      ADD CONSTRAINT chk_gate_matched_rules_is_array CHECK (jsonb_typeof(matched_rules) = 'array');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_gate_completeness_is_object') THEN
    ALTER TABLE gate_results
      ADD CONSTRAINT chk_gate_completeness_is_object CHECK (jsonb_typeof(completeness) = 'object');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_gate_decision_snapshot_is_object') THEN
    ALTER TABLE gate_results
      ADD CONSTRAINT chk_gate_decision_snapshot_is_object CHECK (jsonb_typeof(decision_snapshot) = 'object');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_gate_confidence_range') THEN
    ALTER TABLE gate_results
      ADD CONSTRAINT chk_gate_confidence_range CHECK (confidence >= 0 AND confidence <= 1);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_gate_results_policy_version
  ON gate_results(policy_version_id);
CREATE INDEX IF NOT EXISTS idx_gate_results_input_fingerprint
  ON gate_results(input_fingerprint);
CREATE INDEX IF NOT EXISTS idx_gate_results_decision_snapshot_hash
  ON gate_results(decision_snapshot_hash);

COMMENT ON COLUMN gate_results.decision_snapshot IS
  'Frozen phase8.gate-decision-snapshot.v1 produced by the sole Service-owned GateEvaluator.';
COMMENT ON COLUMN gate_results.input_fingerprint IS
  'Canonical material Gate input fingerprint; request/trace correlation is excluded.';
