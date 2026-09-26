-- Bounded Community coverage analysis materialization.
-- This capability creates only immutable/non-authoritative analysis snapshots;
-- it does not grant generic Change/Graph/Impact/Replay mutations.

INSERT INTO capability_registry (
  capability_key,
  category,
  description,
  risk_level,
  is_active
)
VALUES (
  'coverage.materialize',
  'coverage',
  'Materialize bounded non-authoritative Community coverage analysis snapshots.',
  'medium',
  TRUE
)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = TRUE;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES ('community', 'coverage.materialize', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;
