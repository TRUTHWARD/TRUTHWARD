-- Bounded Community Trace-to-Candidate observation.
-- This grants only lifecycle-owned, non-authoritative materialization; it does
-- not grant the generic candidate command, promotion, model, Gate, Memory, CI,
-- Approval, execution, retry, or external-write capabilities.

INSERT INTO capability_registry (
  capability_key,
  category,
  description,
  risk_level,
  is_active
)
VALUES (
  'graph.candidate.observe',
  'graph',
  'Materialize bounded non-authoritative Candidate Path observations from persisted Community executions.',
  'medium',
  TRUE
)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = TRUE;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES ('community', 'graph.candidate.observe', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;
