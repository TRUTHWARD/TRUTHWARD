-- Keep the Enterprise capability ceiling aligned with the runtime registry
-- after the two bounded Community analysis capabilities were introduced.
-- These grants do not add routes or broaden either capability's semantics.

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('enterprise', 'coverage.materialize', TRUE),
  ('enterprise', 'graph.candidate.observe', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;
