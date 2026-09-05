-- Align the protected impact-analysis mutation with the authoritative
-- authorization matrix. This changes capability metadata only; it does not
-- execute analysis, create Approval decisions, or alter frozen Impact Results.

INSERT INTO capability_registry (
  capability_key,
  category,
  description,
  risk_level,
  is_active
)
VALUES (
  'impact.analyze',
  'impact',
  'Run bounded evidence-backed impact analysis from frozen Change Set and CEG inputs.',
  'high',
  TRUE
)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = EXCLUDED.is_active;
