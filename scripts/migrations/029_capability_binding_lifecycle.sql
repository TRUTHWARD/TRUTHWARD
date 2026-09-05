-- Capability Binding lifecycle productization closure.
-- Extends the existing capability_bindings table; does not create a parallel catalog or execution API.

ALTER TABLE capability_bindings
  ADD COLUMN IF NOT EXISTS pending_change JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE capability_bindings
  ALTER COLUMN pending_change TYPE JSONB USING pending_change::jsonb,
  ALTER COLUMN approval_refs TYPE JSONB USING approval_refs::jsonb,
  ALTER COLUMN guardrail_event_refs TYPE JSONB USING guardrail_event_refs::jsonb,
  ALTER COLUMN audit_refs TYPE JSONB USING audit_refs::jsonb;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_capability_bindings_pending_change_object') THEN
    ALTER TABLE capability_bindings
      ADD CONSTRAINT chk_capability_bindings_pending_change_object CHECK (jsonb_typeof(pending_change::jsonb) = 'object');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_capability_bindings_approval_refs_array') THEN
    ALTER TABLE capability_bindings
      ADD CONSTRAINT chk_capability_bindings_approval_refs_array CHECK (jsonb_typeof(approval_refs::jsonb) = 'array');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_capability_bindings_guardrail_event_refs_array') THEN
    ALTER TABLE capability_bindings
      ADD CONSTRAINT chk_capability_bindings_guardrail_event_refs_array CHECK (jsonb_typeof(guardrail_event_refs::jsonb) = 'array');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_capability_bindings_audit_refs_array') THEN
    ALTER TABLE capability_bindings
      ADD CONSTRAINT chk_capability_bindings_audit_refs_array CHECK (jsonb_typeof(audit_refs::jsonb) = 'array');
  END IF;
END $$;

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('capability_bindings.read', 'skills', 'Read workflow capability bindings and graph projections.', 'low', TRUE),
  ('capability_bindings.write', 'skills', 'Request capability binding lifecycle changes through backend capability, guardrail, approval, and audit controls.', 'high', TRUE),
  ('capability_bindings.admin', 'skills', 'Administer capability binding lifecycle and connector binding governance.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = EXCLUDED.is_active;
