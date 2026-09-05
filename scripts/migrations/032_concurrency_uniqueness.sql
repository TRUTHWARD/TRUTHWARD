-- Batch 26 TST-P1-027: database backstops for service-owned race handling.

CREATE UNIQUE INDEX IF NOT EXISTS uq_approvals_pending_resource
  ON approvals(type, resource_type, resource_id)
  WHERE status = 'pending';

CREATE UNIQUE INDEX IF NOT EXISTS uq_integration_events_source_type_ref
  ON integration_events(source, event_type, external_ref)
  WHERE external_ref IS NOT NULL;
