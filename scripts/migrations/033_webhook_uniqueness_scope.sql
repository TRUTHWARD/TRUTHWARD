-- Batch 26 TST-P1-027: keep event uniqueness scoped to issue-tracker webhooks.

DROP INDEX IF EXISTS uq_integration_events_source_type_ref;

CREATE UNIQUE INDEX uq_integration_events_source_type_ref
  ON integration_events(source, event_type, external_ref)
  WHERE external_ref IS NOT NULL AND source LIKE 'issue-tracker:%';
