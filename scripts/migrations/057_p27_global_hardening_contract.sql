-- P27 global security/operations hardening contract.
-- No business table or lifecycle stage is added. The common Service builder
-- enforces the snapshot allowlist before every new persistence operation.

COMMENT ON COLUMN requirement_intake_drafts.connector_binding_snapshot IS
  'P27 allowlist-only Connector Binding safe projection for connector source replay; excludes Secret, resolvable credential refs, raw config, and unknown metadata/extensions.';

COMMENT ON COLUMN requirement_intake_previews.connector_binding_snapshot IS
  'P27 allowlist-only Connector Binding safe projection copied from Draft for replay.';

COMMENT ON COLUMN skill_invocations.connector_binding_snapshot IS
  'P27 allowlist-only Connector Binding safe projection for replay; excludes Secret, resolvable secretRef/credentialRef, raw config, and unknown metadata/extensions.';

COMMENT ON TABLE skill_connector_bindings IS
  'Legacy authoritative Connector runtime locator boundary. Values must never be serialized into DB snapshots, Trace, Audit, Replay, Storage, API responses, logs, or frontend state; downstream consumers receive only the P27 Safe Projection.';
