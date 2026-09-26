-- Performance P0 read-path indexes shared by Full and Community OSS.
-- B-tree indexes can serve the descending keyset scans in reverse order.

CREATE INDEX IF NOT EXISTS idx_executions_created_id
  ON executions(created_at, id);

CREATE INDEX IF NOT EXISTS idx_execution_tasks_execution_order
  ON execution_tasks(execution_id, priority, created_at, id);

CREATE INDEX IF NOT EXISTS idx_execution_artifacts_task_created
  ON execution_artifacts(task_id, created_at);

CREATE INDEX IF NOT EXISTS idx_execution_metrics_task_created
  ON execution_metrics(task_id, created_at);

CREATE INDEX IF NOT EXISTS idx_execution_logs_task_created
  ON execution_logs(task_id, created_at);

CREATE INDEX IF NOT EXISTS idx_raw_findings_execution_created
  ON raw_findings(execution_id, created_at, id);

CREATE INDEX IF NOT EXISTS idx_findings_execution_created_id
  ON findings(execution_id, created_at, id);

CREATE INDEX IF NOT EXISTS idx_findings_execution_domain_created
  ON findings(execution_id, domain, created_at, id);

CREATE INDEX IF NOT EXISTS idx_findings_execution_severity_created
  ON findings(execution_id, severity, created_at, id);

CREATE INDEX IF NOT EXISTS idx_replay_repository_expiry_scan
  ON replay_repository_entries(retention_status, legal_hold, retention_until, id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_expiry_scan
  ON audit_logs(retention_status, legal_hold, retention_until, id);
