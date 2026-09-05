-- Normalize databases created by earlier SQLAlchemy auto-create baselines.
-- Legacy enum types used class-style names and enum member names, for example:
--   userstatus.ACTIVE
-- Phase 8 uses schema-level canonical names and enum values, for example:
--   user_status.active

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'provider_type') THEN
    CREATE TYPE provider_type AS ENUM ('openai', 'anthropic', 'ollama', 'vllm', 'openai_compatible', 'custom');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'model_role') THEN
    CREATE TYPE model_role AS ENUM ('PRIMARY', 'CHALLENGER', 'JUDGE', 'LOCAL_FALLBACK');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'health_status') THEN
    CREATE TYPE health_status AS ENUM ('healthy', 'degraded', 'unavailable', 'unknown');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'risk_level') THEN
    CREATE TYPE risk_level AS ENUM ('low', 'medium', 'high');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'task_status') THEN
    CREATE TYPE task_status AS ENUM ('queued', 'running', 'analyzing', 'completed', 'failed', 'cancelled');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'execution_stage') THEN
    CREATE TYPE execution_stage AS ENUM ('PREPARE', 'EXECUTE', 'OBSERVE', 'ANALYZE', 'NORMALIZE', 'GATE');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'plan_status') THEN
    CREATE TYPE plan_status AS ENUM ('draft', 'ready', 'running', 'completed', 'failed', 'cancelled');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'test_domain') THEN
    CREATE TYPE test_domain AS ENUM ('functional', 'performance', 'security');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'finding_severity') THEN
    CREATE TYPE finding_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'finding_status') THEN
    CREATE TYPE finding_status AS ENUM ('open', 'ignored', 'false_positive', 'accepted_risk', 'resolved');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'finding_source') THEN
    CREATE TYPE finding_source AS ENUM ('playwright', 'visual_grounding', 'k6', 'zap', 'semgrep', 'nuclei', 'system', 'agent', 'manual', 'custom');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'finding_category') THEN
    CREATE TYPE finding_category AS ENUM (
      'functional_ui', 'functional_api', 'performance_latency', 'performance_capacity',
      'dast', 'sast', 'template_scan', 'network', 'reliability', 'configuration',
      'authorization', 'authentication', 'other'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'memory_type') THEN
    CREATE TYPE memory_type AS ENUM ('episodic', 'semantic', 'procedural');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'memory_scope') THEN
    CREATE TYPE memory_scope AS ENUM ('session', 'project', 'org');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'artifact_type') THEN
    CREATE TYPE artifact_type AS ENUM (
      'trace', 'screenshot', 'dom_snapshot', 'accessibility_tree', 'vision_annotation',
      'ocr_output', 'video', 'log', 'report', 'har', 'console', 'network', 'patch', 'other'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'approval_status') THEN
    CREATE TYPE approval_status AS ENUM ('pending', 'approved', 'rejected', 'cancelled');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'approval_type') THEN
    CREATE TYPE approval_type AS ENUM ('healing_patch', 'gate_override', 'accepted_risk', 'manual_rerun', 'visual_action', 'other');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'job_status') THEN
    CREATE TYPE job_status AS ENUM ('queued', 'running', 'completed', 'failed', 'cancelled');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'agent_run_status') THEN
    CREATE TYPE agent_run_status AS ENUM ('queued', 'running', 'completed', 'failed', 'cancelled');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'triage_category') THEN
    CREATE TYPE triage_category AS ENUM ('bug', 'flaky', 'env', 'test_issue', 'performance_issue', 'security_issue', 'unknown');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'gate_result') THEN
    CREATE TYPE gate_result AS ENUM ('pass', 'warn', 'fail', 'blocked');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_status') THEN
    CREATE TYPE user_status AS ENUM ('active', 'inactive', 'disabled');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'source_type') THEN
    CREATE TYPE source_type AS ENUM ('pr', 'manual', 'schedule', 'api');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'integration_event_status') THEN
    CREATE TYPE integration_event_status AS ENUM ('received', 'processed', 'failed');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'guardrail_decision') THEN
    CREATE TYPE guardrail_decision AS ENUM ('allow', 'warn', 'block');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'guardrail_scope') THEN
    CREATE TYPE guardrail_scope AS ENUM ('request', 'routing', 'agent_output', 'memory_write', 'action', 'tool', 'skill', 'connector', 'system');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'guardrail_policy_status') THEN
    CREATE TYPE guardrail_policy_status AS ENUM ('draft', 'active', 'disabled', 'archived');
  END IF;
END $$;

CREATE OR REPLACE FUNCTION phase8_convert_enum_column(
  p_table TEXT,
  p_column TEXT,
  p_target_type TEXT,
  p_preserve_case BOOLEAN DEFAULT FALSE,
  p_default_value TEXT DEFAULT NULL
)
RETURNS VOID AS $$
DECLARE
  current_type TEXT;
  value_expression TEXT;
BEGIN
  SELECT c.udt_name
    INTO current_type
  FROM information_schema.columns c
  WHERE c.table_schema = 'public'
    AND c.table_name = p_table
    AND c.column_name = p_column;

  IF current_type IS NULL OR current_type = p_target_type THEN
    RETURN;
  END IF;

  EXECUTE format('ALTER TABLE %I ALTER COLUMN %I DROP DEFAULT', p_table, p_column);

  IF p_preserve_case THEN
    value_expression := format('%I::text::%I', p_column, p_target_type);
  ELSE
    value_expression := format('lower(%I::text)::%I', p_column, p_target_type);
  END IF;

  EXECUTE format(
    'ALTER TABLE %I ALTER COLUMN %I TYPE %I USING %s',
    p_table,
    p_column,
    p_target_type,
    value_expression
  );

  IF p_default_value IS NOT NULL THEN
    EXECUTE format(
      'ALTER TABLE %I ALTER COLUMN %I SET DEFAULT %L::%I',
      p_table,
      p_column,
      p_default_value,
      p_target_type
    );
  END IF;
END;
$$ LANGUAGE plpgsql;

SELECT phase8_convert_enum_column('users', 'status', 'user_status', FALSE, 'active');
SELECT phase8_convert_enum_column('models', 'provider', 'provider_type');
SELECT phase8_convert_enum_column('models', 'health_status', 'health_status', FALSE, 'unknown');
SELECT phase8_convert_enum_column('model_roles', 'role', 'model_role', TRUE);
SELECT phase8_convert_enum_column('model_health_checks', 'status', 'health_status');
SELECT phase8_convert_enum_column('routing_policies', 'risk_level', 'risk_level');
SELECT phase8_convert_enum_column('guardrail_policies', 'scope', 'guardrail_scope');
SELECT phase8_convert_enum_column('guardrail_policies', 'status', 'guardrail_policy_status', FALSE, 'active');
SELECT phase8_convert_enum_column('guardrail_policies', 'decision_override', 'guardrail_decision');
SELECT phase8_convert_enum_column('test_plans', 'source_type', 'source_type');
SELECT phase8_convert_enum_column('test_plans', 'risk_level', 'risk_level', FALSE, 'medium');
SELECT phase8_convert_enum_column('test_plans', 'status', 'plan_status', FALSE, 'draft');
SELECT phase8_convert_enum_column('test_plan_domains', 'domain', 'test_domain');
SELECT phase8_convert_enum_column('executions', 'status', 'task_status', FALSE, 'queued');
SELECT phase8_convert_enum_column('executions', 'stage', 'execution_stage', TRUE, 'PREPARE');
SELECT phase8_convert_enum_column('execution_tasks', 'domain', 'test_domain');
SELECT phase8_convert_enum_column('execution_tasks', 'status', 'task_status', FALSE, 'queued');
SELECT phase8_convert_enum_column('execution_tasks', 'stage', 'execution_stage', TRUE);
SELECT phase8_convert_enum_column('execution_artifacts', 'artifact_type', 'artifact_type');
SELECT phase8_convert_enum_column('findings', 'domain', 'test_domain');
SELECT phase8_convert_enum_column('findings', 'source', 'finding_source');
SELECT phase8_convert_enum_column('findings', 'severity', 'finding_severity');
SELECT phase8_convert_enum_column('findings', 'status', 'finding_status', FALSE, 'open');
SELECT phase8_convert_enum_column('findings', 'category', 'finding_category');
SELECT phase8_convert_enum_column('triage_results', 'category', 'triage_category', FALSE, 'unknown');
SELECT phase8_convert_enum_column('gate_results', 'functional', 'gate_result', FALSE, 'warn');
SELECT phase8_convert_enum_column('gate_results', 'performance', 'gate_result', FALSE, 'warn');
SELECT phase8_convert_enum_column('gate_results', 'security', 'gate_result', FALSE, 'warn');
SELECT phase8_convert_enum_column('gate_results', 'overall', 'gate_result', FALSE, 'warn');
SELECT phase8_convert_enum_column('memories', 'type', 'memory_type');
SELECT phase8_convert_enum_column('memories', 'scope', 'memory_scope');
SELECT phase8_convert_enum_column('memory_jobs', 'scope', 'memory_scope');
SELECT phase8_convert_enum_column('memory_jobs', 'status', 'job_status', FALSE, 'queued');
SELECT phase8_convert_enum_column('agent_runs', 'status', 'agent_run_status', FALSE, 'queued');
SELECT phase8_convert_enum_column('guardrail_events', 'decision', 'guardrail_decision');
SELECT phase8_convert_enum_column('approvals', 'type', 'approval_type');
SELECT phase8_convert_enum_column('approvals', 'status', 'approval_status', FALSE, 'pending');
SELECT phase8_convert_enum_column('jobs', 'status', 'job_status', FALSE, 'queued');
SELECT phase8_convert_enum_column('integration_events', 'status', 'integration_event_status', FALSE, 'received');
SELECT phase8_convert_enum_column('orchestration_runs', 'status', 'job_status', FALSE, 'queued');
SELECT phase8_convert_enum_column('orchestration_checkpoints', 'status', 'job_status', FALSE, 'queued');

DROP FUNCTION phase8_convert_enum_column(TEXT, TEXT, TEXT, BOOLEAN, TEXT);
