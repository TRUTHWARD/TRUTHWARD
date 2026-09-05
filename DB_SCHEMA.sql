-- DB_SCHEMA.sql
-- AI测试平台数据库结构（PostgreSQL 15+）
-- Document Version: 3.0
-- Baseline: Phase 8 Controlled Skill Layer Baseline
--
-- 对齐文档：
--   - AGENTS.md
--   - ARCHITECTURE.md
--   - API_SPEC.md
--   - docs/EXECUTION_PROTOCOLS.md
--
-- 推荐扩展：
--   pgcrypto -> gen_random_uuid()
--
-- 可选扩展：
--   citext
--   pg_trgm

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- pgvector is intentionally optional for local bring-up.
-- Embeddings are stored as JSONB in the Phase 8 baseline.

CREATE TABLE IF NOT EXISTS schema_migrations (
  migration_name VARCHAR(255) PRIMARY KEY,
  checksum VARCHAR(128) NOT NULL,
  executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE schema_migrations IS 'Applied database migration ledger. Historical migration hash changes must be blocked.';

-- =========================================================
-- 1. 通用更新时间触发器
-- =========================================================

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- =========================================================
-- 2. 枚举类型
-- =========================================================

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'provider_type') THEN
    CREATE TYPE provider_type AS ENUM (
      'openai',
      'anthropic',
      'ollama',
      'vllm',
      'openai_compatible',
      'custom'
    );
  END IF;

  -- 模型角色：只保留模型路由角色，不混入 Agent 类型
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'model_role') THEN
    CREATE TYPE model_role AS ENUM (
      'PRIMARY',
      'CHALLENGER',
      'JUDGE',
      'LOCAL_FALLBACK'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'health_status') THEN
    CREATE TYPE health_status AS ENUM (
      'healthy',
      'degraded',
      'unavailable',
      'unknown'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'risk_level') THEN
    CREATE TYPE risk_level AS ENUM (
      'low',
      'medium',
      'high'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'traceability_relation_status') THEN
    CREATE TYPE traceability_relation_status AS ENUM (
      'candidate',
      'confirmed',
      'system_verified',
      'stale',
      'invalid',
      'rejected'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'traceability_relation_source') THEN
    CREATE TYPE traceability_relation_source AS ENUM (
      'manual',
      'approval',
      'deterministic_rule',
      'execution_result',
      'import',
      'model_candidate',
      'metadata_candidate',
      'string_match_candidate'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'coverage_status') THEN
    CREATE TYPE coverage_status AS ENUM (
      'covered',
      'partial',
      'not_covered',
      'blocked',
      'not_applicable',
      'unknown'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'proof_status') THEN
    CREATE TYPE proof_status AS ENUM (
      'valid',
      'stale',
      'broken',
      'superseded'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'task_status') THEN
    CREATE TYPE task_status AS ENUM (
      'queued',
      'running',
      'analyzing',
      'completed',
      'failed',
      'cancelled'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'execution_stage') THEN
    CREATE TYPE execution_stage AS ENUM (
      'PREPARE',
      'EXECUTE',
      'OBSERVE',
      'ANALYZE',
      'NORMALIZE',
      'GATE'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'plan_status') THEN
    CREATE TYPE plan_status AS ENUM (
      'draft',
      'ready',
      'running',
      'completed',
      'failed',
      'cancelled'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'test_domain') THEN
    CREATE TYPE test_domain AS ENUM (
      'functional',
      'performance',
      'security'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'finding_severity') THEN
    CREATE TYPE finding_severity AS ENUM (
      'critical',
      'high',
      'medium',
      'low',
      'info'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'finding_status') THEN
    CREATE TYPE finding_status AS ENUM (
      'open',
      'ignored',
      'false_positive',
      'accepted_risk',
      'resolved'
    );
  END IF;

  -- 对齐 EXECUTION_PROTOCOLS 的 canonical enums
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'finding_source') THEN
    CREATE TYPE finding_source AS ENUM (
      'playwright',
      'visual_grounding',
      'k6',
      'zap',
      'semgrep',
      'nuclei',
      'system',
      'agent',
      'manual',
      'custom'
    );
  END IF;
  ALTER TYPE finding_source ADD VALUE IF NOT EXISTS 'visual_grounding';

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'finding_category') THEN
    CREATE TYPE finding_category AS ENUM (
      'functional_ui',
      'functional_api',
      'performance_latency',
      'performance_capacity',
      'dast',
      'sast',
      'template_scan',
      'network',
      'reliability',
      'configuration',
      'authorization',
      'authentication',
      'other'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'memory_type') THEN
    CREATE TYPE memory_type AS ENUM (
      'episodic',
      'semantic',
      'procedural'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'memory_scope') THEN
    CREATE TYPE memory_scope AS ENUM (
      'session',
      'project',
      'org'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'artifact_type') THEN
    CREATE TYPE artifact_type AS ENUM (
      'trace',
      'screenshot',
      'dom_snapshot',
      'accessibility_tree',
      'vision_annotation',
      'ocr_output',
      'video',
      'log',
      'report',
      'har',
      'console',
      'network',
      'patch',
      'other'
    );
  END IF;
  ALTER TYPE artifact_type ADD VALUE IF NOT EXISTS 'dom_snapshot';
  ALTER TYPE artifact_type ADD VALUE IF NOT EXISTS 'accessibility_tree';
  ALTER TYPE artifact_type ADD VALUE IF NOT EXISTS 'vision_annotation';
  ALTER TYPE artifact_type ADD VALUE IF NOT EXISTS 'ocr_output';

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'approval_status') THEN
    CREATE TYPE approval_status AS ENUM (
      'pending',
      'approved',
      'rejected',
      'cancelled',
      'expired'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'approval_type') THEN
    CREATE TYPE approval_type AS ENUM (
      'healing_patch',
      'gate_override',
      'accepted_risk',
      'manual_rerun',
      'visual_action',
      'other'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'job_status') THEN
    CREATE TYPE job_status AS ENUM (
      'queued',
      'running',
      'completed',
      'failed',
      'cancelled'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'agent_run_status') THEN
    CREATE TYPE agent_run_status AS ENUM (
      'queued',
      'running',
      'completed',
      'failed',
      'cancelled'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'triage_category') THEN
    CREATE TYPE triage_category AS ENUM (
      'bug',
      'flaky',
      'env',
      'test_issue',
      'performance_issue',
      'security_issue',
      'unknown'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'gate_result') THEN
    CREATE TYPE gate_result AS ENUM (
      'pass',
      'warn',
      'fail',
      'blocked'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'gate_policy_status') THEN
    CREATE TYPE gate_policy_status AS ENUM (
      'draft',
      'active',
      'disabled',
      'deprecated',
      'archived'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'gate_policy_scope_type') THEN
    CREATE TYPE gate_policy_scope_type AS ENUM (
      'global',
      'workspace',
      'project',
      'environment',
      'stage',
      'domain'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'gate_policy_mode') THEN
    CREATE TYPE gate_policy_mode AS ENUM (
      'observe',
      'shadow',
      'enforce'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_status') THEN
    CREATE TYPE user_status AS ENUM (
      'active',
      'inactive',
      'disabled'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'source_type') THEN
    CREATE TYPE source_type AS ENUM (
      'pr',
      'manual',
      'schedule',
      'api'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'integration_event_status') THEN
    CREATE TYPE integration_event_status AS ENUM (
      'received',
      'processed',
      'failed',
      'ignored'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'guardrail_decision') THEN
    CREATE TYPE guardrail_decision AS ENUM (
      'allow',
      'warn',
      'block'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'guardrail_scope') THEN
    CREATE TYPE guardrail_scope AS ENUM (
      'request',
      'routing',
      'agent_output',
      'memory_write',
      'skill',
      'connector',
      'action',
      'tool',
      'system'
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'guardrail_policy_status') THEN
    CREATE TYPE guardrail_policy_status AS ENUM (
      'draft',
      'active',
      'disabled',
      'archived'
    );
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_enum
    WHERE enumlabel = 'skill'
      AND enumtypid = 'guardrail_scope'::regtype
  ) THEN
    ALTER TYPE guardrail_scope ADD VALUE 'skill';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_enum
    WHERE enumlabel = 'connector'
      AND enumtypid = 'guardrail_scope'::regtype
  ) THEN
    ALTER TYPE guardrail_scope ADD VALUE 'connector';
  END IF;
END $$;

-- =========================================================
-- 3. 用户与认证（Lightweight RBAC）
-- =========================================================

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(100) NOT NULL,
  username VARCHAR(100) UNIQUE,
  email VARCHAR(255) NOT NULL UNIQUE,
  display_name VARCHAR(255),
  password_hash VARCHAR(512),
  roles JSONB NOT NULL DEFAULT '["user"]'::jsonb,
  edition VARCHAR(32) NOT NULL DEFAULT 'basic',
  status user_status NOT NULL DEFAULT 'active',
  token_version INTEGER NOT NULL DEFAULT 1,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_users_roles_is_array CHECK (jsonb_typeof(roles) = 'array'),
  CONSTRAINT chk_users_edition CHECK (edition IN ('basic', 'community', 'pro', 'enterprise'))
);

COMMENT ON COLUMN users.roles IS '轻量 RBAC 角色数组，允许值：admin/user/system/agent';
COMMENT ON COLUMN users.edition IS 'Product edition for capability calculation: basic/community/pro/enterprise';
COMMENT ON COLUMN users.password_hash IS 'Scrypt verifier for local OSS Community authentication; plaintext passwords are never stored.';

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_edition ON users(edition);

CREATE TRIGGER trg_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS auth_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash VARCHAR(255) NOT NULL UNIQUE,
  token_name VARCHAR(100),
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_tokens_user_id ON auth_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires_at ON auth_tokens(expires_at);

CREATE TABLE IF NOT EXISTS projects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key VARCHAR(80) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_projects_status CHECK (status IN ('active', 'archived')),
  CONSTRAINT chk_projects_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

COMMENT ON TABLE projects IS 'Real project settings records used by ProjectSwitcher and governance settings.';

CREATE INDEX IF NOT EXISTS idx_projects_status ON projects(status);
CREATE INDEX IF NOT EXISTS idx_projects_created_by ON projects(created_by);

CREATE TRIGGER trg_projects_updated_at
BEFORE UPDATE ON projects
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS project_environments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  key VARCHAR(80) NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  base_url TEXT,
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  variables JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_project_environments_project_key UNIQUE (project_id, key),
  CONSTRAINT uq_project_environments_id_project UNIQUE (id, project_id),
  CONSTRAINT chk_project_environments_status CHECK (status IN ('active', 'disabled', 'archived')),
  CONSTRAINT chk_project_environments_variables_object CHECK (jsonb_typeof(variables) = 'object'),
  CONSTRAINT chk_project_environments_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

COMMENT ON TABLE project_environments IS 'Project-scoped environment settings. Execution visual grounding remains execution-service internal.';

CREATE INDEX IF NOT EXISTS idx_project_environments_project ON project_environments(project_id);
CREATE INDEX IF NOT EXISTS idx_project_environments_status ON project_environments(status);
CREATE INDEX IF NOT EXISTS idx_project_environments_created_by ON project_environments(created_by);

CREATE TRIGGER trg_project_environments_updated_at
BEFORE UPDATE ON project_environments
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS project_members (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  role VARCHAR(32) NOT NULL DEFAULT 'viewer',
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_project_members_project_user UNIQUE (project_id, user_id),
  CONSTRAINT chk_project_members_role CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
  CONSTRAINT chk_project_members_status CHECK (status IN ('active', 'inactive')),
  CONSTRAINT chk_project_members_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

COMMENT ON TABLE project_members IS 'Project member role assignments. Backend capability checks remain the authorization boundary.';

CREATE INDEX IF NOT EXISTS idx_project_members_project ON project_members(project_id);
CREATE INDEX IF NOT EXISTS idx_project_members_user ON project_members(user_id);
CREATE INDEX IF NOT EXISTS idx_project_members_role ON project_members(role);

CREATE TRIGGER trg_project_members_updated_at
BEFORE UPDATE ON project_members
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS capability_registry (
  capability_key VARCHAR(120) PRIMARY KEY,
  category VARCHAR(80) NOT NULL,
  description TEXT NOT NULL,
  risk_level VARCHAR(32) NOT NULL DEFAULT 'low',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_capability_registry_risk_level CHECK (risk_level IN ('low', 'medium', 'high'))
);

CREATE INDEX IF NOT EXISTS idx_capability_registry_category ON capability_registry(category);
CREATE INDEX IF NOT EXISTS idx_capability_registry_active ON capability_registry(is_active);

CREATE TRIGGER trg_capability_registry_updated_at
BEFORE UPDATE ON capability_registry
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS edition_capabilities (
  edition VARCHAR(32) NOT NULL,
  capability_key VARCHAR(120) NOT NULL REFERENCES capability_registry(capability_key) ON DELETE CASCADE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (edition, capability_key),
  CONSTRAINT chk_edition_capabilities_edition CHECK (edition IN ('basic', 'community', 'pro', 'enterprise'))
);

CREATE INDEX IF NOT EXISTS idx_edition_capabilities_capability ON edition_capabilities(capability_key);
CREATE INDEX IF NOT EXISTS idx_edition_capabilities_enabled ON edition_capabilities(enabled);

CREATE TABLE IF NOT EXISTS user_entitlements (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  capability_key VARCHAR(120) NOT NULL REFERENCES capability_registry(capability_key) ON DELETE CASCADE,
  effect VARCHAR(16) NOT NULL DEFAULT 'allow',
  reason TEXT,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_user_entitlements_effect CHECK (effect IN ('allow', 'deny')),
  CONSTRAINT uq_user_entitlements_user_capability UNIQUE (user_id, capability_key)
);

CREATE INDEX IF NOT EXISTS idx_user_entitlements_user_id ON user_entitlements(user_id);
CREATE INDEX IF NOT EXISTS idx_user_entitlements_capability_key ON user_entitlements(capability_key);
CREATE INDEX IF NOT EXISTS idx_user_entitlements_expires_at ON user_entitlements(expires_at);

CREATE TABLE IF NOT EXISTS rbac_role_capabilities (
  role_name VARCHAR(80) NOT NULL,
  capability_key VARCHAR(120) NOT NULL REFERENCES capability_registry(capability_key) ON DELETE CASCADE,
  effect VARCHAR(16) NOT NULL DEFAULT 'allow',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (role_name, capability_key),
  CONSTRAINT chk_rbac_role_capabilities_effect CHECK (effect IN ('allow', 'deny'))
);

CREATE INDEX IF NOT EXISTS idx_rbac_role_capabilities_capability
  ON rbac_role_capabilities(capability_key);
CREATE INDEX IF NOT EXISTS idx_rbac_role_capabilities_effect
  ON rbac_role_capabilities(effect);

CREATE TRIGGER trg_rbac_role_capabilities_updated_at
BEFORE UPDATE ON rbac_role_capabilities
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- =========================================================
-- 4. 模型管理
-- =========================================================

CREATE TABLE IF NOT EXISTS models (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(150) NOT NULL UNIQUE,
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  environment_id UUID REFERENCES project_environments(id) ON DELETE CASCADE,
  provider provider_type NOT NULL,
  model_name VARCHAR(255) NOT NULL,
  base_url TEXT,
  api_key_ref VARCHAR(255),
  priority INTEGER NOT NULL DEFAULT 100,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  health_status health_status NOT NULL DEFAULT 'unknown',
  last_health_check_at TIMESTAMPTZ,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  capabilities JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_models_environment_project
    FOREIGN KEY (environment_id, project_id)
    REFERENCES project_environments(id, project_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_models_provider ON models(provider);
CREATE INDEX IF NOT EXISTS idx_models_enabled ON models(enabled);
CREATE INDEX IF NOT EXISTS idx_models_priority ON models(priority DESC);
CREATE INDEX IF NOT EXISTS idx_models_project_id ON models(project_id);
CREATE INDEX IF NOT EXISTS idx_models_environment_id ON models(environment_id);

CREATE TRIGGER trg_models_updated_at
BEFORE UPDATE ON models
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS model_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  model_id UUID NOT NULL REFERENCES models(id) ON DELETE CASCADE,
  role model_role NOT NULL,
  weight INTEGER NOT NULL DEFAULT 100,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (model_id, role)
);

CREATE INDEX IF NOT EXISTS idx_model_roles_role ON model_roles(role);
CREATE INDEX IF NOT EXISTS idx_model_roles_model_id ON model_roles(model_id);

CREATE TABLE IF NOT EXISTS model_health_checks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  model_id UUID NOT NULL REFERENCES models(id) ON DELETE CASCADE,
  status health_status NOT NULL,
  latency_ms INTEGER,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_model_health_checks_model_id ON model_health_checks(model_id);
CREATE INDEX IF NOT EXISTS idx_model_health_checks_checked_at ON model_health_checks(checked_at DESC);

CREATE TABLE IF NOT EXISTS model_capability_scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  model_id UUID NOT NULL REFERENCES models(id) ON DELETE CASCADE,
  scanner VARCHAR(120) NOT NULL DEFAULT 'model-gateway-config',
  capabilities JSONB NOT NULL DEFAULT '{}'::jsonb,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_model_capability_scans_model_id ON model_capability_scans(model_id);
CREATE INDEX IF NOT EXISTS idx_model_capability_scans_scanned_at ON model_capability_scans(scanned_at DESC);

-- =========================================================
-- 5. 路由策略
-- =========================================================

CREATE TABLE IF NOT EXISTS routing_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(150) NOT NULL UNIQUE,
  task_type VARCHAR(100) NOT NULL,
  risk_level risk_level NOT NULL,
  requires_tools BOOLEAN NOT NULL DEFAULT FALSE,
  requires_vision BOOLEAN NOT NULL DEFAULT FALSE,
  requires_json BOOLEAN NOT NULL DEFAULT FALSE,
  data_sensitivity VARCHAR(50) DEFAULT 'internal',
  prefer_local BOOLEAN NOT NULL DEFAULT FALSE,
  challenger_required BOOLEAN NOT NULL DEFAULT FALSE,
  fallback_required BOOLEAN NOT NULL DEFAULT FALSE,
  human_approval_required BOOLEAN NOT NULL DEFAULT FALSE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_routing_policies_task_type ON routing_policies(task_type);
CREATE INDEX IF NOT EXISTS idx_routing_policies_enabled ON routing_policies(enabled);

CREATE TRIGGER trg_routing_policies_updated_at
BEFORE UPDATE ON routing_policies
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- =========================================================
-- 6. 测试计划
-- =========================================================

CREATE TABLE IF NOT EXISTS requirement_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_ref VARCHAR(255) NOT NULL,
  version_no INTEGER NOT NULL,
  content_hash VARCHAR(80) NOT NULL,
  document TEXT NOT NULL,
  requirements JSONB NOT NULL DEFAULT '[]'::jsonb,
  acceptance_criteria JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (source_ref, version_no),
  UNIQUE (source_ref, content_hash),
  CONSTRAINT chk_requirement_versions_requirements_array CHECK (jsonb_typeof(requirements) = 'array'),
  CONSTRAINT chk_requirement_versions_acceptance_array CHECK (jsonb_typeof(acceptance_criteria) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_requirement_versions_source_ref ON requirement_versions(source_ref);
CREATE INDEX IF NOT EXISTS idx_requirement_versions_content_hash ON requirement_versions(content_hash);

CREATE TRIGGER trg_requirement_versions_updated_at
BEFORE UPDATE ON requirement_versions
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS requirement_scopes (
  scope_id VARCHAR(255) PRIMARY KEY,
  schema_version VARCHAR(80) NOT NULL,
  primary_requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE RESTRICT,
  scope_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_requirement_scopes_primary_version ON requirement_scopes(primary_requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_requirement_scopes_schema_version ON requirement_scopes(schema_version);

CREATE TABLE IF NOT EXISTS requirement_scope_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scope_id VARCHAR(255) NOT NULL REFERENCES requirement_scopes(scope_id) ON DELETE CASCADE,
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE RESTRICT,
  requirement_item_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  UNIQUE (scope_id, requirement_version_id),
  CONSTRAINT chk_requirement_scope_version_items_array CHECK (jsonb_typeof(requirement_item_ids) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_requirement_scope_versions_version ON requirement_scope_versions(requirement_version_id);

CREATE TABLE IF NOT EXISTS clarification_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE CASCADE,
  question_key VARCHAR(100) NOT NULL,
  question TEXT NOT NULL,
  priority VARCHAR(10) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'open',
  answer TEXT,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  answered_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_clarification_priority CHECK (priority IN ('P0', 'P1', 'P2')),
  CONSTRAINT chk_clarification_status CHECK (status IN ('open', 'answered', 'closed'))
);

CREATE INDEX IF NOT EXISTS idx_clarification_requirement ON clarification_items(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_clarification_status ON clarification_items(status, priority);

CREATE TRIGGER trg_clarification_items_updated_at
BEFORE UPDATE ON clarification_items
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS test_plans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  source_type source_type NOT NULL,
  source_ref VARCHAR(255),
  environment VARCHAR(100) NOT NULL,
  project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
  environment_id UUID REFERENCES project_environments(id) ON DELETE SET NULL,
  risk_level risk_level NOT NULL DEFAULT 'medium',
  status plan_status NOT NULL DEFAULT 'draft',
  input_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  generated_plan JSONB NOT NULL DEFAULT '{}'::jsonb,
  requirement_scope JSONB NOT NULL DEFAULT '{}'::jsonb,
  requirement_scope_id VARCHAR(255) REFERENCES requirement_scopes(scope_id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_test_plans_status ON test_plans(status);
CREATE INDEX IF NOT EXISTS idx_test_plans_environment ON test_plans(environment);
CREATE INDEX IF NOT EXISTS idx_test_plans_project ON test_plans(project_id);
CREATE INDEX IF NOT EXISTS idx_test_plans_environment_ref ON test_plans(environment_id);
CREATE INDEX IF NOT EXISTS idx_test_plans_source_type ON test_plans(source_type);
CREATE INDEX IF NOT EXISTS idx_test_plans_created_at ON test_plans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_test_plans_requirement_version_id ON test_plans(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_test_plans_requirement_scope_id ON test_plans(requirement_scope_id);

CREATE TRIGGER trg_test_plans_updated_at
BEFORE UPDATE ON test_plans
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS test_plan_domains (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  plan_id UUID NOT NULL REFERENCES test_plans(id) ON DELETE CASCADE,
  domain test_domain NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (plan_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_test_plan_domains_plan_id ON test_plan_domains(plan_id);

CREATE TABLE IF NOT EXISTS test_assets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE CASCADE,
  test_plan_id UUID REFERENCES test_plans(id) ON DELETE SET NULL,
  asset_type VARCHAR(30) NOT NULL,
  domain VARCHAR(50) NOT NULL,
  title VARCHAR(255) NOT NULL,
  objective TEXT NOT NULL,
  requirement_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  status VARCHAR(30) NOT NULL DEFAULT 'draft',
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_test_asset_type CHECK (asset_type IN ('test_point', 'test_case')),
  CONSTRAINT chk_test_asset_status CHECK (status IN ('draft', 'reviewed', 'approved', 'invalidated'))
);

CREATE INDEX IF NOT EXISTS idx_test_assets_requirement ON test_assets(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_test_assets_plan ON test_assets(test_plan_id);

CREATE TRIGGER trg_test_assets_updated_at
BEFORE UPDATE ON test_assets
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS test_asset_reviews (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE CASCADE,
  test_plan_id UUID NOT NULL REFERENCES test_plans(id) ON DELETE CASCADE,
  status VARCHAR(30) NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  issues JSONB NOT NULL DEFAULT '[]'::jsonb,
  coverage_map JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_test_asset_review_status CHECK (status IN ('approved', 'needs_review', 'rejected')),
  CONSTRAINT chk_test_asset_review_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE INDEX IF NOT EXISTS idx_test_asset_reviews_requirement ON test_asset_reviews(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_test_asset_reviews_plan ON test_asset_reviews(test_plan_id);

CREATE TRIGGER trg_test_asset_reviews_updated_at
BEFORE UPDATE ON test_asset_reviews
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS execution_plans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE CASCADE,
  test_plan_id UUID NOT NULL REFERENCES test_plans(id) ON DELETE CASCADE,
  status VARCHAR(30) NOT NULL,
  risk_level risk_level NOT NULL,
  approval_required BOOLEAN NOT NULL DEFAULT FALSE,
  tasks JSONB NOT NULL DEFAULT '[]'::jsonb,
  asset_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  retry_strategy JSONB NOT NULL DEFAULT '{}'::jsonb,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  requirement_scope JSONB NOT NULL DEFAULT '{}'::jsonb,
  requirement_scope_id VARCHAR(255) REFERENCES requirement_scopes(scope_id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_execution_plan_status CHECK (status IN ('draft', 'approved', 'blocked'))
);

CREATE INDEX IF NOT EXISTS idx_execution_plans_requirement ON execution_plans(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_execution_plans_test_plan ON execution_plans(test_plan_id);
CREATE INDEX IF NOT EXISTS idx_execution_plans_requirement_scope_id ON execution_plans(requirement_scope_id);

CREATE TRIGGER trg_execution_plans_updated_at
BEFORE UPDATE ON execution_plans
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- =========================================================
-- 7. 执行与任务
-- =========================================================

CREATE TABLE IF NOT EXISTS executions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  plan_id UUID NOT NULL REFERENCES test_plans(id) ON DELETE CASCADE,
  status task_status NOT NULL DEFAULT 'queued',
  stage execution_stage NOT NULL DEFAULT 'PREPARE',
  environment VARCHAR(100) NOT NULL,
  triggered_by UUID REFERENCES users(id) ON DELETE SET NULL,
  trigger_source VARCHAR(50) DEFAULT 'manual',
  options JSONB NOT NULL DEFAULT '{}'::jsonb,
  summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  started_at TIMESTAMPTZ,
  ended_at TIMESTAMPTZ,
  execution_plan_id UUID REFERENCES execution_plans(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_executions_plan_id ON executions(plan_id);
CREATE INDEX IF NOT EXISTS idx_executions_status ON executions(status);
CREATE INDEX IF NOT EXISTS idx_executions_stage ON executions(stage);
CREATE INDEX IF NOT EXISTS idx_executions_environment ON executions(environment);
CREATE INDEX IF NOT EXISTS idx_executions_created_at ON executions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_executions_execution_plan_id ON executions(execution_plan_id);

CREATE TRIGGER trg_executions_updated_at
BEFORE UPDATE ON executions
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS correction_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE CASCADE,
  execution_id UUID REFERENCES executions(id) ON DELETE SET NULL,
  target_type VARCHAR(50) NOT NULL,
  target_id VARCHAR(255) NOT NULL,
  before_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  after_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  reason TEXT NOT NULL,
  actor_ref JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  affected_asset_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_correction_requirement ON correction_records(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_correction_execution ON correction_records(execution_id);

CREATE TRIGGER trg_correction_records_updated_at
BEFORE UPDATE ON correction_records
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS correction_proposals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  proposal_type VARCHAR(80) NOT NULL,
  status VARCHAR(40) NOT NULL DEFAULT 'draft',
  proposed_change JSONB NOT NULL DEFAULT '{}'::jsonb,
  requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE SET NULL,
  execution_id UUID REFERENCES executions(id) ON DELETE SET NULL,
  finding_id UUID,
  attribution_id VARCHAR(255),
  risk_level risk_level NOT NULL,
  requester_ref JSONB NOT NULL DEFAULT '{}'::jsonb,
  requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  promotion_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  promoted_at TIMESTAMPTZ,
  contract_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  request_id VARCHAR(255),
  idempotency_key VARCHAR(255) UNIQUE,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_correction_proposals_status CHECK (
    status IN ('draft', 'pending_approval', 'approved', 'rejected', 'cancelled', 'expired')
  )
);

CREATE INDEX IF NOT EXISTS idx_correction_proposals_requirement ON correction_proposals(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_correction_proposals_execution ON correction_proposals(execution_id);
CREATE INDEX IF NOT EXISTS idx_correction_proposals_status ON correction_proposals(status);
CREATE INDEX IF NOT EXISTS idx_correction_proposals_type ON correction_proposals(proposal_type);

CREATE TABLE IF NOT EXISTS correction_applications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  correction_proposal_id UUID NOT NULL REFERENCES correction_proposals(id) ON DELETE CASCADE,
  idempotency_key VARCHAR(255) NOT NULL,
  request_id VARCHAR(255) NOT NULL,
  status VARCHAR(40) NOT NULL DEFAULT 'pending',
  applied_change_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  side_effect_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  contract_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  applied_by UUID REFERENCES users(id) ON DELETE SET NULL,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_correction_applications_status CHECK (
    status IN ('pending', 'applying', 'applied', 'failed_to_apply')
  ),
  CONSTRAINT uq_correction_applications_proposal_idempotency UNIQUE (correction_proposal_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_correction_applications_proposal ON correction_applications(correction_proposal_id);
CREATE INDEX IF NOT EXISTS idx_correction_applications_status ON correction_applications(status);
CREATE INDEX IF NOT EXISTS idx_correction_applications_request ON correction_applications(request_id);

CREATE TABLE IF NOT EXISTS correction_validations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  correction_proposal_id UUID NOT NULL REFERENCES correction_proposals(id) ON DELETE CASCADE,
  correction_application_id UUID NOT NULL REFERENCES correction_applications(id) ON DELETE CASCADE,
  idempotency_key VARCHAR(255) NOT NULL,
  request_id VARCHAR(255) NOT NULL,
  status VARCHAR(40) NOT NULL DEFAULT 'pending',
  result JSONB NOT NULL DEFAULT '{}'::jsonb,
  trace_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  contract_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_correction_validations_status CHECK (
    status IN ('pending', 'running', 'validated', 'validation_failed', 'cancelled', 'error')
  ),
  CONSTRAINT uq_correction_validations_application_idempotency UNIQUE (correction_application_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_correction_validations_proposal ON correction_validations(correction_proposal_id);
CREATE INDEX IF NOT EXISTS idx_correction_validations_application ON correction_validations(correction_application_id);
CREATE INDEX IF NOT EXISTS idx_correction_validations_status ON correction_validations(status);
CREATE INDEX IF NOT EXISTS idx_correction_validations_request ON correction_validations(request_id);

CREATE TABLE IF NOT EXISTS rollback_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  correction_proposal_id UUID NOT NULL REFERENCES correction_proposals(id) ON DELETE CASCADE,
  correction_application_id UUID REFERENCES correction_applications(id) ON DELETE SET NULL,
  correction_validation_id UUID REFERENCES correction_validations(id) ON DELETE SET NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  request_id VARCHAR(255) NOT NULL,
  status VARCHAR(40) NOT NULL,
  rollback_reason TEXT NOT NULL,
  rollback_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  contract_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_rollback_records_status CHECK (
    status IN ('rollback_not_required', 'rolling_back', 'rolled_back', 'rollback_failed')
  ),
  CONSTRAINT uq_rollback_records_proposal_idempotency UNIQUE (correction_proposal_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_rollback_records_proposal ON rollback_records(correction_proposal_id);
CREATE INDEX IF NOT EXISTS idx_rollback_records_application ON rollback_records(correction_application_id);
CREATE INDEX IF NOT EXISTS idx_rollback_records_validation ON rollback_records(correction_validation_id);
CREATE INDEX IF NOT EXISTS idx_rollback_records_status ON rollback_records(status);
CREATE INDEX IF NOT EXISTS idx_rollback_records_request ON rollback_records(request_id);

CREATE TABLE IF NOT EXISTS execution_tasks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  parent_task_id UUID REFERENCES execution_tasks(id) ON DELETE SET NULL,
  domain test_domain NOT NULL,
  task_type VARCHAR(150) NOT NULL,
  runner VARCHAR(100) NOT NULL,
  status task_status NOT NULL DEFAULT 'queued',
  stage execution_stage,
  priority INTEGER NOT NULL DEFAULT 100,
  retry_count INTEGER NOT NULL DEFAULT 0,
  max_retries INTEGER NOT NULL DEFAULT 0,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  result_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_message TEXT,
  started_at TIMESTAMPTZ,
  ended_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_execution_tasks_execution_id ON execution_tasks(execution_id);
CREATE INDEX IF NOT EXISTS idx_execution_tasks_status ON execution_tasks(status);
CREATE INDEX IF NOT EXISTS idx_execution_tasks_domain ON execution_tasks(domain);
CREATE INDEX IF NOT EXISTS idx_execution_tasks_task_type ON execution_tasks(task_type);
CREATE INDEX IF NOT EXISTS idx_execution_tasks_parent_task_id ON execution_tasks(parent_task_id);

CREATE TRIGGER trg_execution_tasks_updated_at
BEFORE UPDATE ON execution_tasks
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS execution_metrics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  task_id UUID REFERENCES execution_tasks(id) ON DELETE CASCADE,
  metric_name VARCHAR(150) NOT NULL,
  metric_value NUMERIC(20,6) NOT NULL,
  metric_unit VARCHAR(50),
  threshold_value NUMERIC(20,6),
  baseline_value NUMERIC(20,6),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_execution_metrics_execution_id ON execution_metrics(execution_id);
CREATE INDEX IF NOT EXISTS idx_execution_metrics_task_id ON execution_metrics(task_id);
CREATE INDEX IF NOT EXISTS idx_execution_metrics_metric_name ON execution_metrics(metric_name);

CREATE TABLE IF NOT EXISTS execution_artifacts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  task_id UUID REFERENCES execution_tasks(id) ON DELETE CASCADE,
  artifact_type artifact_type NOT NULL,
  uri TEXT NOT NULL,
  summary TEXT,
  redaction_status VARCHAR(50) NOT NULL DEFAULT 'not_required',
  redacted_uri TEXT,
  expires_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_execution_artifacts_execution_id ON execution_artifacts(execution_id);
CREATE INDEX IF NOT EXISTS idx_execution_artifacts_task_id ON execution_artifacts(task_id);
CREATE INDEX IF NOT EXISTS idx_execution_artifacts_type ON execution_artifacts(artifact_type);

CREATE TABLE IF NOT EXISTS execution_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  task_id UUID REFERENCES execution_tasks(id) ON DELETE CASCADE,
  level VARCHAR(20) NOT NULL DEFAULT 'info',
  message TEXT NOT NULL,
  context JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_execution_logs_execution_id ON execution_logs(execution_id);
CREATE INDEX IF NOT EXISTS idx_execution_logs_task_id ON execution_logs(task_id);
CREATE INDEX IF NOT EXISTS idx_execution_logs_created_at ON execution_logs(created_at DESC);

-- =========================================================
-- 7A. Trace foundation (must precede tables with trace_id FKs)
-- =========================================================

CREATE TABLE IF NOT EXISTS traces (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_id UUID REFERENCES executions(id) ON DELETE CASCADE,
  root_span_name VARCHAR(255),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_traces_execution_id ON traces(execution_id);

CREATE TABLE IF NOT EXISTS trace_spans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE CASCADE,
  parent_span_id UUID REFERENCES trace_spans(id) ON DELETE CASCADE,
  span_name VARCHAR(255) NOT NULL,
  span_type VARCHAR(100),
  service_name VARCHAR(100),
  status VARCHAR(50),
  start_time TIMESTAMPTZ NOT NULL,
  end_time TIMESTAMPTZ,
  duration_ms INTEGER,
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trace_spans_trace_id ON trace_spans(trace_id);
CREATE INDEX IF NOT EXISTS idx_trace_spans_parent_span_id ON trace_spans(parent_span_id);
CREATE INDEX IF NOT EXISTS idx_trace_spans_span_name ON trace_spans(span_name);

-- =========================================================
-- 8. Findings（对齐 normalized finding contract）
-- =========================================================

CREATE TABLE IF NOT EXISTS findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  task_id UUID REFERENCES execution_tasks(id) ON DELETE SET NULL,
  domain test_domain NOT NULL,
  source finding_source NOT NULL,
  severity finding_severity NOT NULL,
  status finding_status NOT NULL DEFAULT 'open',
  category finding_category NOT NULL,
  title VARCHAR(255) NOT NULL,
  summary TEXT NOT NULL,
  description TEXT,
  confidence NUMERIC(5,4),
  dedupe_key VARCHAR(255) NOT NULL,
  raw_ref VARCHAR(255) NOT NULL,
  location JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_ref UUID REFERENCES execution_artifacts(id) ON DELETE SET NULL,
  comment TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_findings_confidence_range CHECK (
    confidence IS NULL OR (confidence >= 0 AND confidence <= 1)
  ),
  CONSTRAINT chk_findings_location_is_object CHECK (jsonb_typeof(location) = 'object'),
  CONSTRAINT chk_findings_evidence_is_array CHECK (jsonb_typeof(evidence) = 'array')
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_execution_dedupe_key
  ON findings(execution_id, dedupe_key);

CREATE INDEX IF NOT EXISTS idx_findings_execution_id ON findings(execution_id);
CREATE INDEX IF NOT EXISTS idx_findings_task_id ON findings(task_id);
CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings(domain);
CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(source);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_raw_ref ON findings(raw_ref);

CREATE TRIGGER trg_findings_updated_at
BEFORE UPDATE ON findings
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- =========================================================
-- 8A. WorkItems (human collaboration tasks)
-- =========================================================

CREATE TABLE IF NOT EXISTS work_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE SET NULL,
  requirement_item_id VARCHAR(255),
  execution_id UUID REFERENCES executions(id) ON DELETE SET NULL,
  finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
  evidence_artifact_id UUID REFERENCES execution_artifacts(id) ON DELETE SET NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  status VARCHAR(32) NOT NULL DEFAULT 'open',
  priority VARCHAR(32) NOT NULL DEFAULT 'medium',
  assignee_id UUID REFERENCES users(id) ON DELETE SET NULL,
  claimed_by UUID REFERENCES users(id) ON DELETE SET NULL,
  completed_at TIMESTAMPTZ,
  cancelled_at TIMESTAMPTZ,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_work_items_status CHECK (status IN ('open', 'assigned', 'in_progress', 'completed', 'cancelled')),
  CONSTRAINT chk_work_items_priority CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
  CONSTRAINT chk_work_items_evidence_refs_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
  CONSTRAINT chk_work_items_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

COMMENT ON TABLE work_items IS 'Service-owned human collaboration tasks. WorkItems are distinct from execution_tasks and do not write Gate decisions.';
COMMENT ON COLUMN work_items.execution_id IS 'Optional reference to an Execution for context; does not mutate execution lifecycle.';
COMMENT ON COLUMN work_items.finding_id IS 'Optional reference to a canonical Finding after NORMALIZE.';
COMMENT ON COLUMN work_items.evidence_artifact_id IS 'Optional reference to persisted execution evidence.';

CREATE INDEX IF NOT EXISTS idx_work_items_project ON work_items(project_id);
CREATE INDEX IF NOT EXISTS idx_work_items_requirement_version ON work_items(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_work_items_execution ON work_items(execution_id);
CREATE INDEX IF NOT EXISTS idx_work_items_finding ON work_items(finding_id);
CREATE INDEX IF NOT EXISTS idx_work_items_evidence_artifact ON work_items(evidence_artifact_id);
CREATE INDEX IF NOT EXISTS idx_work_items_assignee ON work_items(assignee_id);
CREATE INDEX IF NOT EXISTS idx_work_items_claimed_by ON work_items(claimed_by);
CREATE INDEX IF NOT EXISTS idx_work_items_status ON work_items(status);
CREATE INDEX IF NOT EXISTS idx_work_items_created_at ON work_items(created_at DESC);

CREATE TRIGGER trg_work_items_updated_at
BEFORE UPDATE ON work_items
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS raw_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  task_id UUID REFERENCES execution_tasks(id) ON DELETE CASCADE,
  source VARCHAR(100) NOT NULL,
  category VARCHAR(100) NOT NULL,
  severity VARCHAR(50) NOT NULL,
  title VARCHAR(255) NOT NULL,
  summary TEXT NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  dedupe_key VARCHAR(255) NOT NULL,
  raw_ref VARCHAR(255) NOT NULL,
  location JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  normalized_finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_raw_findings_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE INDEX IF NOT EXISTS idx_raw_findings_execution ON raw_findings(execution_id);
CREATE INDEX IF NOT EXISTS idx_raw_findings_task ON raw_findings(task_id);
CREATE INDEX IF NOT EXISTS idx_raw_findings_normalized ON raw_findings(normalized_finding_id);

-- =========================================================
-- 9. 归因与修复
-- =========================================================

CREATE TABLE IF NOT EXISTS triage_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  task_id UUID REFERENCES execution_tasks(id) ON DELETE CASCADE,
  category triage_category NOT NULL DEFAULT 'unknown',
  confidence NUMERIC(5,4) NOT NULL DEFAULT 0.0000,
  evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
  challenged BOOLEAN NOT NULL DEFAULT FALSE,
  final_decision_by VARCHAR(50),
  raw_output JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_triage_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_triage_evidence_is_array CHECK (jsonb_typeof(evidence) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_triage_results_execution_id ON triage_results(execution_id);
CREATE INDEX IF NOT EXISTS idx_triage_results_task_id ON triage_results(task_id);
CREATE INDEX IF NOT EXISTS idx_triage_results_category ON triage_results(category);

CREATE TABLE IF NOT EXISTS healing_suggestions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  task_id UUID REFERENCES execution_tasks(id) ON DELETE CASCADE,
  suggestion_type VARCHAR(100) NOT NULL,
  summary TEXT NOT NULL,
  patch TEXT,
  success BOOLEAN,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_healing_suggestions_execution_id ON healing_suggestions(execution_id);
CREATE INDEX IF NOT EXISTS idx_healing_suggestions_task_id ON healing_suggestions(task_id);

-- =========================================================
-- 10. Gate
-- =========================================================

CREATE TABLE IF NOT EXISTS gate_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_id UUID NOT NULL UNIQUE REFERENCES executions(id) ON DELETE CASCADE,
  functional gate_result NOT NULL DEFAULT 'warn',
  performance gate_result NOT NULL DEFAULT 'warn',
  security gate_result NOT NULL DEFAULT 'warn',
  overall gate_result NOT NULL DEFAULT 'warn',
  reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
  decided_by VARCHAR(50) DEFAULT 'system',
  policy_version_id VARCHAR(255),
  policy_version_hash VARCHAR(80),
  policy_binding_ref VARCHAR(500),
  reason_codes JSONB NOT NULL DEFAULT '[]'::jsonb,
  matched_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
  completeness JSONB NOT NULL DEFAULT '{}'::jsonb,
  confidence NUMERIC(5,4) NOT NULL DEFAULT 0,
  input_fingerprint VARCHAR(80),
  decision_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  decision_snapshot_hash VARCHAR(80),
  evaluator_version VARCHAR(80) NOT NULL DEFAULT 'legacy.gate-evaluator.v1',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_gate_reasons_is_array CHECK (jsonb_typeof(reasons) = 'array'),
  CONSTRAINT chk_gate_reason_codes_is_array CHECK (jsonb_typeof(reason_codes) = 'array'),
  CONSTRAINT chk_gate_matched_rules_is_array CHECK (jsonb_typeof(matched_rules) = 'array'),
  CONSTRAINT chk_gate_completeness_is_object CHECK (jsonb_typeof(completeness) = 'object'),
  CONSTRAINT chk_gate_decision_snapshot_is_object CHECK (jsonb_typeof(decision_snapshot) = 'object'),
  CONSTRAINT chk_gate_confidence_range CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE INDEX IF NOT EXISTS idx_gate_results_policy_version ON gate_results(policy_version_id);
CREATE INDEX IF NOT EXISTS idx_gate_results_input_fingerprint ON gate_results(input_fingerprint);
CREATE INDEX IF NOT EXISTS idx_gate_results_decision_snapshot_hash ON gate_results(decision_snapshot_hash);

COMMENT ON COLUMN gate_results.decision_snapshot IS
  'Frozen phase8.gate-decision-snapshot.v1 produced by the Service-owned GateEvaluator.';
COMMENT ON COLUMN gate_results.input_fingerprint IS
  'Canonical material Gate input fingerprint; request/trace correlation is excluded.';

CREATE TRIGGER trg_gate_results_updated_at
BEFORE UPDATE ON gate_results
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- =========================================================
-- 10.0.1 Gate Policy Data Foundation (P01)
-- =========================================================

CREATE TABLE IF NOT EXISTS gate_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID REFERENCES projects(id) ON DELETE RESTRICT,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  policy_key VARCHAR(128) NOT NULL,
  policy_ref VARCHAR(500) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  status gate_policy_status NOT NULL DEFAULT 'draft',
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_gate_policies_scope_key UNIQUE (tenant_id, workspace_id, policy_key),
  CONSTRAINT uq_gate_policies_tenant_identity UNIQUE (id, tenant_id, workspace_id),
  CONSTRAINT chk_gate_policies_tenant_not_blank CHECK (length(trim(tenant_id)) > 0),
  CONSTRAINT chk_gate_policies_workspace_not_blank CHECK (length(trim(workspace_id)) > 0),
  CONSTRAINT chk_gate_policies_lock_version CHECK (lock_version > 0)
);

CREATE INDEX IF NOT EXISTS idx_gate_policies_tenant_workspace
  ON gate_policies(tenant_id, workspace_id);
CREATE INDEX IF NOT EXISTS idx_gate_policies_project
  ON gate_policies(project_id);
CREATE INDEX IF NOT EXISTS idx_gate_policies_status
  ON gate_policies(status);

CREATE TABLE IF NOT EXISTS gate_policy_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id UUID NOT NULL,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  version_number INTEGER NOT NULL,
  version_ref VARCHAR(500) NOT NULL UNIQUE,
  schema_version VARCHAR(80) NOT NULL,
  status gate_policy_status NOT NULL,
  policy_snapshot JSONB NOT NULL,
  content_hash VARCHAR(80) NOT NULL,
  capability_ref VARCHAR(500),
  approval_policy_ref VARCHAR(500),
  validation_status VARCHAR(32) NOT NULL DEFAULT 'not_validated',
  validation_report JSONB NOT NULL DEFAULT '{}'::jsonb,
  validated_at TIMESTAMPTZ,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  governance_status VARCHAR(40) NOT NULL DEFAULT 'draft',
  current_approval_id UUID,
  submitted_at TIMESTAMPTZ,
  submitted_by UUID REFERENCES users(id) ON DELETE SET NULL,
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_gate_policy_versions_policy_scope
    FOREIGN KEY (policy_id, tenant_id, workspace_id)
    REFERENCES gate_policies(id, tenant_id, workspace_id)
    ON DELETE RESTRICT,
  CONSTRAINT uq_gate_policy_versions_policy_version UNIQUE (policy_id, version_number),
  CONSTRAINT uq_gate_policy_versions_policy_hash UNIQUE (policy_id, content_hash),
  CONSTRAINT uq_gate_policy_versions_tenant_identity
    UNIQUE (id, policy_id, tenant_id, workspace_id, content_hash),
  CONSTRAINT chk_gate_policy_versions_number CHECK (version_number > 0),
  CONSTRAINT chk_gate_policy_versions_hash_length CHECK (length(content_hash) = 71),
  CONSTRAINT chk_gate_policy_versions_hash_prefix CHECK (substr(content_hash, 1, 7) = 'sha256:'),
  CONSTRAINT chk_gate_policy_versions_lock_version CHECK (lock_version > 0),
  CONSTRAINT chk_gate_policy_versions_validation_status
    CHECK (validation_status IN ('not_validated', 'valid', 'invalid')),
  CONSTRAINT chk_gate_policy_versions_governance_status CHECK (governance_status IN (
    'draft', 'review_pending', 'review_approved', 'review_rejected',
    'review_cancelled', 'review_expired', 'transition_pending',
    'transition_applied', 'transition_rejected', 'transition_cancelled', 'transition_expired'
  )),
  CONSTRAINT chk_gate_policy_versions_snapshot_object CHECK (jsonb_typeof(policy_snapshot) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_gate_policy_versions_policy_status
  ON gate_policy_versions(policy_id, status);
CREATE INDEX IF NOT EXISTS idx_gate_policy_versions_scope
  ON gate_policy_versions(tenant_id, workspace_id);
CREATE INDEX IF NOT EXISTS idx_gate_policy_versions_hash
  ON gate_policy_versions(content_hash);
CREATE INDEX IF NOT EXISTS idx_gate_policy_versions_governance
  ON gate_policy_versions(tenant_id, workspace_id, governance_status);
CREATE INDEX IF NOT EXISTS idx_gate_policy_versions_current_approval
  ON gate_policy_versions(current_approval_id);

CREATE TABLE IF NOT EXISTS gate_policy_bindings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  policy_id UUID NOT NULL,
  policy_version_id UUID NOT NULL,
  policy_version_hash VARCHAR(80) NOT NULL,
  binding_ref VARCHAR(500) NOT NULL UNIQUE,
  scope_type gate_policy_scope_type NOT NULL,
  scope_id VARCHAR(255),
  scope_key VARCHAR(255) NOT NULL,
  status gate_policy_status NOT NULL DEFAULT 'draft',
  mode gate_policy_mode NOT NULL DEFAULT 'enforce',
  effective_from TIMESTAMPTZ NOT NULL,
  effective_until TIMESTAMPTZ,
  capability_ref VARCHAR(500),
  approval_policy_ref VARCHAR(500),
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_gate_policy_bindings_version_scope
    FOREIGN KEY (policy_version_id, policy_id, tenant_id, workspace_id, policy_version_hash)
    REFERENCES gate_policy_versions(id, policy_id, tenant_id, workspace_id, content_hash)
    ON DELETE RESTRICT,
  CONSTRAINT uq_gate_policy_bindings_idempotency
    UNIQUE (tenant_id, workspace_id, idempotency_key),
  CONSTRAINT uq_gate_policy_bindings_effective_scope
    UNIQUE (tenant_id, workspace_id, policy_id, scope_type, scope_key, effective_from),
  CONSTRAINT chk_gate_policy_bindings_tenant_not_blank CHECK (length(trim(tenant_id)) > 0),
  CONSTRAINT chk_gate_policy_bindings_workspace_not_blank CHECK (length(trim(workspace_id)) > 0),
  CONSTRAINT chk_gate_policy_bindings_scope_identity CHECK (
    (scope_type = 'global' AND scope_id IS NULL AND scope_key = 'global')
    OR
    (scope_type <> 'global' AND scope_id IS NOT NULL AND length(trim(scope_id)) > 0 AND scope_key = scope_id)
  ),
  CONSTRAINT chk_gate_policy_bindings_workspace_scope CHECK (
    scope_type <> 'workspace' OR scope_id = workspace_id
  ),
  CONSTRAINT chk_gate_policy_bindings_effective_window CHECK (
    effective_until IS NULL OR effective_until > effective_from
  ),
  CONSTRAINT chk_gate_policy_bindings_mode CHECK (mode IN ('observe', 'shadow', 'enforce')),
  CONSTRAINT chk_gate_policy_bindings_hash_length CHECK (length(policy_version_hash) = 71),
  CONSTRAINT chk_gate_policy_bindings_hash_prefix CHECK (substr(policy_version_hash, 1, 7) = 'sha256:'),
  CONSTRAINT chk_gate_policy_bindings_request_hash_length CHECK (length(request_hash) = 71),
  CONSTRAINT chk_gate_policy_bindings_request_hash_prefix CHECK (substr(request_hash, 1, 7) = 'sha256:'),
  CONSTRAINT chk_gate_policy_bindings_lock_version CHECK (lock_version > 0)
);

CREATE INDEX IF NOT EXISTS idx_gate_policy_bindings_resolution
  ON gate_policy_bindings(tenant_id, workspace_id, scope_type, scope_key, status);
CREATE INDEX IF NOT EXISTS idx_gate_policy_bindings_version
  ON gate_policy_bindings(policy_version_id);
CREATE INDEX IF NOT EXISTS idx_gate_policy_bindings_effective
  ON gate_policy_bindings(effective_from, effective_until);
CREATE INDEX IF NOT EXISTS idx_gate_policy_bindings_mode_resolution
  ON gate_policy_bindings(tenant_id, workspace_id, scope_type, scope_key, mode, status);

CREATE TABLE IF NOT EXISTS gate_policy_governance_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  operation VARCHAR(80) NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  resource_type VARCHAR(100) NOT NULL,
  resource_id VARCHAR(255) NOT NULL,
  approval_id UUID,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_gate_policy_governance_request_idempotency
    UNIQUE (tenant_id, workspace_id, operation, idempotency_key),
  CONSTRAINT chk_gate_policy_governance_tenant_not_blank CHECK (length(trim(tenant_id)) > 0),
  CONSTRAINT chk_gate_policy_governance_workspace_not_blank CHECK (length(trim(workspace_id)) > 0),
  CONSTRAINT chk_gate_policy_governance_hash_length CHECK (length(request_hash) = 71),
  CONSTRAINT chk_gate_policy_governance_hash_prefix CHECK (substr(request_hash, 1, 7) = 'sha256:')
);

CREATE INDEX IF NOT EXISTS idx_gate_policy_governance_project
  ON gate_policy_governance_requests(project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_gate_policy_governance_resource
  ON gate_policy_governance_requests(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_gate_policy_governance_approval
  ON gate_policy_governance_requests(approval_id);

CREATE TABLE IF NOT EXISTS gate_policy_simulation_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  policy_id UUID NOT NULL REFERENCES gate_policies(id) ON DELETE RESTRICT,
  source_policy_version_id UUID REFERENCES gate_policy_versions(id) ON DELETE SET NULL,
  policy_version_id UUID NOT NULL REFERENCES gate_policy_versions(id) ON DELETE RESTRICT,
  policy_version_hash VARCHAR(80) NOT NULL,
  evaluator_version VARCHAR(80) NOT NULL,
  run_type VARCHAR(24) NOT NULL DEFAULT 'historical',
  status VARCHAR(24) NOT NULL DEFAULT 'queued',
  dataset_fingerprint VARCHAR(80) NOT NULL,
  case_snapshot_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  total_cases INTEGER NOT NULL DEFAULT 0,
  completed_cases INTEGER NOT NULL DEFAULT 0,
  unavailable_cases INTEGER NOT NULL DEFAULT 0,
  failed_cases INTEGER NOT NULL DEFAULT 0,
  error_code VARCHAR(120),
  job_id UUID,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  retention_until TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_gate_policy_simulation_run_idempotency UNIQUE (tenant_id, workspace_id, run_type, idempotency_key),
  CONSTRAINT chk_gate_policy_simulation_run_type CHECK (run_type IN ('historical', 'shadow')),
  CONSTRAINT chk_gate_policy_simulation_run_status CHECK (status IN ('queued', 'running', 'completed', 'partial', 'failed', 'cancelled', 'timed_out')),
  CONSTRAINT chk_gate_policy_simulation_dataset_hash_length CHECK (length(dataset_fingerprint) = 71),
  CONSTRAINT chk_gate_policy_simulation_dataset_hash_prefix CHECK (substr(dataset_fingerprint, 1, 7) = 'sha256:'),
  CONSTRAINT chk_gate_policy_simulation_policy_hash_length CHECK (length(policy_version_hash) = 71),
  CONSTRAINT chk_gate_policy_simulation_policy_hash_prefix CHECK (substr(policy_version_hash, 1, 7) = 'sha256:'),
  CONSTRAINT chk_gate_policy_simulation_request_hash_length CHECK (length(request_hash) = 71),
  CONSTRAINT chk_gate_policy_simulation_request_hash_prefix CHECK (substr(request_hash, 1, 7) = 'sha256:'),
  CONSTRAINT chk_gate_policy_simulation_counts CHECK (total_cases >= 0 AND completed_cases >= 0 AND unavailable_cases >= 0 AND failed_cases >= 0),
  CONSTRAINT chk_gate_policy_simulation_case_refs_array CHECK (jsonb_typeof(case_snapshot_refs) = 'array'),
  CONSTRAINT chk_gate_policy_simulation_summary_object CHECK (jsonb_typeof(summary) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_gate_policy_simulation_project ON gate_policy_simulation_runs(project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_gate_policy_simulation_version ON gate_policy_simulation_runs(policy_version_id, status);
CREATE INDEX IF NOT EXISTS idx_gate_policy_simulation_retention ON gate_policy_simulation_runs(retention_until);

CREATE TABLE IF NOT EXISTS gate_policy_simulation_cases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  simulation_run_id UUID NOT NULL REFERENCES gate_policy_simulation_runs(id) ON DELETE CASCADE,
  case_index INTEGER NOT NULL,
  gate_input_snapshot_id UUID,
  gate_decision_id UUID REFERENCES gate_results(id) ON DELETE SET NULL,
  execution_id UUID REFERENCES executions(id) ON DELETE SET NULL,
  gate_input_snapshot_ref VARCHAR(500) NOT NULL,
  gate_input_snapshot_hash VARCHAR(80) NOT NULL,
  input_fingerprint VARCHAR(80),
  case_snapshot_hash VARCHAR(80) NOT NULL,
  status VARCHAR(24) NOT NULL,
  old_decision VARCHAR(24),
  new_decision VARCHAR(24),
  old_decision_snapshot_hash VARCHAR(80),
  new_decision_snapshot_hash VARCHAR(80),
  reason_diff JSONB NOT NULL DEFAULT '{}'::jsonb,
  false_pass_risk BOOLEAN NOT NULL DEFAULT FALSE,
  new_block BOOLEAN NOT NULL DEFAULT FALSE,
  error_code VARCHAR(120),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_gate_policy_simulation_case_index UNIQUE (simulation_run_id, case_index),
  CONSTRAINT uq_gate_policy_simulation_case_snapshot UNIQUE (simulation_run_id, gate_input_snapshot_ref),
  CONSTRAINT chk_gate_policy_simulation_case_status CHECK (status IN ('completed', 'unavailable', 'failed')),
  CONSTRAINT chk_gate_policy_simulation_reason_diff_object CHECK (jsonb_typeof(reason_diff) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_gate_policy_simulation_case_run ON gate_policy_simulation_cases(simulation_run_id, case_index);
CREATE INDEX IF NOT EXISTS idx_gate_policy_simulation_case_gate ON gate_policy_simulation_cases(gate_decision_id);

CREATE TABLE IF NOT EXISTS gate_policy_binding_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  action VARCHAR(24) NOT NULL,
  mode gate_policy_mode NOT NULL,
  status VARCHAR(24) NOT NULL,
  binding_id UUID NOT NULL REFERENCES gate_policy_bindings(id) ON DELETE RESTRICT,
  previous_binding_id UUID REFERENCES gate_policy_bindings(id) ON DELETE SET NULL,
  policy_version_id UUID NOT NULL REFERENCES gate_policy_versions(id) ON DELETE RESTRICT,
  previous_policy_version_id UUID REFERENCES gate_policy_versions(id) ON DELETE SET NULL,
  simulation_run_id UUID REFERENCES gate_policy_simulation_runs(id) ON DELETE SET NULL,
  approval_id UUID,
  before_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  after_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_gate_policy_binding_history_idempotency UNIQUE (tenant_id, workspace_id, action, idempotency_key),
  CONSTRAINT chk_gate_policy_binding_history_action CHECK (action IN ('mode_change', 'activation', 'rollback')),
  CONSTRAINT chk_gate_policy_binding_history_mode CHECK (mode IN ('observe', 'shadow', 'enforce')),
  CONSTRAINT chk_gate_policy_binding_history_status CHECK (status IN ('applied', 'failed')),
  CONSTRAINT chk_gate_policy_binding_history_before_object CHECK (jsonb_typeof(before_snapshot) = 'object'),
  CONSTRAINT chk_gate_policy_binding_history_after_object CHECK (jsonb_typeof(after_snapshot) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_gate_policy_binding_history_project ON gate_policy_binding_history(project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_gate_policy_binding_history_binding ON gate_policy_binding_history(binding_id);

CREATE OR REPLACE FUNCTION prevent_published_gate_policy_version_update()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.status <> 'draft' AND (
    NEW.policy_id IS DISTINCT FROM OLD.policy_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
    OR NEW.version_number IS DISTINCT FROM OLD.version_number
    OR NEW.version_ref IS DISTINCT FROM OLD.version_ref
    OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
    OR NEW.policy_snapshot IS DISTINCT FROM OLD.policy_snapshot
    OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
    OR NEW.capability_ref IS DISTINCT FROM OLD.capability_ref
    OR NEW.approval_policy_ref IS DISTINCT FROM OLD.approval_policy_ref
  ) THEN
    RAISE EXCEPTION 'published Gate Policy versions are immutable'
      USING ERRCODE = '55000';
  END IF;

  IF NEW.status <> 'draft' AND (
    NEW.policy_id IS DISTINCT FROM OLD.policy_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
    OR NEW.version_number IS DISTINCT FROM OLD.version_number
    OR NEW.version_ref IS DISTINCT FROM OLD.version_ref
    OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
    OR NEW.policy_snapshot IS DISTINCT FROM OLD.policy_snapshot
    OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
    OR NEW.capability_ref IS DISTINCT FROM OLD.capability_ref
    OR NEW.approval_policy_ref IS DISTINCT FROM OLD.approval_policy_ref
  ) THEN
    RAISE EXCEPTION 'publishing a Gate Policy version cannot change frozen content'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_gate_policies_updated_at ON gate_policies;
CREATE TRIGGER trg_gate_policies_updated_at
BEFORE UPDATE ON gate_policies
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_gate_policy_versions_updated_at ON gate_policy_versions;
CREATE TRIGGER trg_gate_policy_versions_updated_at
BEFORE UPDATE ON gate_policy_versions
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_gate_policy_versions_immutable ON gate_policy_versions;
CREATE TRIGGER trg_gate_policy_versions_immutable
BEFORE UPDATE ON gate_policy_versions
FOR EACH ROW EXECUTE FUNCTION prevent_published_gate_policy_version_update();

DROP TRIGGER IF EXISTS trg_gate_policy_bindings_updated_at ON gate_policy_bindings;
CREATE TRIGGER trg_gate_policy_bindings_updated_at
BEFORE UPDATE ON gate_policy_bindings
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_gate_policy_governance_requests_updated_at ON gate_policy_governance_requests;
CREATE TRIGGER trg_gate_policy_governance_requests_updated_at
BEFORE UPDATE ON gate_policy_governance_requests
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_gate_policy_simulation_runs_updated_at ON gate_policy_simulation_runs;
CREATE TRIGGER trg_gate_policy_simulation_runs_updated_at
BEFORE UPDATE ON gate_policy_simulation_runs
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE OR REPLACE FUNCTION prevent_gate_policy_binding_history_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Gate Policy binding history is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_gate_policy_binding_history_immutable ON gate_policy_binding_history;
CREATE TRIGGER trg_gate_policy_binding_history_immutable
BEFORE UPDATE OR DELETE ON gate_policy_binding_history
FOR EACH ROW EXECUTE FUNCTION prevent_gate_policy_binding_history_mutation();

COMMENT ON TABLE gate_policies IS
  'P01 Service-owned Gate Policy identities. This table does not evaluate or write Gate decisions.';
COMMENT ON TABLE gate_policy_versions IS
  'Versioned declarative gate-policy.v1 snapshots with canonical hashes. Published rows are immutable.';
COMMENT ON TABLE gate_policy_bindings IS
  'Tenant/workspace-scoped exact Version refs. P02 resolves only active Enforce bindings; Observe/Shadow remain non-authoritative.';
COMMENT ON TABLE gate_policy_governance_requests IS
  'P04 Service-owned idempotency journal for Gate Policy management operations; never executes Gate or Skill.';
COMMENT ON TABLE gate_policy_simulation_runs IS
  'P06 immutable-dataset, non-authoritative historical and Shadow Gate Policy simulation runs.';
COMMENT ON TABLE gate_policy_simulation_cases IS
  'P06 backend-computed old/new Gate diffs; never authoritative Gate decisions.';
COMMENT ON TABLE gate_policy_binding_history IS
  'P06 append-only mode/activation/rollback binding history.';

-- =========================================================
-- 10.1 Traceability & Coverage Matrix 显式关系表
-- =========================================================

CREATE TABLE IF NOT EXISTS requirement_item_test_points (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requirement_item_id VARCHAR(255) NOT NULL,
  test_point_id UUID NOT NULL REFERENCES test_assets(id) ON DELETE CASCADE,
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE CASCADE,
  relation_type VARCHAR(80) NOT NULL DEFAULT 'covers',
  scope_id VARCHAR(255) NOT NULL,
  status traceability_relation_status NOT NULL DEFAULT 'candidate',
  source traceability_relation_source NOT NULL,
  confidence NUMERIC(5,4) NOT NULL DEFAULT 1.0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  validated_at TIMESTAMPTZ,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  invalidated_at TIMESTAMPTZ,
  invalidated_reason TEXT,
  trace_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_requirement_item_test_points_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE TABLE IF NOT EXISTS test_point_test_cases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  test_point_id UUID NOT NULL REFERENCES test_assets(id) ON DELETE CASCADE,
  test_case_id UUID NOT NULL REFERENCES test_assets(id) ON DELETE CASCADE,
  relation_type VARCHAR(80) NOT NULL DEFAULT 'covers',
  scope_id VARCHAR(255) NOT NULL,
  status traceability_relation_status NOT NULL DEFAULT 'candidate',
  source traceability_relation_source NOT NULL,
  confidence NUMERIC(5,4) NOT NULL DEFAULT 1.0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  validated_at TIMESTAMPTZ,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  invalidated_at TIMESTAMPTZ,
  invalidated_reason TEXT,
  trace_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_test_point_test_cases_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE TABLE IF NOT EXISTS test_case_execution_tasks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  test_case_id UUID NOT NULL REFERENCES test_assets(id) ON DELETE CASCADE,
  execution_task_id UUID NOT NULL REFERENCES execution_tasks(id) ON DELETE CASCADE,
  run_id UUID,
  relation_type VARCHAR(80) NOT NULL DEFAULT 'covers',
  scope_id VARCHAR(255) NOT NULL,
  status traceability_relation_status NOT NULL DEFAULT 'candidate',
  source traceability_relation_source NOT NULL,
  confidence NUMERIC(5,4) NOT NULL DEFAULT 1.0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  validated_at TIMESTAMPTZ,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  invalidated_at TIMESTAMPTZ,
  invalidated_reason TEXT,
  trace_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_test_case_execution_tasks_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE TABLE IF NOT EXISTS execution_task_evidence_artifacts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_task_id UUID NOT NULL REFERENCES execution_tasks(id) ON DELETE CASCADE,
  evidence_artifact_id UUID NOT NULL REFERENCES execution_artifacts(id) ON DELETE CASCADE,
  artifact_type VARCHAR(80) NOT NULL,
  relation_type VARCHAR(80) NOT NULL DEFAULT 'covers',
  scope_id VARCHAR(255) NOT NULL,
  status traceability_relation_status NOT NULL DEFAULT 'candidate',
  source traceability_relation_source NOT NULL,
  confidence NUMERIC(5,4) NOT NULL DEFAULT 1.0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  validated_at TIMESTAMPTZ,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  invalidated_at TIMESTAMPTZ,
  invalidated_reason TEXT,
  trace_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_execution_task_evidence_artifacts_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE TABLE IF NOT EXISTS evidence_raw_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  evidence_artifact_id UUID NOT NULL REFERENCES execution_artifacts(id) ON DELETE CASCADE,
  raw_finding_id UUID NOT NULL REFERENCES raw_findings(id) ON DELETE CASCADE,
  relation_type VARCHAR(80) NOT NULL DEFAULT 'supports',
  scope_id VARCHAR(255) NOT NULL,
  status traceability_relation_status NOT NULL DEFAULT 'candidate',
  source traceability_relation_source NOT NULL,
  confidence NUMERIC(5,4) NOT NULL DEFAULT 1.0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  validated_at TIMESTAMPTZ,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  invalidated_at TIMESTAMPTZ,
  invalidated_reason TEXT,
  trace_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_evidence_raw_findings_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE TABLE IF NOT EXISTS raw_normalized_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  raw_finding_id UUID NOT NULL REFERENCES raw_findings(id) ON DELETE CASCADE,
  normalized_finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  normalization_method VARCHAR(100) NOT NULL,
  dedupe_key VARCHAR(255) NOT NULL,
  merge_group_id VARCHAR(255),
  relation_type VARCHAR(80) NOT NULL DEFAULT 'normalizes',
  scope_id VARCHAR(255) NOT NULL,
  status traceability_relation_status NOT NULL DEFAULT 'candidate',
  source traceability_relation_source NOT NULL,
  confidence NUMERIC(5,4) NOT NULL DEFAULT 1.0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  validated_at TIMESTAMPTZ,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  invalidated_at TIMESTAMPTZ,
  invalidated_reason TEXT,
  trace_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_raw_normalized_findings_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE TABLE IF NOT EXISTS normalized_finding_gate_decisions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  normalized_finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  gate_decision_id UUID NOT NULL REFERENCES gate_results(id) ON DELETE CASCADE,
  impact VARCHAR(80) NOT NULL,
  reason TEXT NOT NULL,
  relation_type VARCHAR(80) NOT NULL DEFAULT 'impacts',
  scope_id VARCHAR(255) NOT NULL,
  status traceability_relation_status NOT NULL DEFAULT 'candidate',
  source traceability_relation_source NOT NULL,
  confidence NUMERIC(5,4) NOT NULL DEFAULT 1.0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  validated_at TIMESTAMPTZ,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  invalidated_at TIMESTAMPTZ,
  invalidated_reason TEXT,
  trace_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_normalized_finding_gate_decisions_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE TABLE IF NOT EXISTS gate_decision_replay_exports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  gate_decision_id UUID NOT NULL REFERENCES gate_results(id) ON DELETE CASCADE,
  replay_export_id VARCHAR(255) NOT NULL,
  export_hash VARCHAR(80) NOT NULL,
  relation_type VARCHAR(80) NOT NULL DEFAULT 'included_in_replay',
  scope_id VARCHAR(255) NOT NULL,
  status traceability_relation_status NOT NULL DEFAULT 'candidate',
  source traceability_relation_source NOT NULL,
  confidence NUMERIC(5,4) NOT NULL DEFAULT 1.0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  validated_at TIMESTAMPTZ,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  invalidated_at TIMESTAMPTZ,
  invalidated_reason TEXT,
  trace_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_gate_decision_replay_exports_confidence CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_requirement_item_test_points_effective
  ON requirement_item_test_points(requirement_item_id, test_point_id, relation_type, scope_id)
  WHERE status IN ('confirmed', 'system_verified');
CREATE UNIQUE INDEX IF NOT EXISTS uq_test_point_test_cases_effective
  ON test_point_test_cases(test_point_id, test_case_id, relation_type, scope_id)
  WHERE status IN ('confirmed', 'system_verified');
CREATE UNIQUE INDEX IF NOT EXISTS uq_test_case_execution_tasks_effective
  ON test_case_execution_tasks(test_case_id, execution_task_id, relation_type, scope_id)
  WHERE status IN ('confirmed', 'system_verified');
CREATE UNIQUE INDEX IF NOT EXISTS uq_execution_task_evidence_artifacts_effective
  ON execution_task_evidence_artifacts(execution_task_id, evidence_artifact_id, relation_type, scope_id)
  WHERE status IN ('confirmed', 'system_verified');
CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_raw_findings_effective
  ON evidence_raw_findings(evidence_artifact_id, raw_finding_id, relation_type, scope_id)
  WHERE status IN ('confirmed', 'system_verified');
CREATE UNIQUE INDEX IF NOT EXISTS uq_raw_normalized_findings_effective
  ON raw_normalized_findings(raw_finding_id, normalized_finding_id, relation_type, scope_id)
  WHERE status IN ('confirmed', 'system_verified');
CREATE UNIQUE INDEX IF NOT EXISTS uq_normalized_finding_gate_decisions_effective
  ON normalized_finding_gate_decisions(normalized_finding_id, gate_decision_id, relation_type, scope_id)
  WHERE status IN ('confirmed', 'system_verified');
CREATE UNIQUE INDEX IF NOT EXISTS uq_gate_decision_replay_exports_effective
  ON gate_decision_replay_exports(gate_decision_id, replay_export_id, relation_type, scope_id)
  WHERE status IN ('confirmed', 'system_verified');

CREATE INDEX IF NOT EXISTS idx_requirement_item_test_points_requirement ON requirement_item_test_points(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_requirement_item_test_points_test_point ON requirement_item_test_points(test_point_id);
CREATE INDEX IF NOT EXISTS idx_requirement_item_test_points_status ON requirement_item_test_points(status);
CREATE INDEX IF NOT EXISTS idx_test_point_test_cases_test_point ON test_point_test_cases(test_point_id);
CREATE INDEX IF NOT EXISTS idx_test_point_test_cases_test_case ON test_point_test_cases(test_case_id);
CREATE INDEX IF NOT EXISTS idx_test_point_test_cases_status ON test_point_test_cases(status);
CREATE INDEX IF NOT EXISTS idx_test_case_execution_tasks_test_case ON test_case_execution_tasks(test_case_id);
CREATE INDEX IF NOT EXISTS idx_test_case_execution_tasks_task ON test_case_execution_tasks(execution_task_id);
CREATE INDEX IF NOT EXISTS idx_test_case_execution_tasks_run ON test_case_execution_tasks(run_id);
CREATE INDEX IF NOT EXISTS idx_test_case_execution_tasks_status ON test_case_execution_tasks(status);
CREATE INDEX IF NOT EXISTS idx_execution_task_evidence_artifacts_task ON execution_task_evidence_artifacts(execution_task_id);
CREATE INDEX IF NOT EXISTS idx_execution_task_evidence_artifacts_artifact ON execution_task_evidence_artifacts(evidence_artifact_id);
CREATE INDEX IF NOT EXISTS idx_execution_task_evidence_artifacts_status ON execution_task_evidence_artifacts(status);
CREATE INDEX IF NOT EXISTS idx_evidence_raw_findings_artifact ON evidence_raw_findings(evidence_artifact_id);
CREATE INDEX IF NOT EXISTS idx_evidence_raw_findings_raw ON evidence_raw_findings(raw_finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_raw_findings_status ON evidence_raw_findings(status);
CREATE INDEX IF NOT EXISTS idx_raw_normalized_findings_raw ON raw_normalized_findings(raw_finding_id);
CREATE INDEX IF NOT EXISTS idx_raw_normalized_findings_normalized ON raw_normalized_findings(normalized_finding_id);
CREATE INDEX IF NOT EXISTS idx_raw_normalized_findings_status ON raw_normalized_findings(status);
CREATE INDEX IF NOT EXISTS idx_normalized_finding_gate_decisions_finding ON normalized_finding_gate_decisions(normalized_finding_id);
CREATE INDEX IF NOT EXISTS idx_normalized_finding_gate_decisions_gate ON normalized_finding_gate_decisions(gate_decision_id);
CREATE INDEX IF NOT EXISTS idx_normalized_finding_gate_decisions_status ON normalized_finding_gate_decisions(status);
CREATE INDEX IF NOT EXISTS idx_gate_decision_replay_exports_gate ON gate_decision_replay_exports(gate_decision_id);
CREATE INDEX IF NOT EXISTS idx_gate_decision_replay_exports_export ON gate_decision_replay_exports(replay_export_id);
CREATE INDEX IF NOT EXISTS idx_gate_decision_replay_exports_status ON gate_decision_replay_exports(status);

-- =========================================================
-- 10.1A Replay Repository frozen metadata and section index
-- =========================================================

CREATE TABLE IF NOT EXISTS replay_repository_entries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  replay_id VARCHAR(120) NOT NULL,
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE RESTRICT,
  schema_version VARCHAR(80) NOT NULL DEFAULT 'phase8.replay-repository.v1',
  source_replay_export_hash VARCHAR(80) NOT NULL,
  export_payload_hash VARCHAR(80) NOT NULL,
  manifest_hash VARCHAR(80) NOT NULL,
  payload_hash VARCHAR(80) NOT NULL,
  manifest JSONB NOT NULL DEFAULT '{}'::jsonb,
  summary_projection JSONB NOT NULL DEFAULT '{}'::jsonb,
  section_index JSONB NOT NULL DEFAULT '[]'::jsonb,
  storage_adapter VARCHAR(40) NOT NULL DEFAULT 'local',
  redaction_status VARCHAR(40) NOT NULL DEFAULT 'redacted',
  validity_status VARCHAR(40) NOT NULL DEFAULT 'valid',
  approval_mode VARCHAR(40) NOT NULL DEFAULT 'always',
  approval_state VARCHAR(40) NOT NULL DEFAULT 'approved',
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  retention_policy VARCHAR(80) NOT NULL DEFAULT 'default',
  retention_until TIMESTAMPTZ,
  legal_hold BOOLEAN NOT NULL DEFAULT FALSE,
  archived_at TIMESTAMPTZ,
  purge_eligible_at TIMESTAMPTZ,
  retention_status VARCHAR(40) NOT NULL DEFAULT 'active',
  frozen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_replay_repository_entries_replay_id UNIQUE (replay_id),
  CONSTRAINT uq_replay_repository_entries_export_hash UNIQUE (source_replay_export_hash),
  CONSTRAINT chk_replay_repository_entries_approval_mode CHECK (approval_mode IN ('always', 'policy_only', 'threshold')),
  CONSTRAINT chk_replay_repository_entries_approval_state CHECK (approval_state IN ('pending', 'approved', 'not_required', 'rejected', 'cancelled')),
  CONSTRAINT chk_replay_repository_entries_retention_status CHECK (retention_status IN ('active', 'archived', 'purge_eligible', 'purged', 'legal_hold')),
  CONSTRAINT chk_replay_repository_entries_validity_status CHECK (validity_status IN ('valid', 'invalid', 'unknown')),
  CONSTRAINT chk_replay_repository_entries_manifest_object CHECK (jsonb_typeof(manifest) = 'object'),
  CONSTRAINT chk_replay_repository_entries_summary_object CHECK (jsonb_typeof(summary_projection) = 'object'),
  CONSTRAINT chk_replay_repository_entries_section_index_array CHECK (jsonb_typeof(section_index) = 'array'),
  CONSTRAINT chk_replay_repository_entries_approval_refs_array CHECK (jsonb_typeof(approval_refs) = 'array'),
  CONSTRAINT chk_replay_repository_entries_guardrail_refs_array CHECK (jsonb_typeof(guardrail_event_refs) = 'array'),
  CONSTRAINT chk_replay_repository_entries_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_replay_repository_entries_execution
  ON replay_repository_entries(execution_id);
CREATE INDEX IF NOT EXISTS idx_replay_repository_entries_created_at
  ON replay_repository_entries(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_replay_repository_entries_retention
  ON replay_repository_entries(retention_status);

DROP TRIGGER IF EXISTS trg_replay_repository_entries_updated_at ON replay_repository_entries;
CREATE TRIGGER trg_replay_repository_entries_updated_at
BEFORE UPDATE ON replay_repository_entries
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS replay_repository_sections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  replay_entry_id UUID NOT NULL REFERENCES replay_repository_entries(id) ON DELETE CASCADE,
  section_name VARCHAR(120) NOT NULL,
  storage_ref VARCHAR(500) NOT NULL,
  content_hash VARCHAR(80) NOT NULL,
  byte_size INTEGER NOT NULL DEFAULT 0,
  compression VARCHAR(40) NOT NULL DEFAULT 'none',
  redaction_status VARCHAR(40) NOT NULL DEFAULT 'redacted',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_replay_repository_sections_entry_section UNIQUE (replay_entry_id, section_name),
  CONSTRAINT chk_replay_repository_sections_byte_size CHECK (byte_size >= 0)
);

CREATE INDEX IF NOT EXISTS idx_replay_repository_sections_entry
  ON replay_repository_sections(replay_entry_id);
CREATE INDEX IF NOT EXISTS idx_replay_repository_sections_name
  ON replay_repository_sections(section_name);

CREATE TABLE IF NOT EXISTS replay_governance_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scope_type VARCHAR(40) NOT NULL DEFAULT 'global',
  scope_id VARCHAR(120) NOT NULL DEFAULT 'global',
  approval_mode VARCHAR(40) NOT NULL DEFAULT 'always',
  threshold_level VARCHAR(40) NOT NULL DEFAULT 'high',
  policy_rules JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_replay_governance_policies_scope UNIQUE (scope_type, scope_id),
  CONSTRAINT chk_replay_governance_policies_approval_mode CHECK (approval_mode IN ('always', 'policy_only', 'threshold')),
  CONSTRAINT chk_replay_governance_policies_threshold_level CHECK (threshold_level IN ('low', 'medium', 'high')),
  CONSTRAINT chk_replay_governance_policies_rules_object CHECK (jsonb_typeof(policy_rules) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_replay_governance_policies_scope
  ON replay_governance_policies(scope_type, scope_id);

DROP TRIGGER IF EXISTS trg_replay_governance_policies_updated_at ON replay_governance_policies;
CREATE TRIGGER trg_replay_governance_policies_updated_at
BEFORE UPDATE ON replay_governance_policies
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS replay_exports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  export_id VARCHAR(120) NOT NULL,
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  schema_version VARCHAR(80) NOT NULL DEFAULT 'phase8.replay-export.v1',
  export_hash VARCHAR(80) NOT NULL,
  export_payload_hash VARCHAR(80) NOT NULL,
  storage_ref VARCHAR(500),
  export_artifact_ref VARCHAR(500),
  redaction_status VARCHAR(40) NOT NULL,
  trace_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  request_id VARCHAR(255),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_replay_exports_execution_payload_hash UNIQUE (execution_id, export_payload_hash),
  CONSTRAINT uq_replay_exports_export_id UNIQUE (export_id),
  CONSTRAINT uq_replay_exports_export_hash UNIQUE (export_hash),
  CONSTRAINT chk_replay_exports_trace_refs_array CHECK (jsonb_typeof(trace_refs) = 'array'),
  CONSTRAINT chk_replay_exports_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array'),
  CONSTRAINT chk_replay_exports_payload_object CHECK (jsonb_typeof(payload) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_replay_exports_execution ON replay_exports(execution_id);
CREATE INDEX IF NOT EXISTS idx_replay_exports_created_at ON replay_exports(created_at DESC);

COMMENT ON TABLE replay_exports IS
  'Service-owned frozen Replay Export metadata. payload stores the canonical package inline through 64 MiB or a phase8.replay-export-storage-manifest.v1 object for an ArtifactStorageAdapter-backed package; export hashes remain authoritative for the complete frozen package.';

-- =========================================================
-- 10.2 Coverage Proof Bundle snapshot/proof storage
-- =========================================================

CREATE TABLE IF NOT EXISTS traceability_snapshots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE CASCADE,
  scope_id VARCHAR(255) NOT NULL,
  traceability_snapshot_ref VARCHAR(255) NOT NULL,
  traceability_snapshot_hash VARCHAR(80) NOT NULL,
  traceability_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  coverage_summary_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  coverage_matrix_snapshot_ref VARCHAR(255) NOT NULL,
  coverage_matrix_snapshot_hash VARCHAR(80) NOT NULL,
  coverage_matrix_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  relation_snapshot JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_traceability_snapshots_hash UNIQUE (traceability_snapshot_hash)
);

CREATE INDEX IF NOT EXISTS idx_traceability_snapshots_requirement ON traceability_snapshots(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_traceability_snapshots_scope ON traceability_snapshots(scope_id);

CREATE TABLE IF NOT EXISTS gate_input_snapshots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  gate_decision_id UUID NOT NULL REFERENCES gate_results(id) ON DELETE CASCADE,
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  gate_input_snapshot_ref VARCHAR(255) NOT NULL,
  gate_input_snapshot_hash VARCHAR(80) NOT NULL,
  gate_input_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  policy_snapshot_ref VARCHAR(255),
  policy_snapshot_hash VARCHAR(80),
  policy_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_gate_input_snapshots_hash UNIQUE (gate_input_snapshot_hash)
);

CREATE INDEX IF NOT EXISTS idx_gate_input_snapshots_gate ON gate_input_snapshots(gate_decision_id);
CREATE INDEX IF NOT EXISTS idx_gate_input_snapshots_execution ON gate_input_snapshots(execution_id);

ALTER TABLE gate_policy_simulation_cases
  ADD CONSTRAINT fk_gate_policy_simulation_cases_input_snapshot
  FOREIGN KEY (gate_input_snapshot_id) REFERENCES gate_input_snapshots(id) ON DELETE SET NULL;

COMMENT ON TABLE gate_input_snapshots IS
  'Service-owned canonical Gate input freeze. gate_input_snapshot stores the full snapshot inline through 64 MiB or a phase8.gate-input-snapshot-manifest.v1 object; gate_input_snapshot_hash always hashes the complete canonical input, never only the manifest.';

CREATE TABLE IF NOT EXISTS coverage_proof_bundles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE CASCADE,
  requirement_item_id VARCHAR(255) NOT NULL,
  traceability_snapshot_id UUID NOT NULL REFERENCES traceability_snapshots(id) ON DELETE RESTRICT,
  gate_input_snapshot_id UUID REFERENCES gate_input_snapshots(id) ON DELETE SET NULL,
  coverage_status coverage_status NOT NULL,
  proof_status proof_status NOT NULL,
  proof_bundle JSONB NOT NULL DEFAULT '{}'::jsonb,
  proof_chain JSONB NOT NULL DEFAULT '[]'::jsonb,
  proof_issues JSONB NOT NULL DEFAULT '[]'::jsonb,
  replay_export_ref VARCHAR(255),
  replay_export_hash VARCHAR(80),
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_coverage_proof_bundles_requirement
  ON coverage_proof_bundles(requirement_version_id, requirement_item_id);
CREATE INDEX IF NOT EXISTS idx_coverage_proof_bundles_snapshot
  ON coverage_proof_bundles(traceability_snapshot_id);
CREATE INDEX IF NOT EXISTS idx_coverage_proof_bundles_status
  ON coverage_proof_bundles(coverage_status, proof_status);

CREATE TABLE IF NOT EXISTS coverage_proof_replay_refs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  coverage_proof_bundle_id UUID NOT NULL REFERENCES coverage_proof_bundles(id) ON DELETE CASCADE,
  replay_export_ref VARCHAR(255) NOT NULL,
  replay_export_hash VARCHAR(80) NOT NULL,
  traceability_snapshot_ref VARCHAR(255) NOT NULL,
  traceability_snapshot_hash VARCHAR(80) NOT NULL,
  coverage_matrix_snapshot_ref VARCHAR(255) NOT NULL,
  coverage_matrix_snapshot_hash VARCHAR(80) NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_coverage_proof_replay_refs_bundle_hash UNIQUE (coverage_proof_bundle_id, replay_export_hash)
);

CREATE INDEX IF NOT EXISTS idx_coverage_proof_replay_refs_bundle
  ON coverage_proof_replay_refs(coverage_proof_bundle_id);
CREATE INDEX IF NOT EXISTS idx_coverage_proof_replay_refs_export
  ON coverage_proof_replay_refs(replay_export_ref);
CREATE INDEX IF NOT EXISTS idx_coverage_proof_replay_refs_hash
  ON coverage_proof_replay_refs(replay_export_hash);

CREATE TABLE IF NOT EXISTS knowledge_promotion_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source VARCHAR(80) NOT NULL,
  source_correction_id UUID NOT NULL REFERENCES correction_proposals(id) ON DELETE CASCADE,
  correction_validation_id UUID NOT NULL REFERENCES correction_validations(id) ON DELETE RESTRICT,
  replay_validation_id VARCHAR(255),
  replay_validation_ref JSONB NOT NULL DEFAULT '{}'::jsonb,
  coverage_proof_bundle_id UUID NOT NULL REFERENCES coverage_proof_bundles(id) ON DELETE RESTRICT,
  coverage_proof_ref JSONB NOT NULL DEFAULT '{}'::jsonb,
  knowledge_entry_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  approval_state VARCHAR(40) NOT NULL,
  policy_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  rollback_ref JSONB NOT NULL DEFAULT '{}'::jsonb,
  supersede_ref JSONB NOT NULL DEFAULT '{}'::jsonb,
  projection_state VARCHAR(40) NOT NULL DEFAULT 'skipped',
  projection_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  status VARCHAR(40) NOT NULL DEFAULT 'pending',
  promoted_at TIMESTAMPTZ,
  promoted_by UUID REFERENCES users(id) ON DELETE SET NULL,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  contract_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  request_id VARCHAR(255) NOT NULL,
  idempotency_key VARCHAR(255),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_knowledge_promotion_records_status CHECK (
    status IN ('pending', 'promoted', 'rejected', 'rolled_back', 'superseded')
  ),
  CONSTRAINT chk_knowledge_promotion_records_approval_state CHECK (
    approval_state IN ('satisfied', 'not_required')
  ),
  CONSTRAINT chk_knowledge_promotion_records_projection_state CHECK (
    projection_state IN ('skipped', 'projected', 'projection_failed', 'retry')
  ),
  CONSTRAINT uq_knowledge_promotion_records_proposal_idempotency UNIQUE (source_correction_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_knowledge_promotion_records_source
  ON knowledge_promotion_records(source_correction_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_promotion_records_validation
  ON knowledge_promotion_records(correction_validation_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_promotion_records_coverage_proof
  ON knowledge_promotion_records(coverage_proof_bundle_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_promotion_records_status
  ON knowledge_promotion_records(status);

CREATE TRIGGER trg_knowledge_promotion_records_updated_at
BEFORE UPDATE ON knowledge_promotion_records
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- =========================================================
-- 11. 记忆系统
-- =========================================================

CREATE TABLE IF NOT EXISTS memories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type memory_type NOT NULL,
  scope memory_scope NOT NULL,
  namespace VARCHAR(255) NOT NULL,
  content TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  embedding JSONB,
  source_type VARCHAR(100),
  source_ref VARCHAR(255),
  heat_score NUMERIC(10,4) NOT NULL DEFAULT 0,
  archived BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_memories_type ON memories(type);
CREATE INDEX IF NOT EXISTS idx_memories_scope ON memories(scope);
CREATE INDEX IF NOT EXISTS idx_memories_namespace ON memories(namespace);
CREATE INDEX IF NOT EXISTS idx_memories_archived ON memories(archived);
CREATE INDEX IF NOT EXISTS idx_memories_heat_score ON memories(heat_score DESC);

CREATE TRIGGER trg_memories_updated_at
BEFORE UPDATE ON memories
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- 可选向量索引
-- Optional pgvector index if the deployment promotes embedding storage to vector(1536).
-- CREATE INDEX IF NOT EXISTS idx_memories_embedding_ivfflat
-- ON memories USING ivfflat (embedding vector_cosine_ops)
-- WITH (lists = 100);

CREATE TABLE IF NOT EXISTS memory_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_type VARCHAR(50) NOT NULL, -- summarize/compress/consolidate
  scope memory_scope NOT NULL,
  namespace VARCHAR(255),
  status job_status NOT NULL DEFAULT 'queued',
  progress INTEGER NOT NULL DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
  result_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_message TEXT,
  started_at TIMESTAMPTZ,
  ended_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_memory_jobs_status ON memory_jobs(status);
CREATE INDEX IF NOT EXISTS idx_memory_jobs_scope ON memory_jobs(scope);

CREATE TRIGGER trg_memory_jobs_updated_at
BEFORE UPDATE ON memory_jobs
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- =========================================================
-- 12. Agent 运行
-- =========================================================

CREATE TABLE IF NOT EXISTS agent_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_id UUID REFERENCES executions(id) ON DELETE CASCADE,
  task_id UUID REFERENCES execution_tasks(id) ON DELETE CASCADE,
  trace_id UUID,
  agent_name VARCHAR(100) NOT NULL,
  status agent_run_status NOT NULL DEFAULT 'queued',
  input_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  output_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  model_id UUID REFERENCES models(id) ON DELETE SET NULL,
  latency_ms INTEGER,
  error_message TEXT,
  started_at TIMESTAMPTZ,
  ended_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_runs_execution_id ON agent_runs(execution_id);
CREATE INDEX IF NOT EXISTS idx_agent_runs_task_id ON agent_runs(task_id);
CREATE INDEX IF NOT EXISTS idx_agent_runs_agent_name ON agent_runs(agent_name);
CREATE INDEX IF NOT EXISTS idx_agent_runs_status ON agent_runs(status);
CREATE INDEX IF NOT EXISTS idx_agent_runs_model_id ON agent_runs(model_id);
CREATE INDEX IF NOT EXISTS idx_agent_runs_trace_id ON agent_runs(trace_id);

-- =========================================================
-- 13. Guardrails
-- =========================================================

CREATE TABLE IF NOT EXISTS guardrail_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id VARCHAR(255) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  scope guardrail_scope NOT NULL,
  status guardrail_policy_status NOT NULL DEFAULT 'active',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  decision_override guardrail_decision,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_guardrail_policies_scope ON guardrail_policies(scope);
CREATE INDEX IF NOT EXISTS idx_guardrail_policies_status ON guardrail_policies(status);
CREATE INDEX IF NOT EXISTS idx_guardrail_policies_enabled ON guardrail_policies(enabled);

CREATE TRIGGER trg_guardrail_policies_updated_at
BEFORE UPDATE ON guardrail_policies
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS guardrail_policy_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id UUID NOT NULL REFERENCES guardrail_policies(id) ON DELETE CASCADE,
  rule_id VARCHAR(255) NOT NULL,
  version_no INTEGER NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  status guardrail_policy_status NOT NULL,
  decision_override guardrail_decision,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  change_reason TEXT,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_guardrail_policy_versions_policy_version UNIQUE (policy_id, version_no),
  CONSTRAINT chk_guardrail_policy_versions_config_object CHECK (jsonb_typeof(config) = 'object'),
  CONSTRAINT chk_guardrail_policy_versions_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_guardrail_policy_versions_rule
  ON guardrail_policy_versions(rule_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_policy_versions_policy
  ON guardrail_policy_versions(policy_id);

CREATE TABLE IF NOT EXISTS guardrail_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id UUID REFERENCES guardrail_policies(id) ON DELETE SET NULL,
  policy_version_id UUID REFERENCES guardrail_policy_versions(id) ON DELETE SET NULL,
  rule_id VARCHAR(255) NOT NULL,
  decision guardrail_decision NOT NULL,
  execution_id UUID REFERENCES executions(id) ON DELETE SET NULL,
  trace_id UUID,
  agent_run_id UUID REFERENCES agent_runs(id) ON DELETE SET NULL,
  skill_invocation_id UUID,
  connector_binding_id UUID,
  tool_call_id UUID,
  request_id VARCHAR(255),
  severity VARCHAR(50),
  message TEXT NOT NULL,
  evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_guardrail_events_evidence_is_array CHECK (jsonb_typeof(evidence) = 'array')
);

ALTER TABLE guardrail_events
  ADD COLUMN IF NOT EXISTS skill_invocation_id UUID,
  ADD COLUMN IF NOT EXISTS connector_binding_id UUID,
  ADD COLUMN IF NOT EXISTS tool_call_id UUID;

CREATE INDEX IF NOT EXISTS idx_guardrail_events_policy_id ON guardrail_events(policy_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_events_rule_id ON guardrail_events(rule_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_events_decision ON guardrail_events(decision);
CREATE INDEX IF NOT EXISTS idx_guardrail_events_execution_id ON guardrail_events(execution_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_events_trace_id ON guardrail_events(trace_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_events_agent_run_id ON guardrail_events(agent_run_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_events_skill_invocation_id ON guardrail_events(skill_invocation_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_events_connector_binding_id ON guardrail_events(connector_binding_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_events_tool_call_id ON guardrail_events(tool_call_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_events_created_at ON guardrail_events(created_at DESC);

-- =========================================================
-- 14. 审批
-- =========================================================

CREATE TABLE IF NOT EXISTS approvals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type approval_type NOT NULL,
  resource_type VARCHAR(100) NOT NULL,
  resource_id VARCHAR(255) NOT NULL,
  summary TEXT NOT NULL,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  status approval_status NOT NULL DEFAULT 'pending',
  requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
  decided_by UUID REFERENCES users(id) ON DELETE SET NULL,
  decision_comment TEXT,
  decided_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
CREATE INDEX IF NOT EXISTS idx_approvals_type ON approvals(type);
CREATE INDEX IF NOT EXISTS idx_approvals_resource_type ON approvals(resource_type);
CREATE INDEX IF NOT EXISTS idx_approvals_resource_id ON approvals(resource_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_approvals_pending_resource
  ON approvals(type, resource_type, resource_id)
  WHERE status = 'pending';

ALTER TABLE gate_policy_versions
  ADD CONSTRAINT fk_gate_policy_versions_current_approval
  FOREIGN KEY (current_approval_id) REFERENCES approvals(id) ON DELETE SET NULL;

ALTER TABLE gate_policy_governance_requests
  ADD CONSTRAINT fk_gate_policy_governance_request_approval
  FOREIGN KEY (approval_id) REFERENCES approvals(id) ON DELETE SET NULL;

ALTER TABLE gate_policy_binding_history
  ADD CONSTRAINT fk_gate_policy_binding_history_approval
  FOREIGN KEY (approval_id) REFERENCES approvals(id) ON DELETE SET NULL;

CREATE TRIGGER trg_approvals_updated_at
BEFORE UPDATE ON approvals
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- =========================================================
-- 15. 作业队列抽象
-- =========================================================

CREATE TABLE IF NOT EXISTS jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_type VARCHAR(100) NOT NULL,
  status job_status NOT NULL DEFAULT 'queued',
  priority INTEGER NOT NULL DEFAULT 100,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  result_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  result_ref VARCHAR(255),
  error_message TEXT,
  progress INTEGER NOT NULL DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
  idempotency_key VARCHAR(255),
  started_at TIMESTAMPTZ,
  ended_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_job_type ON jobs(job_type);
CREATE INDEX IF NOT EXISTS idx_jobs_priority ON jobs(priority DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at DESC);

ALTER TABLE gate_policy_simulation_runs
  ADD CONSTRAINT fk_gate_policy_simulation_runs_job
  FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE SET NULL;

CREATE TRIGGER trg_jobs_updated_at
BEFORE UPDATE ON jobs
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- =========================================================
-- 16. Trace 与审计
-- =========================================================

-- =========================================================
-- 16.0 Batch 5 Exploratory Testing Workbench
-- =========================================================

CREATE TABLE IF NOT EXISTS exploratory_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  environment_id UUID NOT NULL REFERENCES project_environments(id) ON DELETE RESTRICT,
  backing_plan_id UUID NOT NULL REFERENCES test_plans(id) ON DELETE RESTRICT,
  backing_execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE RESTRICT,
  charter TEXT NOT NULL,
  scope JSONB NOT NULL DEFAULT '[]'::jsonb,
  timebox_minutes INTEGER NOT NULL,
  tester_id UUID REFERENCES users(id) ON DELETE SET NULL,
  tester_name VARCHAR(255) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ended_at TIMESTAMPTZ,
  debrief JSONB NOT NULL DEFAULT '{}'::jsonb,
  report_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_exploratory_sessions_status CHECK (status IN ('active', 'completed', 'cancelled')),
  CONSTRAINT chk_exploratory_sessions_timebox CHECK (timebox_minutes > 0),
  CONSTRAINT chk_exploratory_sessions_scope_array CHECK (jsonb_typeof(scope) = 'array'),
  CONSTRAINT chk_exploratory_sessions_replay_refs_array CHECK (jsonb_typeof(replay_refs) = 'array')
);

COMMENT ON TABLE exploratory_sessions IS 'Service-owned exploratory testing sessions. Backing execution anchors evidence, normalized Findings, trace, and replay refs; this is not a Skill workflow.';

CREATE INDEX IF NOT EXISTS idx_exploratory_sessions_project ON exploratory_sessions(project_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_sessions_environment ON exploratory_sessions(environment_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_sessions_execution ON exploratory_sessions(backing_execution_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_sessions_status ON exploratory_sessions(status);
CREATE INDEX IF NOT EXISTS idx_exploratory_sessions_created_at ON exploratory_sessions(created_at DESC);

CREATE TRIGGER trg_exploratory_sessions_updated_at
BEFORE UPDATE ON exploratory_sessions
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS exploratory_session_notes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id UUID NOT NULL REFERENCES exploratory_sessions(id) ON DELETE CASCADE,
  note_type VARCHAR(32) NOT NULL,
  content TEXT NOT NULL,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_exploratory_session_notes_type CHECK (note_type IN ('note', 'observation', 'risk', 'question')),
  CONSTRAINT chk_exploratory_session_notes_evidence_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
  CONSTRAINT chk_exploratory_session_notes_replay_array CHECK (jsonb_typeof(replay_refs) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_exploratory_session_notes_session ON exploratory_session_notes(session_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_session_notes_type ON exploratory_session_notes(note_type);
CREATE INDEX IF NOT EXISTS idx_exploratory_session_notes_created_at ON exploratory_session_notes(created_at DESC);

CREATE TABLE IF NOT EXISTS exploratory_bug_candidates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id UUID NOT NULL REFERENCES exploratory_sessions(id) ON DELETE CASCADE,
  raw_finding_id UUID REFERENCES raw_findings(id) ON DELETE SET NULL,
  normalized_finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
  title VARCHAR(255) NOT NULL,
  summary TEXT NOT NULL,
  severity VARCHAR(50) NOT NULL,
  category VARCHAR(100) NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  location JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  status VARCHAR(32) NOT NULL DEFAULT 'candidate',
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_exploratory_bug_candidates_status CHECK (status IN ('candidate', 'normalized', 'rejected')),
  CONSTRAINT chk_exploratory_bug_candidates_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_exploratory_bug_candidates_location_object CHECK (jsonb_typeof(location) = 'object'),
  CONSTRAINT chk_exploratory_bug_candidates_evidence_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
  CONSTRAINT chk_exploratory_bug_candidates_replay_array CHECK (jsonb_typeof(replay_refs) = 'array')
);

COMMENT ON TABLE exploratory_bug_candidates IS 'Exploratory bug candidates. Candidates become canonical Findings only after NORMALIZE creates raw_findings.normalized_finding_id.';

CREATE INDEX IF NOT EXISTS idx_exploratory_bug_candidates_session ON exploratory_bug_candidates(session_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_bug_candidates_raw ON exploratory_bug_candidates(raw_finding_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_bug_candidates_normalized ON exploratory_bug_candidates(normalized_finding_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_bug_candidates_status ON exploratory_bug_candidates(status);

CREATE TRIGGER trg_exploratory_bug_candidates_updated_at
BEFORE UPDATE ON exploratory_bug_candidates
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS exploratory_evidence_refs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id UUID NOT NULL REFERENCES exploratory_sessions(id) ON DELETE CASCADE,
  note_id UUID REFERENCES exploratory_session_notes(id) ON DELETE SET NULL,
  candidate_id UUID REFERENCES exploratory_bug_candidates(id) ON DELETE SET NULL,
  artifact_id UUID REFERENCES execution_artifacts(id) ON DELETE SET NULL,
  evidence_type VARCHAR(80) NOT NULL,
  ref TEXT NOT NULL,
  summary TEXT,
  redaction_status VARCHAR(50) NOT NULL DEFAULT 'redacted',
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_exploratory_evidence_refs_redaction CHECK (redaction_status IN ('not_required', 'redacted', 'pending')),
  CONSTRAINT chk_exploratory_evidence_refs_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

COMMENT ON TABLE exploratory_evidence_refs IS 'Reference-only evidence refs for exploratory testing. File upload is intentionally not implemented in this batch.';

CREATE INDEX IF NOT EXISTS idx_exploratory_evidence_refs_session ON exploratory_evidence_refs(session_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_evidence_refs_note ON exploratory_evidence_refs(note_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_evidence_refs_candidate ON exploratory_evidence_refs(candidate_id);
CREATE INDEX IF NOT EXISTS idx_exploratory_evidence_refs_artifact ON exploratory_evidence_refs(artifact_id);

-- =========================================================
-- 16.1 Phase 7 Visual Grounding 执行证据
-- =========================================================

CREATE TABLE IF NOT EXISTS visual_grounding_attempts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  task_id UUID REFERENCES execution_tasks(id) ON DELETE CASCADE,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  trace_span_id UUID REFERENCES trace_spans(id) ON DELETE SET NULL,
  action_id VARCHAR(150) NOT NULL,
  action_type VARCHAR(50) NOT NULL,
  semantic_action JSONB NOT NULL DEFAULT '{}'::jsonb,
  locator_strategy JSONB NOT NULL DEFAULT '{}'::jsonb,
  fallback_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
  candidate_locators JSONB NOT NULL DEFAULT '[]'::jsonb,
  chosen_locator JSONB NOT NULL DEFAULT '{}'::jsonb,
  confidence NUMERIC(5,4),
  threshold NUMERIC(5,4),
  coordinate_click_allowed BOOLEAN NOT NULL DEFAULT FALSE,
  risk_level risk_level NOT NULL DEFAULT 'medium',
  guardrail_decision guardrail_decision,
  guardrail_event_id UUID REFERENCES guardrail_events(id) ON DELETE SET NULL,
  verification_status VARCHAR(50),
  verification_result JSONB NOT NULL DEFAULT '{}'::jsonb,
  artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  redaction_status VARCHAR(50) NOT NULL DEFAULT 'redacted',
  status VARCHAR(50) NOT NULL DEFAULT 'completed',
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_visual_grounding_confidence_range CHECK (
    confidence IS NULL OR (confidence >= 0 AND confidence <= 1)
  ),
  CONSTRAINT chk_visual_grounding_threshold_range CHECK (
    threshold IS NULL OR (threshold >= 0 AND threshold <= 1)
  ),
  CONSTRAINT chk_visual_grounding_semantic_action_object CHECK (jsonb_typeof(semantic_action) = 'object'),
  CONSTRAINT chk_visual_grounding_candidates_array CHECK (jsonb_typeof(candidate_locators) = 'array'),
  CONSTRAINT chk_visual_grounding_artifact_refs_array CHECK (jsonb_typeof(artifact_refs) = 'array')
);

COMMENT ON TABLE visual_grounding_attempts IS 'Phase 7 execution evidence for visual target resolution; not a business decision table and not a Gate input by itself.';
COMMENT ON COLUMN visual_grounding_attempts.artifact_refs IS 'Redacted artifact refs captured before or during visual grounding, including Playwright screenshot/dom_snapshot/accessibility_tree refs and model-gateway vision annotations.';

CREATE INDEX IF NOT EXISTS idx_visual_grounding_attempts_execution_id ON visual_grounding_attempts(execution_id);
CREATE INDEX IF NOT EXISTS idx_visual_grounding_attempts_task_id ON visual_grounding_attempts(task_id);
CREATE INDEX IF NOT EXISTS idx_visual_grounding_attempts_action_id ON visual_grounding_attempts(action_id);
CREATE INDEX IF NOT EXISTS idx_visual_grounding_attempts_trace_id ON visual_grounding_attempts(trace_id);
CREATE INDEX IF NOT EXISTS idx_visual_grounding_attempts_guardrail_event_id ON visual_grounding_attempts(guardrail_event_id);
CREATE INDEX IF NOT EXISTS idx_visual_grounding_attempts_created_at ON visual_grounding_attempts(created_at DESC);

CREATE TABLE IF NOT EXISTS verification_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  task_id UUID REFERENCES execution_tasks(id) ON DELETE CASCADE,
  visual_attempt_id UUID REFERENCES visual_grounding_attempts(id) ON DELETE SET NULL,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  verification_type VARCHAR(100) NOT NULL,
  status VARCHAR(50) NOT NULL,
  confidence NUMERIC(5,4),
  evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
  artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  result_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  normalized_finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_verification_results_confidence_range CHECK (
    confidence IS NULL OR (confidence >= 0 AND confidence <= 1)
  ),
  CONSTRAINT chk_verification_results_evidence_array CHECK (jsonb_typeof(evidence) = 'array'),
  CONSTRAINT chk_verification_results_artifact_refs_array CHECK (jsonb_typeof(artifact_refs) = 'array')
);

COMMENT ON TABLE verification_results IS 'Execution verification outcomes, including Phase 7 visual action verification; failures must normalize into findings or execution failures.';
COMMENT ON COLUMN verification_results.artifact_refs IS 'Verification evidence refs only; raw screenshots, DOM dumps, and model payload blobs must not be embedded here.';

CREATE INDEX IF NOT EXISTS idx_verification_results_execution_id ON verification_results(execution_id);
CREATE INDEX IF NOT EXISTS idx_verification_results_task_id ON verification_results(task_id);
CREATE INDEX IF NOT EXISTS idx_verification_results_visual_attempt_id ON verification_results(visual_attempt_id);
CREATE INDEX IF NOT EXISTS idx_verification_results_trace_id ON verification_results(trace_id);
CREATE INDEX IF NOT EXISTS idx_verification_results_finding_id ON verification_results(normalized_finding_id);
CREATE INDEX IF NOT EXISTS idx_verification_results_created_at ON verification_results(created_at DESC);

CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action VARCHAR(100) NOT NULL,
  resource_type VARCHAR(100) NOT NULL,
  resource_id VARCHAR(255) NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  request_id VARCHAR(255),
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  retention_policy VARCHAR(80) NOT NULL DEFAULT 'default-audit-log-retention',
  retention_until TIMESTAMPTZ,
  legal_hold BOOLEAN NOT NULL DEFAULT FALSE,
  archived_at TIMESTAMPTZ,
  purge_eligible_at TIMESTAMPTZ,
  retention_status VARCHAR(40) NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_audit_logs_retention_status CHECK (
    retention_status IN ('active', 'archived', 'purge_eligible', 'purged', 'legal_hold')
  )
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_id ON audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_type ON audit_logs(resource_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_id ON audit_logs(resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_retention_status ON audit_logs(retention_status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);

CREATE TABLE IF NOT EXISTS domain_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id VARCHAR(100) NOT NULL UNIQUE,
  event_type VARCHAR(100) NOT NULL,
  schema_version VARCHAR(50) NOT NULL,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  correlation_refs JSONB NOT NULL DEFAULT '{}'::jsonb,
  occurred_at TIMESTAMPTZ NOT NULL,
  actor_ref JSONB,
  source_ref JSONB,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_domain_events_type ON domain_events(event_type);
CREATE INDEX IF NOT EXISTS idx_domain_events_trace ON domain_events(trace_id);
CREATE INDEX IF NOT EXISTS idx_domain_events_occurred_at ON domain_events(occurred_at);
CREATE INDEX IF NOT EXISTS idx_domain_events_created_at ON domain_events(created_at);

-- P09 Evidence Index stores redacted metadata and stable refs only. Original
-- source payload ownership remains with Evidence/Artifact/Trace/Replay tables.
CREATE TABLE IF NOT EXISTS evidence_index_entries (
  entry_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  source_type VARCHAR(40) NOT NULL,
  source_id VARCHAR(255) NOT NULL,
  source_version VARCHAR(255) NOT NULL,
  content_hash VARCHAR(80) NOT NULL,
  title VARCHAR(500) NOT NULL,
  summary TEXT NOT NULL,
  search_text TEXT NOT NULL,
  facets JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  classification VARCHAR(40) NOT NULL,
  redaction_version VARCHAR(80) NOT NULL,
  indexed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  source_updated_at TIMESTAMPTZ,
  stale BOOLEAN NOT NULL DEFAULT FALSE,
  retention_state VARCHAR(40) NOT NULL DEFAULT 'active',
  unavailable_reason_code VARCHAR(120),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT uq_evidence_index_source_version_hash UNIQUE (
    tenant_id, workspace_id, project_id, source_type, source_id,
    source_version, content_hash, redaction_version
  ),
  CONSTRAINT chk_evidence_index_source_type CHECK (
    source_type IN ('execution', 'finding', 'gate', 'policy', 'trace', 'replay', 'graph', 'artifact')
  ),
  CONSTRAINT chk_evidence_index_classification CHECK (
    classification IN ('public', 'internal', 'confidential', 'restricted')
  ),
  CONSTRAINT chk_evidence_index_retention_state CHECK (
    retention_state IN ('active', 'archived', 'purge_eligible', 'purged', 'legal_hold')
  ),
  CONSTRAINT chk_evidence_index_content_hash CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_evidence_index_scope
  ON evidence_index_entries(tenant_id, workspace_id, project_id, stale);
CREATE INDEX IF NOT EXISTS idx_evidence_index_source
  ON evidence_index_entries(source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_evidence_index_classification
  ON evidence_index_entries(classification);
CREATE INDEX IF NOT EXISTS idx_evidence_index_indexed_at
  ON evidence_index_entries(indexed_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_index_retention
  ON evidence_index_entries(retention_state);
CREATE INDEX IF NOT EXISTS idx_evidence_index_facets_gin
  ON evidence_index_entries USING GIN(facets);
CREATE INDEX IF NOT EXISTS idx_evidence_index_search_fts
  ON evidence_index_entries USING GIN(to_tsvector('simple', search_text));

CREATE TABLE IF NOT EXISTS evidence_index_jobs (
  job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  job_type VARCHAR(40) NOT NULL DEFAULT 'incremental',
  status VARCHAR(40) NOT NULL DEFAULT 'queued',
  idempotency_key VARCHAR(255) NOT NULL,
  source_types JSONB NOT NULL DEFAULT '[]'::jsonb,
  scanned_count INTEGER NOT NULL DEFAULT 0,
  upserted_count INTEGER NOT NULL DEFAULT 0,
  unchanged_count INTEGER NOT NULL DEFAULT 0,
  stale_count INTEGER NOT NULL DEFAULT 0,
  redaction_version VARCHAR(80) NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  error_code VARCHAR(120),
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_evidence_index_jobs_scope_idempotency UNIQUE (
    tenant_id, workspace_id, project_id, idempotency_key
  ),
  CONSTRAINT chk_evidence_index_jobs_type CHECK (
    job_type IN ('incremental', 'rebuild', 'redaction_reindex')
  ),
  CONSTRAINT chk_evidence_index_jobs_status CHECK (
    status IN ('queued', 'running', 'completed', 'failed')
  ),
  CONSTRAINT chk_evidence_index_jobs_counts CHECK (
    scanned_count >= 0 AND upserted_count >= 0 AND unchanged_count >= 0 AND stale_count >= 0
  )
);

CREATE INDEX IF NOT EXISTS idx_evidence_index_jobs_scope
  ON evidence_index_jobs(tenant_id, workspace_id, project_id);
CREATE INDEX IF NOT EXISTS idx_evidence_index_jobs_status
  ON evidence_index_jobs(status, created_at DESC);

-- =========================================================
-- 17. 集成触发记录
-- =========================================================

CREATE TABLE IF NOT EXISTS orchestration_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source VARCHAR(100) NOT NULL,
  trigger_type VARCHAR(100) NOT NULL,
  status job_status NOT NULL DEFAULT 'queued',
  current_step VARCHAR(100) NOT NULL DEFAULT 'PLAN',
  request_id VARCHAR(255),
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  linked_plan_id UUID REFERENCES test_plans(id) ON DELETE SET NULL,
  linked_execution_id UUID REFERENCES executions(id) ON DELETE SET NULL,
  linked_requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE SET NULL,
  requirement_scope_id VARCHAR(255) REFERENCES requirement_scopes(scope_id) ON DELETE SET NULL,
  requirement_scope JSONB NOT NULL DEFAULT '{}'::jsonb,
  envelope_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  result_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_message TEXT,
  started_at TIMESTAMPTZ,
  ended_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_orchestration_runs_status ON orchestration_runs(status);
CREATE INDEX IF NOT EXISTS idx_orchestration_runs_trace_id ON orchestration_runs(trace_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_runs_plan_id ON orchestration_runs(linked_plan_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_runs_execution_id ON orchestration_runs(linked_execution_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_runs_requirement_id ON orchestration_runs(linked_requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_runs_requirement_scope_id ON orchestration_runs(requirement_scope_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_runs_created_at ON orchestration_runs(created_at DESC);

CREATE TRIGGER trg_orchestration_runs_updated_at
BEFORE UPDATE ON orchestration_runs
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS orchestration_checkpoints (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id UUID NOT NULL REFERENCES orchestration_runs(id) ON DELETE CASCADE,
  sequence_no INTEGER NOT NULL,
  step_name VARCHAR(100) NOT NULL,
  execution_stage VARCHAR(50),
  status job_status NOT NULL DEFAULT 'queued',
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  execution_id UUID REFERENCES executions(id) ON DELETE SET NULL,
  envelope_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  result_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_message TEXT,
  started_at TIMESTAMPTZ,
  ended_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (run_id, sequence_no)
);

CREATE INDEX IF NOT EXISTS idx_orchestration_checkpoints_run_id ON orchestration_checkpoints(run_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_checkpoints_trace_id ON orchestration_checkpoints(trace_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_checkpoints_execution_id ON orchestration_checkpoints(execution_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_checkpoints_created_at ON orchestration_checkpoints(created_at DESC);

CREATE TABLE IF NOT EXISTS requirement_intake_drafts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_type VARCHAR(32) NOT NULL DEFAULT 'paste',
  source_ref VARCHAR(255) NOT NULL,
  source_uri VARCHAR(2048),
  name VARCHAR(255) NOT NULL,
  raw_content TEXT NOT NULL,
  normalized_document TEXT NOT NULL,
  storage_ref VARCHAR(500),
  content_hash VARCHAR(80),
  mime_type VARCHAR(120),
  byte_size INTEGER,
  artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  redaction_status VARCHAR(32) NOT NULL DEFAULT 'not_required',
  project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
  environment_id UUID REFERENCES project_environments(id) ON DELETE SET NULL,
  environment VARCHAR(100) NOT NULL DEFAULT 'local',
  domains JSONB NOT NULL DEFAULT '[]'::jsonb,
  risk_level risk_level NOT NULL DEFAULT 'medium',
  status VARCHAR(32) NOT NULL DEFAULT 'draft',
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  skill_invocation_id UUID,
  connector_binding_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  connector_call_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_requirement_intake_drafts_source_type CHECK (source_type IN ('paste', 'upload', 'ocr_upload', 'external_link', 'connector')),
  CONSTRAINT chk_requirement_intake_drafts_status CHECK (status IN ('draft', 'previewed', 'review_required', 'blocked', 'confirmed', 'discarded')),
  CONSTRAINT chk_requirement_intake_drafts_redaction_status CHECK (redaction_status IN ('not_required', 'redacted', 'pending')),
  CONSTRAINT chk_requirement_intake_drafts_artifact_refs_array CHECK (jsonb_typeof(artifact_refs) = 'array'),
  CONSTRAINT chk_requirement_intake_drafts_evidence_refs_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
  CONSTRAINT chk_requirement_intake_drafts_connector_snapshot_object CHECK (jsonb_typeof(connector_binding_snapshot) = 'object'),
  CONSTRAINT chk_requirement_intake_drafts_connector_call_refs_array CHECK (jsonb_typeof(connector_call_refs) = 'array'),
  CONSTRAINT chk_requirement_intake_drafts_domains_array CHECK (jsonb_typeof(domains) = 'array'),
  CONSTRAINT chk_requirement_intake_drafts_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

COMMENT ON TABLE requirement_intake_drafts IS 'Service-owned Requirement Intake drafts for paste, text/document upload, independent OCR upload, controlled external link, and connector sources. OCR binary stays behind StorageAdapter refs.';
COMMENT ON COLUMN requirement_intake_drafts.raw_content IS 'Redacted paste text only; upload, ocr_upload, external_link, and connector drafts keep this empty and reference StorageAdapter artifacts.';
COMMENT ON COLUMN requirement_intake_drafts.normalized_document IS 'Redacted text for paste and OCR sources only; OCR images/PDF binary must never be stored here.';
COMMENT ON COLUMN requirement_intake_drafts.source_uri IS 'Sanitized external_link source URI or connector-native source URI only. Credentials, cookies, tokens, and URL fragments must not be persisted.';
COMMENT ON COLUMN requirement_intake_drafts.storage_ref IS 'StorageAdapter reference for upload, external_link, and connector source payloads. DB stores metadata only, not binary payloads.';
COMMENT ON COLUMN requirement_intake_drafts.evidence_refs IS 'Service-generated evidence refs for imported source artifacts and guardrail/redaction preflight.';
COMMENT ON COLUMN requirement_intake_drafts.skill_invocation_id IS 'Service-managed integration-intake Skill Invocation used for connector source normalization.';
COMMENT ON COLUMN requirement_intake_drafts.connector_binding_snapshot IS 'P27 allowlist-only Connector Binding safe projection for connector source replay; must not contain Secret, resolvable credential refs, raw config, or unknown metadata/extensions.';
COMMENT ON COLUMN requirement_intake_drafts.connector_call_refs IS 'Frozen connector call refs for connector source replay.';

CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_source_ref ON requirement_intake_drafts(source_ref);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_source_type ON requirement_intake_drafts(source_type);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_source_uri ON requirement_intake_drafts(source_uri);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_content_hash ON requirement_intake_drafts(content_hash);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_skill_invocation ON requirement_intake_drafts(skill_invocation_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_project ON requirement_intake_drafts(project_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_environment ON requirement_intake_drafts(environment_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_status ON requirement_intake_drafts(status);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_created_by ON requirement_intake_drafts(created_by);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_drafts_created_at ON requirement_intake_drafts(created_at DESC);

CREATE TRIGGER trg_requirement_intake_drafts_updated_at
BEFORE UPDATE ON requirement_intake_drafts
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS requirement_intake_previews (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  draft_id UUID NOT NULL REFERENCES requirement_intake_drafts(id) ON DELETE CASCADE,
  source_type VARCHAR(32) NOT NULL DEFAULT 'paste',
  source_ref VARCHAR(255) NOT NULL,
  source_uri VARCHAR(2048),
  document TEXT NOT NULL,
  storage_ref VARCHAR(500),
  content_hash VARCHAR(80),
  mime_type VARCHAR(120),
  byte_size INTEGER,
  artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  redaction_status VARCHAR(32) NOT NULL DEFAULT 'not_required',
  requirements JSONB NOT NULL DEFAULT '[]'::jsonb,
  acceptance_criteria JSONB NOT NULL DEFAULT '[]'::jsonb,
  pipeline_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
  status VARCHAR(32) NOT NULL DEFAULT 'generated',
  linked_requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE SET NULL,
  linked_pipeline_id UUID REFERENCES orchestration_runs(id) ON DELETE SET NULL,
  confirmed_at TIMESTAMPTZ,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  skill_invocation_id UUID,
  connector_binding_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  connector_call_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_requirement_intake_previews_source_type CHECK (source_type IN ('paste', 'upload', 'ocr_upload', 'external_link', 'connector')),
  CONSTRAINT chk_requirement_intake_previews_status CHECK (status IN ('generated', 'review_required', 'blocked', 'confirmed', 'superseded')),
  CONSTRAINT chk_requirement_intake_previews_redaction_status CHECK (redaction_status IN ('not_required', 'redacted', 'pending')),
  CONSTRAINT chk_requirement_intake_previews_artifact_refs_array CHECK (jsonb_typeof(artifact_refs) = 'array'),
  CONSTRAINT chk_requirement_intake_previews_evidence_refs_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
  CONSTRAINT chk_requirement_intake_previews_connector_snapshot_object CHECK (jsonb_typeof(connector_binding_snapshot) = 'object'),
  CONSTRAINT chk_requirement_intake_previews_connector_call_refs_array CHECK (jsonb_typeof(connector_call_refs) = 'array'),
  CONSTRAINT chk_requirement_intake_previews_requirements_array CHECK (jsonb_typeof(requirements) = 'array'),
  CONSTRAINT chk_requirement_intake_previews_acceptance_array CHECK (jsonb_typeof(acceptance_criteria) = 'array'),
  CONSTRAINT chk_requirement_intake_previews_pipeline_payload_object CHECK (jsonb_typeof(pipeline_payload) = 'object'),
  CONSTRAINT chk_requirement_intake_previews_warnings_array CHECK (jsonb_typeof(warnings) = 'array'),
  CONSTRAINT chk_requirement_intake_previews_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

COMMENT ON TABLE requirement_intake_previews IS 'Requirement Intake Preview records including OCR confidence/review projections in metadata. Confirmed previews call OrchestratorService.run_requirement_pipeline and link to existing RequirementVersion and OrchestrationRun records.';
COMMENT ON COLUMN requirement_intake_previews.source_uri IS 'Sanitized external_link or connector-native source URI copied from Draft.';
COMMENT ON COLUMN requirement_intake_previews.evidence_refs IS 'Evidence refs copied from Draft for preview and confirm replayability.';
COMMENT ON COLUMN requirement_intake_previews.skill_invocation_id IS 'Service-managed integration-intake Skill Invocation copied from connector Draft.';
COMMENT ON COLUMN requirement_intake_previews.connector_binding_snapshot IS 'P27 allowlist-only Connector Binding safe projection copied from Draft for replay.';
COMMENT ON COLUMN requirement_intake_previews.connector_call_refs IS 'Frozen connector call refs copied from Draft for replay.';

CREATE INDEX IF NOT EXISTS idx_requirement_intake_previews_draft ON requirement_intake_previews(draft_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_previews_source_type ON requirement_intake_previews(source_type);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_previews_source_uri ON requirement_intake_previews(source_uri);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_previews_content_hash ON requirement_intake_previews(content_hash);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_previews_skill_invocation ON requirement_intake_previews(skill_invocation_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_previews_pipeline ON requirement_intake_previews(linked_pipeline_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_previews_requirement ON requirement_intake_previews(linked_requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_previews_status ON requirement_intake_previews(status);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_previews_created_by ON requirement_intake_previews(created_by);

CREATE TRIGGER trg_requirement_intake_previews_updated_at
BEFORE UPDATE ON requirement_intake_previews
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS requirement_intake_batches (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  idempotency_key VARCHAR(120),
  status VARCHAR(32) NOT NULL DEFAULT 'pending',
  environment VARCHAR(100) NOT NULL DEFAULT 'local',
  project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
  environment_id UUID REFERENCES project_environments(id) ON DELETE SET NULL,
  domains JSONB NOT NULL DEFAULT '[]'::jsonb,
  risk_level risk_level NOT NULL DEFAULT 'medium',
  summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_requirement_intake_batches_status CHECK (status IN ('pending', 'ready', 'partially_failed', 'failed', 'partially_confirmed', 'confirmed')),
  CONSTRAINT chk_requirement_intake_batches_domains_array CHECK (jsonb_typeof(domains) = 'array'),
  CONSTRAINT chk_requirement_intake_batches_summary_object CHECK (jsonb_typeof(summary) = 'object'),
  CONSTRAINT chk_requirement_intake_batches_metadata_object CHECK (jsonb_typeof(metadata) = 'object'),
  CONSTRAINT uq_requirement_intake_batches_created_by_idempotency UNIQUE (created_by, idempotency_key)
);

COMMENT ON TABLE requirement_intake_batches IS 'Service-owned Requirement Intake batch aggregate for multiple independent sources. This is not a new pipeline, skill-service, or integration-service.';
COMMENT ON COLUMN requirement_intake_batches.idempotency_key IS 'Optional client idempotency key scoped by created_by for safe retry of batch creation.';
COMMENT ON COLUMN requirement_intake_batches.summary IS 'Backend-computed source status counts for batch views.';

CREATE INDEX IF NOT EXISTS idx_requirement_intake_batches_status ON requirement_intake_batches(status);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_batches_project ON requirement_intake_batches(project_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_batches_environment ON requirement_intake_batches(environment_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_batches_created_by ON requirement_intake_batches(created_by);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_batches_created_at ON requirement_intake_batches(created_at DESC);

CREATE TRIGGER trg_requirement_intake_batches_updated_at
BEFORE UPDATE ON requirement_intake_batches
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS requirement_intake_batch_sources (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  batch_id UUID NOT NULL REFERENCES requirement_intake_batches(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  source_type VARCHAR(32) NOT NULL,
  source_key VARCHAR(180) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'pending',
  draft_id UUID REFERENCES requirement_intake_drafts(id) ON DELETE SET NULL,
  preview_id UUID REFERENCES requirement_intake_previews(id) ON DELETE SET NULL,
  linked_requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE SET NULL,
  linked_pipeline_id UUID REFERENCES orchestration_runs(id) ON DELETE SET NULL,
  error_message TEXT,
  artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  retry_count INTEGER NOT NULL DEFAULT 0,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_requirement_intake_batch_sources_source_type CHECK (source_type IN ('paste', 'upload', 'external_link', 'connector')),
  CONSTRAINT chk_requirement_intake_batch_sources_status CHECK (status IN ('pending', 'pending_confirm', 'failed', 'confirmed')),
  CONSTRAINT chk_requirement_intake_batch_sources_artifact_refs_array CHECK (jsonb_typeof(artifact_refs) = 'array'),
  CONSTRAINT chk_requirement_intake_batch_sources_evidence_refs_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
  CONSTRAINT chk_requirement_intake_batch_sources_metadata_object CHECK (jsonb_typeof(metadata) = 'object'),
  CONSTRAINT uq_requirement_intake_batch_sources_key UNIQUE (batch_id, source_key)
);

COMMENT ON TABLE requirement_intake_batch_sources IS 'One independent source inside a Requirement Intake batch. Each source links to its own Draft and Preview and keeps independent evidence, artifacts, status, and error state.';
COMMENT ON COLUMN requirement_intake_batch_sources.draft_id IS 'Independent single-source Draft created through the existing RequirementIntakeService boundary.';
COMMENT ON COLUMN requirement_intake_batch_sources.preview_id IS 'Independent single-source Preview; confirm reuses the existing requirement pipeline through RequirementIntakeService.confirm_preview.';
COMMENT ON COLUMN requirement_intake_batch_sources.evidence_refs IS 'Per-source evidence refs copied from the independent Draft/Preview. Documents are never concatenated into one Draft.';

CREATE INDEX IF NOT EXISTS idx_requirement_intake_batch_sources_batch ON requirement_intake_batch_sources(batch_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_batch_sources_status ON requirement_intake_batch_sources(status);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_batch_sources_source_type ON requirement_intake_batch_sources(source_type);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_batch_sources_draft ON requirement_intake_batch_sources(draft_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_batch_sources_preview ON requirement_intake_batch_sources(preview_id);
CREATE INDEX IF NOT EXISTS idx_requirement_intake_batch_sources_pipeline ON requirement_intake_batch_sources(linked_pipeline_id);

CREATE TRIGGER trg_requirement_intake_batch_sources_updated_at
BEFORE UPDATE ON requirement_intake_batch_sources
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS integration_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source VARCHAR(100) NOT NULL, -- git/ci/jira/other
  event_type VARCHAR(100) NOT NULL,
  external_ref VARCHAR(255),
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  status integration_event_status NOT NULL DEFAULT 'received',
  linked_pipeline_id UUID REFERENCES orchestration_runs(id) ON DELETE SET NULL,
  linked_plan_id UUID REFERENCES test_plans(id) ON DELETE SET NULL,
  linked_execution_id UUID REFERENCES executions(id) ON DELETE SET NULL,
  linked_requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE integration_events IS 'External integration event records. /integrations/* is a compatibility facade and external trigger endpoint, not an integration-service microservice.';

CREATE INDEX IF NOT EXISTS idx_integration_events_source ON integration_events(source);
CREATE INDEX IF NOT EXISTS idx_integration_events_event_type ON integration_events(event_type);
CREATE INDEX IF NOT EXISTS idx_integration_events_external_ref ON integration_events(external_ref);
CREATE INDEX IF NOT EXISTS idx_integration_events_pipeline_id ON integration_events(linked_pipeline_id);
CREATE INDEX IF NOT EXISTS idx_integration_events_requirement_id ON integration_events(linked_requirement_version_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_integration_events_source_type_ref
  ON integration_events(source, event_type, external_ref)
  WHERE external_ref IS NOT NULL AND source LIKE 'issue-tracker:%';

CREATE TRIGGER trg_integration_events_updated_at
BEFORE UPDATE ON integration_events
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- =========================================================
-- 18. Phase 8 Controlled Skill Layer
-- =========================================================

CREATE TABLE IF NOT EXISTS skills (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  skill_id VARCHAR(128) NOT NULL UNIQUE,
  display_name VARCHAR(255) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_skills_status CHECK (status IN ('active', 'disabled', 'archived'))
);

COMMENT ON TABLE skills IS 'Phase 8 Skill logical catalog. Skills are controlled capability modules, not services, agents, tools, connectors, or visual grounding.';

CREATE TRIGGER trg_skills_updated_at
BEFORE UPDATE ON skills
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS skill_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  skill_ref_id UUID NOT NULL REFERENCES skills(id) ON DELETE CASCADE,
  version VARCHAR(64) NOT NULL,
  manifest_hash VARCHAR(128) NOT NULL,
  manifest_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  capabilities JSONB NOT NULL DEFAULT '{}'::jsonb,
  input_schema JSONB NOT NULL DEFAULT '{}'::jsonb,
  output_schema JSONB NOT NULL DEFAULT '{}'::jsonb,
  allowed_tools JSONB NOT NULL DEFAULT '[]'::jsonb,
  allowed_connectors JSONB NOT NULL DEFAULT '[]'::jsonb,
  risk_profile JSONB NOT NULL DEFAULT '{}'::jsonb,
  approval_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
  data_access_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
  replay_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
  extension_points JSONB NOT NULL DEFAULT '[]'::jsonb,
  compatibility JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_skill_manifest UNIQUE (skill_ref_id, version, manifest_hash),
  CONSTRAINT chk_skill_versions_manifest_object CHECK (jsonb_typeof(manifest_snapshot) = 'object'),
  CONSTRAINT chk_skill_versions_capabilities_object CHECK (jsonb_typeof(capabilities) = 'object'),
  CONSTRAINT chk_skill_versions_input_schema_object CHECK (jsonb_typeof(input_schema) = 'object'),
  CONSTRAINT chk_skill_versions_output_schema_object CHECK (jsonb_typeof(output_schema) = 'object'),
  CONSTRAINT chk_skill_versions_allowed_tools_array CHECK (jsonb_typeof(allowed_tools) = 'array'),
  CONSTRAINT chk_skill_versions_allowed_connectors_array CHECK (jsonb_typeof(allowed_connectors) = 'array'),
  CONSTRAINT chk_skill_versions_risk_profile_object CHECK (jsonb_typeof(risk_profile) = 'object'),
  CONSTRAINT chk_skill_versions_approval_policy_object CHECK (jsonb_typeof(approval_policy) = 'object'),
  CONSTRAINT chk_skill_versions_data_access_policy_object CHECK (jsonb_typeof(data_access_policy) = 'object'),
  CONSTRAINT chk_skill_versions_replay_policy_object CHECK (jsonb_typeof(replay_policy) = 'object'),
  CONSTRAINT chk_skill_versions_extension_points_array CHECK (jsonb_typeof(extension_points) = 'array'),
  CONSTRAINT chk_skill_versions_compatibility_object CHECK (jsonb_typeof(compatibility) = 'object')
);

COMMENT ON TABLE skill_versions IS 'Immutable Skill manifest versions. Replay must freeze manifest snapshot and manifest hash.';

CREATE INDEX IF NOT EXISTS idx_skill_versions_skill_ref_id ON skill_versions(skill_ref_id);
CREATE INDEX IF NOT EXISTS idx_skill_versions_manifest_hash ON skill_versions(manifest_hash);

CREATE TRIGGER trg_skill_versions_updated_at
BEFORE UPDATE ON skill_versions
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS skill_connector_bindings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  connector_name VARCHAR(128) NOT NULL,
  secret_ref TEXT NOT NULL,
  credential_ref TEXT,
  scope JSONB NOT NULL DEFAULT '{}'::jsonb,
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_skill_connector_bindings_scope_object CHECK (jsonb_typeof(scope) = 'object'),
  CONSTRAINT chk_skill_connector_bindings_secret_ref_not_blank CHECK (length(trim(secret_ref)) > 0)
);

COMMENT ON TABLE skill_connector_bindings IS 'Legacy authoritative Connector runtime locator boundary. Values must never be serialized into DB snapshots, Trace, Audit, Replay, Storage, API responses, logs, or frontend state; downstream consumers receive only the P27 Safe Projection.';

CREATE INDEX IF NOT EXISTS idx_skill_connector_bindings_connector_name ON skill_connector_bindings(connector_name);

CREATE TRIGGER trg_skill_connector_bindings_updated_at
BEFORE UPDATE ON skill_connector_bindings
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS external_issue_links (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  connector_binding_id UUID REFERENCES skill_connector_bindings(id) ON DELETE SET NULL,
  connector_name VARCHAR(128) NOT NULL,
  external_issue_id VARCHAR(255),
  external_issue_key VARCHAR(255),
  external_issue_url TEXT,
  external_status VARCHAR(80),
  sync_status VARCHAR(40) NOT NULL DEFAULT 'pending',
  idempotency_key VARCHAR(255) NOT NULL,
  last_synced_at TIMESTAMPTZ,
  last_status_synced_at TIMESTAMPTZ,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  connector_call_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  payload_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_external_issue_links_idempotency_key UNIQUE (idempotency_key),
  CONSTRAINT chk_external_issue_links_status CHECK (sync_status IN ('pending', 'synced', 'failed')),
  CONSTRAINT chk_external_issue_links_evidence_refs_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
  CONSTRAINT chk_external_issue_links_replay_refs_array CHECK (jsonb_typeof(replay_refs) = 'array'),
  CONSTRAINT chk_external_issue_links_trace_refs_array CHECK (jsonb_typeof(trace_refs) = 'array'),
  CONSTRAINT chk_external_issue_links_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array'),
  CONSTRAINT chk_external_issue_links_connector_refs_array CHECK (jsonb_typeof(connector_call_refs) = 'array'),
  CONSTRAINT chk_external_issue_links_payload_object CHECK (jsonb_typeof(payload_snapshot) = 'object')
);

COMMENT ON TABLE external_issue_links IS 'Service-owned normalized Finding to external issue tracker link records. Stores connector binding refs and external issue status only, never plaintext credentials.';

CREATE INDEX IF NOT EXISTS idx_external_issue_links_finding ON external_issue_links(finding_id);
CREATE INDEX IF NOT EXISTS idx_external_issue_links_execution ON external_issue_links(execution_id);
CREATE INDEX IF NOT EXISTS idx_external_issue_links_connector ON external_issue_links(connector_name);
CREATE INDEX IF NOT EXISTS idx_external_issue_links_external_issue ON external_issue_links(connector_name, external_issue_key);
CREATE INDEX IF NOT EXISTS idx_external_issue_links_sync_status ON external_issue_links(sync_status);

CREATE TRIGGER trg_external_issue_links_updated_at
BEFORE UPDATE ON external_issue_links
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS capability_bindings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  extension_point_id VARCHAR(160) NOT NULL,
  skill_version_id UUID NOT NULL REFERENCES skill_versions(id) ON DELETE RESTRICT,
  scope_type VARCHAR(40) NOT NULL DEFAULT 'global',
  scope_id VARCHAR(255),
  project_id VARCHAR(255),
  environment VARCHAR(120),
  stage VARCHAR(80),
  domain VARCHAR(80),
  status VARCHAR(32) NOT NULL DEFAULT 'draft',
  priority INTEGER NOT NULL DEFAULT 0,
  binding_config JSONB NOT NULL DEFAULT '{}'::jsonb,
  pending_change JSONB NOT NULL DEFAULT '{}'::jsonb,
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_capability_bindings_status CHECK (status IN ('draft', 'active', 'disabled', 'deprecated', 'archived')),
  CONSTRAINT chk_capability_bindings_scope_type CHECK (scope_type IN ('global', 'workspace', 'project', 'environment', 'stage', 'domain')),
  CONSTRAINT chk_capability_bindings_config_object CHECK (jsonb_typeof(binding_config) = 'object'),
  CONSTRAINT chk_capability_bindings_pending_change_object CHECK (jsonb_typeof(pending_change) = 'object'),
  CONSTRAINT chk_capability_bindings_approval_refs_array CHECK (jsonb_typeof(approval_refs) = 'array'),
  CONSTRAINT chk_capability_bindings_guardrail_event_refs_array CHECK (jsonb_typeof(guardrail_event_refs) = 'array'),
  CONSTRAINT chk_capability_bindings_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array')
);

COMMENT ON TABLE capability_bindings IS 'Service-owned extension point to SkillVersion binding records. They configure capability use but do not execute Skills.';

CREATE INDEX IF NOT EXISTS idx_capability_bindings_extension_status ON capability_bindings(extension_point_id, status);
CREATE INDEX IF NOT EXISTS idx_capability_bindings_scope ON capability_bindings(scope_type, scope_id);
CREATE INDEX IF NOT EXISTS idx_capability_bindings_skill_version ON capability_bindings(skill_version_id);

CREATE TRIGGER trg_capability_bindings_updated_at
BEFORE UPDATE ON capability_bindings
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS skill_invocations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  execution_id UUID REFERENCES executions(id) ON DELETE SET NULL,
  agent_run_id UUID REFERENCES agent_runs(id) ON DELETE SET NULL,
  skill_version_id UUID NOT NULL REFERENCES skill_versions(id) ON DELETE RESTRICT,
  binding_id UUID REFERENCES capability_bindings(id) ON DELETE SET NULL,
  extension_point_id VARCHAR(160),
  source_workflow VARCHAR(120),
  idempotency_key VARCHAR(255) UNIQUE,
  input_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  output_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  policy_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  resolution_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  connector_binding_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  tool_call_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  connector_call_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  status VARCHAR(32) NOT NULL DEFAULT 'queued',
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_skill_invocations_input_object CHECK (jsonb_typeof(input_snapshot) = 'object'),
  CONSTRAINT chk_skill_invocations_output_object CHECK (jsonb_typeof(output_snapshot) = 'object'),
  CONSTRAINT chk_skill_invocations_policy_object CHECK (jsonb_typeof(policy_snapshot) = 'object'),
  CONSTRAINT chk_skill_invocations_resolution_object CHECK (jsonb_typeof(resolution_snapshot) = 'object'),
  CONSTRAINT chk_skill_invocations_connector_snapshot_object CHECK (jsonb_typeof(connector_binding_snapshot) = 'object'),
  CONSTRAINT chk_skill_invocations_approval_refs_array CHECK (jsonb_typeof(approval_refs) = 'array'),
  CONSTRAINT chk_skill_invocations_artifact_refs_array CHECK (jsonb_typeof(artifact_refs) = 'array'),
  CONSTRAINT chk_skill_invocations_tool_call_refs_array CHECK (jsonb_typeof(tool_call_refs) = 'array'),
  CONSTRAINT chk_skill_invocations_connector_call_refs_array CHECK (jsonb_typeof(connector_call_refs) = 'array'),
  CONSTRAINT chk_skill_invocations_status CHECK (status IN ('created', 'queued', 'running', 'completed', 'failed', 'cancelled', 'blocked', 'preflight_blocked', 'pending_approval', 'invalid_output'))
);

COMMENT ON TABLE skill_invocations IS 'Service-managed Skill Invocation records. Skill results must normalize before entering Gate, Memory, or UI.';
COMMENT ON COLUMN skill_invocations.connector_binding_snapshot IS 'P27 allowlist-only Connector Binding safe projection for replay; excludes Secret, resolvable secretRef/credentialRef, raw config, and unknown metadata/extensions.';
COMMENT ON COLUMN skill_invocations.policy_snapshot IS 'Includes the migration-free skill-invocation-execution-policy.v1 freeze for timeout, cancellation, retry, effects, size/call/token/cost budget, concurrency/quota, kill switch, fallback, risk/Approval, and process-local Adapter health.';
COMMENT ON COLUMN skill_invocations.status IS 'Compatibility storage status constrained by the existing schema. Effective reliability status is frozen in output_snapshot.metadata.status and terminal SkillInvocationEvent payload: degraded stores completed; unavailable/timed_out store failed. API exposes both effective status and storageStatus.';

CREATE INDEX IF NOT EXISTS idx_skill_invocations_trace_id ON skill_invocations(trace_id);
CREATE INDEX IF NOT EXISTS idx_skill_invocations_execution_id ON skill_invocations(execution_id);
CREATE INDEX IF NOT EXISTS idx_skill_invocations_agent_run_id ON skill_invocations(agent_run_id);
CREATE INDEX IF NOT EXISTS idx_skill_invocations_skill_version_id ON skill_invocations(skill_version_id);
CREATE INDEX IF NOT EXISTS idx_skill_invocations_binding_id ON skill_invocations(binding_id);
CREATE INDEX IF NOT EXISTS idx_skill_invocations_extension_point_id ON skill_invocations(extension_point_id);
CREATE INDEX IF NOT EXISTS idx_skill_invocations_source_workflow ON skill_invocations(source_workflow);
CREATE INDEX IF NOT EXISTS idx_skill_invocations_idempotency_key ON skill_invocations(idempotency_key);
CREATE INDEX IF NOT EXISTS idx_skill_invocations_status ON skill_invocations(status);
CREATE INDEX IF NOT EXISTS idx_skill_invocations_created_at ON skill_invocations(created_at DESC);

CREATE TRIGGER trg_skill_invocations_updated_at
BEFORE UPDATE ON skill_invocations
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS skill_invocation_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  skill_invocation_id UUID NOT NULL REFERENCES skill_invocations(id) ON DELETE CASCADE,
  event_type VARCHAR(80) NOT NULL,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_skill_invocation_events_payload_object CHECK (jsonb_typeof(payload) = 'object')
);

COMMENT ON TABLE skill_invocation_events IS 'Append-only Skill Invocation trace events, including binding resolution, policy freeze, each bounded attempt/backoff, circuit/fallback, and effective terminal status/ReasonCode.';

CREATE INDEX IF NOT EXISTS idx_skill_invocation_events_invocation ON skill_invocation_events(skill_invocation_id);
CREATE INDEX IF NOT EXISTS idx_skill_invocation_events_type ON skill_invocation_events(event_type);
CREATE INDEX IF NOT EXISTS idx_skill_invocation_events_trace ON skill_invocation_events(trace_id);

CREATE TABLE IF NOT EXISTS skill_tool_calls (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  skill_invocation_id UUID NOT NULL REFERENCES skill_invocations(id) ON DELETE CASCADE,
  tool_name VARCHAR(128) NOT NULL,
  tool_call_ref TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE skill_tool_calls IS 'Tool call refs requested through Service-managed Skill Invocation. Tool calls are adapters, not business decisions.';

CREATE INDEX IF NOT EXISTS idx_skill_tool_calls_invocation_id ON skill_tool_calls(skill_invocation_id);
CREATE INDEX IF NOT EXISTS idx_skill_tool_calls_tool_name ON skill_tool_calls(tool_name);

CREATE TABLE IF NOT EXISTS skill_connector_calls (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  skill_invocation_id UUID NOT NULL REFERENCES skill_invocations(id) ON DELETE CASCADE,
  connector_name VARCHAR(128) NOT NULL,
  connector_call_ref TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE skill_connector_calls IS 'Connector call refs requested through Service-managed Skill Invocation. Connectors adapt external systems and do not own business decisions.';

CREATE INDEX IF NOT EXISTS idx_skill_connector_calls_invocation_id ON skill_connector_calls(skill_invocation_id);
CREATE INDEX IF NOT EXISTS idx_skill_connector_calls_connector_name ON skill_connector_calls(connector_name);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_requirement_intake_drafts_skill_invocation_id'
  ) THEN
    ALTER TABLE requirement_intake_drafts
      ADD CONSTRAINT fk_requirement_intake_drafts_skill_invocation_id
      FOREIGN KEY (skill_invocation_id) REFERENCES skill_invocations(id) ON DELETE SET NULL;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_requirement_intake_previews_skill_invocation_id'
  ) THEN
    ALTER TABLE requirement_intake_previews
      ADD CONSTRAINT fk_requirement_intake_previews_skill_invocation_id
      FOREIGN KEY (skill_invocation_id) REFERENCES skill_invocations(id) ON DELETE SET NULL;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_guardrail_events_skill_invocation_id'
  ) THEN
    ALTER TABLE guardrail_events
      ADD CONSTRAINT fk_guardrail_events_skill_invocation_id
      FOREIGN KEY (skill_invocation_id) REFERENCES skill_invocations(id) ON DELETE SET NULL;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_guardrail_events_connector_binding_id'
  ) THEN
    ALTER TABLE guardrail_events
      ADD CONSTRAINT fk_guardrail_events_connector_binding_id
      FOREIGN KEY (connector_binding_id) REFERENCES skill_connector_bindings(id) ON DELETE SET NULL;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_guardrail_events_tool_call_id'
  ) THEN
    ALTER TABLE guardrail_events
      ADD CONSTRAINT fk_guardrail_events_tool_call_id
      FOREIGN KEY (tool_call_id) REFERENCES skill_tool_calls(id) ON DELETE SET NULL;
  END IF;
END $$;

-- Visual Grounding remains execution-service internal evidence:
-- visual-grounding does not enter skills or skill_invocations. It may produce Replay / Evidence refs only.

-- Phase 8 Controlled Extension Points / Capability Bindings implemented baseline:
-- This schema contains the canonical Phase 8 Skill catalog, binding, invocation,
-- and invocation-event tables:
--   skills
--   skill_versions
--   capability_bindings
--   skill_invocations
--   skill_invocation_events
--   skill_connector_bindings
--   skill_tool_calls
--   skill_connector_calls
-- Future changes MUST NOT create skill_catalog_entries, a second skill_versions table,
-- or a second skill_invocations table.
-- Skill Catalog MUST remain a read-only projection from skills + skill_versions.
-- Skill Invocation records MUST reuse skill_invocations and be created only by
-- Service-owned business workflows.
-- Bindable business workflows enter through the code-owned
-- ExtensionPointContractRegistry + SkillService.invoke_extension boundary;
-- ManagedSkillRuntimeRegistry is the lower frozen-Adapter dispatcher only.
-- The lower start/execute/complete/fail constructors remain internal compatibility
-- building blocks for SkillService and non-bindable Integration Skill workflows.
-- Empty skill_versions.extension_points means non-bindable, never wildcard.
-- skill_versions.compatibility may declare runtimeAdapter/runtimeResultKind;
-- the Service validates these values against the code-owned managed runtime
-- registry and freezes the resolved contract in skill_invocations.resolution_snapshot.
-- Runtime adapter registration is not a database code-loading mechanism.
-- This schema does not authorize arbitrary uploaded/third-party code execution.
-- Connector Binding read/write APIs are backend-guarded by capability_bindings.admin.
-- Capability Binding changes MUST continue to land through numbered migrations
-- with matching ORM, API, Service logic, frontend behavior, static checks, tests,
-- smoke scripts, and IMPLEMENTATION_STATUS.md updates.

-- =========================================================
-- 19. 模型调用记录
-- =========================================================

CREATE TABLE IF NOT EXISTS model_invocations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  model_id UUID REFERENCES models(id) ON DELETE SET NULL,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  execution_id UUID REFERENCES executions(id) ON DELETE SET NULL,
  agent_run_id UUID REFERENCES agent_runs(id) ON DELETE SET NULL,
  request_summary TEXT,
  request_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  response_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  prompt_tokens INTEGER,
  completion_tokens INTEGER,
  total_tokens INTEGER,
  latency_ms INTEGER,
  cost_amount NUMERIC(18,6),
  currency VARCHAR(16) DEFAULT 'USD',
  success BOOLEAN NOT NULL DEFAULT TRUE,
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_model_invocations_model_id ON model_invocations(model_id);
CREATE INDEX IF NOT EXISTS idx_model_invocations_execution_id ON model_invocations(execution_id);
CREATE INDEX IF NOT EXISTS idx_model_invocations_trace_id ON model_invocations(trace_id);
CREATE INDEX IF NOT EXISTS idx_model_invocations_agent_run_id ON model_invocations(agent_run_id);
CREATE INDEX IF NOT EXISTS idx_model_invocations_created_at ON model_invocations(created_at DESC);

COMMENT ON COLUMN model_invocations.response_payload IS
  'Redacted normalized Model Gateway response: canonical output plus explicit mode/status/limitations/fallback metadata; raw provider content is not persisted.';
COMMENT ON COLUMN model_invocations.success IS
  'True only for completed live structured output that passed JSON object and declared Schema/Pydantic validation.';

-- =========================================================
-- 20. 视图：执行摘要视图
-- =========================================================

CREATE OR REPLACE VIEW v_execution_overview AS
SELECT
  e.id AS execution_id,
  e.plan_id,
  e.status,
  e.stage,
  e.environment,
  e.started_at,
  e.ended_at,
  COALESCE(gr.functional::text, 'warn') AS functional_gate,
  COALESCE(gr.performance::text, 'warn') AS performance_gate,
  COALESCE(gr.security::text, 'warn') AS security_gate,
  COALESCE(gr.overall::text, 'warn') AS overall_gate,
  (
    SELECT COUNT(*)
    FROM execution_tasks t
    WHERE t.execution_id = e.id
  ) AS total_tasks,
  (
    SELECT COUNT(*)
    FROM execution_tasks t
    WHERE t.execution_id = e.id
      AND t.status = 'failed'
  ) AS failed_tasks,
  (
    SELECT COUNT(*)
    FROM findings f
    WHERE f.execution_id = e.id
  ) AS total_findings
FROM executions e
LEFT JOIN gate_results gr ON gr.execution_id = e.id;

-- =========================================================
-- 21. Canonical Execution Graph foundation (P10)
-- =========================================================

DO $$
BEGIN
  CREATE TYPE graph_status AS ENUM (
    'draft', 'candidate', 'under_review', 'active',
    'superseded', 'deprecated', 'archived'
  );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE TYPE graph_scope AS ENUM ('project', 'environment');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE TYPE graph_source AS ENUM ('observed', 'candidate', 'canonical');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS canonical_execution_graphs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  environment_id UUID,
  scope_type graph_scope NOT NULL,
  scope_id UUID NOT NULL,
  graph_key VARCHAR(128) NOT NULL,
  graph_ref VARCHAR(500) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  status graph_status NOT NULL DEFAULT 'draft',
  retention_policy VARCHAR(80) NOT NULL DEFAULT 'default',
  retention_until TIMESTAMPTZ,
  retention_status VARCHAR(40) NOT NULL DEFAULT 'active',
  legal_hold BOOLEAN NOT NULL DEFAULT FALSE,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_ceg_graphs_environment_project
    FOREIGN KEY (environment_id, project_id)
    REFERENCES project_environments(id, project_id) ON DELETE RESTRICT,
  CONSTRAINT uq_ceg_graphs_scope_key UNIQUE (
    tenant_id, workspace_id, project_id, scope_type, scope_id, graph_key
  ),
  CONSTRAINT uq_ceg_graphs_scoped_identity UNIQUE (
    id, tenant_id, workspace_id, project_id, scope_type, scope_id
  ),
  CONSTRAINT uq_ceg_graphs_idempotency UNIQUE (tenant_id, workspace_id, idempotency_key),
  CONSTRAINT chk_ceg_graphs_tenant_not_blank CHECK (length(trim(tenant_id)) > 0),
  CONSTRAINT chk_ceg_graphs_workspace_not_blank CHECK (length(trim(workspace_id)) > 0),
  CONSTRAINT chk_ceg_graphs_scope_identity CHECK (
    (scope_type = 'project' AND environment_id IS NULL AND scope_id = project_id)
    OR
    (scope_type = 'environment' AND environment_id IS NOT NULL AND scope_id = environment_id)
  ),
  CONSTRAINT chk_ceg_graphs_request_hash_length CHECK (length(request_hash) = 71),
  CONSTRAINT chk_ceg_graphs_request_hash_prefix CHECK (substr(request_hash, 1, 7) = 'sha256:'),
  CONSTRAINT chk_ceg_graphs_lock_version CHECK (lock_version > 0),
  CONSTRAINT chk_ceg_graphs_retention_status CHECK (
    retention_status IN ('active', 'archived', 'purge_eligible', 'legal_hold')
  ),
  CONSTRAINT chk_ceg_graphs_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array'),
  CONSTRAINT chk_ceg_graphs_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_ceg_graphs_scope
  ON canonical_execution_graphs(tenant_id, workspace_id, project_id, scope_type, scope_id);
CREATE INDEX IF NOT EXISTS idx_ceg_graphs_environment
  ON canonical_execution_graphs(environment_id);
CREATE INDEX IF NOT EXISTS idx_ceg_graphs_status
  ON canonical_execution_graphs(status);
CREATE INDEX IF NOT EXISTS idx_ceg_graphs_retention
  ON canonical_execution_graphs(retention_status, retention_until);

CREATE TABLE IF NOT EXISTS canonical_execution_graph_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  graph_id UUID NOT NULL,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL,
  environment_id UUID,
  scope_type graph_scope NOT NULL,
  scope_id UUID NOT NULL,
  version_number INTEGER NOT NULL,
  version_ref VARCHAR(500) NOT NULL UNIQUE,
  parent_version_id UUID,
  status graph_status NOT NULL DEFAULT 'draft',
  source graph_source NOT NULL,
  schema_version VARCHAR(80) NOT NULL DEFAULT 'ceg.v1',
  content_hash VARCHAR(80) NOT NULL,
  source_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  applicability JSONB NOT NULL DEFAULT '{}'::jsonb,
  is_frozen BOOLEAN NOT NULL DEFAULT FALSE,
  frozen_at TIMESTAMPTZ,
  frozen_by UUID REFERENCES users(id) ON DELETE SET NULL,
  retention_policy VARCHAR(80) NOT NULL DEFAULT 'default',
  retention_until TIMESTAMPTZ,
  retention_status VARCHAR(40) NOT NULL DEFAULT 'active',
  legal_hold BOOLEAN NOT NULL DEFAULT FALSE,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_ceg_versions_graph_scope
    FOREIGN KEY (graph_id, tenant_id, workspace_id, project_id, scope_type, scope_id)
    REFERENCES canonical_execution_graphs(
      id, tenant_id, workspace_id, project_id, scope_type, scope_id
    ) ON DELETE RESTRICT,
  CONSTRAINT fk_ceg_versions_environment_project
    FOREIGN KEY (environment_id, project_id)
    REFERENCES project_environments(id, project_id) ON DELETE RESTRICT,
  CONSTRAINT fk_ceg_versions_parent_scope
    FOREIGN KEY (parent_version_id, graph_id, tenant_id, workspace_id, project_id, scope_id)
    REFERENCES canonical_execution_graph_versions(
      id, graph_id, tenant_id, workspace_id, project_id, scope_id
    ) ON DELETE RESTRICT,
  CONSTRAINT uq_ceg_versions_graph_version UNIQUE (graph_id, version_number),
  CONSTRAINT uq_ceg_versions_graph_hash UNIQUE (graph_id, content_hash),
  CONSTRAINT uq_ceg_versions_parent_identity UNIQUE (
    id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ),
  CONSTRAINT uq_ceg_versions_idempotency UNIQUE (tenant_id, workspace_id, idempotency_key),
  CONSTRAINT chk_ceg_versions_number CHECK (version_number > 0),
  CONSTRAINT chk_ceg_versions_parent_not_self CHECK (parent_version_id IS NULL OR parent_version_id <> id),
  CONSTRAINT chk_ceg_versions_scope_identity CHECK (
    (scope_type = 'project' AND environment_id IS NULL AND scope_id = project_id)
    OR
    (scope_type = 'environment' AND environment_id IS NOT NULL AND scope_id = environment_id)
  ),
  CONSTRAINT chk_ceg_versions_content_hash_length CHECK (length(content_hash) = 71),
  CONSTRAINT chk_ceg_versions_content_hash_prefix CHECK (substr(content_hash, 1, 7) = 'sha256:'),
  CONSTRAINT chk_ceg_versions_request_hash_length CHECK (length(request_hash) = 71),
  CONSTRAINT chk_ceg_versions_request_hash_prefix CHECK (substr(request_hash, 1, 7) = 'sha256:'),
  CONSTRAINT chk_ceg_versions_lock_version CHECK (lock_version > 0),
  CONSTRAINT chk_ceg_versions_retention_status CHECK (
    retention_status IN ('active', 'archived', 'purge_eligible', 'legal_hold')
  ),
  CONSTRAINT chk_ceg_versions_frozen_metadata CHECK (
    (is_frozen = FALSE AND frozen_at IS NULL AND frozen_by IS NULL)
    OR (is_frozen = TRUE AND frozen_at IS NOT NULL)
  ),
  CONSTRAINT chk_ceg_versions_canonical_frozen CHECK (
    source <> 'canonical'
    OR (is_frozen = TRUE AND status IN ('active', 'superseded', 'deprecated', 'archived'))
  ),
  CONSTRAINT chk_ceg_versions_active_canonical CHECK (
    status <> 'active' OR (source = 'canonical' AND is_frozen = TRUE)
  ),
  CONSTRAINT chk_ceg_versions_source_refs_array CHECK (jsonb_typeof(source_refs) = 'array'),
  CONSTRAINT chk_ceg_versions_applicability_object CHECK (jsonb_typeof(applicability) = 'object'),
  CONSTRAINT chk_ceg_versions_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array'),
  CONSTRAINT chk_ceg_versions_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_ceg_versions_graph
  ON canonical_execution_graph_versions(graph_id, version_number);
CREATE INDEX IF NOT EXISTS idx_ceg_versions_scope
  ON canonical_execution_graph_versions(tenant_id, workspace_id, project_id, scope_id);
CREATE INDEX IF NOT EXISTS idx_ceg_versions_parent
  ON canonical_execution_graph_versions(parent_version_id);
CREATE INDEX IF NOT EXISTS idx_ceg_versions_status_source
  ON canonical_execution_graph_versions(status, source);
CREATE INDEX IF NOT EXISTS idx_ceg_versions_hash
  ON canonical_execution_graph_versions(content_hash);
CREATE INDEX IF NOT EXISTS idx_ceg_versions_retention
  ON canonical_execution_graph_versions(retention_status, retention_until);

CREATE OR REPLACE FUNCTION prevent_ceg_identity_scope_update()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.status = 'archived' THEN
    RAISE EXCEPTION 'archived Canonical Execution Graph identities are immutable'
      USING ERRCODE = '55000';
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
    OR NEW.project_id IS DISTINCT FROM OLD.project_id
    OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
    OR NEW.scope_type IS DISTINCT FROM OLD.scope_type
    OR NEW.scope_id IS DISTINCT FROM OLD.scope_id
    OR NEW.graph_key IS DISTINCT FROM OLD.graph_key
    OR NEW.graph_ref IS DISTINCT FROM OLD.graph_ref
  THEN
    RAISE EXCEPTION 'Canonical Execution Graph identity and scope are immutable'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION prevent_ceg_version_content_update()
RETURNS TRIGGER AS $$
DECLARE
  content_changed BOOLEAN;
BEGIN
  IF OLD.status = 'archived' THEN
    RAISE EXCEPTION 'archived Canonical Execution Graph versions are immutable'
      USING ERRCODE = '55000';
  END IF;
  content_changed :=
    NEW.graph_id IS DISTINCT FROM OLD.graph_id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
    OR NEW.project_id IS DISTINCT FROM OLD.project_id
    OR NEW.environment_id IS DISTINCT FROM OLD.environment_id
    OR NEW.scope_type IS DISTINCT FROM OLD.scope_type
    OR NEW.scope_id IS DISTINCT FROM OLD.scope_id
    OR NEW.version_number IS DISTINCT FROM OLD.version_number
    OR NEW.version_ref IS DISTINCT FROM OLD.version_ref
    OR NEW.parent_version_id IS DISTINCT FROM OLD.parent_version_id
    OR NEW.source IS DISTINCT FROM OLD.source
    OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
    OR NEW.content_hash IS DISTINCT FROM OLD.content_hash
    OR NEW.source_refs IS DISTINCT FROM OLD.source_refs
    OR NEW.applicability IS DISTINCT FROM OLD.applicability
    OR NEW.metadata IS DISTINCT FROM OLD.metadata;
  IF (OLD.is_frozen OR OLD.status NOT IN ('draft', 'candidate')) AND content_changed THEN
    RAISE EXCEPTION 'frozen or published Canonical Execution Graph version content is immutable'
      USING ERRCODE = '55000';
  END IF;
  IF (NEW.is_frozen OR NEW.status NOT IN ('draft', 'candidate')) AND content_changed THEN
    RAISE EXCEPTION 'freezing or publishing a Canonical Execution Graph version cannot change content'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION prevent_ceg_published_version_delete()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.is_frozen OR OLD.status NOT IN ('draft', 'candidate') THEN
    RAISE EXCEPTION 'frozen or published Canonical Execution Graph versions cannot be deleted'
      USING ERRCODE = '55000';
  END IF;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ceg_graphs_immutable ON canonical_execution_graphs;
CREATE TRIGGER trg_ceg_graphs_immutable
BEFORE UPDATE ON canonical_execution_graphs
FOR EACH ROW EXECUTE FUNCTION prevent_ceg_identity_scope_update();

DROP TRIGGER IF EXISTS trg_ceg_graphs_updated_at ON canonical_execution_graphs;
CREATE TRIGGER trg_ceg_graphs_updated_at
BEFORE UPDATE ON canonical_execution_graphs
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_ceg_versions_immutable ON canonical_execution_graph_versions;
CREATE TRIGGER trg_ceg_versions_immutable
BEFORE UPDATE ON canonical_execution_graph_versions
FOR EACH ROW EXECUTE FUNCTION prevent_ceg_version_content_update();

DROP TRIGGER IF EXISTS trg_ceg_versions_delete_guard ON canonical_execution_graph_versions;
CREATE TRIGGER trg_ceg_versions_delete_guard
BEFORE DELETE ON canonical_execution_graph_versions
FOR EACH ROW EXECUTE FUNCTION prevent_ceg_published_version_delete();

DROP TRIGGER IF EXISTS trg_ceg_versions_updated_at ON canonical_execution_graph_versions;
CREATE TRIGGER trg_ceg_versions_updated_at
BEFORE UPDATE ON canonical_execution_graph_versions
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('graph.read', 'graph', 'Reserved read access for Canonical Execution Graph data.', 'low', TRUE),
  ('graph.manage', 'graph', 'Reserved managed write access for draft/candidate CEG topology.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = EXCLUDED.is_active;

COMMENT ON TABLE canonical_execution_graphs IS
  'P10 Service-owned CEG identity. CEG is not a Skill, Agent, service, or lifecycle stage.';
COMMENT ON TABLE canonical_execution_graph_versions IS
  'CEG version metadata, stable refs, and P11 topology owner. Canonical promotion remains pending.';

-- P11 structured CEG topology. These tables extend the P10 identity/version
-- authority and do not execute actions or duplicate Trace/Replay/Gate/Memory.
CREATE TABLE IF NOT EXISTS canonical_execution_graph_nodes (
  id UUID PRIMARY KEY,
  node_ref VARCHAR(500) NOT NULL UNIQUE,
  version_id UUID NOT NULL,
  graph_id UUID NOT NULL,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL,
  scope_id UUID NOT NULL,
  client_key VARCHAR(128) NOT NULL,
  semantic_key VARCHAR(256) NOT NULL,
  node_type VARCHAR(40) NOT NULL,
  display_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  external_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  risk_level VARCHAR(20) NOT NULL DEFAULT 'low',
  source VARCHAR(40) NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_ceg_nodes_version_scope FOREIGN KEY (
    version_id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) REFERENCES canonical_execution_graph_versions(
    id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) ON DELETE CASCADE,
  CONSTRAINT uq_ceg_nodes_version_identity UNIQUE (id, version_id),
  CONSTRAINT uq_ceg_nodes_client_key UNIQUE (version_id, client_key),
  CONSTRAINT uq_ceg_nodes_semantic_key UNIQUE (version_id, semantic_key),
  CONSTRAINT chk_ceg_nodes_type CHECK (node_type IN (
    'requirement', 'capability', 'page', 'component', 'element', 'action',
    'assertion', 'data', 'api', 'code', 'test', 'evidence'
  )),
  CONSTRAINT chk_ceg_nodes_risk CHECK (risk_level IN ('low', 'medium', 'high')),
  CONSTRAINT chk_ceg_nodes_source CHECK (source IN ('observed', 'candidate', 'imported', 'manual', 'canonical')),
  CONSTRAINT chk_ceg_nodes_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_ceg_nodes_lock_version CHECK (lock_version > 0),
  CONSTRAINT chk_ceg_nodes_request_hash CHECK (length(request_hash) = 71 AND request_hash LIKE 'sha256:%'),
  CONSTRAINT chk_ceg_nodes_display_object CHECK (jsonb_typeof(display_metadata) = 'object'),
  CONSTRAINT chk_ceg_nodes_attributes_object CHECK (jsonb_typeof(attributes) = 'object'),
  CONSTRAINT chk_ceg_nodes_external_refs_array CHECK (jsonb_typeof(external_refs) = 'array'),
  CONSTRAINT chk_ceg_nodes_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_ceg_nodes_version_type ON canonical_execution_graph_nodes(version_id, node_type);
CREATE INDEX IF NOT EXISTS idx_ceg_nodes_scope ON canonical_execution_graph_nodes(tenant_id, workspace_id, project_id, scope_id);
CREATE INDEX IF NOT EXISTS idx_ceg_nodes_semantic ON canonical_execution_graph_nodes(version_id, semantic_key);

CREATE TABLE IF NOT EXISTS canonical_execution_graph_edges (
  id UUID PRIMARY KEY,
  edge_ref VARCHAR(500) NOT NULL UNIQUE,
  version_id UUID NOT NULL,
  graph_id UUID NOT NULL,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL,
  scope_id UUID NOT NULL,
  client_key VARCHAR(128) NOT NULL,
  edge_type VARCHAR(40) NOT NULL,
  source_node_id UUID NOT NULL,
  target_node_id UUID NOT NULL,
  condition JSONB,
  risk_level VARCHAR(20) NOT NULL DEFAULT 'low',
  review_status VARCHAR(40) NOT NULL DEFAULT 'not_required',
  source VARCHAR(40) NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  semantic_hash VARCHAR(80) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_ceg_edges_version_scope FOREIGN KEY (
    version_id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) REFERENCES canonical_execution_graph_versions(
    id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) ON DELETE CASCADE,
  CONSTRAINT fk_ceg_edges_source_version FOREIGN KEY (source_node_id, version_id)
    REFERENCES canonical_execution_graph_nodes(id, version_id) ON DELETE RESTRICT,
  CONSTRAINT fk_ceg_edges_target_version FOREIGN KEY (target_node_id, version_id)
    REFERENCES canonical_execution_graph_nodes(id, version_id) ON DELETE RESTRICT,
  CONSTRAINT uq_ceg_edges_version_identity UNIQUE (id, version_id),
  CONSTRAINT uq_ceg_edges_client_key UNIQUE (version_id, client_key),
  CONSTRAINT uq_ceg_edges_semantic_hash UNIQUE (version_id, semantic_hash),
  CONSTRAINT chk_ceg_edges_type CHECK (edge_type IN (
    'contains', 'precedes', 'transitions_to', 'depends_on', 'implements',
    'verifies', 'produces', 'evidenced_by', 'changes', 'affects'
  )),
  CONSTRAINT chk_ceg_edges_not_self CHECK (source_node_id <> target_node_id),
  CONSTRAINT chk_ceg_edges_risk CHECK (risk_level IN ('low', 'medium', 'high')),
  CONSTRAINT chk_ceg_edges_review_status CHECK (review_status IN ('not_required', 'pending_review', 'approved', 'rejected')),
  CONSTRAINT chk_ceg_edges_source CHECK (source IN ('observed', 'candidate', 'imported', 'manual', 'canonical')),
  CONSTRAINT chk_ceg_edges_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_ceg_edges_lock_version CHECK (lock_version > 0),
  CONSTRAINT chk_ceg_edges_semantic_hash CHECK (length(semantic_hash) = 71 AND semantic_hash LIKE 'sha256:%'),
  CONSTRAINT chk_ceg_edges_request_hash CHECK (length(request_hash) = 71 AND request_hash LIKE 'sha256:%'),
  CONSTRAINT chk_ceg_edges_condition_object CHECK (condition IS NULL OR jsonb_typeof(condition) = 'object'),
  CONSTRAINT chk_ceg_edges_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_ceg_edges_version_type ON canonical_execution_graph_edges(version_id, edge_type);
CREATE INDEX IF NOT EXISTS idx_ceg_edges_source ON canonical_execution_graph_edges(version_id, source_node_id);
CREATE INDEX IF NOT EXISTS idx_ceg_edges_target ON canonical_execution_graph_edges(version_id, target_node_id);
CREATE INDEX IF NOT EXISTS idx_ceg_edges_scope ON canonical_execution_graph_edges(tenant_id, workspace_id, project_id, scope_id);

CREATE TABLE IF NOT EXISTS canonical_execution_graph_paths (
  id UUID PRIMARY KEY,
  path_ref VARCHAR(500) NOT NULL UNIQUE,
  version_id UUID NOT NULL,
  graph_id UUID NOT NULL,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL,
  scope_id UUID NOT NULL,
  client_key VARCHAR(128) NOT NULL,
  path_key VARCHAR(256) NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  entry_node_id UUID NOT NULL,
  exit_node_id UUID NOT NULL,
  preconditions JSONB NOT NULL DEFAULT '[]'::jsonb,
  postconditions JSONB NOT NULL DEFAULT '[]'::jsonb,
  risk_level VARCHAR(20) NOT NULL DEFAULT 'low',
  applicability JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  source VARCHAR(40) NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_ceg_paths_version_scope FOREIGN KEY (
    version_id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) REFERENCES canonical_execution_graph_versions(
    id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) ON DELETE CASCADE,
  CONSTRAINT fk_ceg_paths_entry_version FOREIGN KEY (entry_node_id, version_id)
    REFERENCES canonical_execution_graph_nodes(id, version_id) ON DELETE RESTRICT,
  CONSTRAINT fk_ceg_paths_exit_version FOREIGN KEY (exit_node_id, version_id)
    REFERENCES canonical_execution_graph_nodes(id, version_id) ON DELETE RESTRICT,
  CONSTRAINT uq_ceg_paths_version_identity UNIQUE (id, version_id),
  CONSTRAINT uq_ceg_paths_client_key UNIQUE (version_id, client_key),
  CONSTRAINT uq_ceg_paths_path_key UNIQUE (version_id, path_key),
  CONSTRAINT chk_ceg_paths_risk CHECK (risk_level IN ('low', 'medium', 'high')),
  CONSTRAINT chk_ceg_paths_source CHECK (source IN ('observed', 'candidate', 'imported', 'manual', 'canonical')),
  CONSTRAINT chk_ceg_paths_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_ceg_paths_lock_version CHECK (lock_version > 0),
  CONSTRAINT chk_ceg_paths_request_hash CHECK (length(request_hash) = 71 AND request_hash LIKE 'sha256:%'),
  CONSTRAINT chk_ceg_paths_preconditions_array CHECK (jsonb_typeof(preconditions) = 'array'),
  CONSTRAINT chk_ceg_paths_postconditions_array CHECK (jsonb_typeof(postconditions) = 'array'),
  CONSTRAINT chk_ceg_paths_applicability_object CHECK (jsonb_typeof(applicability) = 'object'),
  CONSTRAINT chk_ceg_paths_evidence_refs_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
  CONSTRAINT chk_ceg_paths_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_ceg_paths_version ON canonical_execution_graph_paths(version_id, path_key);
CREATE INDEX IF NOT EXISTS idx_ceg_paths_entry ON canonical_execution_graph_paths(version_id, entry_node_id);
CREATE INDEX IF NOT EXISTS idx_ceg_paths_exit ON canonical_execution_graph_paths(version_id, exit_node_id);
CREATE INDEX IF NOT EXISTS idx_ceg_paths_scope ON canonical_execution_graph_paths(tenant_id, workspace_id, project_id, scope_id);

CREATE TABLE IF NOT EXISTS canonical_execution_graph_path_steps (
  id UUID PRIMARY KEY,
  step_ref VARCHAR(500) NOT NULL UNIQUE,
  path_id UUID NOT NULL,
  version_id UUID NOT NULL,
  graph_id UUID NOT NULL,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL,
  scope_id UUID NOT NULL,
  client_key VARCHAR(128) NOT NULL,
  step_order INTEGER NOT NULL,
  node_id UUID NOT NULL,
  via_edge_id UUID,
  conditions JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_ceg_steps_version_scope FOREIGN KEY (
    version_id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) REFERENCES canonical_execution_graph_versions(
    id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) ON DELETE CASCADE,
  CONSTRAINT fk_ceg_steps_path_version FOREIGN KEY (path_id, version_id)
    REFERENCES canonical_execution_graph_paths(id, version_id) ON DELETE CASCADE,
  CONSTRAINT fk_ceg_steps_node_version FOREIGN KEY (node_id, version_id)
    REFERENCES canonical_execution_graph_nodes(id, version_id) ON DELETE RESTRICT,
  CONSTRAINT fk_ceg_steps_edge_version FOREIGN KEY (via_edge_id, version_id)
    REFERENCES canonical_execution_graph_edges(id, version_id) ON DELETE RESTRICT,
  CONSTRAINT uq_ceg_steps_path_order UNIQUE (path_id, step_order),
  CONSTRAINT uq_ceg_steps_client_key UNIQUE (path_id, client_key),
  CONSTRAINT chk_ceg_steps_order CHECK (step_order > 0),
  CONSTRAINT chk_ceg_steps_lock_version CHECK (lock_version > 0),
  CONSTRAINT chk_ceg_steps_conditions_array CHECK (jsonb_typeof(conditions) = 'array'),
  CONSTRAINT chk_ceg_steps_evidence_refs_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
  CONSTRAINT chk_ceg_steps_audit_refs_array CHECK (jsonb_typeof(audit_refs) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_ceg_steps_version ON canonical_execution_graph_path_steps(version_id, path_id);
CREATE INDEX IF NOT EXISTS idx_ceg_steps_node ON canonical_execution_graph_path_steps(version_id, node_id);
CREATE INDEX IF NOT EXISTS idx_ceg_steps_edge ON canonical_execution_graph_path_steps(version_id, via_edge_id);
CREATE INDEX IF NOT EXISTS idx_ceg_steps_scope ON canonical_execution_graph_path_steps(tenant_id, workspace_id, project_id, scope_id);

CREATE OR REPLACE FUNCTION prevent_ceg_topology_on_immutable_version()
RETURNS TRIGGER AS $$
DECLARE
  target_version_id UUID;
  target_status graph_status;
  target_frozen BOOLEAN;
BEGIN
  IF TG_OP = 'DELETE' THEN
    target_version_id := OLD.version_id;
  ELSE
    target_version_id := NEW.version_id;
  END IF;
  SELECT status, is_frozen INTO target_status, target_frozen
  FROM canonical_execution_graph_versions WHERE id = target_version_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Canonical Execution Graph topology requires an existing version';
  END IF;
  IF target_frozen OR target_status NOT IN ('draft', 'candidate') THEN
    RAISE EXCEPTION 'canonical or published Canonical Execution Graph topology is immutable';
  END IF;
  IF TG_OP = 'UPDATE' AND (
    OLD.id IS DISTINCT FROM NEW.id OR OLD.version_id IS DISTINCT FROM NEW.version_id OR
    OLD.graph_id IS DISTINCT FROM NEW.graph_id OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR
    OLD.workspace_id IS DISTINCT FROM NEW.workspace_id OR OLD.project_id IS DISTINCT FROM NEW.project_id OR
    OLD.scope_id IS DISTINCT FROM NEW.scope_id OR OLD.client_key IS DISTINCT FROM NEW.client_key
  ) THEN
    RAISE EXCEPTION 'Canonical Execution Graph topology identity and scope are immutable';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ceg_nodes_version_guard ON canonical_execution_graph_nodes;
CREATE TRIGGER trg_ceg_nodes_version_guard BEFORE INSERT OR UPDATE OR DELETE ON canonical_execution_graph_nodes
FOR EACH ROW EXECUTE FUNCTION prevent_ceg_topology_on_immutable_version();
DROP TRIGGER IF EXISTS trg_ceg_edges_version_guard ON canonical_execution_graph_edges;
CREATE TRIGGER trg_ceg_edges_version_guard BEFORE INSERT OR UPDATE OR DELETE ON canonical_execution_graph_edges
FOR EACH ROW EXECUTE FUNCTION prevent_ceg_topology_on_immutable_version();
DROP TRIGGER IF EXISTS trg_ceg_paths_version_guard ON canonical_execution_graph_paths;
CREATE TRIGGER trg_ceg_paths_version_guard BEFORE INSERT OR UPDATE OR DELETE ON canonical_execution_graph_paths
FOR EACH ROW EXECUTE FUNCTION prevent_ceg_topology_on_immutable_version();
DROP TRIGGER IF EXISTS trg_ceg_steps_version_guard ON canonical_execution_graph_path_steps;
CREATE TRIGGER trg_ceg_steps_version_guard BEFORE INSERT OR UPDATE OR DELETE ON canonical_execution_graph_path_steps
FOR EACH ROW EXECUTE FUNCTION prevent_ceg_topology_on_immutable_version();

DROP TRIGGER IF EXISTS trg_ceg_nodes_updated_at ON canonical_execution_graph_nodes;
CREATE TRIGGER trg_ceg_nodes_updated_at BEFORE UPDATE ON canonical_execution_graph_nodes FOR EACH ROW EXECUTE FUNCTION set_updated_at();
DROP TRIGGER IF EXISTS trg_ceg_edges_updated_at ON canonical_execution_graph_edges;
CREATE TRIGGER trg_ceg_edges_updated_at BEFORE UPDATE ON canonical_execution_graph_edges FOR EACH ROW EXECUTE FUNCTION set_updated_at();
DROP TRIGGER IF EXISTS trg_ceg_paths_updated_at ON canonical_execution_graph_paths;
CREATE TRIGGER trg_ceg_paths_updated_at BEFORE UPDATE ON canonical_execution_graph_paths FOR EACH ROW EXECUTE FUNCTION set_updated_at();
DROP TRIGGER IF EXISTS trg_ceg_steps_updated_at ON canonical_execution_graph_path_steps;
CREATE TRIGGER trg_ceg_steps_updated_at BEFORE UPDATE ON canonical_execution_graph_path_steps FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE canonical_execution_graph_nodes IS
  'P11 structured semantic CEG nodes; not browser, Tool, SemanticAction, or Visual Grounding executors.';
COMMENT ON TABLE canonical_execution_graph_edges IS
  'P11 controlled CEG relations; high-risk relations remain pending review and do not approve themselves.';
COMMENT ON TABLE canonical_execution_graph_paths IS
  'P11 ordered Canonical Path candidates owned by a single scoped graph version.';
COMMENT ON TABLE canonical_execution_graph_path_steps IS
  'P11 ordered path steps referencing existing same-version nodes and connecting edges.';

CREATE TABLE IF NOT EXISTS candidate_graph_build_runs (
  id UUID PRIMARY KEY,
  build_ref VARCHAR(500) NOT NULL UNIQUE,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL,
  graph_id UUID NOT NULL,
  scope_id UUID NOT NULL,
  candidate_version_id UUID NOT NULL,
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE RESTRICT,
  source_identity_hash VARCHAR(80) NOT NULL,
  semantic_path_hash VARCHAR(80) NOT NULL,
  transformer_version VARCHAR(80) NOT NULL,
  config_hash VARCHAR(80) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'running',
  outcome VARCHAR(32) NOT NULL DEFAULT 'unknown',
  source_revision_hash VARCHAR(80),
  source_environment VARCHAR(100) NOT NULL,
  source_observed_at TIMESTAMPTZ NOT NULL,
  action_count INTEGER NOT NULL,
  verified_action_count INTEGER NOT NULL DEFAULT 0,
  retry_count INTEGER NOT NULL DEFAULT 0,
  coordinate_click_count INTEGER NOT NULL DEFAULT 0,
  fallback_types JSONB NOT NULL DEFAULT '[]'::jsonb,
  observed_trace_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  ambiguities JSONB NOT NULL DEFAULT '[]'::jsonb,
  model_suggestion JSONB NOT NULL DEFAULT '{}'::jsonb,
  model_invocation_id UUID REFERENCES model_invocations(id) ON DELETE SET NULL,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  canonical BOOLEAN NOT NULL DEFAULT FALSE,
  active BOOLEAN NOT NULL DEFAULT FALSE,
  promotion_performed BOOLEAN NOT NULL DEFAULT FALSE,
  error_code VARCHAR(120),
  started_at TIMESTAMPTZ NOT NULL,
  finished_at TIMESTAMPTZ,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_candidate_builds_version_scope FOREIGN KEY (
    candidate_version_id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) REFERENCES canonical_execution_graph_versions(
    id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) ON DELETE RESTRICT,
  CONSTRAINT uq_candidate_builds_idempotency UNIQUE (
    tenant_id, workspace_id, graph_id, execution_id, transformer_version, config_hash
  ),
  CONSTRAINT chk_candidate_builds_status CHECK (status IN ('running', 'completed', 'failed')),
  CONSTRAINT chk_candidate_builds_outcome CHECK (outcome IN ('success', 'failure', 'partial', 'unknown')),
  CONSTRAINT chk_candidate_builds_config_hash CHECK (length(config_hash) = 71 AND config_hash LIKE 'sha256:%'),
  CONSTRAINT chk_candidate_builds_request_hash CHECK (length(request_hash) = 71 AND request_hash LIKE 'sha256:%'),
  CONSTRAINT chk_candidate_builds_source_identity_hash CHECK (length(source_identity_hash) = 71 AND source_identity_hash LIKE 'sha256:%'),
  CONSTRAINT chk_candidate_builds_semantic_path_hash CHECK (length(semantic_path_hash) = 71 AND semantic_path_hash LIKE 'sha256:%'),
  CONSTRAINT chk_candidate_builds_revision_hash CHECK (source_revision_hash IS NULL OR (length(source_revision_hash) = 71 AND source_revision_hash LIKE 'sha256:%')),
  CONSTRAINT chk_candidate_builds_action_count CHECK (action_count > 0),
  CONSTRAINT chk_candidate_builds_verified_count CHECK (verified_action_count >= 0 AND verified_action_count <= action_count),
  CONSTRAINT chk_candidate_builds_counts CHECK (retry_count >= 0 AND coordinate_click_count >= 0),
  CONSTRAINT chk_candidate_builds_never_canonical CHECK (
    canonical = FALSE AND active = FALSE AND promotion_performed = FALSE
  ),
  CONSTRAINT chk_candidate_builds_fallback_array CHECK (jsonb_typeof(fallback_types) = 'array'),
  CONSTRAINT chk_candidate_builds_observed_object CHECK (jsonb_typeof(observed_trace_snapshot) = 'object'),
  CONSTRAINT chk_candidate_builds_summary_object CHECK (jsonb_typeof(evidence_summary) = 'object'),
  CONSTRAINT chk_candidate_builds_ambiguities_array CHECK (jsonb_typeof(ambiguities) = 'array'),
  CONSTRAINT chk_candidate_builds_model_object CHECK (jsonb_typeof(model_suggestion) = 'object'),
  CONSTRAINT chk_candidate_builds_guardrail_array CHECK (jsonb_typeof(guardrail_event_refs) = 'array'),
  CONSTRAINT chk_candidate_builds_audit_array CHECK (jsonb_typeof(audit_refs) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_candidate_builds_scope
  ON candidate_graph_build_runs(tenant_id, workspace_id, project_id, graph_id);
CREATE INDEX IF NOT EXISTS idx_candidate_builds_execution
  ON candidate_graph_build_runs(execution_id);
CREATE INDEX IF NOT EXISTS idx_candidate_builds_semantic_path
  ON candidate_graph_build_runs(graph_id, semantic_path_hash, created_at);
CREATE INDEX IF NOT EXISTS idx_candidate_builds_version
  ON candidate_graph_build_runs(candidate_version_id);

CREATE TABLE IF NOT EXISTS candidate_graph_source_mappings (
  id UUID PRIMARY KEY,
  build_id UUID NOT NULL REFERENCES candidate_graph_build_runs(id) ON DELETE CASCADE,
  candidate_version_id UUID NOT NULL,
  graph_id UUID NOT NULL,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL,
  scope_id UUID NOT NULL,
  entity_type VARCHAR(32) NOT NULL,
  entity_id UUID NOT NULL,
  entity_ref VARCHAR(500) NOT NULL,
  source_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  observation_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  transformer_version VARCHAR(80) NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  ambiguities JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_candidate_mappings_version_scope FOREIGN KEY (
    candidate_version_id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) REFERENCES canonical_execution_graph_versions(
    id, graph_id, tenant_id, workspace_id, project_id, scope_id
  ) ON DELETE CASCADE,
  CONSTRAINT uq_candidate_mappings_build_entity UNIQUE (build_id, entity_type, entity_id),
  CONSTRAINT chk_candidate_mappings_entity_type CHECK (entity_type IN ('node', 'edge', 'path', 'path_step')),
  CONSTRAINT chk_candidate_mappings_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_candidate_mappings_source_array CHECK (jsonb_typeof(source_event_refs) = 'array'),
  CONSTRAINT chk_candidate_mappings_evidence_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
  CONSTRAINT chk_candidate_mappings_observation_object CHECK (jsonb_typeof(observation_summary) = 'object'),
  CONSTRAINT chk_candidate_mappings_ambiguities_array CHECK (jsonb_typeof(ambiguities) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_candidate_mappings_build
  ON candidate_graph_source_mappings(build_id, entity_type);
CREATE INDEX IF NOT EXISTS idx_candidate_mappings_version_entity
  ON candidate_graph_source_mappings(candidate_version_id, entity_type, entity_id);

DROP TRIGGER IF EXISTS trg_candidate_builds_updated_at ON candidate_graph_build_runs;
CREATE TRIGGER trg_candidate_builds_updated_at BEFORE UPDATE ON candidate_graph_build_runs
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE OR REPLACE FUNCTION protect_candidate_graph_build_mutation()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Candidate build provenance cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
    OR NEW.build_ref IS DISTINCT FROM OLD.build_ref
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
    OR NEW.project_id IS DISTINCT FROM OLD.project_id
    OR NEW.graph_id IS DISTINCT FROM OLD.graph_id
    OR NEW.scope_id IS DISTINCT FROM OLD.scope_id
    OR NEW.candidate_version_id IS DISTINCT FROM OLD.candidate_version_id
    OR NEW.execution_id IS DISTINCT FROM OLD.execution_id
    OR NEW.source_identity_hash IS DISTINCT FROM OLD.source_identity_hash
    OR NEW.semantic_path_hash IS DISTINCT FROM OLD.semantic_path_hash
    OR NEW.transformer_version IS DISTINCT FROM OLD.transformer_version
    OR NEW.config_hash IS DISTINCT FROM OLD.config_hash
    OR NEW.request_hash IS DISTINCT FROM OLD.request_hash
    OR NEW.status IS DISTINCT FROM OLD.status
    OR NEW.outcome IS DISTINCT FROM OLD.outcome
    OR NEW.source_revision_hash IS DISTINCT FROM OLD.source_revision_hash
    OR NEW.source_environment IS DISTINCT FROM OLD.source_environment
    OR NEW.source_observed_at IS DISTINCT FROM OLD.source_observed_at
    OR NEW.action_count IS DISTINCT FROM OLD.action_count
    OR NEW.verified_action_count IS DISTINCT FROM OLD.verified_action_count
    OR NEW.retry_count IS DISTINCT FROM OLD.retry_count
    OR NEW.coordinate_click_count IS DISTINCT FROM OLD.coordinate_click_count
    OR NEW.fallback_types IS DISTINCT FROM OLD.fallback_types
    OR NEW.observed_trace_snapshot IS DISTINCT FROM OLD.observed_trace_snapshot
    OR NEW.ambiguities IS DISTINCT FROM OLD.ambiguities
    OR NEW.model_suggestion IS DISTINCT FROM OLD.model_suggestion
    OR NEW.model_invocation_id IS DISTINCT FROM OLD.model_invocation_id
    OR NEW.guardrail_event_refs IS DISTINCT FROM OLD.guardrail_event_refs
    OR NEW.trace_id IS DISTINCT FROM OLD.trace_id
    OR NEW.canonical IS DISTINCT FROM OLD.canonical
    OR NEW.active IS DISTINCT FROM OLD.active
    OR NEW.promotion_performed IS DISTINCT FROM OLD.promotion_performed THEN
    RAISE EXCEPTION 'Candidate build facts and source identity are immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_candidate_builds_immutable ON candidate_graph_build_runs;
CREATE TRIGGER trg_candidate_builds_immutable
BEFORE UPDATE OR DELETE ON candidate_graph_build_runs
FOR EACH ROW EXECUTE FUNCTION protect_candidate_graph_build_mutation();

CREATE OR REPLACE FUNCTION protect_candidate_source_mapping_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Candidate source mappings are append-only' USING ERRCODE = '55000';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_candidate_mappings_append_only ON candidate_graph_source_mappings;
CREATE TRIGGER trg_candidate_mappings_append_only
BEFORE UPDATE OR DELETE ON candidate_graph_source_mappings
FOR EACH ROW EXECUTE FUNCTION protect_candidate_source_mapping_mutation();

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('graph.candidate.read', 'graph', 'Read Trace-derived Candidate Path observations.', 'low', TRUE),
  ('graph.candidate.create', 'graph', 'Run the internal Trace-to-Candidate transformation.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = EXCLUDED.is_active;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'graph.candidate.read', TRUE),
  ('pro', 'graph.candidate.read', TRUE),
  ('enterprise', 'graph.candidate.read', TRUE),
  ('enterprise', 'graph.candidate.create', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = EXCLUDED.enabled;

INSERT INTO rbac_role_capabilities (role_name, capability_key, effect)
VALUES
  ('user', 'graph.candidate.read', 'allow'),
  ('admin', 'graph.candidate.read', 'allow'),
  ('admin', 'graph.candidate.create', 'allow'),
  ('system', 'graph.candidate.read', 'allow'),
  ('system', 'graph.candidate.create', 'allow')
ON CONFLICT (role_name, capability_key) DO UPDATE SET effect = EXCLUDED.effect;

COMMENT ON TABLE candidate_graph_build_runs IS
  'P12 Trace-to-Candidate build/audit state. A build can never be active canonical and performs no Promotion.';
COMMENT ON TABLE candidate_graph_source_mappings IS
  'P12 per-element provenance and observation summaries; sensitive source payloads remain referenced, not copied.';

-- 24. P13 controlled Graph Promotion

CREATE TABLE IF NOT EXISTS graph_correction_proposals (
  id UUID PRIMARY KEY,
  correction_proposal_id UUID NOT NULL UNIQUE REFERENCES correction_proposals(id) ON DELETE CASCADE,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  environment_id UUID REFERENCES project_environments(id) ON DELETE RESTRICT,
  graph_id UUID NOT NULL REFERENCES canonical_execution_graphs(id) ON DELETE RESTRICT,
  base_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  base_version_hash VARCHAR(80) NOT NULL CHECK (base_version_hash LIKE 'sha256:%'),
  base_version_lock_version INTEGER NOT NULL CHECK (base_version_lock_version > 0),
  candidate_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  candidate_version_hash VARCHAR(80) NOT NULL CHECK (candidate_version_hash LIKE 'sha256:%'),
  candidate_build_id UUID NOT NULL REFERENCES candidate_graph_build_runs(id) ON DELETE RESTRICT,
  structured_patch JSONB NOT NULL,
  patch_hash VARCHAR(80) NOT NULL CHECK (patch_hash LIKE 'sha256:%'),
  rationale_code VARCHAR(120) NOT NULL,
  risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('low', 'medium', 'high')),
  status VARCHAR(32) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'validated', 'invalid', 'pending_review', 'promoted', 'rejected')),
  validation_report JSONB NOT NULL DEFAULT '{}'::jsonb,
  validation_hash VARCHAR(80),
  validator_version VARCHAR(80),
  validated_at TIMESTAMPTZ,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  policy_decision_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  rollback_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  latest_assessment_id UUID,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL CHECK (request_hash LIKE 'sha256:%'),
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  lock_version INTEGER NOT NULL DEFAULT 1 CHECK (lock_version > 0),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_graph_corrections_idempotency UNIQUE (tenant_id, workspace_id, idempotency_key)
  ,CONSTRAINT chk_graph_corrections_status CHECK (status IN ('draft', 'validated', 'invalid', 'pending_review', 'promoted', 'rejected'))
  ,CONSTRAINT chk_graph_corrections_risk CHECK (risk_level IN ('low', 'medium', 'high'))
  ,CONSTRAINT chk_graph_corrections_lock_version CHECK (lock_version > 0)
);
CREATE INDEX IF NOT EXISTS idx_graph_corrections_graph ON graph_correction_proposals(graph_id, created_at);
CREATE INDEX IF NOT EXISTS idx_graph_corrections_candidate ON graph_correction_proposals(candidate_version_id);
CREATE INDEX IF NOT EXISTS idx_graph_corrections_status ON graph_correction_proposals(status);

CREATE TABLE IF NOT EXISTS graph_learning_policies (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  policy_key VARCHAR(128) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'disabled', 'deprecated', 'archived')),
  lock_version INTEGER NOT NULL DEFAULT 1 CHECK (lock_version > 0),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_graph_learning_policy_key UNIQUE (tenant_id, workspace_id, project_id, policy_key),
  CONSTRAINT chk_graph_learning_policy_status CHECK (status IN ('draft', 'active', 'disabled', 'deprecated', 'archived')),
  CONSTRAINT chk_graph_learning_policy_lock CHECK (lock_version > 0)
);
CREATE INDEX IF NOT EXISTS idx_graph_learning_policy_scope ON graph_learning_policies(tenant_id, workspace_id, project_id);

CREATE TABLE IF NOT EXISTS graph_learning_policy_versions (
  id UUID PRIMARY KEY,
  policy_id UUID NOT NULL REFERENCES graph_learning_policies(id) ON DELETE RESTRICT,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  version_number INTEGER NOT NULL CHECK (version_number > 0),
  status VARCHAR(32) NOT NULL CHECK (status IN ('draft', 'active', 'disabled', 'deprecated', 'archived')),
  policy_document JSONB NOT NULL,
  content_hash VARCHAR(80) NOT NULL CHECK (content_hash LIKE 'sha256:%'),
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL CHECK (request_hash LIKE 'sha256:%'),
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  lock_version INTEGER NOT NULL DEFAULT 1 CHECK (lock_version > 0),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_graph_learning_policy_version UNIQUE (policy_id, version_number),
  CONSTRAINT uq_graph_learning_policy_hash UNIQUE (policy_id, content_hash),
  CONSTRAINT uq_graph_learning_policy_version_idempotency UNIQUE (tenant_id, workspace_id, idempotency_key),
  CONSTRAINT chk_graph_learning_policy_version_status CHECK (status IN ('draft', 'active', 'disabled', 'deprecated', 'archived')),
  CONSTRAINT chk_graph_learning_policy_version_numbers CHECK (version_number > 0 AND lock_version > 0)
);
CREATE INDEX IF NOT EXISTS idx_graph_learning_policy_version_scope ON graph_learning_policy_versions(tenant_id, workspace_id, project_id, status);

CREATE TABLE IF NOT EXISTS graph_learning_policy_bindings (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  environment_id UUID REFERENCES project_environments(id) ON DELETE CASCADE,
  scope_type VARCHAR(32) NOT NULL CHECK (scope_type IN ('project', 'environment')),
  scope_id UUID NOT NULL,
  policy_version_id UUID NOT NULL REFERENCES graph_learning_policy_versions(id) ON DELETE RESTRICT,
  policy_version_hash VARCHAR(80) NOT NULL CHECK (policy_version_hash LIKE 'sha256:%'),
  learning_mode VARCHAR(40) NOT NULL DEFAULT 'human_supervised' CHECK (learning_mode IN ('learn_only', 'human_supervised', 'controlled_autonomy')),
  status VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'deprecated', 'archived')),
  autonomy_paused BOOLEAN NOT NULL DEFAULT FALSE,
  pause_reason_code VARCHAR(120),
  paused_at TIMESTAMPTZ,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL CHECK (request_hash LIKE 'sha256:%'),
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  lock_version INTEGER NOT NULL DEFAULT 1 CHECK (lock_version > 0),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_graph_learning_binding_scope UNIQUE (tenant_id, workspace_id, project_id, scope_type, scope_id),
  CONSTRAINT uq_graph_learning_binding_idempotency UNIQUE (tenant_id, workspace_id, idempotency_key),
  CONSTRAINT chk_graph_learning_binding_scope_identity CHECK ((scope_type = 'project' AND environment_id IS NULL AND scope_id = project_id) OR (scope_type = 'environment' AND environment_id IS NOT NULL AND scope_id = environment_id)),
  CONSTRAINT chk_graph_learning_binding_scope CHECK (scope_type IN ('project', 'environment')),
  CONSTRAINT chk_graph_learning_binding_mode CHECK (learning_mode IN ('learn_only', 'human_supervised', 'controlled_autonomy')),
  CONSTRAINT chk_graph_learning_binding_status CHECK (status IN ('active', 'disabled', 'deprecated', 'archived')),
  CONSTRAINT chk_graph_learning_binding_lock CHECK (lock_version > 0)
);
CREATE INDEX IF NOT EXISTS idx_graph_learning_binding_resolve ON graph_learning_policy_bindings(tenant_id, workspace_id, project_id, environment_id, status);

CREATE TABLE IF NOT EXISTS graph_promotion_eligibility_assessments (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  proposal_id UUID NOT NULL REFERENCES graph_correction_proposals(id) ON DELETE CASCADE,
  graph_id UUID NOT NULL REFERENCES canonical_execution_graphs(id) ON DELETE RESTRICT,
  candidate_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  base_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  learning_mode VARCHAR(40) NOT NULL CHECK (learning_mode IN ('learn_only', 'human_supervised', 'controlled_autonomy')),
  risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('low', 'medium', 'high')),
  eligible BOOLEAN NOT NULL,
  automatic_promotion_allowed BOOLEAN NOT NULL,
  human_review_required BOOLEAN NOT NULL,
  checks_snapshot JSONB NOT NULL,
  reason_codes JSONB NOT NULL,
  input_snapshot JSONB NOT NULL,
  policy_version_id UUID REFERENCES graph_learning_policy_versions(id) ON DELETE RESTRICT,
  policy_version_hash VARCHAR(80) NOT NULL,
  binding_id UUID REFERENCES graph_learning_policy_bindings(id) ON DELETE RESTRICT,
  eligibility_hash VARCHAR(80) NOT NULL CHECK (eligibility_hash LIKE 'sha256:%'),
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL CHECK (request_hash LIKE 'sha256:%'),
  policy_decision_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  evaluated_at TIMESTAMPTZ NOT NULL,
  evaluated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_graph_promotion_assessment_idempotency UNIQUE (tenant_id, workspace_id, proposal_id, idempotency_key),
  CONSTRAINT chk_graph_promotion_assessment_mode CHECK (learning_mode IN ('learn_only', 'human_supervised', 'controlled_autonomy')),
  CONSTRAINT chk_graph_promotion_assessment_risk CHECK (risk_level IN ('low', 'medium', 'high'))
);
CREATE INDEX IF NOT EXISTS idx_graph_promotion_assessment_proposal ON graph_promotion_eligibility_assessments(proposal_id, evaluated_at);

CREATE TABLE IF NOT EXISTS canonical_graph_promotion_records (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  graph_id UUID NOT NULL REFERENCES canonical_execution_graphs(id) ON DELETE RESTRICT,
  proposal_id UUID NOT NULL REFERENCES graph_correction_proposals(id) ON DELETE RESTRICT,
  assessment_id UUID NOT NULL REFERENCES graph_promotion_eligibility_assessments(id) ON DELETE RESTRICT,
  before_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  before_version_hash VARCHAR(80) NOT NULL,
  candidate_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  target_version_id UUID NOT NULL UNIQUE REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  target_version_hash VARCHAR(80) NOT NULL,
  promotion_type VARCHAR(48) NOT NULL CHECK (promotion_type IN ('human_approved_promotion', 'policy_approved_auto_promotion', 'human_approved_rollback')),
  actor_type VARCHAR(16) NOT NULL CHECK (actor_type IN ('human', 'system')),
  actor_ref VARCHAR(500) NOT NULL,
  human_approval BOOLEAN NOT NULL,
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  policy_decision_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  eligibility_snapshot JSONB NOT NULL,
  policy_version_id UUID REFERENCES graph_learning_policy_versions(id) ON DELETE RESTRICT,
  policy_version_hash VARCHAR(80) NOT NULL,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  shadow_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  rollback_target_version_id UUID REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  status VARCHAR(24) NOT NULL CHECK (status IN ('promoted', 'rolled_back')),
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  promoted_at TIMESTAMPTZ NOT NULL,
  promoted_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_canonical_graph_promotion_idempotency UNIQUE (tenant_id, workspace_id, idempotency_key),
  CONSTRAINT chk_canonical_graph_promotion_type CHECK (promotion_type IN ('human_approved_promotion', 'policy_approved_auto_promotion', 'human_approved_rollback')),
  CONSTRAINT chk_canonical_graph_promotion_actor CHECK (actor_type IN ('human', 'system')),
  CONSTRAINT chk_canonical_graph_promotion_status CHECK (status IN ('promoted', 'rolled_back')),
  CONSTRAINT chk_canonical_graph_promotion_actor_ref CHECK ((actor_type = 'system' AND actor_ref = 'system://controlled-graph-promotion') OR (actor_type = 'human' AND actor_ref LIKE 'user://users/%')),
  CONSTRAINT chk_canonical_graph_promotion_approval_truth CHECK ((promotion_type = 'policy_approved_auto_promotion' AND human_approval = FALSE) OR (promotion_type <> 'policy_approved_auto_promotion' AND human_approval = TRUE)),
  CONSTRAINT chk_canonical_graph_promotion_approval_refs_truth CHECK ((promotion_type = 'policy_approved_auto_promotion' AND jsonb_array_length(approval_refs) = 0) OR (promotion_type <> 'policy_approved_auto_promotion' AND jsonb_array_length(approval_refs) > 0))
);
CREATE INDEX IF NOT EXISTS idx_canonical_graph_promotion_graph ON canonical_graph_promotion_records(graph_id, promoted_at);
CREATE INDEX IF NOT EXISTS idx_canonical_graph_promotion_proposal ON canonical_graph_promotion_records(proposal_id);

CREATE OR REPLACE FUNCTION protect_graph_promotion_fact_mutation()
RETURNS TRIGGER AS $$ BEGIN
  RAISE EXCEPTION 'Graph Promotion eligibility and result facts are immutable' USING ERRCODE = '55000';
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_graph_promotion_assessment_immutable BEFORE UPDATE OR DELETE ON graph_promotion_eligibility_assessments FOR EACH ROW EXECUTE FUNCTION protect_graph_promotion_fact_mutation();
CREATE TRIGGER trg_canonical_graph_promotion_immutable BEFORE UPDATE OR DELETE ON canonical_graph_promotion_records FOR EACH ROW EXECUTE FUNCTION protect_graph_promotion_fact_mutation();

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('graph.correction.read', 'graph', 'Read Graph Correction and controlled Promotion projections.', 'low', TRUE),
  ('graph.correction.propose', 'graph', 'Create or edit structured Graph Correction proposals.', 'high', TRUE),
  ('graph.correction.validate', 'graph', 'Validate structured Graph Correction proposals.', 'high', TRUE),
  ('graph.promotion.assess', 'graph', 'Evaluate Graph Promotion eligibility from persisted evidence.', 'high', TRUE),
  ('graph.promotion.promote', 'graph', 'Promote a validated Graph candidate through controlled governance.', 'high', TRUE),
  ('graph.learning_policy.manage', 'graph', 'Manage versioned Graph Learning Policy and Binding.', 'high', TRUE),
  ('graph.autonomy.pause', 'graph', 'Pause or resume controlled Graph autonomy.', 'high', TRUE),
  ('graph.promotion.rollback', 'graph', 'Rollback to an immutable Canonical Graph version.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET category = EXCLUDED.category, description = EXCLUDED.description, risk_level = EXCLUDED.risk_level, is_active = TRUE;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES ('basic', 'graph.correction.read', TRUE), ('pro', 'graph.correction.read', TRUE), ('enterprise', 'graph.correction.read', TRUE), ('enterprise', 'graph.correction.propose', TRUE), ('enterprise', 'graph.correction.validate', TRUE), ('enterprise', 'graph.promotion.assess', TRUE), ('enterprise', 'graph.promotion.promote', TRUE), ('enterprise', 'graph.learning_policy.manage', TRUE), ('enterprise', 'graph.autonomy.pause', TRUE), ('enterprise', 'graph.promotion.rollback', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;

COMMENT ON TABLE graph_correction_proposals IS 'P13 graph-specific extension of existing CCG proposals; structured operations and stable version refs only.';
COMMENT ON TABLE graph_promotion_eligibility_assessments IS 'Immutable fail-closed P13 eligibility snapshots; unknown and unavailable checks never pass.';
COMMENT ON TABLE canonical_graph_promotion_records IS 'Immutable controlled Canonical Graph Promotion facts; policy outcomes are distinct from human Approval.';

CREATE OR REPLACE FUNCTION prevent_ceg_version_content_update()
RETURNS TRIGGER AS $$
DECLARE
  content_changed BOOLEAN;
  controlled_promotion_transition BOOLEAN;
BEGIN
  IF OLD.status = 'archived' THEN
    RAISE EXCEPTION 'archived Canonical Execution Graph versions are immutable' USING ERRCODE = '55000';
  END IF;
  content_changed :=
    NEW.graph_id IS DISTINCT FROM OLD.graph_id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
    NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.project_id IS DISTINCT FROM OLD.project_id OR
    NEW.environment_id IS DISTINCT FROM OLD.environment_id OR NEW.scope_type IS DISTINCT FROM OLD.scope_type OR
    NEW.scope_id IS DISTINCT FROM OLD.scope_id OR NEW.version_number IS DISTINCT FROM OLD.version_number OR
    NEW.version_ref IS DISTINCT FROM OLD.version_ref OR NEW.parent_version_id IS DISTINCT FROM OLD.parent_version_id OR
    NEW.source IS DISTINCT FROM OLD.source OR NEW.schema_version IS DISTINCT FROM OLD.schema_version OR
    NEW.content_hash IS DISTINCT FROM OLD.content_hash OR NEW.source_refs IS DISTINCT FROM OLD.source_refs OR
    NEW.applicability IS DISTINCT FROM OLD.applicability OR NEW.metadata IS DISTINCT FROM OLD.metadata;
  IF (OLD.is_frozen OR OLD.status NOT IN ('draft', 'candidate')) AND content_changed THEN
    RAISE EXCEPTION 'frozen or published Canonical Execution Graph version content is immutable' USING ERRCODE = '55000';
  END IF;
  controlled_promotion_transition :=
    OLD.is_frozen = FALSE AND OLD.status IN ('draft', 'candidate') AND
    NEW.is_frozen = TRUE AND NEW.status = 'active' AND NEW.source = 'canonical' AND
    NEW.metadata->>'promotionType' IN ('human_approved_promotion', 'policy_approved_auto_promotion', 'human_approved_rollback');
  IF (NEW.is_frozen OR NEW.status NOT IN ('draft', 'candidate')) AND content_changed AND NOT controlled_promotion_transition THEN
    RAISE EXCEPTION 'freezing or publishing a Canonical Execution Graph version cannot change content' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- P14 Canonical Graph staleness / applicability sidecar governance.
CREATE TABLE IF NOT EXISTS canonical_graph_staleness_assessments (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  graph_id UUID NOT NULL REFERENCES canonical_execution_graphs(id) ON DELETE RESTRICT,
  graph_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  status VARCHAR(24) NOT NULL,
  applicability_range JSONB NOT NULL,
  signals_snapshot JSONB NOT NULL,
  source_fingerprint VARCHAR(80) NOT NULL,
  rule_version VARCHAR(80) NOT NULL,
  reason_codes JSONB NOT NULL,
  impact_snapshot JSONB NOT NULL,
  automatic_promotion_eligible BOOLEAN NOT NULL DEFAULT FALSE,
  assessment_hash VARCHAR(80) NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  assessed_at TIMESTAMPTZ NOT NULL,
  assessed_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_ceg_staleness_source_fingerprint UNIQUE (tenant_id, workspace_id, graph_version_id, source_fingerprint),
  CONSTRAINT uq_ceg_staleness_idempotency UNIQUE (tenant_id, workspace_id, graph_version_id, idempotency_key),
  CONSTRAINT chk_ceg_staleness_status CHECK (status IN ('fresh', 'suspect', 'stale', 'invalid', 'unknown')),
  CONSTRAINT chk_ceg_staleness_source_fingerprint CHECK (length(source_fingerprint) = 71 AND source_fingerprint LIKE 'sha256:%'),
  CONSTRAINT chk_ceg_staleness_assessment_hash CHECK (length(assessment_hash) = 71 AND assessment_hash LIKE 'sha256:%'),
  CONSTRAINT chk_ceg_staleness_applicability_object CHECK (jsonb_typeof(applicability_range) = 'object'),
  CONSTRAINT chk_ceg_staleness_signals_array CHECK (jsonb_typeof(signals_snapshot) = 'array'),
  CONSTRAINT chk_ceg_staleness_reasons_array CHECK (jsonb_typeof(reason_codes) = 'array'),
  CONSTRAINT chk_ceg_staleness_impact_object CHECK (jsonb_typeof(impact_snapshot) = 'object'),
  CONSTRAINT chk_ceg_staleness_fresh_only_autonomy CHECK (automatic_promotion_eligible = FALSE OR status = 'fresh')
);
CREATE INDEX IF NOT EXISTS idx_ceg_staleness_current ON canonical_graph_staleness_assessments(tenant_id, workspace_id, project_id, graph_version_id, assessed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ceg_staleness_status ON canonical_graph_staleness_assessments(status, assessed_at DESC);

CREATE TABLE IF NOT EXISTS canonical_graph_staleness_reviews (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  graph_id UUID NOT NULL REFERENCES canonical_execution_graphs(id) ON DELETE RESTRICT,
  graph_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  assessment_id UUID NOT NULL REFERENCES canonical_graph_staleness_assessments(id) ON DELETE RESTRICT,
  action VARCHAR(24) NOT NULL,
  requested_status VARCHAR(24),
  reason_code VARCHAR(120) NOT NULL,
  evidence_refs JSONB NOT NULL,
  expires_at TIMESTAMPTZ,
  status VARCHAR(24) NOT NULL DEFAULT 'pending',
  approval_id UUID NOT NULL REFERENCES approvals(id) ON DELETE RESTRICT,
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  lock_version INTEGER NOT NULL DEFAULT 1,
  requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
  applied_at TIMESTAMPTZ,
  applied_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_ceg_staleness_review_idempotency UNIQUE (tenant_id, workspace_id, graph_version_id, idempotency_key),
  CONSTRAINT chk_ceg_staleness_review_action CHECK (action IN ('confirm', 'override', 'deprecate')),
  CONSTRAINT chk_ceg_staleness_review_status CHECK (status IN ('pending', 'applied', 'rejected', 'expired')),
  CONSTRAINT chk_ceg_staleness_review_requested_status CHECK (requested_status IS NULL OR requested_status IN ('fresh', 'suspect', 'stale', 'invalid', 'unknown')),
  CONSTRAINT chk_ceg_staleness_review_lock CHECK (lock_version > 0),
  CONSTRAINT chk_ceg_staleness_review_override_expiry CHECK ((action = 'override' AND requested_status IS NOT NULL AND expires_at IS NOT NULL) OR (action <> 'override' AND requested_status IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_ceg_staleness_review_version ON canonical_graph_staleness_reviews(graph_version_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ceg_staleness_review_status ON canonical_graph_staleness_reviews(status, expires_at);

CREATE OR REPLACE FUNCTION protect_ceg_staleness_assessment_mutation()
RETURNS TRIGGER AS $$ BEGIN
  RAISE EXCEPTION 'Canonical Graph staleness assessments are immutable' USING ERRCODE = '55000';
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_ceg_staleness_assessment_immutable BEFORE UPDATE OR DELETE ON canonical_graph_staleness_assessments FOR EACH ROW EXECUTE FUNCTION protect_ceg_staleness_assessment_mutation();

CREATE OR REPLACE FUNCTION prevent_ceg_version_content_update()
RETURNS TRIGGER AS $$
DECLARE
  content_changed BOOLEAN;
  controlled_promotion_transition BOOLEAN;
BEGIN
  IF OLD.status = 'archived' THEN
    RAISE EXCEPTION 'archived Canonical Execution Graph versions are immutable' USING ERRCODE = '55000';
  END IF;
  content_changed :=
    NEW.graph_id IS DISTINCT FROM OLD.graph_id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
    NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.project_id IS DISTINCT FROM OLD.project_id OR
    NEW.environment_id IS DISTINCT FROM OLD.environment_id OR NEW.scope_type IS DISTINCT FROM OLD.scope_type OR
    NEW.scope_id IS DISTINCT FROM OLD.scope_id OR NEW.version_number IS DISTINCT FROM OLD.version_number OR
    NEW.version_ref IS DISTINCT FROM OLD.version_ref OR NEW.parent_version_id IS DISTINCT FROM OLD.parent_version_id OR
    NEW.source IS DISTINCT FROM OLD.source OR NEW.schema_version IS DISTINCT FROM OLD.schema_version OR
    NEW.content_hash IS DISTINCT FROM OLD.content_hash OR NEW.source_refs IS DISTINCT FROM OLD.source_refs OR
    NEW.applicability IS DISTINCT FROM OLD.applicability OR NEW.metadata IS DISTINCT FROM OLD.metadata;
  IF (OLD.is_frozen OR OLD.status NOT IN ('draft', 'candidate')) AND content_changed THEN
    RAISE EXCEPTION 'frozen or published Canonical Execution Graph version content is immutable' USING ERRCODE = '55000';
  END IF;
  controlled_promotion_transition :=
    OLD.is_frozen = FALSE AND OLD.status IN ('draft', 'candidate') AND
    NEW.is_frozen = TRUE AND NEW.status = 'active' AND NEW.source = 'canonical' AND
    NEW.metadata->>'promotionType' IN ('human_approved_promotion', 'policy_approved_auto_promotion', 'human_approved_rollback');
  IF (NEW.is_frozen OR NEW.status NOT IN ('draft', 'candidate')) AND content_changed AND NOT controlled_promotion_transition THEN
    RAISE EXCEPTION 'freezing or publishing a Canonical Execution Graph version cannot change content' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('graph.staleness.read', 'graph', 'Read Canonical Graph applicability, staleness, and selection projections.', 'low', TRUE),
  ('graph.staleness.assess', 'graph', 'Assess Canonical Graph applicability and staleness from persisted signals.', 'high', TRUE),
  ('graph.staleness.review', 'graph', 'Request and apply human staleness confirmation or bounded override.', 'high', TRUE),
  ('graph.staleness.deprecate', 'graph', 'Request and apply approval-backed Canonical Graph deprecation.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET category = EXCLUDED.category, description = EXCLUDED.description, risk_level = EXCLUDED.risk_level, is_active = TRUE;
INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'graph.staleness.read', TRUE), ('pro', 'graph.staleness.read', TRUE),
  ('enterprise', 'graph.staleness.read', TRUE), ('enterprise', 'graph.staleness.assess', TRUE),
  ('enterprise', 'graph.staleness.review', TRUE), ('enterprise', 'graph.staleness.deprecate', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;

COMMENT ON TABLE canonical_graph_staleness_assessments IS 'Immutable P14 applicability/staleness facts. unknown is fail-closed and only fresh may qualify controlled autonomy.';
COMMENT ON TABLE canonical_graph_staleness_reviews IS 'Approval-backed human confirmation, bounded override, or deprecation. Overrides never restore controlled autonomy.';

-- P15 CEG Traceability / Graph Coverage sidecar. The existing
-- traceability_snapshots + coverage_proof_bundles remain the proof authority.
CREATE TABLE IF NOT EXISTS graph_coverage_snapshots (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  graph_id UUID NOT NULL REFERENCES canonical_execution_graphs(id) ON DELETE RESTRICT,
  graph_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  coverage_proof_bundle_id UUID REFERENCES coverage_proof_bundles(id) ON DELETE SET NULL,
  requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE RESTRICT,
  execution_id UUID REFERENCES executions(id) ON DELETE SET NULL,
  staleness_assessment_id UUID REFERENCES canonical_graph_staleness_assessments(id) ON DELETE SET NULL,
  algorithm_version VARCHAR(80) NOT NULL,
  input_fingerprint VARCHAR(80) NOT NULL,
  snapshot_ref VARCHAR(500) NOT NULL UNIQUE,
  snapshot_hash VARCHAR(80) NOT NULL,
  status VARCHAR(32) NOT NULL,
  input_snapshot JSONB NOT NULL,
  result_snapshot JSONB NOT NULL,
  coverage_proof_ref JSONB,
  traceability_snapshot JSONB NOT NULL,
  metric_snapshot JSONB NOT NULL,
  gap_snapshot JSONB NOT NULL,
  raw_finding_refs JSONB NOT NULL,
  normalized_finding_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_graph_coverage_snapshots_input UNIQUE (tenant_id, workspace_id, input_fingerprint),
  CONSTRAINT uq_graph_coverage_snapshots_hash UNIQUE (snapshot_hash),
  CONSTRAINT chk_graph_coverage_snapshots_status CHECK (status IN ('covered', 'partial', 'uncovered', 'not_applicable', 'unknown')),
  CONSTRAINT chk_graph_coverage_snapshots_input_hash CHECK (length(input_fingerprint) = 71 AND input_fingerprint LIKE 'sha256:%'),
  CONSTRAINT chk_graph_coverage_snapshots_snapshot_hash CHECK (length(snapshot_hash) = 71 AND snapshot_hash LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS idx_graph_coverage_snapshots_graph ON graph_coverage_snapshots(tenant_id, workspace_id, project_id, graph_version_id, computed_at DESC);
CREATE INDEX IF NOT EXISTS idx_graph_coverage_snapshots_execution ON graph_coverage_snapshots(execution_id);
CREATE INDEX IF NOT EXISTS idx_graph_coverage_snapshots_requirement ON graph_coverage_snapshots(requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_graph_coverage_snapshots_proof ON graph_coverage_snapshots(coverage_proof_bundle_id);

CREATE OR REPLACE FUNCTION protect_graph_coverage_snapshot_mutation()
RETURNS TRIGGER AS $$ BEGIN
  RAISE EXCEPTION 'Graph Coverage snapshots are immutable' USING ERRCODE = '55000';
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_graph_coverage_snapshot_immutable BEFORE UPDATE OR DELETE ON graph_coverage_snapshots FOR EACH ROW EXECUTE FUNCTION protect_graph_coverage_snapshot_mutation();
COMMENT ON TABLE graph_coverage_snapshots IS 'Immutable P15 CEG dimension snapshot linked to the existing Coverage Proof authority; not a second Coverage Proof truth.';

-- P17 governed Requirement/Code Change Set normalization.
CREATE TABLE IF NOT EXISTS change_source_snapshots (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  environment_id UUID REFERENCES project_environments(id) ON DELETE SET NULL,
  source_type VARCHAR(80) NOT NULL,
  source_id VARCHAR(500) NOT NULL,
  revision VARCHAR(255) NOT NULL,
  content_hash VARCHAR(80) NOT NULL,
  snapshot_ref VARCHAR(1000) NOT NULL UNIQUE,
  source_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  snapshot_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  trace_id UUID REFERENCES traces(id) ON DELETE SET NULL,
  acquired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT uq_change_source_snapshots_identity UNIQUE (tenant_id, workspace_id, project_id, source_type, source_id, revision, content_hash),
  CONSTRAINT chk_change_source_snapshots_content_hash CHECK (length(content_hash) = 71)
);
CREATE INDEX IF NOT EXISTS idx_change_source_snapshots_scope ON change_source_snapshots(tenant_id, workspace_id, project_id, acquired_at);
CREATE INDEX IF NOT EXISTS idx_change_source_snapshots_source ON change_source_snapshots(source_type, source_id, revision);

CREATE TABLE IF NOT EXISTS change_sets (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  environment_id UUID REFERENCES project_environments(id) ON DELETE SET NULL,
  source_snapshot_id UUID NOT NULL REFERENCES change_source_snapshots(id) ON DELETE RESTRICT,
  change_set_type VARCHAR(32) NOT NULL,
  fingerprint VARCHAR(80) NOT NULL,
  normalizer_version VARCHAR(80) NOT NULL,
  status VARCHAR(32) NOT NULL,
  item_count INTEGER NOT NULL DEFAULT 0,
  issue_count INTEGER NOT NULL DEFAULT 0,
  sensitive BOOLEAN NOT NULL DEFAULT FALSE,
  artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  replay_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_change_sets_fingerprint UNIQUE (tenant_id, workspace_id, project_id, fingerprint),
  CONSTRAINT chk_change_sets_type CHECK (change_set_type IN ('requirement', 'code')),
  CONSTRAINT chk_change_sets_status CHECK (status IN ('completed', 'partial', 'unknown')),
  CONSTRAINT chk_change_sets_counts CHECK (item_count >= 0 AND issue_count >= 0),
  CONSTRAINT chk_change_sets_fingerprint CHECK (length(fingerprint) = 71)
);
CREATE INDEX IF NOT EXISTS idx_change_sets_scope ON change_sets(tenant_id, workspace_id, project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_change_sets_source_snapshot ON change_sets(source_snapshot_id);
CREATE INDEX IF NOT EXISTS idx_change_sets_type_status ON change_sets(change_set_type, status);

CREATE TABLE IF NOT EXISTS requirement_change_sets (
  change_set_id UUID PRIMARY KEY REFERENCES change_sets(id) ON DELETE CASCADE,
  base_requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE RESTRICT,
  head_requirement_version_id UUID NOT NULL REFERENCES requirement_versions(id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_requirement_change_sets_head ON requirement_change_sets(head_requirement_version_id);
CREATE INDEX IF NOT EXISTS idx_requirement_change_sets_base ON requirement_change_sets(base_requirement_version_id);

CREATE TABLE IF NOT EXISTS requirement_change_items (
  id UUID PRIMARY KEY,
  change_set_id UUID NOT NULL REFERENCES requirement_change_sets(change_set_id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  requirement_id VARCHAR(255) NOT NULL,
  before_requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE RESTRICT,
  after_requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE RESTRICT,
  change_type VARCHAR(32) NOT NULL,
  before_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  after_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  changed_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
  explicit_capability_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  related_requirement_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  confidence NUMERIC(5,4) NOT NULL,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  CONSTRAINT uq_requirement_change_items_ordinal UNIQUE (change_set_id, ordinal),
  CONSTRAINT chk_requirement_change_items_type CHECK (change_type IN ('add', 'update', 'remove', 'rename', 'split', 'merge', 'unknown')),
  CONSTRAINT chk_requirement_change_items_confidence CHECK (confidence >= 0 AND confidence <= 1)
);
CREATE INDEX IF NOT EXISTS idx_requirement_change_items_requirement ON requirement_change_items(requirement_id);

CREATE TABLE IF NOT EXISTS code_change_sets (
  change_set_id UUID PRIMARY KEY REFERENCES change_sets(id) ON DELETE CASCADE,
  repository_ref VARCHAR(1000) NOT NULL,
  base_sha VARCHAR(64) NOT NULL,
  head_sha VARCHAR(64) NOT NULL,
  empty_diff BOOLEAN NOT NULL DEFAULT FALSE,
  force_push BOOLEAN NOT NULL DEFAULT FALSE,
  base_reachable BOOLEAN NOT NULL DEFAULT TRUE,
  CONSTRAINT chk_code_change_sets_revision CHECK (base_sha <> head_sha OR empty_diff = TRUE)
);
CREATE INDEX IF NOT EXISTS idx_code_change_sets_repository ON code_change_sets(repository_ref, head_sha);

CREATE TABLE IF NOT EXISTS code_change_files (
  id UUID PRIMARY KEY,
  change_set_id UUID NOT NULL REFERENCES code_change_sets(change_set_id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  path VARCHAR(2000) NOT NULL,
  old_path VARCHAR(2000),
  change_type VARCHAR(32) NOT NULL,
  language VARCHAR(80),
  "binary" BOOLEAN NOT NULL DEFAULT FALSE,
  generated BOOLEAN NOT NULL DEFAULT FALSE,
  vendor BOOLEAN NOT NULL DEFAULT FALSE,
  submodule BOOLEAN NOT NULL DEFAULT FALSE,
  risk_hints JSONB NOT NULL DEFAULT '[]'::jsonb,
  diff_artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  CONSTRAINT uq_code_change_files_ordinal UNIQUE (change_set_id, ordinal),
  CONSTRAINT uq_code_change_files_path UNIQUE (change_set_id, path),
  CONSTRAINT chk_code_change_files_type CHECK (change_type IN ('add', 'update', 'remove', 'rename', 'copy', 'unknown'))
);
CREATE INDEX IF NOT EXISTS idx_code_change_files_path ON code_change_files(path);

CREATE TABLE IF NOT EXISTS code_change_hunks (
  id UUID PRIMARY KEY,
  file_id UUID NOT NULL REFERENCES code_change_files(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  header VARCHAR(500) NOT NULL,
  old_line_start INTEGER,
  old_line_count INTEGER,
  new_line_start INTEGER,
  new_line_count INTEGER,
  content_hash VARCHAR(80) NOT NULL,
  diff_artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  sensitive BOOLEAN NOT NULL DEFAULT FALSE,
  redaction_count INTEGER NOT NULL DEFAULT 0,
  CONSTRAINT uq_code_change_hunks_ordinal UNIQUE (file_id, ordinal),
  CONSTRAINT chk_code_change_hunks_redaction_count CHECK (redaction_count >= 0),
  CONSTRAINT chk_code_change_hunks_content_hash CHECK (length(content_hash) = 71)
);
CREATE INDEX IF NOT EXISTS idx_code_change_hunks_file ON code_change_hunks(file_id);

CREATE TABLE IF NOT EXISTS code_change_symbols (
  id UUID PRIMARY KEY,
  hunk_id UUID NOT NULL REFERENCES code_change_hunks(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  name VARCHAR(500) NOT NULL,
  kind VARCHAR(80) NOT NULL,
  change_type VARCHAR(32) NOT NULL,
  old_line_start INTEGER,
  old_line_end INTEGER,
  new_line_start INTEGER,
  new_line_end INTEGER,
  confidence NUMERIC(5,4) NOT NULL,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  CONSTRAINT uq_code_change_symbols_ordinal UNIQUE (hunk_id, ordinal),
  CONSTRAINT chk_code_change_symbols_type CHECK (change_type IN ('add', 'update', 'remove', 'unknown')),
  CONSTRAINT chk_code_change_symbols_confidence CHECK (confidence >= 0 AND confidence <= 1)
);
CREATE INDEX IF NOT EXISTS idx_code_change_symbols_name ON code_change_symbols(name);

CREATE TABLE IF NOT EXISTS change_normalization_issues (
  id UUID PRIMARY KEY,
  change_set_id UUID NOT NULL REFERENCES change_sets(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  category VARCHAR(32) NOT NULL,
  code VARCHAR(120) NOT NULL,
  message VARCHAR(1000) NOT NULL,
  field VARCHAR(255),
  recoverable BOOLEAN NOT NULL DEFAULT TRUE,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  CONSTRAINT uq_change_normalization_issues_ordinal UNIQUE (change_set_id, ordinal),
  CONSTRAINT chk_change_normalization_issues_category CHECK (category IN ('incomplete', 'ambiguous', 'unsupported', 'sensitive'))
);
CREATE INDEX IF NOT EXISTS idx_change_normalization_issues_category ON change_normalization_issues(category);

CREATE OR REPLACE FUNCTION protect_change_set_snapshot_mutation() RETURNS TRIGGER AS $$ BEGIN RAISE EXCEPTION 'Change Set snapshots are immutable' USING ERRCODE = '55000'; END; $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_change_source_snapshot_immutable BEFORE UPDATE OR DELETE ON change_source_snapshots FOR EACH ROW EXECUTE FUNCTION protect_change_set_snapshot_mutation();
CREATE TRIGGER trg_change_set_immutable BEFORE UPDATE OR DELETE ON change_sets FOR EACH ROW EXECUTE FUNCTION protect_change_set_snapshot_mutation();
CREATE TRIGGER trg_requirement_change_set_immutable BEFORE UPDATE OR DELETE ON requirement_change_sets FOR EACH ROW EXECUTE FUNCTION protect_change_set_snapshot_mutation();
CREATE TRIGGER trg_requirement_change_item_immutable BEFORE UPDATE OR DELETE ON requirement_change_items FOR EACH ROW EXECUTE FUNCTION protect_change_set_snapshot_mutation();
CREATE TRIGGER trg_code_change_set_immutable BEFORE UPDATE OR DELETE ON code_change_sets FOR EACH ROW EXECUTE FUNCTION protect_change_set_snapshot_mutation();
CREATE TRIGGER trg_code_change_file_immutable BEFORE UPDATE OR DELETE ON code_change_files FOR EACH ROW EXECUTE FUNCTION protect_change_set_snapshot_mutation();
CREATE TRIGGER trg_code_change_hunk_immutable BEFORE UPDATE OR DELETE ON code_change_hunks FOR EACH ROW EXECUTE FUNCTION protect_change_set_snapshot_mutation();
CREATE TRIGGER trg_code_change_symbol_immutable BEFORE UPDATE OR DELETE ON code_change_symbols FOR EACH ROW EXECUTE FUNCTION protect_change_set_snapshot_mutation();
CREATE TRIGGER trg_change_normalization_issue_immutable BEFORE UPDATE OR DELETE ON change_normalization_issues FOR EACH ROW EXECUTE FUNCTION protect_change_set_snapshot_mutation();

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active) VALUES
  ('change.read', 'change', 'Read normalized Requirement and Code Change Sets.', 'low', TRUE),
  ('change.create', 'change', 'Ingest governed sources into normalized Change Sets.', 'medium', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET category = EXCLUDED.category, description = EXCLUDED.description, risk_level = EXCLUDED.risk_level, is_active = TRUE;
INSERT INTO edition_capabilities (edition, capability_key, enabled) VALUES
  ('basic', 'change.read', TRUE), ('pro', 'change.read', TRUE), ('enterprise', 'change.read', TRUE), ('enterprise', 'change.create', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;

COMMENT ON TABLE change_sets IS 'P17 stable normalized input only. It never writes Gate, Memory, or impact conclusions.';
COMMENT ON TABLE code_change_hunks IS 'Hunk metadata and governed artifact refs only; full diff content is not stored in this table.';

-- P18 Capability Mapping and evidence-backed Impact Analysis snapshots.
CREATE TABLE IF NOT EXISTS capability_mappings (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  mapping_key VARCHAR(80) NOT NULL,
  version INTEGER NOT NULL,
  source_entity_type VARCHAR(40) NOT NULL,
  source_entity_ref VARCHAR(1000) NOT NULL,
  capability_ref VARCHAR(1000) NOT NULL,
  mapping_source VARCHAR(40) NOT NULL,
  source_priority INTEGER NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'active',
  repository_ref VARCHAR(1000),
  graph_version_id UUID REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  content_hash VARCHAR(80) NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_capability_mappings_version UNIQUE (tenant_id, workspace_id, project_id, mapping_key, version),
  CONSTRAINT uq_capability_mappings_idempotency UNIQUE (tenant_id, workspace_id, project_id, idempotency_key),
  CONSTRAINT chk_capability_mappings_entity_type CHECK (source_entity_type IN ('requirement', 'code_path', 'code_symbol', 'test')),
  CONSTRAINT chk_capability_mappings_source CHECK (mapping_source IN ('manual', 'explicit_configuration', 'verified_traceability', 'static_symbol_coverage', 'historical_evidence')),
  CONSTRAINT chk_capability_mappings_status CHECK (status IN ('active', 'superseded', 'disabled')),
  CONSTRAINT chk_capability_mappings_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_capability_mappings_priority CHECK (source_priority >= 0),
  CONSTRAINT chk_capability_mappings_version CHECK (version > 0),
  CONSTRAINT chk_capability_mappings_content_hash CHECK (length(content_hash) = 71 AND content_hash LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS idx_capability_mappings_scope_source ON capability_mappings(tenant_id, workspace_id, project_id, source_entity_type, source_entity_ref);
CREATE INDEX IF NOT EXISTS idx_capability_mappings_capability ON capability_mappings(project_id, capability_ref, status);
CREATE INDEX IF NOT EXISTS idx_capability_mappings_repository ON capability_mappings(project_id, repository_ref, status);

CREATE TABLE IF NOT EXISTS impact_results (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  change_set_ids JSONB NOT NULL,
  graph_id UUID NOT NULL REFERENCES canonical_execution_graphs(id) ON DELETE RESTRICT,
  graph_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  graph_assessment_id UUID REFERENCES canonical_graph_staleness_assessments(id) ON DELETE SET NULL,
  graph_staleness VARCHAR(24) NOT NULL,
  input_fingerprint VARCHAR(80) NOT NULL,
  mapping_snapshot_hash VARCHAR(80) NOT NULL,
  mapping_version_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  algorithm_version VARCHAR(80) NOT NULL,
  model_invocation_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  status VARCHAR(24) NOT NULL,
  risk_level VARCHAR(20) NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  review_required BOOLEAN NOT NULL DEFAULT FALSE,
  approval_id UUID REFERENCES approvals(id) ON DELETE SET NULL,
  truncated BOOLEAN NOT NULL DEFAULT FALSE,
  visited_node_count INTEGER NOT NULL DEFAULT 0,
  result_snapshot JSONB NOT NULL,
  replay_snapshot JSONB NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_impact_results_fingerprint UNIQUE (tenant_id, workspace_id, project_id, input_fingerprint),
  CONSTRAINT chk_impact_results_status CHECK (status IN ('complete', 'partial', 'unknown')),
  CONSTRAINT chk_impact_results_risk CHECK (risk_level IN ('low', 'medium', 'high')),
  CONSTRAINT chk_impact_results_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_impact_results_visited CHECK (visited_node_count >= 0),
  CONSTRAINT chk_impact_results_fingerprint CHECK (length(input_fingerprint) = 71 AND input_fingerprint LIKE 'sha256:%'),
  CONSTRAINT chk_impact_results_mapping_hash CHECK (length(mapping_snapshot_hash) = 71 AND mapping_snapshot_hash LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS idx_impact_results_scope ON impact_results(tenant_id, workspace_id, project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_impact_results_change_sets ON impact_results(project_id);
CREATE INDEX IF NOT EXISTS idx_impact_results_graph_version ON impact_results(graph_version_id, created_at);

CREATE OR REPLACE FUNCTION protect_impact_snapshot_mutation() RETURNS TRIGGER AS $$ BEGIN RAISE EXCEPTION 'Capability Mapping versions and Impact Result snapshots are immutable' USING ERRCODE = '55000'; END; $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_capability_mapping_immutable BEFORE UPDATE OR DELETE ON capability_mappings FOR EACH ROW EXECUTE FUNCTION protect_impact_snapshot_mutation();
CREATE TRIGGER trg_impact_result_immutable BEFORE UPDATE OR DELETE ON impact_results FOR EACH ROW EXECUTE FUNCTION protect_impact_snapshot_mutation();

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active) VALUES
  ('impact.read', 'impact', 'Read backend-computed Capability Mapping and Impact Result projections.', 'low', TRUE),
  ('impact.analyze', 'impact', 'Run bounded evidence-backed impact analysis from frozen Change Set and CEG inputs.', 'high', TRUE),
  ('impact.manage_mapping', 'impact', 'Create versioned canonical Capability Mappings; AI suggestions are excluded.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET category = EXCLUDED.category, description = EXCLUDED.description, risk_level = EXCLUDED.risk_level, is_active = TRUE;
INSERT INTO edition_capabilities (edition, capability_key, enabled) VALUES
  ('basic', 'impact.read', TRUE), ('pro', 'impact.read', TRUE), ('enterprise', 'impact.read', TRUE),
  ('enterprise', 'impact.analyze', TRUE), ('enterprise', 'impact.manage_mapping', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;

COMMENT ON TABLE capability_mappings IS 'P18 canonical evidence-backed mapping versions. AI suggestions are never persisted here.';
COMMENT ON TABLE impact_results IS 'P18 frozen impact evaluation inputs/results for downstream P19 admission input; not Gate, Memory, Replay selection, or test execution.';

-- P19 Selective Replay planning snapshots. Planning never creates execution tasks or retries.
CREATE TABLE IF NOT EXISTS selective_replay_plans (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  impact_result_id UUID NOT NULL REFERENCES impact_results(id) ON DELETE RESTRICT,
  base_execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE RESTRICT,
  coverage_snapshot_id UUID NOT NULL REFERENCES graph_coverage_snapshots(id) ON DELETE RESTRICT,
  environment_id UUID REFERENCES project_environments(id) ON DELETE RESTRICT,
  graph_version_id UUID NOT NULL REFERENCES canonical_execution_graph_versions(id) ON DELETE RESTRICT,
  graph_assessment_id UUID REFERENCES canonical_graph_staleness_assessments(id) ON DELETE RESTRICT,
  algorithm_version VARCHAR(80) NOT NULL,
  input_fingerprint VARCHAR(80) NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  plan_hash VARCHAR(80) NOT NULL,
  status VARCHAR(24) NOT NULL,
  risk_level VARCHAR(20) NOT NULL,
  fallback_used BOOLEAN NOT NULL DEFAULT FALSE,
  selected_test_count INTEGER NOT NULL,
  estimated_seconds INTEGER NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  plan_snapshot JSONB NOT NULL,
  replay_snapshot JSONB NOT NULL,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_selective_replay_plans_fingerprint UNIQUE (tenant_id, workspace_id, project_id, input_fingerprint),
  CONSTRAINT uq_selective_replay_plans_idempotency UNIQUE (tenant_id, workspace_id, project_id, idempotency_key),
  CONSTRAINT uq_selective_replay_plans_hash UNIQUE (plan_hash),
  CONSTRAINT chk_selective_replay_plans_status CHECK (status IN ('ready', 'fallback')),
  CONSTRAINT chk_selective_replay_plans_risk CHECK (risk_level IN ('low', 'medium', 'high')),
  CONSTRAINT chk_selective_replay_plans_nonempty CHECK (selected_test_count > 0),
  CONSTRAINT chk_selective_replay_plans_cost CHECK (estimated_seconds > 0),
  CONSTRAINT chk_selective_replay_plans_fingerprint CHECK (length(input_fingerprint) = 71 AND input_fingerprint LIKE 'sha256:%'),
  CONSTRAINT chk_selective_replay_plans_plan_hash CHECK (length(plan_hash) = 71 AND plan_hash LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS idx_selective_replay_plans_scope ON selective_replay_plans(tenant_id, workspace_id, project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_selective_replay_plans_impact ON selective_replay_plans(impact_result_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_selective_replay_plans_execution ON selective_replay_plans(base_execution_id, created_at DESC);
CREATE OR REPLACE FUNCTION protect_selective_replay_plan_mutation() RETURNS TRIGGER AS $$ BEGIN RAISE EXCEPTION 'Selective Replay plan snapshots are immutable' USING ERRCODE = '55000'; END; $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_selective_replay_plan_immutable BEFORE UPDATE OR DELETE ON selective_replay_plans FOR EACH ROW EXECUTE FUNCTION protect_selective_replay_plan_mutation();
INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active) VALUES
  ('replay.plan.read', 'replay', 'Read backend-computed Selective Replay plans.', 'low', TRUE),
  ('replay.plan.create', 'replay', 'Create an immutable Selective Replay plan without executing it.', 'low', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET category = EXCLUDED.category, description = EXCLUDED.description, risk_level = EXCLUDED.risk_level, is_active = TRUE;
INSERT INTO edition_capabilities (edition, capability_key, enabled) VALUES
  ('basic', 'replay.plan.read', TRUE), ('pro', 'replay.plan.read', TRUE), ('enterprise', 'replay.plan.read', TRUE),
  ('enterprise', 'replay.plan.create', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;
COMMENT ON TABLE selective_replay_plans IS 'P19 immutable planning facts only. Service-managed execution remains the sole task creation and execution boundary.';

-- P20 verified SCM Webhook intake and immutable PR Context / Requirement Match facts.
CREATE TABLE IF NOT EXISTS scm_webhook_receipts (
  id UUID PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL, workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  connector_binding_id UUID NOT NULL REFERENCES skill_connector_bindings(id) ON DELETE RESTRICT,
  provider VARCHAR(32) NOT NULL, delivery_id VARCHAR(255) NOT NULL, event_type VARCHAR(80) NOT NULL,
  action VARCHAR(80) NOT NULL, installation_ref VARCHAR(500) NOT NULL, repository_ref VARCHAR(1000) NOT NULL,
  repository_native_id VARCHAR(255) NOT NULL, pull_request_number INTEGER NOT NULL, head_sha VARCHAR(64),
  provider_event_at TIMESTAMPTZ NOT NULL, received_at TIMESTAMPTZ NOT NULL,
  payload_hash VARCHAR(80) NOT NULL, idempotency_key VARCHAR(80) NOT NULL,
  envelope_snapshot JSONB NOT NULL, binding_snapshot JSONB NOT NULL,
  status VARCHAR(40) NOT NULL DEFAULT 'queued', attempt_count INTEGER NOT NULL DEFAULT 0,
  error_code VARCHAR(160), pr_context_version_id UUID, trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb, audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_scm_webhook_receipts_delivery UNIQUE (connector_binding_id, provider, delivery_id),
  CONSTRAINT uq_scm_webhook_receipts_idempotency UNIQUE (idempotency_key),
  CONSTRAINT chk_scm_webhook_receipts_provider CHECK (provider IN ('github', 'gitlab', 'mock-scm')),
  CONSTRAINT chk_scm_webhook_receipts_status CHECK (status IN ('queued', 'processing', 'processed', 'ignored_out_of_order', 'failed')),
  CONSTRAINT chk_scm_webhook_receipts_attempt_count CHECK (attempt_count >= 0),
  CONSTRAINT chk_scm_webhook_receipts_payload_hash CHECK (length(payload_hash) = 71 AND payload_hash LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS idx_scm_webhook_receipts_scope ON scm_webhook_receipts(tenant_id, workspace_id, project_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_scm_webhook_receipts_status ON scm_webhook_receipts(status, created_at);
CREATE INDEX IF NOT EXISTS idx_scm_webhook_receipts_pr ON scm_webhook_receipts(project_id, repository_ref, pull_request_number);
CREATE TABLE IF NOT EXISTS scm_pr_contexts (
  id UUID PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL, workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  connector_binding_id UUID NOT NULL REFERENCES skill_connector_bindings(id) ON DELETE RESTRICT,
  provider VARCHAR(32) NOT NULL, repository_ref VARCHAR(1000) NOT NULL, repository_native_id VARCHAR(255) NOT NULL,
  pull_request_number INTEGER NOT NULL, state VARCHAR(20) NOT NULL, latest_version INTEGER NOT NULL DEFAULT 1,
  latest_head_sha VARCHAR(64) NOT NULL, latest_provider_event_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_scm_pr_contexts_identity UNIQUE (tenant_id, workspace_id, project_id, provider, repository_ref, pull_request_number),
  CONSTRAINT chk_scm_pr_contexts_state CHECK (state IN ('open', 'closed', 'merged', 'unknown')),
  CONSTRAINT chk_scm_pr_contexts_version CHECK (latest_version > 0)
);
CREATE INDEX IF NOT EXISTS idx_scm_pr_contexts_scope ON scm_pr_contexts(tenant_id, workspace_id, project_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_scm_pr_contexts_repository ON scm_pr_contexts(project_id, repository_ref, pull_request_number);
CREATE TABLE IF NOT EXISTS scm_pr_context_versions (
  id UUID PRIMARY KEY, context_id UUID NOT NULL REFERENCES scm_pr_contexts(id) ON DELETE RESTRICT,
  webhook_receipt_id UUID NOT NULL REFERENCES scm_webhook_receipts(id) ON DELETE RESTRICT, version INTEGER NOT NULL,
  base_ref VARCHAR(500) NOT NULL, base_sha VARCHAR(64) NOT NULL, head_ref VARCHAR(500) NOT NULL, head_sha VARCHAR(64) NOT NULL,
  change_set_id UUID REFERENCES change_sets(id) ON DELETE RESTRICT,
  skill_invocation_id UUID REFERENCES skill_invocations(id) ON DELETE SET NULL,
  context_hash VARCHAR(80) NOT NULL, context_snapshot JSONB NOT NULL, replay_snapshot JSONB NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_scm_pr_context_versions_number UNIQUE (context_id, version),
  CONSTRAINT uq_scm_pr_context_versions_receipt UNIQUE (webhook_receipt_id),
  CONSTRAINT uq_scm_pr_context_versions_hash UNIQUE (context_hash),
  CONSTRAINT chk_scm_pr_context_versions_version CHECK (version > 0),
  CONSTRAINT chk_scm_pr_context_versions_hash CHECK (length(context_hash) = 71 AND context_hash LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS idx_scm_pr_context_versions_context ON scm_pr_context_versions(context_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_scm_pr_context_versions_head ON scm_pr_context_versions(context_id, head_sha);
CREATE TABLE IF NOT EXISTS requirement_match_snapshots (
  id UUID PRIMARY KEY, pr_context_version_id UUID NOT NULL REFERENCES scm_pr_context_versions(id) ON DELETE RESTRICT,
  algorithm_version VARCHAR(80) NOT NULL, status VARCHAR(24) NOT NULL, review_required BOOLEAN NOT NULL,
  explicit_unknown_refs JSONB NOT NULL DEFAULT '[]'::jsonb, model_invocation_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb, audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  snapshot_hash VARCHAR(80) NOT NULL, replay_snapshot JSONB NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_requirement_match_snapshots_context_version UNIQUE (pr_context_version_id),
  CONSTRAINT uq_requirement_match_snapshots_hash UNIQUE (snapshot_hash),
  CONSTRAINT chk_requirement_match_snapshots_status CHECK (status IN ('confirmed', 'candidate', 'conflict', 'unknown')),
  CONSTRAINT chk_requirement_match_snapshots_hash CHECK (length(snapshot_hash) = 71 AND snapshot_hash LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS idx_requirement_match_snapshots_context ON requirement_match_snapshots(pr_context_version_id, created_at DESC);
CREATE TABLE IF NOT EXISTS requirement_matches (
  id UUID PRIMARY KEY, snapshot_id UUID NOT NULL REFERENCES requirement_match_snapshots(id) ON DELETE RESTRICT,
  ordinal INTEGER NOT NULL, requirement_id VARCHAR(255) NOT NULL,
  requirement_version_id UUID REFERENCES requirement_versions(id) ON DELETE RESTRICT,
  source VARCHAR(40) NOT NULL, confidence NUMERIC(5,4) NOT NULL, status VARCHAR(24) NOT NULL,
  review_required BOOLEAN NOT NULL, reasons JSONB NOT NULL, evidence_refs JSONB NOT NULL,
  model_invocation_ref JSONB, match_hash VARCHAR(80) NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_requirement_matches_ordinal UNIQUE (snapshot_id, ordinal),
  CONSTRAINT uq_requirement_matches_hash UNIQUE (match_hash),
  CONSTRAINT chk_requirement_matches_source CHECK (source IN ('explicit_reference', 'manual_mapping', 'verified_traceability', 'rule', 'history', 'ai_suggestion')),
  CONSTRAINT chk_requirement_matches_status CHECK (status IN ('confirmed', 'candidate', 'rejected', 'unknown')),
  CONSTRAINT chk_requirement_matches_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_requirement_matches_confirmed_confidence CHECK (status <> 'confirmed' OR confidence >= 0.8),
  CONSTRAINT chk_requirement_matches_no_implicit_confirmation CHECK (NOT (source IN ('rule', 'history', 'ai_suggestion') AND status = 'confirmed')),
  CONSTRAINT chk_requirement_matches_hash CHECK (length(match_hash) = 71 AND match_hash LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS idx_requirement_matches_snapshot ON requirement_matches(snapshot_id, ordinal);
CREATE INDEX IF NOT EXISTS idx_requirement_matches_requirement ON requirement_matches(requirement_id, status);
ALTER TABLE scm_webhook_receipts ADD CONSTRAINT fk_scm_webhook_receipts_context_version FOREIGN KEY (pr_context_version_id) REFERENCES scm_pr_context_versions(id) ON DELETE SET NULL;
CREATE OR REPLACE FUNCTION protect_scm_context_fact_mutation() RETURNS TRIGGER AS $$ BEGIN RAISE EXCEPTION 'PR Context versions and Requirement Match snapshots are immutable' USING ERRCODE = '55000'; END; $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_scm_pr_context_version_immutable BEFORE UPDATE OR DELETE ON scm_pr_context_versions FOR EACH ROW EXECUTE FUNCTION protect_scm_context_fact_mutation();
CREATE TRIGGER trg_requirement_match_snapshot_immutable BEFORE UPDATE OR DELETE ON requirement_match_snapshots FOR EACH ROW EXECUTE FUNCTION protect_scm_context_fact_mutation();
CREATE TRIGGER trg_requirement_match_immutable BEFORE UPDATE OR DELETE ON requirement_matches FOR EACH ROW EXECUTE FUNCTION protect_scm_context_fact_mutation();
INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active) VALUES
  ('webhook.service', 'integrations', 'Authenticate and admit verified SCM Webhook deliveries.', 'high', TRUE),
  ('pr.read', 'integrations', 'Read provider-neutral PR Context and Requirement Match projections.', 'low', TRUE),
  ('match.review', 'integrations', 'Review Requirement Match candidates through a governed follow-up workflow.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET is_active = TRUE;
INSERT INTO edition_capabilities (edition, capability_key, enabled) VALUES
  ('basic', 'pr.read', TRUE), ('pro', 'pr.read', TRUE), ('enterprise', 'pr.read', TRUE),
  ('enterprise', 'match.review', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;
INSERT INTO rbac_role_capabilities (role_name, capability_key, effect) VALUES
  ('system', 'webhook.service', 'allow')
ON CONFLICT (role_name, capability_key) DO UPDATE SET effect = 'allow';
COMMENT ON TABLE scm_webhook_receipts IS 'P20 verified receipts only; raw payloads and secrets are not persisted.';
COMMENT ON TABLE scm_pr_context_versions IS 'P20 immutable PR Context facts; not Gate, CI, admission, or execution decisions.';

-- P21 static scan, selective smoke, and untrusted-code sandbox execution refs.
CREATE TABLE IF NOT EXISTS admission_runs (
  id UUID PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL, workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  pr_context_version_id UUID NOT NULL REFERENCES scm_pr_context_versions(id) ON DELETE RESTRICT,
  requirement_match_snapshot_id UUID REFERENCES requirement_match_snapshots(id) ON DELETE RESTRICT,
  selective_replay_plan_id UUID NOT NULL REFERENCES selective_replay_plans(id) ON DELETE RESTRICT,
  environment_id UUID REFERENCES project_environments(id) ON DELETE RESTRICT,
  execution_id UUID NOT NULL REFERENCES executions(id) ON DELETE RESTRICT,
  repository_ref VARCHAR(1000) NOT NULL, pull_request_number INTEGER NOT NULL,
  base_sha VARCHAR(64) NOT NULL, source_head_sha VARCHAR(64) NOT NULL,
  admission_mode VARCHAR(16) NOT NULL DEFAULT 'observe',
  workflow_version VARCHAR(120) NOT NULL DEFAULT 'p22.observe-shadow.v1',
  non_authoritative BOOLEAN NOT NULL DEFAULT TRUE,
  input_fingerprint VARCHAR(80) NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL, request_hash VARCHAR(80) NOT NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'queued', sandbox_profile JSONB NOT NULL,
  plan_snapshot JSONB NOT NULL, stage_snapshot JSONB NOT NULL DEFAULT '[]'::jsonb,
  result_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb, result_snapshot_hash VARCHAR(80),
  shadow_gate_snapshot JSONB, retry_snapshot JSONB NOT NULL DEFAULT '{"attemptCount":1,"state":"not_requested"}'::jsonb,
  attempt_count INTEGER NOT NULL DEFAULT 1,
  replay_snapshot JSONB NOT NULL, trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb, audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_admission_runs_fingerprint UNIQUE (tenant_id, workspace_id, project_id, input_fingerprint),
  CONSTRAINT uq_admission_runs_idempotency UNIQUE (tenant_id, workspace_id, project_id, idempotency_key),
  CONSTRAINT uq_admission_runs_execution UNIQUE (execution_id),
  CONSTRAINT uq_admission_runs_orchestration UNIQUE (tenant_id, workspace_id, project_id, repository_ref, pull_request_number, source_head_sha, admission_mode, workflow_version),
  CONSTRAINT chk_admission_runs_status CHECK (status IN ('queued', 'running', 'completed', 'failed', 'partial', 'unavailable', 'cancelled', 'stale')),
  CONSTRAINT chk_admission_runs_fingerprint CHECK (length(input_fingerprint) = 71 AND input_fingerprint LIKE 'sha256:%'),
  CONSTRAINT chk_admission_runs_mode CHECK (admission_mode IN ('observe', 'shadow')),
  CONSTRAINT chk_admission_runs_non_authoritative CHECK (non_authoritative = TRUE)
);
CREATE INDEX IF NOT EXISTS idx_admission_runs_scope ON admission_runs(tenant_id, workspace_id, project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admission_runs_pr_context ON admission_runs(pr_context_version_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admission_runs_status ON admission_runs(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_admission_runs_pr_head_mode ON admission_runs(project_id, repository_ref, pull_request_number, source_head_sha, admission_mode, created_at DESC);
INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active) VALUES
  ('admission.read', 'integrations', 'Read PR Admission Observe/Shadow runs, timelines, evidence, reviews, and non-authoritative results.', 'low', TRUE),
  ('admission.execute', 'integrations', 'Start the fixed service-managed PR Admission workflow.', 'high', TRUE),
  ('admission.review', 'integrations', 'Request and decide governed human review of a non-authoritative Admission result.', 'high', TRUE),
  ('admission.retry', 'integrations', 'Retry Admission execution through the existing approval-backed retry workflow.', 'high', TRUE),
  ('admission.mode.manage', 'integrations', 'Select Observe or Shadow mode for a new Admission run.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET category = EXCLUDED.category, description = EXCLUDED.description, risk_level = EXCLUDED.risk_level, is_active = TRUE;
INSERT INTO edition_capabilities (edition, capability_key, enabled) VALUES
  ('basic', 'admission.read', TRUE), ('pro', 'admission.read', TRUE), ('enterprise', 'admission.read', TRUE),
  ('enterprise', 'admission.execute', TRUE), ('enterprise', 'admission.review', TRUE),
  ('enterprise', 'admission.retry', TRUE), ('enterprise', 'admission.mode.manage', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;
COMMENT ON TABLE admission_runs IS 'P22 admission decision is Observe/Shadow-only and non-authoritative. Service-owned orchestration reuses the existing lifecycle; Enforce and CI writeback are pending P23.';

-- P23 Service-owned CI conclusion, Enforce policy, and exact-head writeback.
ALTER TABLE admission_runs ALTER COLUMN workflow_version SET DEFAULT 'p23.ci-enforce.v1';
ALTER TABLE admission_runs DROP CONSTRAINT IF EXISTS chk_admission_runs_mode;
ALTER TABLE admission_runs ADD CONSTRAINT chk_admission_runs_mode CHECK (admission_mode IN ('observe', 'shadow', 'enforce'));
ALTER TABLE admission_runs DROP CONSTRAINT IF EXISTS chk_admission_runs_non_authoritative;
ALTER TABLE admission_runs ADD CONSTRAINT chk_admission_runs_non_authoritative CHECK (
  (admission_mode = 'enforce' AND non_authoritative = FALSE) OR
  (admission_mode <> 'enforce' AND non_authoritative = TRUE)
);
CREATE TABLE IF NOT EXISTS ci_enforcement_policies (
  id UUID PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL, workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  repository_ref VARCHAR(1000) NOT NULL, check_name VARCHAR(120) NOT NULL,
  mode VARCHAR(16) NOT NULL, status VARCHAR(24) NOT NULL,
  branch_protection_configured BOOLEAN NOT NULL DEFAULT FALSE, policy_hash VARCHAR(80) NOT NULL,
  activation_approval_id UUID REFERENCES approvals(id) ON DELETE RESTRICT,
  pending_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb, idempotency_key VARCHAR(255) NOT NULL,
  lock_version INTEGER NOT NULL DEFAULT 1, guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb, created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_ci_enforcement_policy_scope UNIQUE (tenant_id, workspace_id, project_id, repository_ref, check_name),
  CONSTRAINT chk_ci_enforcement_policy_mode CHECK (mode IN ('observe', 'shadow', 'enforce')),
  CONSTRAINT chk_ci_enforcement_policy_status CHECK (status IN ('active', 'approval_pending', 'disabled')),
  CONSTRAINT chk_ci_enforcement_policy_hash CHECK (length(policy_hash) = 71 AND policy_hash LIKE 'sha256:%'),
  CONSTRAINT chk_ci_enforcement_policy_lock CHECK (lock_version > 0)
);
CREATE INDEX IF NOT EXISTS idx_ci_enforcement_policy_scope ON ci_enforcement_policies(tenant_id, workspace_id, project_id, repository_ref);
CREATE TABLE IF NOT EXISTS ci_writeback_attempts (
  id UUID PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL, workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  admission_run_id UUID NOT NULL REFERENCES admission_runs(id) ON DELETE RESTRICT,
  connector_binding_id UUID NOT NULL REFERENCES skill_connector_bindings(id) ON DELETE RESTRICT,
  provider VARCHAR(32) NOT NULL, repository_ref VARCHAR(1000) NOT NULL, pull_request_number INTEGER NOT NULL,
  head_sha VARCHAR(64) NOT NULL, check_name VARCHAR(120) NOT NULL, admission_mode VARCHAR(16) NOT NULL,
  policy_hash VARCHAR(80) NOT NULL, idempotency_key VARCHAR(80) NOT NULL, request_hash VARCHAR(80) NOT NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'pending', conclusion_snapshot JSONB NOT NULL, enforcement_snapshot JSONB NOT NULL,
  stale_revision_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb, request_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  response_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb, external_action_ref JSONB, legacy_field_notice JSONB,
  connector_call_refs JSONB NOT NULL DEFAULT '[]'::jsonb, guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb, audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  attempt_count INTEGER NOT NULL DEFAULT 1, last_error_code VARCHAR(160),
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_ci_writeback_attempt_idempotency UNIQUE (idempotency_key),
  CONSTRAINT chk_ci_writeback_attempt_status CHECK (status IN ('pending', 'in_progress', 'success', 'failure', 'neutral', 'cancelled', 'stale', 'write_failed', 'unknown')),
  CONSTRAINT chk_ci_writeback_attempt_provider CHECK (provider IN ('github', 'gitlab', 'mock-scm')),
  CONSTRAINT chk_ci_writeback_attempt_mode CHECK (admission_mode IN ('observe', 'shadow', 'enforce')),
  CONSTRAINT chk_ci_writeback_attempt_count CHECK (attempt_count > 0),
  CONSTRAINT chk_ci_writeback_attempt_request_hash CHECK (length(request_hash) = 71 AND request_hash LIKE 'sha256:%')
);
CREATE INDEX IF NOT EXISTS idx_ci_writeback_attempt_scope ON ci_writeback_attempts(tenant_id, workspace_id, project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ci_writeback_attempt_pr_head ON ci_writeback_attempts(project_id, repository_ref, pull_request_number, head_sha, check_name);
CREATE INDEX IF NOT EXISTS idx_ci_writeback_attempt_admission ON ci_writeback_attempts(admission_run_id, created_at DESC);
INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active) VALUES
  ('ci.write', 'integrations', 'Write a Service-owned Admission CI conclusion through a scoped SCM Connector binding.', 'high', TRUE),
  ('enforce.manage', 'integrations', 'Request and approve governed PR Admission Enforce policy changes.', 'high', TRUE),
  ('ci.retry', 'integrations', 'Request an approval-backed retry of a failed or unknown CI writeback attempt.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET category=EXCLUDED.category, description=EXCLUDED.description, risk_level=EXCLUDED.risk_level, is_active=TRUE;
INSERT INTO edition_capabilities (edition, capability_key, enabled) VALUES
  ('enterprise', 'ci.write', TRUE), ('enterprise', 'enforce.manage', TRUE), ('enterprise', 'ci.retry', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled=TRUE;
COMMENT ON TABLE ci_enforcement_policies IS 'P23 approval-backed Service policy; branch protection remains external.';
COMMENT ON TABLE ci_writeback_attempts IS 'P23 exact-head, redacted CI Connector writeback facts; no dangerous PR mutation.';

-- P24 Service-owned Lessons Center and controlled Knowledge Promotion.
CREATE TABLE IF NOT EXISTS lesson_candidates (
  id UUID PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  lesson_type VARCHAR(64) NOT NULL,
  source_event_type VARCHAR(40) NOT NULL,
  source_event_id VARCHAR(255) NOT NULL,
  source_version VARCHAR(255),
  source_event_hash VARCHAR(80) NOT NULL,
  scope_type VARCHAR(32) NOT NULL,
  scope_id VARCHAR(1000) NOT NULL,
  summary TEXT NOT NULL,
  observations JSONB NOT NULL,
  evidence_refs JSONB NOT NULL,
  raw_refs JSONB NOT NULL,
  confidence NUMERIC(5,4) NOT NULL,
  frequency INTEGER NOT NULL,
  impact VARCHAR(16) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'candidate',
  dedupe_key VARCHAR(255) NOT NULL,
  cluster_key VARCHAR(80) NOT NULL,
  expires_at TIMESTAMPTZ,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  lock_version INTEGER NOT NULL DEFAULT 1,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_lesson_candidate_source_taxonomy_scope_dedupe UNIQUE (
    tenant_id, workspace_id, project_id, source_event_type, source_event_id,
    lesson_type, scope_type, scope_id, dedupe_key
  ),
  CONSTRAINT chk_lesson_candidates_type CHECK (lesson_type IN (
    'false_positive', 'false_negative', 'repeated_failure', 'flaky',
    'environment_issue', 'test_issue', 'human_override', 'graph_correction',
    'gate_disagreement', 'admission_outcome', 'auto_promotion_conflict',
    'auto_promotion_rollback', 'promotion_policy_too_strict',
    'promotion_policy_too_loose'
  )),
  CONSTRAINT chk_lesson_candidates_source_type CHECK (source_event_type IN (
    'finding', 'admission_run', 'gate_decision', 'graph_correction',
    'graph_promotion', 'domain_event'
  )),
  CONSTRAINT chk_lesson_candidates_scope_type CHECK (scope_type IN ('project', 'environment', 'repository')),
  CONSTRAINT chk_lesson_candidates_status CHECK (status IN ('candidate', 'under_review', 'accepted', 'rejected', 'promoted', 'expired')),
  CONSTRAINT chk_lesson_candidates_impact CHECK (impact IN ('low', 'medium', 'high', 'critical')),
  CONSTRAINT chk_lesson_candidates_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_lesson_candidates_frequency CHECK (frequency > 0),
  CONSTRAINT chk_lesson_candidates_lock CHECK (lock_version > 0)
);
CREATE INDEX IF NOT EXISTS idx_lesson_candidates_scope_status
  ON lesson_candidates(tenant_id, workspace_id, project_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_lesson_candidates_cluster
  ON lesson_candidates(tenant_id, workspace_id, project_id, cluster_key);
CREATE INDEX IF NOT EXISTS idx_lesson_candidates_expiry ON lesson_candidates(expires_at);
CREATE TRIGGER trg_lesson_candidates_updated_at
BEFORE UPDATE ON lesson_candidates
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS lesson_evidence (
  id UUID PRIMARY KEY,
  candidate_id UUID NOT NULL REFERENCES lesson_candidates(id) ON DELETE CASCADE,
  evidence_ref JSONB NOT NULL,
  raw_ref JSONB NOT NULL,
  content_hash VARCHAR(80) NOT NULL,
  retention_state VARCHAR(24) NOT NULL DEFAULT 'active',
  classification VARCHAR(24) NOT NULL DEFAULT 'internal',
  redaction_status VARCHAR(24) NOT NULL DEFAULT 'not_required',
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_lesson_evidence_candidate_hash UNIQUE (candidate_id, content_hash),
  CONSTRAINT chk_lesson_evidence_retention CHECK (retention_state IN ('active', 'missing', 'purged', 'expired')),
  CONSTRAINT chk_lesson_evidence_classification CHECK (classification IN ('public', 'internal', 'confidential', 'restricted')),
  CONSTRAINT chk_lesson_evidence_redaction CHECK (redaction_status IN ('not_required', 'redacted', 'unavailable'))
);
CREATE INDEX IF NOT EXISTS idx_lesson_evidence_candidate ON lesson_evidence(candidate_id, captured_at);

CREATE TABLE IF NOT EXISTS lesson_feedback (
  id UUID PRIMARY KEY,
  candidate_id UUID NOT NULL REFERENCES lesson_candidates(id) ON DELETE CASCADE,
  feedback_type VARCHAR(24) NOT NULL,
  reason TEXT NOT NULL,
  observations JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_lesson_feedback_actor_idempotency UNIQUE (candidate_id, created_by, idempotency_key),
  CONSTRAINT chk_lesson_feedback_type CHECK (feedback_type IN ('confirm', 'refute', 'supplement', 'uncertain'))
);
CREATE INDEX IF NOT EXISTS idx_lesson_feedback_candidate ON lesson_feedback(candidate_id, created_at);

CREATE TABLE IF NOT EXISTS lesson_reviews (
  id UUID PRIMARY KEY,
  candidate_id UUID NOT NULL REFERENCES lesson_candidates(id) ON DELETE CASCADE,
  decision VARCHAR(24) NOT NULL,
  confirmed_fact BOOLEAN NOT NULL,
  reason TEXT NOT NULL,
  evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  candidate_lock_version INTEGER NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  reviewed_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  reviewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_lesson_reviews_candidate_idempotency UNIQUE (candidate_id, idempotency_key),
  CONSTRAINT chk_lesson_reviews_decision CHECK (decision IN ('accepted', 'rejected', 'needs_evidence')),
  CONSTRAINT chk_lesson_reviews_confirmed_fact CHECK (
    (decision = 'accepted' AND confirmed_fact = TRUE) OR
    (decision <> 'accepted' AND confirmed_fact = FALSE)
  )
);
CREATE INDEX IF NOT EXISTS idx_lesson_reviews_candidate ON lesson_reviews(candidate_id, reviewed_at);

CREATE TABLE IF NOT EXISTS lesson_promotion_results (
  id UUID PRIMARY KEY,
  candidate_id UUID NOT NULL REFERENCES lesson_candidates(id) ON DELETE RESTRICT,
  status VARCHAR(32) NOT NULL,
  memory_type VARCHAR(24) NOT NULL,
  memory_ref JSONB NOT NULL DEFAULT '{}'::jsonb,
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  approval_state VARCHAR(24) NOT NULL,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence_refs JSONB NOT NULL,
  raw_refs JSONB NOT NULL,
  policy_snapshot JSONB NOT NULL,
  projection_state VARCHAR(32) NOT NULL DEFAULT 'skipped',
  reason_code VARCHAR(160),
  idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_lesson_promotion_candidate_idempotency UNIQUE (candidate_id, idempotency_key),
  CONSTRAINT chk_lesson_promotion_results_status CHECK (status IN ('approval_pending', 'promoted', 'rejected', 'failed', 'partial')),
  CONSTRAINT chk_lesson_promotion_results_memory_type CHECK (memory_type IN ('episodic', 'semantic', 'procedural')),
  CONSTRAINT chk_lesson_promotion_results_approval CHECK (approval_state IN ('pending', 'satisfied', 'not_required', 'rejected')),
  CONSTRAINT chk_lesson_promotion_results_projection CHECK (projection_state IN ('skipped', 'projected', 'projection_failed'))
);
CREATE INDEX IF NOT EXISTS idx_lesson_promotion_candidate ON lesson_promotion_results(candidate_id, created_at);
CREATE INDEX IF NOT EXISTS idx_lesson_promotion_status ON lesson_promotion_results(status, created_at);
CREATE TRIGGER trg_lesson_promotion_results_updated_at
BEFORE UPDATE ON lesson_promotion_results
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active)
VALUES
  ('lesson.read', 'knowledge', 'Read project-scoped Lesson Candidate and governed promotion projections.', 'low', TRUE),
  ('lesson.feedback', 'knowledge', 'Submit project-scoped structured feedback with evidence.', 'high', TRUE),
  ('lesson.review', 'knowledge', 'Review evidence-backed Lesson Candidates.', 'high', TRUE),
  ('lesson.promote', 'knowledge', 'Promote an accepted confirmed Lesson through controlled Knowledge governance.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET
  category = EXCLUDED.category,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  is_active = TRUE;

INSERT INTO edition_capabilities (edition, capability_key, enabled)
VALUES
  ('basic', 'lesson.read', TRUE),
  ('pro', 'lesson.read', TRUE),
  ('enterprise', 'lesson.read', TRUE),
  ('enterprise', 'lesson.feedback', TRUE),
  ('enterprise', 'lesson.review', TRUE),
  ('enterprise', 'lesson.promote', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled = TRUE;

COMMENT ON TABLE lesson_candidates IS
  'P24 project-scoped evidence-backed Lesson Candidates. Candidate state never implies Knowledge or Memory promotion.';
COMMENT ON TABLE lesson_promotion_results IS
  'P24 controlled Knowledge Promotion results. Only explicit reviewed and guarded promotion may project to Memory.';

-- P25 typed Improvement Proposal Governance.
ALTER TABLE skill_versions
  ADD COLUMN IF NOT EXISTS governance_status VARCHAR(24) NOT NULL DEFAULT 'active';
ALTER TABLE skill_versions DROP CONSTRAINT IF EXISTS chk_skill_versions_governance_status;
ALTER TABLE skill_versions ADD CONSTRAINT chk_skill_versions_governance_status
  CHECK (governance_status IN ('draft', 'active', 'rejected', 'deprecated', 'archived'));

CREATE TABLE IF NOT EXISTS improvement_proposals (
  id UUID PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL, workspace_id VARCHAR(128) NOT NULL,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  source_lesson_refs JSONB NOT NULL, source_lessons_hash VARCHAR(80) NOT NULL,
  target_type VARCHAR(48) NOT NULL, target_id VARCHAR(255) NOT NULL, target_key VARCHAR(255) NOT NULL,
  target_base_version VARCHAR(255) NOT NULL, target_base_hash VARCHAR(80) NOT NULL,
  target_snapshot JSONB NOT NULL, structured_change JSONB NOT NULL, change_hash VARCHAR(80) NOT NULL,
  rationale TEXT NOT NULL, evidence_refs JSONB NOT NULL,
  requested_risk VARCHAR(16) NOT NULL, evaluated_risk VARCHAR(16) NOT NULL,
  confidence NUMERIC(5,4) NOT NULL, validation_plan JSONB NOT NULL,
  validation_refs JSONB NOT NULL DEFAULT '[]'::jsonb, status VARCHAR(40) NOT NULL DEFAULT 'draft',
  approval_refs JSONB NOT NULL DEFAULT '[]'::jsonb, route_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  effectiveness_refs JSONB NOT NULL DEFAULT '[]'::jsonb, rollback_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  guardrail_event_refs JSONB NOT NULL DEFAULT '[]'::jsonb, audit_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
  effectiveness_window JSONB NOT NULL, trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  lock_version INTEGER NOT NULL DEFAULT 1, idempotency_key VARCHAR(255) NOT NULL,
  request_hash VARCHAR(80) NOT NULL, created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_improvement_proposal_idempotency UNIQUE (tenant_id, workspace_id, project_id, idempotency_key),
  CONSTRAINT chk_improvement_proposals_target_type CHECK (target_type IN ('skill', 'gate_policy', 'graph', 'graph_learning_policy', 'test_case', 'test_step', 'tool_config', 'connector_config')),
  CONSTRAINT chk_improvement_proposals_status CHECK (status IN ('draft', 'validation_failed', 'validated', 'review_pending', 'review_approved', 'review_rejected', 'routed', 'effectiveness_pending', 'effective', 'ineffective', 'inconclusive', 'rollback_pending', 'rollback_routed', 'partial', 'failed', 'archived')),
  CONSTRAINT chk_improvement_proposals_risk CHECK (requested_risk IN ('low', 'medium', 'high', 'critical') AND evaluated_risk IN ('low', 'medium', 'high', 'critical')),
  CONSTRAINT chk_improvement_proposals_confidence CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT chk_improvement_proposals_lock CHECK (lock_version > 0)
);
CREATE INDEX IF NOT EXISTS idx_improvement_proposals_scope_status ON improvement_proposals(tenant_id, workspace_id, project_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_improvement_proposals_target ON improvement_proposals(tenant_id, workspace_id, project_id, target_type, target_id);
CREATE TRIGGER trg_improvement_proposals_updated_at BEFORE UPDATE ON improvement_proposals FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS improvement_proposal_versions (
  id UUID PRIMARY KEY, proposal_id UUID NOT NULL REFERENCES improvement_proposals(id) ON DELETE CASCADE,
  version_number INTEGER NOT NULL, content_hash VARCHAR(80) NOT NULL, source_lesson_refs JSONB NOT NULL,
  target_base_version VARCHAR(255) NOT NULL, target_base_hash VARCHAR(80) NOT NULL, snapshot JSONB NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_improvement_proposal_version UNIQUE (proposal_id, version_number),
  CONSTRAINT uq_improvement_proposal_version_hash UNIQUE (proposal_id, content_hash)
);
CREATE INDEX IF NOT EXISTS idx_improvement_proposal_versions_proposal ON improvement_proposal_versions(proposal_id, version_number);

CREATE TABLE IF NOT EXISTS improvement_validation_results (
  id UUID PRIMARY KEY, proposal_id UUID NOT NULL REFERENCES improvement_proposals(id) ON DELETE CASCADE,
  proposal_version INTEGER NOT NULL, status VARCHAR(24) NOT NULL, checks JSONB NOT NULL,
  historical_simulation JSONB NOT NULL, counterexample_regression JSONB, evidence_refs JSONB NOT NULL,
  metrics JSONB NOT NULL DEFAULT '{}'::jsonb, result_hash VARCHAR(80) NOT NULL, validator_version VARCHAR(80) NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL, request_hash VARCHAR(80) NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  validated_by UUID REFERENCES users(id) ON DELETE SET NULL, validated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_improvement_validation_idempotency UNIQUE (proposal_id, idempotency_key),
  CONSTRAINT chk_improvement_validation_status CHECK (status IN ('passed', 'failed', 'insufficient', 'unavailable'))
);
CREATE INDEX IF NOT EXISTS idx_improvement_validation_proposal ON improvement_validation_results(proposal_id, validated_at);

CREATE TABLE IF NOT EXISTS improvement_effectiveness_results (
  id UUID PRIMARY KEY, proposal_id UUID NOT NULL REFERENCES improvement_proposals(id) ON DELETE RESTRICT,
  status VARCHAR(24) NOT NULL, target_outcome_ref JSONB NOT NULL, before_metrics JSONB NOT NULL,
  after_metrics JSONB NOT NULL, deltas JSONB NOT NULL, sample_size INTEGER NOT NULL,
  rollback_required BOOLEAN NOT NULL DEFAULT FALSE, evidence_refs JSONB NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL, request_hash VARCHAR(80) NOT NULL,
  trace_id UUID NOT NULL REFERENCES traces(id) ON DELETE RESTRICT,
  measured_by UUID REFERENCES users(id) ON DELETE SET NULL, measured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_improvement_effectiveness_idempotency UNIQUE (proposal_id, idempotency_key),
  CONSTRAINT chk_improvement_effectiveness_status CHECK (status IN ('effective', 'ineffective', 'inconclusive'))
);
CREATE INDEX IF NOT EXISTS idx_improvement_effectiveness_proposal ON improvement_effectiveness_results(proposal_id, measured_at);

INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active) VALUES
  ('improvement.read', 'knowledge', 'Read project-scoped typed Improvement Proposal projections.', 'low', TRUE),
  ('improvement.create', 'knowledge', 'Create, edit, and validate evidence-backed Improvement Proposals.', 'high', TRUE),
  ('improvement.review', 'knowledge', 'Submit and assess Improvement Proposals and effectiveness evidence.', 'high', TRUE),
  ('improvement.route', 'knowledge', 'Route an approved Improvement Proposal into its target authority workflow.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET category=EXCLUDED.category, description=EXCLUDED.description, risk_level=EXCLUDED.risk_level, is_active=TRUE;
INSERT INTO edition_capabilities (edition, capability_key, enabled) VALUES
  ('basic', 'improvement.read', TRUE), ('pro', 'improvement.read', TRUE), ('enterprise', 'improvement.read', TRUE),
  ('enterprise', 'improvement.create', TRUE), ('enterprise', 'improvement.review', TRUE), ('enterprise', 'improvement.route', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled=TRUE;
COMMENT ON TABLE improvement_proposals IS 'P25 typed Lesson-derived proposals. Routing is approval-backed and cannot directly apply a production change.';
COMMENT ON TABLE improvement_proposal_versions IS 'Immutable P25 proposal snapshots for validation, Replay, conflict detection and rollback provenance.';
COMMENT ON TABLE improvement_effectiveness_results IS 'Evidence-backed before/after outcomes. Ineffective results require governed target-authority rollback routing.';

-- P26 extends the existing Edition/Capability authority; no parallel entitlement system.
INSERT INTO capability_registry (capability_key, category, description, risk_level, is_active) VALUES
  ('governance.read', 'governance', 'Read project-scoped Edition, Capability, Scope, and governance readiness projections.', 'low', TRUE),
  ('governance.aggregate.read', 'governance', 'Read minimum-visibility cross-project governance trends within an authorized workspace.', 'medium', TRUE),
  ('graph.autonomy.configure', 'graph', 'Request approval-backed controlled Graph autonomy configuration for a project or environment.', 'high', TRUE)
ON CONFLICT (capability_key) DO UPDATE SET category=EXCLUDED.category, description=EXCLUDED.description, risk_level=EXCLUDED.risk_level, is_active=TRUE;
INSERT INTO edition_capabilities (edition, capability_key, enabled) VALUES
  ('basic', 'governance.read', TRUE), ('pro', 'governance.read', TRUE),
  ('enterprise', 'governance.read', TRUE), ('enterprise', 'governance.aggregate.read', TRUE),
  ('enterprise', 'graph.autonomy.configure', TRUE)
ON CONFLICT (edition, capability_key) DO UPDATE SET enabled=TRUE;
INSERT INTO rbac_role_capabilities (role_name, capability_key, effect) VALUES
  ('admin', 'governance.read', 'allow'), ('admin', 'governance.aggregate.read', 'allow'),
  ('admin', 'graph.autonomy.configure', 'allow'), ('system', 'governance.read', 'allow'),
  ('system', 'governance.aggregate.read', 'allow'), ('system', 'graph.autonomy.configure', 'allow'),
  ('user', 'governance.read', 'allow')
ON CONFLICT (role_name, capability_key) DO UPDATE SET effect=EXCLUDED.effect;

COMMIT;

-- Community presentation enablement (no schema or migration change): existing
-- capability_bindings.binding_config stores the Service-owned communityEnablement
-- policy, revision and hash-protected validation report; pending_change stores the
-- latest lifecycle idempotency receipt. skill_invocations.resolution_snapshot
-- freezes the validated communityProfile. No Approval or evaluation is fabricated.
