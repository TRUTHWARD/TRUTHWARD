# SPDX-License-Identifier: Apache-2.0
from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = Field(default="local", alias="APP_ENV")
    deployment_profile: Literal["full", "oss"] = Field(
        default="full",
        alias="DEPLOYMENT_PROFILE",
    )
    api_prefix: str = Field(default="/api/v1", alias="API_PREFIX")
    database_url: str = Field(
        default="postgresql+psycopg://postgres:postgres@localhost:5432/agentic_qa",
        alias="DATABASE_URL",
    )
    database_pool_size: int = Field(default=5, ge=1, le=256, alias="DATABASE_POOL_SIZE")
    database_max_overflow: int = Field(
        default=10,
        ge=0,
        le=256,
        alias="DATABASE_MAX_OVERFLOW",
    )
    database_pool_timeout_seconds: float = Field(
        default=30.0,
        gt=0,
        le=600,
        alias="DATABASE_POOL_TIMEOUT_SECONDS",
    )
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    queue_mode: str = Field(default="inline", alias="QUEUE_MODE")
    celery_queue_name: str = Field(default="celery", alias="CELERY_QUEUE_NAME")
    celery_visibility_timeout_seconds: int = Field(
        default=3600,
        ge=1,
        alias="CELERY_VISIBILITY_TIMEOUT_SECONDS",
    )
    object_storage_bucket: str = Field(
        default="agentic-qa-artifacts",
        alias="OBJECT_STORAGE_BUCKET",
    )
    openai_base_url: str = Field(
        default="https://api.openai.com/v1",
        alias="OPENAI_BASE_URL",
    )
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        alias="OLLAMA_BASE_URL",
    )
    ollama_model: str = Field(default="llama3.1", alias="OLLAMA_MODEL")
    runner_artifact_dir: str = Field(default=".tmp/runner-artifacts", alias="RUNNER_ARTIFACT_DIR")
    artifact_storage_dir: str = Field(default=".tmp/artifacts", alias="ARTIFACT_STORAGE_DIR")
    replay_repository_storage_adapter: str = Field(default="local", alias="REPLAY_REPOSITORY_STORAGE_ADAPTER")
    replay_repository_storage_dir: str = Field(default=".tmp/replay-repository", alias="REPLAY_REPOSITORY_STORAGE_DIR")
    replay_repository_object_storage_dir: str = Field(default=".tmp/replay-object-storage", alias="REPLAY_REPOSITORY_OBJECT_STORAGE_DIR")
    replay_repository_object_storage_bucket: str = Field(default="agentic-qa-replay", alias="REPLAY_REPOSITORY_OBJECT_STORAGE_BUCKET")
    k6_binary_path: str = Field(default="", alias="K6_BINARY_PATH")
    semgrep_binary_path: str = Field(default="", alias="SEMGREP_BINARY_PATH")
    nuclei_binary_path: str = Field(default="", alias="NUCLEI_BINARY_PATH")
    zap_binary_path: str = Field(default="", alias="ZAP_BINARY_PATH")
    demo_admin_token: str = Field(default="admin-token", alias="DEMO_ADMIN_TOKEN")
    demo_user_token: str = Field(default="user-token", alias="DEMO_USER_TOKEN")
    community_token_ttl_hours: int = Field(
        default=168,
        ge=1,
        le=24 * 365,
        alias="COMMUNITY_TOKEN_TTL_HOURS",
    )
    community_skill_manifest_dir: str = Field(
        default="community-skills",
        alias="COMMUNITY_SKILL_MANIFEST_DIR",
    )
    auto_create_tables: bool = Field(default=True, alias="AUTO_CREATE_TABLES")
    api_max_request_bytes: int = Field(
        default=16 * 1024 * 1024,
        ge=1024,
        le=64 * 1024 * 1024,
        alias="API_MAX_REQUEST_BYTES",
    )
    api_rate_limit_requests: int = Field(
        default=10_000,
        ge=1,
        le=1_000_000,
        alias="API_RATE_LIMIT_REQUESTS",
    )
    api_rate_limit_window_seconds: int = Field(
        default=60,
        ge=1,
        le=3600,
        alias="API_RATE_LIMIT_WINDOW_SECONDS",
    )
    api_request_timeout_seconds: float = Field(
        default=120.0,
        gt=0,
        le=600,
        alias="API_REQUEST_TIMEOUT_SECONDS",
    )
    controlled_autonomy_global_kill_switch: bool = Field(
        default=False,
        alias="CONTROLLED_AUTONOMY_GLOBAL_KILL_SWITCH",
    )
    controlled_autonomy_max_promotions_per_window: int = Field(
        default=10,
        ge=1,
        le=10_000,
        alias="CONTROLLED_AUTONOMY_MAX_PROMOTIONS_PER_WINDOW",
    )
    controlled_autonomy_window_seconds: int = Field(
        default=3600,
        ge=60,
        le=30 * 24 * 3600,
        alias="CONTROLLED_AUTONOMY_WINDOW_SECONDS",
    )
    controlled_autonomy_rollback_rate_threshold: float = Field(
        default=0.20,
        ge=0.0,
        le=1.0,
        alias="CONTROLLED_AUTONOMY_ROLLBACK_RATE_THRESHOLD",
    )
    controlled_autonomy_minimum_promotions_for_rate_pause: int = Field(
        default=3,
        ge=1,
        le=10_000,
        alias="CONTROLLED_AUTONOMY_MINIMUM_PROMOTIONS_FOR_RATE_PAUSE",
    )
    skill_invocation_global_kill_switch: bool = Field(
        default=False,
        alias="SKILL_INVOCATION_GLOBAL_KILL_SWITCH",
    )
    skill_invocation_timeout_seconds: float = Field(
        default=120.0,
        gt=0.0,
        le=3600.0,
        alias="SKILL_INVOCATION_TIMEOUT_SECONDS",
    )
    skill_invocation_max_attempts: int = Field(
        default=3,
        ge=1,
        le=10,
        alias="SKILL_INVOCATION_MAX_ATTEMPTS",
    )
    skill_invocation_max_input_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=1024,
        le=16 * 1024 * 1024,
        alias="SKILL_INVOCATION_MAX_INPUT_BYTES",
    )
    skill_invocation_max_output_bytes: int = Field(
        default=1024 * 1024,
        ge=1024,
        le=16 * 1024 * 1024,
        alias="SKILL_INVOCATION_MAX_OUTPUT_BYTES",
    )
    skill_invocation_max_model_calls: int = Field(
        default=3,
        ge=0,
        le=100,
        alias="SKILL_INVOCATION_MAX_MODEL_CALLS",
    )
    skill_invocation_max_tool_calls: int = Field(
        default=3,
        ge=0,
        le=100,
        alias="SKILL_INVOCATION_MAX_TOOL_CALLS",
    )
    skill_invocation_max_skill_calls: int = Field(
        default=3,
        ge=0,
        le=100,
        alias="SKILL_INVOCATION_MAX_SKILL_CALLS",
    )
    skill_invocation_tenant_concurrency_limit: int = Field(
        default=32,
        ge=1,
        le=10_000,
        alias="SKILL_INVOCATION_TENANT_CONCURRENCY_LIMIT",
    )
    skill_invocation_project_concurrency_limit: int = Field(
        default=16,
        ge=1,
        le=10_000,
        alias="SKILL_INVOCATION_PROJECT_CONCURRENCY_LIMIT",
    )
    skill_invocation_binding_concurrency_limit: int = Field(
        default=8,
        ge=1,
        le=10_000,
        alias="SKILL_INVOCATION_BINDING_CONCURRENCY_LIMIT",
    )
    skill_invocation_circuit_failure_threshold: int = Field(
        default=3,
        ge=1,
        le=100,
        alias="SKILL_INVOCATION_CIRCUIT_FAILURE_THRESHOLD",
    )
    skill_invocation_circuit_recovery_seconds: float = Field(
        default=30.0,
        ge=0.0,
        le=3600.0,
        alias="SKILL_INVOCATION_CIRCUIT_RECOVERY_SECONDS",
    )

    @model_validator(mode="after")
    def database_pool_capacity_is_bounded(self) -> "Settings":
        if self.database_pool_size + self.database_max_overflow > 256:
            raise ValueError(
                "DATABASE_POOL_SIZE + DATABASE_MAX_OVERFLOW must not exceed 256"
            )
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
