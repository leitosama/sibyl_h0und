from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from sibyl_h0und.budget import DEFAULT_MAX_RUNTIME_CALLS, RUNTIME_CALL_LIMIT
from sibyl_h0und.trace import default_trace_dir

_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    """Scenario-runtime and OpenAI-compatible provider settings."""

    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    scenario_runtime_endpoint: str = Field(
        default="127.0.0.1:50051",
        validation_alias="SCENARIO_RUNTIME_ENDPOINT",
        min_length=1,
    )
    scenario_runtime_token: SecretStr = Field(
        validation_alias="SCENARIO_RUNTIME_TOKEN",
        min_length=1,
    )
    scenario_runtime_verify_tls: bool = Field(
        default=True,
        validation_alias="SCENARIO_RUNTIME_VERIFY_TLS",
    )
    scenario_runtime_arena: str | None = Field(
        default=None,
        validation_alias="SCENARIO_RUNTIME_ARENA",
        min_length=1,
        max_length=64,
    )
    remote_run_label: str = Field(
        default="sibyl-h0und",
        validation_alias="REMOTE_RUN_LABEL",
        min_length=1,
    )
    agent_name: str = Field(
        default="sibyl-h0und",
        validation_alias="AGENT_NAME",
        min_length=1,
        max_length=255,
    )

    llm_base_url: str = Field(validation_alias="LLM_BASE_URL", min_length=1)
    llm_api_key: SecretStr = Field(validation_alias="LLM_API_KEY", min_length=1)
    llm_default_model: str = Field(validation_alias="LLM_DEFAULT_MODEL", min_length=1)
    # Model of the benign challenger; unset, it is the default model (ADR 0025).
    llm_challenger_model: str | None = Field(
        default=None, validation_alias="LLM_CHALLENGER_MODEL", min_length=1
    )
    llm_timeout_seconds: float = Field(
        default=120.0,
        validation_alias="LLM_TIMEOUT_SECONDS",
        gt=0,
    )
    llm_max_completion_tokens: int = Field(
        default=16_384,
        validation_alias="LLM_MAX_COMPLETION_TOKENS",
        gt=0,
    )
    llm_max_step_retries: int = Field(
        default=3,
        validation_alias="LLM_MAX_STEP_RETRIES",
        ge=1,
        le=5,
    )
    # Safety ceiling on runtime calls per task, the report included. It stays
    # below the runtime's own limit of 100 calls (ADR 0004, 0015).
    agent_max_runtime_calls: int = Field(
        default=DEFAULT_MAX_RUNTIME_CALLS,
        validation_alias="BLUESEC_AGENT_MAX_RUNTIME_CALLS",
        ge=2,
        lt=RUNTIME_CALL_LIMIT,
    )
    # Kill switches of the newest behaviour, so a run can turn one off without
    # a code change: the challenger's ruling (ADR 0028) and the alert stage (ADR 0029).
    agent_challenger_ruling: bool = Field(default=True, validation_alias="AGENT_CHALLENGER_RULING")
    agent_alert_stage: bool = Field(default=True, validation_alias="AGENT_ALERT_STAGE")
    trace_enabled: bool = Field(default=True, validation_alias="TRACE_ENABLED")
    trace_dir: Path = Field(default_factory=default_trace_dir, validation_alias="TRACE_DIR")

    @field_validator("llm_challenger_model", mode="before")
    @classmethod
    def _blank_is_unset(cls, value: object) -> object:
        """Read a blank model, such as `LLM_CHALLENGER_MODEL=`, as unset."""
        return None if isinstance(value, str) and not value.strip() else value
