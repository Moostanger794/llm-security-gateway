from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment variables override an optional .env in the working directory."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", frozen=True
    )

    app_name: str = Field(default="AI Security Gateway", min_length=1, max_length=100)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    enable_llm_analysis: bool = False
    allow_external_llm: bool = False
    llm_provider: str = Field(default="openai", max_length=40)
    llm_model: str = Field(default="", pattern=r"^[A-Za-z0-9._:-]{0,128}$")
    llm_api_key: SecretStr = SecretStr("")
    llm_timeout_seconds: float = Field(default=15, gt=0, le=120, allow_inf_nan=False)
    llm_max_retries: int = Field(default=0, ge=0, le=3)
    llm_max_input_chars: int = Field(default=12000, ge=1, le=120000)
    llm_max_output_tokens: int = Field(default=512, ge=64, le=4096)
