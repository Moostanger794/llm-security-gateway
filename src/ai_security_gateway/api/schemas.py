from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai_security_gateway.security.normalization import MAX_PROMPT_LENGTH, validate_text


class HealthResponse(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    status: Literal["ok"] = "ok"
    service: str
    version: str


class ErrorResponse(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    detail: str
    request_id: str


class PromptRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    text: str = Field(min_length=1, max_length=MAX_PROMPT_LENGTH)

    @field_validator("text")
    @classmethod
    def visible_text(cls, value: str) -> str:
        return validate_text(value)
