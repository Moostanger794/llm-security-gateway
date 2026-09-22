from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai_security_gateway.security.email_normalization import (
    MAX_EMAIL_BODY_LENGTH,
    MAX_SENDER_LENGTH,
    MAX_SUBJECT_LENGTH,
    validate_email_field,
)
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


class TextRequest(PromptRequest):
    """Plain untrusted text, sharing prompt validation and limits."""


class EmailRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    sender: str = Field(min_length=1, max_length=MAX_SENDER_LENGTH)
    subject: str = Field(min_length=1, max_length=MAX_SUBJECT_LENGTH)
    body: str = Field(min_length=1, max_length=MAX_EMAIL_BODY_LENGTH)

    @field_validator("sender", "subject", "body")
    @classmethod
    def visible_content(cls, value: str) -> str:
        return validate_email_field(value, MAX_EMAIL_BODY_LENGTH)
