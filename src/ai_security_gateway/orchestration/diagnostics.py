"""Per-call metadata, separate from the stable public SecurityResult JSON."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ai_security_gateway.llm import ClassificationOutcome
from ai_security_gateway.llm.models import LLMStatus
from ai_security_gateway.models.security import SecurityResult


class AnalysisMetadata(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    requested_mode: Literal["rules", "hybrid"]
    actual_mode: Literal["rules", "hybrid", "fallback_rules"]
    llm_status: LLMStatus
    fallback_reason: LLMStatus | None = None
    model: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._:-]{1,128}$")
    requests: int = Field(default=0, ge=0)
    reservations: int = Field(default=0, ge=0)
    released_reservations: int = Field(default=0, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)

    @classmethod
    def rules(cls) -> "AnalysisMetadata":
        return cls(requested_mode="rules", actual_mode="rules", llm_status="disabled")

    @classmethod
    def from_outcome(cls, outcome: ClassificationOutcome) -> "AnalysisMetadata":
        return cls(
            requested_mode="hybrid",
            actual_mode="hybrid" if outcome.status == "success" else "fallback_rules",
            llm_status=outcome.status,
            fallback_reason=outcome.fallback_reason
            or (outcome.status if outcome.status != "success" else None),
            model=outcome.model,
            requests=outcome.requests,
            reservations=outcome.reservations,
            released_reservations=outcome.released_reservations,
            input_tokens=outcome.input_tokens,
            output_tokens=outcome.output_tokens,
        )


class Analysis(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    result: SecurityResult
    metadata: AnalysisMetadata
