from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SecurityAction = Literal["ALLOW", "SANITIZE", "REQUIRE_CONFIRMATION", "BLOCK"]
Assessment = Literal["SAFE", "SUSPICIOUS", "DANGEROUS"]
Threat = Literal[
    "prompt_injection",
    "instruction_override",
    "jailbreak",
    "system_prompt_extraction",
    "secret_extraction",
    "role_manipulation",
    "indirect_prompt_injection",
    "phishing",
    "social_engineering",
    "urgency",
    "credential_request",
    "suspicious_sender",
    "suspicious_url",
]


class SecurityResult(BaseModel):
    """A heuristic assessment, not a guarantee of safety or enforced execution policy."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    safe: bool
    assessment: Assessment
    risk_score: float = Field(ge=0, le=1, allow_inf_nan=False)
    risk_level: RiskLevel
    threats: list[Threat]
    action: SecurityAction
    explanation: str
    recommendations: list[str]
    processing_time_ms: float = Field(ge=0, allow_inf_nan=False)
