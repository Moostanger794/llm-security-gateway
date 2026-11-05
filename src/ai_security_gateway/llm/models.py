"""Small, closed contracts: untrusted text in; validated codes out."""

from typing import Literal, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

InjectionThreat = Literal[
    "prompt_injection",
    "instruction_override",
    "jailbreak",
    "system_prompt_extraction",
    "secret_extraction",
    "role_manipulation",
    "indirect_prompt_injection",
]
ReasonCode = Literal[
    "instruction_redirection",
    "override_hierarchy",
    "privileged_role_claim",
    "extract_privileged_prompt",
    "extract_secrets",
    "disable_safety",
    "manipulate_verdict",
    "no_instruction_attack",
    "insufficient_context",
]
LLMStatus = Literal[
    "disabled",
    "external_not_allowed",
    "missing_key",
    "missing_model",
    "unsupported_provider",
    "success",
    "uncertain",
    "skipped_too_large",
    "timeout",
    "network_error",
    "unauthorized",
    "forbidden",
    "rate_limited",
    "provider_error",
    "refusal",
    "incomplete",
    "invalid_response",
    "invalid_configuration",
    "invalid_headers",
    "request_preparation_error",
    "budget_exhausted",
    "closed",
]

REASON_THREATS: dict[str, frozenset[str]] = {
    "instruction_redirection": frozenset({"prompt_injection", "indirect_prompt_injection"}),
    "override_hierarchy": frozenset({"instruction_override"}),
    "privileged_role_claim": frozenset({"role_manipulation"}),
    "extract_privileged_prompt": frozenset({"system_prompt_extraction"}),
    "extract_secrets": frozenset({"secret_extraction"}),
    "disable_safety": frozenset({"jailbreak"}),
    "manipulate_verdict": frozenset({"prompt_injection", "indirect_prompt_injection"}),
}


class ClassifierInput(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, hide_input_in_errors=True)
    source_type: Literal["prompt", "document", "email"]
    text: str | None = Field(default=None, repr=False)
    sender: str | None = Field(default=None, repr=False)
    subject: str | None = Field(default=None, repr=False)
    body: str | None = Field(default=None, repr=False)

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.source_type == "email":
            if self.text is not None or any(
                v is None for v in (self.sender, self.subject, self.body)
            ):
                raise ValueError("email requires sender, subject, body only")
        elif self.text is None or any(
            v is not None for v in (self.sender, self.subject, self.body)
        ):
            raise ValueError("prompt/document requires text only")
        return self

    @property
    def input_chars(self) -> int:
        return sum(
            len(value) for value in (self.text, self.sender, self.subject, self.body) if value
        )


class ClassifierResponse(BaseModel):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )
    verdict: Literal["attack", "no_attack_detected", "uncertain"]
    threat_types: list[InjectionThreat]
    reason_codes: list[ReasonCode]

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if len(set(self.threat_types)) != len(self.threat_types):
            raise ValueError("duplicate threat type")
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("duplicate reason code")
        if self.verdict == "attack":
            if not self.threat_types or not self.reason_codes:
                raise ValueError("attack requires evidence codes")
            if any(code not in REASON_THREATS for code in self.reason_codes):
                raise ValueError("attack has non-attack reason")
            if any(
                not REASON_THREATS[code].intersection(self.threat_types)
                for code in self.reason_codes
            ):
                raise ValueError("reason does not support a threat")
            supported = set().union(*(REASON_THREATS[code] for code in self.reason_codes))
            if not set(self.threat_types).issubset(supported):
                raise ValueError("threat without supporting reason")
        else:
            expected = (
                "no_instruction_attack"
                if self.verdict == "no_attack_detected"
                else ("insufficient_context")
            )
            if self.threat_types or self.reason_codes != [expected]:
                raise ValueError("non-attack verdict has inconsistent evidence")
        return self


class ClassificationOutcome(BaseModel):
    """Per-call metadata; never contains provider text, exceptions or request IDs."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, hide_input_in_errors=True)
    result: ClassifierResponse | None = None
    status: LLMStatus
    fallback_reason: LLMStatus | None = None
    model: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._:-]{1,128}$")
    requests: int = Field(default=0, ge=0)
    reservations: int = Field(default=0, ge=0)
    released_reservations: int = Field(default=0, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    elapsed_ms: float = Field(default=0, ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.status == "success":
            if self.result is None or self.result.verdict == "uncertain" or self.fallback_reason:
                raise ValueError("success requires a resolved classification without fallback")
        elif self.status == "uncertain":
            if self.result is None or self.result.verdict != "uncertain":
                raise ValueError("uncertain status requires uncertain classification")
        elif self.result is not None:
            raise ValueError("failed classification must not contain a result")
        expected = None if self.status in {"success", "disabled"} else self.status
        if self.fallback_reason is not None and self.fallback_reason != expected:
            raise ValueError("fallback reason must match status")
        # Derive a missing reason from the closed status vocabulary, never provider text.
        object.__setattr__(self, "fallback_reason", expected)
        return self


class Classifier(Protocol):
    def classify(self, data: ClassifierInput) -> ClassificationOutcome: ...

    def close(self) -> None: ...
