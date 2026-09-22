from collections.abc import Iterable
from time import perf_counter
from typing import Protocol

from ai_security_gateway.models.security import SecurityResult
from ai_security_gateway.orchestration.advisor import SecurityAdvisor
from ai_security_gateway.security.email_guard import EmailGuard
from ai_security_gateway.security.email_normalization import (
    MAX_EMAIL_BODY_LENGTH,
    MAX_SENDER_LENGTH,
    MAX_SUBJECT_LENGTH,
    validate_email_field,
)
from ai_security_gateway.security.normalization import canonicalize, validate_text
from ai_security_gateway.security.prompt_guard import PromptGuard
from ai_security_gateway.security.risk_engine import Finding, RiskEngine


class TextDetector(Protocol):
    def detect(self, text: str) -> list[Finding]: ...


class EmailDetector(Protocol):
    def detect(self, sender: str, subject: str, body: str) -> list[Finding]: ...


class SecurityOrchestrator:
    """Stateless service: validate, route, aggregate evidence, apply policy, explain.

    Injected dependencies are trusted code and must return text-free metadata.
    Decisions are deterministic; measured processing time naturally varies.
    """

    def __init__(
        self,
        prompt_guard: TextDetector | None = None,
        email_guard: EmailDetector | None = None,
        risk_engine: RiskEngine | None = None,
        advisor: SecurityAdvisor | None = None,
    ) -> None:
        self.prompt_guard = prompt_guard if prompt_guard is not None else PromptGuard()
        self.email_guard = email_guard if email_guard is not None else EmailGuard()
        self.risk_engine = risk_engine if risk_engine is not None else RiskEngine()
        self.advisor = advisor if advisor is not None else SecurityAdvisor()

    def analyze_prompt(self, text: str) -> SecurityResult:
        return self.analyze_text(text)

    def analyze_text(self, text: str) -> SecurityResult:
        """Analyze plain untrusted text; no email/URL checks or inferred source label."""
        started = perf_counter()
        validate_text(text)
        findings = self.prompt_guard.detect(canonicalize(text))
        return self._result(findings, started)

    def analyze_email(self, sender: str, subject: str, body: str) -> SecurityResult:
        started = perf_counter()
        # Validate at the service boundary even when a detector is replaced.
        validate_email_field(sender, MAX_SENDER_LENGTH)
        validate_email_field(subject, MAX_SUBJECT_LENGTH)
        validate_email_field(body, MAX_EMAIL_BODY_LENGTH)
        findings = self.email_guard.detect(sender, subject, body)
        return self._result(findings, started)

    def _result(self, findings: Iterable[Finding], started: float) -> SecurityResult:
        evidence = sorted(
            set(findings),
            key=lambda f: (f.threat, f.weight, f.explanation, f.recommendation),
        )
        score = self.risk_engine.score(evidence)
        level, action, assessment = self.risk_engine.decide(score)
        explanation, recommendations = self.advisor.advise(evidence, score)
        return SecurityResult(
            safe=assessment == "SAFE",
            assessment=assessment,
            risk_score=score,
            risk_level=level,
            action=action,
            threats=sorted({finding.threat for finding in evidence}),
            explanation=explanation,
            recommendations=recommendations,
            processing_time_ms=(perf_counter() - started) * 1000,
        )
