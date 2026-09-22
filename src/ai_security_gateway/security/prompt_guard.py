from time import perf_counter

from ai_security_gateway.models.security import SecurityResult
from ai_security_gateway.security.normalization import canonicalize, normalize, validate_text
from ai_security_gateway.security.risk_engine import Finding, RiskEngine
from ai_security_gateway.security.rules import (
    EDUCATIONAL_PREFIX,
    EDUCATIONAL_WEIGHT_FACTOR,
    EXECUTION_CUE,
    EXTERNAL_SOURCE,
    INDIRECT_CONTEXT_WEIGHT,
    MODEL_ADDRESS,
    QUOTED,
    ROLE_MARKER,
    ROLE_MARKER_WEIGHT,
    RULES,
)


def _segments(text: str) -> list[tuple[str, float]]:
    """Discount only quoted examples with local explanatory context, never a whole input."""
    segments: list[tuple[str, float]] = []
    start = 0
    execution_requested = EXECUTION_CUE.search(normalize(text)) is not None
    for match in QUOTED.finditer(text):
        prefix = text[start : match.start()]
        educational = EDUCATIONAL_PREFIX.search(normalize(prefix)) and not execution_requested
        quoted_text = normalize(match.group())
        complete_indicator = any(rule.pattern.search(quoted_text) for rule in RULES) or (
            ROLE_MARKER.search(match.group()) is not None
        )
        # Splitting a quote containing only one word would hide cross-quote commands.
        if educational and complete_indicator:
            segments.append((prefix, 1.0))
            segments.append((match.group(), EDUCATIONAL_WEIGHT_FACTOR))
            start = match.end()
    segments.append((text[start:], 1.0))
    return segments


class PromptGuard:
    """Stateless local detector. Produces evidence for a separate, replaceable risk policy."""

    def analyze(self, text: str) -> SecurityResult:
        started = perf_counter()
        validate_text(text)
        canonical = canonicalize(text)
        findings = self.detect(canonical)
        score = RiskEngine.score(findings)
        level, action, assessment = RiskEngine.decide(score)
        explanations = list(dict.fromkeys(f.explanation for f in findings))
        explanation = " ".join(explanations) if findings else "No known attack indicators detected."
        if findings:
            explanation += (
                f" Combined evidence score: {score:.3f}; strongest weight per category, "
                "with reduced weight for contextualized educational quotations."
            )
        recommendations = list(dict.fromkeys(f.recommendation for f in findings))
        return SecurityResult(
            safe=assessment == "SAFE",
            assessment=assessment,
            risk_score=score,
            risk_level=level,
            threats=list(dict.fromkeys(f.threat for f in findings)),
            action=action,
            explanation=explanation,
            recommendations=recommendations
            or ["Continue to treat external content as untrusted data."],
            processing_time_ms=(perf_counter() - started) * 1000,
        )

    def detect(self, text: str) -> list[Finding]:
        """Return text-free evidence; future classifiers may supply additional Findings."""
        findings: list[Finding] = []
        for segment, factor in _segments(text):
            normalized = normalize(segment)
            for rule in RULES:
                if rule.pattern.search(normalized):
                    findings.append(
                        Finding(
                            rule.threat, rule.weight * factor, rule.explanation, rule.recommendation
                        )
                    )
            if ROLE_MARKER.search(segment):
                findings.append(
                    Finding(
                        "role_manipulation",
                        ROLE_MARKER_WEIGHT * factor,
                        "A serialized privileged-role marker appears in untrusted text.",
                        "Never parse user text as trusted conversation roles.",
                    )
                )
        # Source + model address + an actual instruction indicator: a keyword alone is insufficient.
        normalized = normalize(text)
        if (
            any(f.weight > 0.5 for f in findings)
            and EXTERNAL_SOURCE.search(normalized)
            and MODEL_ADDRESS.search(normalized)
        ):
            findings.append(
                Finding(
                    "indirect_prompt_injection",
                    INDIRECT_CONTEXT_WEIGHT,
                    "External-source context addresses the model alongside an instruction "
                    "indicator.",
                    "Do not promote external document text into trusted instructions.",
                )
            )
        return findings
