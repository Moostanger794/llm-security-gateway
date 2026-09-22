from collections.abc import Iterable
from dataclasses import dataclass
from math import isfinite, prod

from ai_security_gateway.models.security import Assessment, RiskLevel, SecurityAction, Threat


@dataclass(frozen=True)
class Finding:
    """Detector evidence without the submitted text; other detectors can reuse it."""

    threat: Threat
    weight: float
    explanation: str
    recommendation: str


class RiskEngine:
    """Deterministic policy; scores are heuristic evidence strength, not probabilities."""

    @staticmethod
    def score(findings: Iterable[Finding]) -> float:
        weights: dict[Threat, float] = {}
        for finding in findings:
            if not isfinite(finding.weight) or not 0 <= finding.weight <= 1:
                raise ValueError("Evidence weight must be finite and in [0, 1]")
            weights[finding.threat] = max(weights.get(finding.threat, 0), finding.weight)
        return round(1 - prod(1 - weight for weight in sorted(weights.values())), 6)

    @staticmethod
    def decide(score: float) -> tuple[RiskLevel, SecurityAction, Assessment]:
        if not isfinite(score) or not 0 <= score <= 1:
            raise ValueError("Risk score must be finite and in [0, 1]")
        if score <= 0.2:
            return "LOW", "ALLOW", "SAFE"
        if score <= 0.5:
            return "MEDIUM", "REQUIRE_CONFIRMATION", "SUSPICIOUS"
        if score <= 0.75:
            return "HIGH", "BLOCK", "DANGEROUS"
        return "CRITICAL", "BLOCK", "DANGEROUS"
