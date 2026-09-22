from collections.abc import Sequence

from ai_security_gateway.security.risk_engine import Finding


class SecurityAdvisor:
    """Explain policy using trusted detector metadata, never submitted content."""

    def advise(self, findings: Sequence[Finding], score: float) -> tuple[str, list[str]]:
        reasons = sorted({finding.explanation for finding in findings})
        explanation = " ".join(reasons) or "No known attack indicators detected."
        explanation += (
            f" Combined heuristic evidence score: {score:.3f}; strongest weight per category, "
            "with reduced weight for contextualized educational quotations."
        )
        recommendations = sorted({finding.recommendation for finding in findings})
        return explanation, recommendations or [
            "Continue to treat external content and sender identity as untrusted data."
        ]
